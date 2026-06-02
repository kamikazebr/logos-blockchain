use lb_cryptarchia_engine::{Epoch, Slot};
use lb_key_management_system_keys::keys::ZkPublicKey;
use lb_utils::bounded_vec::{NonEmptyBoundedVec, UpperBoundedVec};
use nom::IResult;
use serde::{Deserialize, Serialize};

use super::{ChannelId, Ed25519PublicKey, MsgId};
use crate::{
    crypto::{Digest as _, Hasher},
    events::Events,
    mantle::{
        TxHash,
        channel::{ChannelState, Channels, Error, SlotTimeframe, SlotTimeout},
        ledger,
        ledger::{Operation, Utxos},
        nom::{NomBoundedVec, NomDecode, NomEncode},
    },
    proofs::channel_multi_sig_proof::ChannelMultiSigProof,
};

pub const CHANNEL_MAX_KEYS: usize = u16::MAX as usize;
pub type Keys = NonEmptyBoundedVec<Ed25519PublicKey, CHANNEL_MAX_KEYS>;
pub type ZkKeys = UpperBoundedVec<ZkPublicKey, CHANNEL_MAX_KEYS>;
type NomKeys<'a> = NomBoundedVec<'a, Ed25519PublicKey, { Keys::MIN }, { Keys::MAX }, 2>;
type NomZkKeys<'a> = NomBoundedVec<'a, ZkPublicKey, { ZkKeys::MIN }, { ZkKeys::MAX }, 2>;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ChannelConfigOp {
    pub channel: ChannelId,
    pub keys: Keys,
    pub posting_timeframe: SlotTimeframe,
    pub posting_timeout: SlotTimeout,
    pub configuration_threshold: u16,
    pub withdraw_threshold: u16,
    pub sequencer_zk_pks: ZkKeys,
}

impl ChannelConfigOp {
    #[must_use]
    pub fn id(&self) -> MsgId {
        let mut hasher = Hasher::new();
        hasher.update(self.encode());
        MsgId(hasher.finalize().into())
    }
}

// ChannelConfig = ChannelId KeyCount *Ed25519PublicKey PostingTimeframe
// PostingTimeout ConfigThreshold WithdrawThreshold *ZkPublicKey
impl NomEncode for ChannelConfigOp {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.channel.encode());
        bytes.extend(NomKeys::from(&self.keys).encode());
        bytes.extend(self.posting_timeframe.encode());
        bytes.extend(self.posting_timeout.encode());
        bytes.extend(self.configuration_threshold.encode());
        bytes.extend(self.withdraw_threshold.encode());
        bytes.extend(NomZkKeys::from(&self.sequencer_zk_pks).encode());
        bytes
    }
}

impl NomDecode for ChannelConfigOp {
    type Output = Self;

    fn decode(bytes: &[u8]) -> IResult<&[u8], Self::Output> {
        let (bytes, channel) = ChannelId::decode(bytes)?;
        let (bytes, keys) = NomKeys::decode(bytes)?;
        let (bytes, posting_timeframe) = SlotTimeframe::decode(bytes)?;
        let (bytes, posting_timeout) = SlotTimeout::decode(bytes)?;
        let (bytes, configuration_threshold) = u16::decode(bytes)?;
        let (bytes, withdraw_threshold) = u16::decode(bytes)?;
        let (bytes, sequencer_zk_pks) = NomZkKeys::decode(bytes)?;

        Ok((
            bytes,
            Self {
                channel,
                keys,
                posting_timeframe,
                posting_timeout,
                configuration_threshold,
                withdraw_threshold,
                sequencer_zk_pks,
            },
        ))
    }
}

pub struct ChannelConfigValidationContext<'a> {
    pub channels: &'a Channels,
    pub tx_hash: &'a TxHash,
    pub config_sigs: &'a ChannelMultiSigProof,
}

pub struct ChannelConfigExecutionContext {
    pub channels: Channels,
    pub block_slot: Slot,
    pub utxos: Utxos,
}

impl Operation<ChannelConfigValidationContext<'_>> for ChannelConfigOp {
    type ExecutionContext<'a>
        = ChannelConfigExecutionContext
    where
        Self: 'a;
    type Error = Error;

    fn validate(&self, ctx: &ChannelConfigValidationContext<'_>) -> Result<(), Self::Error> {
        // Check that the indexes are unique and there is the same number of proof and
        // index. This is enforced by the proof structure that enforces it.

        // Check config wellformness
        if self.configuration_threshold == 0
            || self.withdraw_threshold == 0
            || self.keys.is_empty()
            || self.keys.len() != self.sequencer_zk_pks.len()
        {
            return Err(Error::InvalidChannelConfig);
        }

        if let Some(channel) = ctx.channels.channels.get(&self.channel).cloned() {
            // Check there is enough signatures
            let signatures = ctx.config_sigs.signatures();
            if signatures.len() != channel.configuration_threshold as usize {
                return Err(Error::ThresholdUnmet {
                    channel_id: self.channel,
                    threshold: channel.configuration_threshold,
                    actual: ctx.config_sigs.signatures().len(),
                });
            }

            // Check the signatures
            for sig in signatures {
                if channel
                    .accredited_keys
                    .get(sig.channel_key_index as usize)
                    .ok_or_else(|| Error::InvalidSignatureIndex {
                        channel_id: self.channel,
                        sequencers: channel.accredited_keys.len(),
                        index: sig.channel_key_index,
                    })?
                    .verify(ctx.tx_hash.as_signing_bytes().as_ref(), &sig.signature)
                    .is_err()
                {
                    return Err(Error::InvalidSignature);
                }
            }
        }

        Ok(())
    }

    fn execute(
        &self,
        mut ctx: Self::ExecutionContext<'_>,
    ) -> Result<(Self::ExecutionContext<'_>, Events), Self::Error> {
        // if the channel doesn't exist, create it otherwise just update the config
        if let Some(channel) = ctx.channels.channels.get_mut(&self.channel) {
            // Get the list of removed sequencers
            let removed_sequencers: Vec<&ZkPublicKey> = channel
                .sequencers_zk_pks
                .iter()
                .filter(|pk| !self.sequencer_zk_pks.as_slice().contains(pk))
                .collect();

            // Collect (Epoch, ZkPublicKey) keys whose sequencer was removed
            let entries_to_remove: Vec<(Epoch, ZkPublicKey)> = channel
                .frozen_note_map
                .iter()
                .filter(|((_, zk_pk), _)| removed_sequencers.contains(&zk_pk))
                .map(|(key, _)| *key)
                .collect();

            for key in entries_to_remove {
                // Pop from frozen_note_map
                let note_id = channel
                    .frozen_note_map
                    .get(&key)
                    .copied()
                    .expect("key was just collected from this map");
                channel.frozen_note_map = channel.frozen_note_map.remove(&key);

                // Unfreeze
                let note = ctx.channels.frozen_notes.unfreeze(&note_id)?;

                // remove from UTXO tree
                (ctx.utxos, _) = ctx
                    .utxos
                    .remove(&note_id)
                    .map_err(|_| Error::Inputs(ledger::InputsError::InexistingNote(note_id)))?;

                // Credit value back to the floating balance
                channel.floating_balance = channel
                    .floating_balance
                    .checked_add(note.value)
                    .ok_or(Error::BalanceOverflow)?;
            }

            // Update the channel
            channel.accredited_keys = self.keys.clone().into();
            channel.configuration_threshold = self.configuration_threshold;
            channel.tip_sequencer = 0;
            channel.tip_sequencer_starting_slot = ctx.block_slot;
            channel.posting_timeframe = self.posting_timeframe.clone();
            channel.posting_timeout = self.posting_timeout.clone();
            channel.withdraw_threshold = self.withdraw_threshold;
            channel.tip_slot = ctx.block_slot;
            channel.tip_message = self.id();
            channel.sequencers_zk_pks = self.sequencer_zk_pks.clone().into();
        } else {
            ctx.channels.channels = ctx.channels.channels.insert(
                self.channel,
                ChannelState {
                    accredited_keys: self.keys.clone().into(),
                    configuration_threshold: self.configuration_threshold,
                    tip_message: self.id(),
                    tip_slot: ctx.block_slot,
                    tip_sequencer: 0,
                    tip_sequencer_starting_slot: ctx.block_slot,
                    posting_timeframe: self.posting_timeframe.clone(),
                    floating_balance: 0,
                    solvency: 0,
                    frozen_note_map: rpds::HashTrieMapSync::default(),
                    sequencers_zk_pks: self.sequencer_zk_pks.clone().into(),
                    withdraw_threshold: self.withdraw_threshold,
                    withdrawal_nonce: 0,
                    posting_timeout: self.posting_timeout.clone(),
                },
            );
        }
        Ok((ctx, Events::new()))
    }
}
