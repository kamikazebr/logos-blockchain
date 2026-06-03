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

            // Mark as mint-eligible if the new sequencer set can now consume the
            // floating balance.
            if channel.sequencers_zk_pks.len() <= channel.floating_balance as usize
                && !ctx.channels.mint_eligible_channels.contains(&self.channel)
            {
                ctx.channels.mint_eligible_channels.push(self.channel);
            }
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

#[cfg(test)]
mod tests {
    use lb_groth16::Fr;
    use lb_key_management_system_keys::keys::UnsecuredZkKey;
    use rpds::HashTrieMapSync;

    use super::*;
    use crate::mantle::{Note, NoteId, Utxo};

    fn dummy_tx_hash() -> TxHash {
        [0u8; 32].into()
    }

    fn empty_proof() -> ChannelMultiSigProof {
        ChannelMultiSigProof::new(vec![]).unwrap()
    }

    fn zk_pk(seed: u8) -> ZkPublicKey {
        UnsecuredZkKey::new(Fr::from(seed)).to_public_key()
    }

    fn ed_pk(seed: u8) -> Ed25519PublicKey {
        use lb_key_management_system_keys::keys::Ed25519Key;
        Ed25519Key::from_bytes(&[seed; 32]).public_key()
    }

    /// Builds a UTXO tree containing the given UTXOs, keyed by their id.
    fn utxo_tree(utxos: impl IntoIterator<Item = Utxo>) -> Utxos {
        let mut tree = Utxos::new();
        for utxo in utxos {
            (tree, _) = tree.insert(utxo.id(), utxo);
        }
        tree
    }

    /// Wraps a single channel state into a fresh `Channels`.
    fn channels_with(channel_id: ChannelId, state: ChannelState) -> Channels {
        let mut channels = Channels::new();
        channels.channels = channels.channels.insert(channel_id, state);
        channels
    }

    /// Constructs a [`ChannelState`] with `1` thresholds and no posting
    /// timeframe/timeout. `frozen_notes` lists the `(epoch, pk, note_id)`
    /// entries to register in the channel's frozen-note map.
    fn channel_state(
        accredited_keys: Vec<Ed25519PublicKey>,
        sequencers: Vec<ZkPublicKey>,
        floating_balance: u64,
        solvency: u64,
        frozen_notes: Vec<(Epoch, ZkPublicKey, NoteId)>,
    ) -> ChannelState {
        let mut frozen_note_map = HashTrieMapSync::new_sync();
        for (epoch, pk, note_id) in frozen_notes {
            frozen_note_map = frozen_note_map.insert((epoch, pk), note_id);
        }
        ChannelState {
            accredited_keys: Keys::try_from(accredited_keys).unwrap().into(),
            configuration_threshold: 1,
            tip_message: MsgId::root(),
            tip_slot: Slot::default(),
            tip_sequencer: 0,
            tip_sequencer_starting_slot: Slot::default(),
            posting_timeframe: 0.into(),
            posting_timeout: 0.into(),
            withdraw_threshold: 1,
            withdrawal_nonce: 0,
            floating_balance,
            solvency,
            frozen_note_map,
            sequencers_zk_pks: ZkKeys::try_from(sequencers).unwrap().into(),
        }
    }

    /// Constructs a [`ChannelConfigOp`] with `1` thresholds and zero posting
    /// timeframe/timeout.
    fn config_op(
        channel: ChannelId,
        keys: Vec<Ed25519PublicKey>,
        sequencers: Vec<ZkPublicKey>,
    ) -> ChannelConfigOp {
        ChannelConfigOp {
            channel,
            keys: Keys::try_from(keys).unwrap(),
            posting_timeframe: 0.into(),
            posting_timeout: 0.into(),
            configuration_threshold: 1,
            withdraw_threshold: 1,
            sequencer_zk_pks: ZkKeys::try_from(sequencers).unwrap(),
        }
    }

    #[test]
    fn config_rejected_when_key_count_differs_from_zk_pk_count() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = Channels::new();
        let tx_hash = dummy_tx_hash();
        let proof = empty_proof();

        // 2 ed keys but only 1 zk key → mismatch
        let op = config_op(channel_id, vec![ed_pk(0), ed_pk(1)], vec![zk_pk(0)]);

        let ctx = ChannelConfigValidationContext {
            channels: &channels,
            tx_hash: &tx_hash,
            config_sigs: &proof,
        };

        assert_eq!(op.validate(&ctx), Err(Error::InvalidChannelConfig));
    }

    #[test]
    fn config_unfreezes_removed_sequencer_frozen_notes() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk_keep = zk_pk(0);
        let pk_remove = zk_pk(1);
        let epoch: Epoch = 1.into();
        let note_value: u64 = 10;

        // Build the frozen note for the sequencer being removed
        let note = Note::new(note_value, pk_remove);
        let utxo = Utxo::new([1u8; 32], 0, note);
        let note_id = utxo.id();

        // Insert note into UTXO tree
        let utxos = utxo_tree([utxo]);

        // Build channel state with both sequencers and the frozen note
        let mut channels = channels_with(
            channel_id,
            channel_state(
                vec![ed_pk(0), ed_pk(1)],
                vec![pk_keep, pk_remove],
                5,
                15,
                vec![(epoch, pk_remove, note_id)],
            ),
        );
        channels.frozen_notes = channels.frozen_notes.freeze(note, &note_id).unwrap();

        // Config op that drops pk_remove and keeps only pk_keep
        let op = config_op(channel_id, vec![ed_pk(0)], vec![pk_keep]);

        let (result, _) = op
            .execute(ChannelConfigExecutionContext {
                channels,
                block_slot: Slot::default(),
                utxos,
            })
            .unwrap();

        let state = result.channels.channel_state(&channel_id).unwrap();

        // Frozen note value returned to floating balance
        assert_eq!(state.floating_balance, 5 + note_value);
        // Removed sequencer's entry cleared from the map
        assert!(state.frozen_note_map.get(&(epoch, pk_remove)).is_none());
        // Note removed from global frozen set
        assert!(!result.channels.frozen_notes.contains(&note_id));
    }

    #[test]
    fn config_keeps_frozen_notes_when_sequencer_set_unchanged() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk = zk_pk(0);
        let epoch: Epoch = 1.into();
        let note_value: u64 = 10;

        let note = Note::new(note_value, pk);
        let utxo = Utxo::new([1u8; 32], 0, note);
        let note_id = utxo.id();

        let utxos = utxo_tree([utxo]);

        let mut channels = channels_with(
            channel_id,
            channel_state(vec![ed_pk(0)], vec![pk], 5, 15, vec![(epoch, pk, note_id)]),
        );
        channels.frozen_notes = channels.frozen_notes.freeze(note, &note_id).unwrap();

        // Config op keeps the same sequencer pk
        let op = config_op(channel_id, vec![ed_pk(0)], vec![pk]);

        let (result, _) = op
            .execute(ChannelConfigExecutionContext {
                channels,
                block_slot: Slot::default(),
                utxos,
            })
            .unwrap();

        let state = result.channels.channel_state(&channel_id).unwrap();

        // Floating balance unchanged
        assert_eq!(state.floating_balance, 5);
        // Frozen note map entry preserved
        assert_eq!(
            state.frozen_note_map.get(&(epoch, pk)).copied(),
            Some(note_id)
        );
        // Frozen note still tracked
        assert!(result.channels.frozen_notes.contains(&note_id));
    }

    #[test]
    fn config_marks_channel_mint_eligible_when_sequencers_added_with_sufficient_balance() {
        let channel_id = ChannelId::from([0u8; 32]);

        // Channel exists with floating balance but no sequencers yet
        let channels = channels_with(
            channel_id,
            channel_state(vec![ed_pk(0)], vec![], 10, 10, vec![]),
        );

        // Config op introduces 2 sequencers — balance 10 > 2
        let op = config_op(
            channel_id,
            vec![ed_pk(0), ed_pk(1)],
            vec![zk_pk(0), zk_pk(1)],
        );

        let (result, _) = op
            .execute(ChannelConfigExecutionContext {
                channels,
                block_slot: Slot::default(),
                utxos: Utxos::new(),
            })
            .unwrap();

        assert!(result.channels.mint_eligible_channels.contains(&channel_id));
    }
}
