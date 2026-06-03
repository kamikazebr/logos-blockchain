use lb_key_management_system_keys::keys::{ZkPublicKey, ZkSignature};
use lb_utils::bounded_vec::UpperBoundedVec;
use nom::IResult;
use serde::{Deserialize, Serialize};

use crate::{
    events::{Event, EventPayload, Events},
    mantle::{
        TxHash,
        channel::{Channels, Error},
        frozen_notes::FrozenNotes,
        ledger::{Inputs, Operation, Utxos},
        nom::{NomBoundedVec, NomDecode, NomEncode},
        ops::{OpId, channel::ChannelId},
    },
    sdp::locked_notes::LockedNotes,
};

pub const MAX_METADATA_SIZE: usize = u32::MAX as usize;
pub type Metadata = UpperBoundedVec<u8, { MAX_METADATA_SIZE }>;
type NomMetadata<'a> = NomBoundedVec<'a, u8, { Metadata::MIN }, { Metadata::MAX }, 4>;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DepositOp {
    pub channel_id: ChannelId,
    pub inputs: Inputs,
    pub metadata: Metadata,
}

impl OpId for DepositOp {
    fn op_bytes(&self) -> Vec<u8> {
        self.encode()
    }
}

impl NomEncode for DepositOp {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.channel_id.encode());
        bytes.extend(self.inputs.encode());
        bytes.extend(NomMetadata::from(&self.metadata).encode());
        bytes
    }
}

impl NomDecode for DepositOp {
    type Output = Self;

    fn decode(bytes: &[u8]) -> IResult<&[u8], Self::Output> {
        let (bytes, channel_id) = ChannelId::decode(bytes)?;
        let (bytes, inputs) = Inputs::decode(bytes)?;
        let (bytes, metadata) = NomMetadata::decode(bytes)?;
        Ok((
            bytes,
            Self {
                channel_id,
                inputs,
                metadata,
            },
        ))
    }
}

pub struct DepositValidationContext<'a> {
    pub channels: &'a Channels,
    pub locked_notes: &'a LockedNotes,
    pub frozen_notes: &'a FrozenNotes,
    pub utxos: &'a Utxos,
    pub tx_hash: &'a TxHash,
    pub deposit_sig: &'a ZkSignature,
}

pub struct DepositExecutionContext {
    pub channels: Channels,
    pub locked_notes: LockedNotes,
    pub utxos: Utxos,
    pub tx_hash: TxHash,
}

impl Operation<DepositValidationContext<'_>> for DepositOp {
    type ExecutionContext<'a>
        = DepositExecutionContext
    where
        Self: 'a;
    type Error = Error;

    fn validate(&self, ctx: &DepositValidationContext<'_>) -> Result<(), Self::Error> {
        // Check that the channel exist
        if !ctx.channels.channels.contains_key(&self.channel_id) {
            return Err(Error::ChannelNotFound {
                channel_id: self.channel_id,
            });
        }

        // Check that inputs are valid
        self.inputs
            .validate(ctx.locked_notes, ctx.frozen_notes, ctx.utxos)?;

        // Check the signature
        let pks = self.inputs.get_pk(ctx.utxos)?;
        if !ZkPublicKey::verify_multi(&pks, &ctx.tx_hash.to_fr(), ctx.deposit_sig) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }

    fn execute(
        &self,
        mut ctx: Self::ExecutionContext<'_>,
    ) -> Result<(Self::ExecutionContext<'_>, Events), Self::Error> {
        // Get the amount deposited
        let amount_deposited = self.inputs.amount(&ctx.utxos)?;

        // Remove inputs from the ledger
        ctx.utxos = self.inputs.execute(ctx.utxos)?;

        if let Some(channel) = ctx.channels.channels.get_mut(&self.channel_id) {
            // Increase the balance of the channel
            channel.floating_balance = channel
                .floating_balance
                .checked_add(amount_deposited)
                .ok_or(Error::BalanceOverflow)?;
            channel.solvency = channel
                .solvency
                .checked_add(amount_deposited)
                .ok_or(Error::BalanceOverflow)?;

            // mark the channel if it is eligible to mint frozen notes and not already
            // marked
            if !channel.sequencers_zk_pks.is_empty()
                && channel.sequencers_zk_pks.len() <= channel.floating_balance as usize
                && !ctx
                    .channels
                    .mint_eligible_channels
                    .contains(&self.channel_id)
            {
                ctx.channels.mint_eligible_channels.push(self.channel_id);
            }

            Ok(self)
        } else {
            Err(Error::ChannelNotFound {
                channel_id: self.channel_id,
            })
        }?;

        let events = std::iter::once(Event::from_tx(
            ctx.tx_hash,
            self.op_id(),
            EventPayload::Deposit {
                channel_id: self.channel_id,
                amount: amount_deposited,
                metadata: self.metadata.clone(),
            },
        ))
        .collect();

        Ok((ctx, events))
    }
}

#[cfg(test)]
mod tests {
    use lb_cryptarchia_engine::{Epoch, Slot};
    use lb_groth16::{Field as _, Fr};
    use lb_key_management_system_keys::keys::{Ed25519Key, UnsecuredZkKey, ZkKey};
    use rand::thread_rng;
    use rpds::HashTrieMapSync;

    use super::*;
    use crate::mantle::{
        Note, NoteId, Utxo,
        channel::ChannelState,
        ops::channel::{
            Ed25519PublicKey, MsgId,
            config::{Keys, ZkKeys},
        },
    };

    fn ed_pk(seed: u8) -> Ed25519PublicKey {
        Ed25519Key::from_bytes(&[seed; 32]).public_key()
    }

    fn zk_pk(seed: u8) -> ZkPublicKey {
        UnsecuredZkKey::new(Fr::from(seed)).to_public_key()
    }

    fn make_utxo(value: u64) -> (ZkKey, Utxo) {
        use lb_utils::blake_rng::RngCore as _;
        let mut op_id = [0u8; 32];
        thread_rng().fill_bytes(&mut op_id);
        let zk_sk = ZkKey::from(Fr::ZERO);
        let utxo = Utxo {
            op_id,
            output_index: 0,
            note: Note::new(value, zk_sk.to_public_key()),
        };
        (zk_sk, utxo)
    }

    fn utxo_tree(utxos: Vec<Utxo>) -> Utxos {
        let mut tree = Utxos::new();
        for u in utxos {
            (tree, _) = tree.insert(u.id(), u);
        }
        tree
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

    /// Wraps a single channel state into a fresh `Channels`.
    fn channels_with(channel_id: ChannelId, state: ChannelState) -> Channels {
        let mut channels = Channels::new();
        channels.channels = channels.channels.insert(channel_id, state);
        channels
    }

    /// Channel with `n` sequencers (zk keys `0..n`), `n.max(1)` accredited keys
    /// and the given floating balance / solvency.
    fn channel_with_sequencers(channel_id: ChannelId, balance: u64, n: u8) -> Channels {
        channels_with(
            channel_id,
            channel_state(
                (0..n.max(1)).map(ed_pk).collect(),
                (0..n).map(zk_pk).collect(),
                balance,
                balance,
                vec![],
            ),
        )
    }

    fn execute_deposit(channels: Channels, value: u64) -> Channels {
        let channel_id = *channels.channels.keys().next().unwrap();
        let (_, utxo) = make_utxo(value);
        let op = DepositOp {
            channel_id,
            inputs: [utxo.id()].into(),
            metadata: Metadata::empty(),
        };
        op.execute(DepositExecutionContext {
            channels,
            locked_notes: LockedNotes::new(),
            utxos: utxo_tree(vec![utxo]),
            tx_hash: [0u8; 32].into(),
        })
        .unwrap()
        .0
        .channels
    }

    #[test]
    fn deposit_marks_mint_eligible_when_balance_meets_or_exceeds_sequencer_count() {
        let channel_id = ChannelId::from([0u8; 32]);

        // balance == n_sequencers (boundary: exactly eligible)
        let channels = channel_with_sequencers(channel_id, 0, 2);
        let updated = execute_deposit(channels, 2);
        assert!(updated.mint_eligible_channels.contains(&channel_id));

        // balance > n_sequencers (clearly eligible)
        let channels = channel_with_sequencers(channel_id, 0, 2);
        let updated = execute_deposit(channels, 5);
        assert!(updated.mint_eligible_channels.contains(&channel_id));
    }

    #[test]
    fn deposit_does_not_mark_mint_eligible_when_no_sequencers() {
        let channel_id = ChannelId::from([0u8; 32]);
        // 0 sequencers → never eligible regardless of balance
        let channels = channel_with_sequencers(channel_id, 0, 0);
        let updated = execute_deposit(channels, 10);
        assert!(!updated.mint_eligible_channels.contains(&channel_id));
    }

    #[test]
    fn deposit_does_not_duplicate_mint_eligible_channels() {
        let channel_id = ChannelId::from([0u8; 32]);
        // First deposit makes the channel eligible
        let channels = channel_with_sequencers(channel_id, 0, 1);
        let updated = execute_deposit(channels, 5);
        assert_eq!(
            updated
                .mint_eligible_channels
                .iter()
                .filter(|&&id| id == channel_id)
                .count(),
            1
        );

        // Second deposit must not add it again
        let updated2 = execute_deposit(updated, 5);
        assert_eq!(
            updated2
                .mint_eligible_channels
                .iter()
                .filter(|&&id| id == channel_id)
                .count(),
            1
        );
    }
}
