use std::sync::Arc;

use lb_cryptarchia_engine::{Epoch, Slot};
use lb_key_management_system_keys::keys::ZkPublicKey;
use nom::{IResult, Parser as _, combinator::map};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{Digest as _, Hash, Hasher},
    events::Events,
    mantle::{
        Note, NoteId, Utxo, Value,
        frozen_notes::{self, FrozenNotes},
        ledger::{self, Operation as _},
        nom::{NomDecode, NomEncode},
        ops::channel::{
            ChannelId, ChannelKeyIndex, MsgId,
            config::{Keys, ZkKeys},
            inscribe::{InscriptionExecutionContext, InscriptionOp},
        },
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct SlotTimeframe(u32);

impl From<u32> for SlotTimeframe {
    fn from(slot: u32) -> Self {
        Self(slot)
    }
}

impl From<SlotTimeframe> for u32 {
    fn from(slot: SlotTimeframe) -> Self {
        slot.0
    }
}

impl NomEncode for SlotTimeframe {
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

impl NomDecode for SlotTimeframe {
    type Output = Self;

    fn decode(bytes: &[u8]) -> IResult<&[u8], Self::Output> {
        map(u32::decode, Self).parse(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct SlotTimeout(u32);

impl From<u32> for SlotTimeout {
    fn from(slot: u32) -> Self {
        Self(slot)
    }
}

impl From<SlotTimeout> for u32 {
    fn from(slot: SlotTimeout) -> Self {
        slot.0
    }
}

impl NomEncode for SlotTimeout {
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

impl NomDecode for SlotTimeout {
    type Output = Self;

    fn decode(bytes: &[u8]) -> IResult<&[u8], Self::Output> {
        map(u32::decode, Self).parse(bytes)
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid parent {parent:?} for channel {channel_id:?}, expected {actual:?}")]
    InvalidParent {
        channel_id: ChannelId,
        parent: [u8; 32],
        actual: [u8; 32],
    },
    #[error("Unauthorized signer {signer:?} for channel {channel_id:?}")]
    UnauthorizedSigner {
        channel_id: ChannelId,
        signer: String,
    },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error(
        "Invalid signature index {index:?} for channel {channel_id:?} which has {sequencers:?} sequencers"
    )]
    InvalidSignatureIndex {
        channel_id: ChannelId,
        sequencers: usize,
        index: ChannelKeyIndex,
    },
    #[error("Channel {channel_id:?} not found")]
    ChannelNotFound { channel_id: ChannelId },
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Balance overflow")]
    BalanceOverflow,
    #[error("The withdraw nonce doesn't correspond to the channel state")]
    InvalidWithdrawNonce,
    #[error("The Channel Config isn't well formed")]
    InvalidChannelConfig,
    #[error("Withdraw Nonce overflow")]
    WithdrawNonceOverflow,
    #[error("Inputs error: {0}")]
    Inputs(#[from] ledger::InputsError),
    #[error("Outputs error: {0}")]
    Outputs(#[from] ledger::OutputsError),
    #[error("Frozen notes error: {0}")]
    FrozenNotes(#[from] frozen_notes::Error),
    #[error(
        "Invalid number of signatures (treshold:?) for channel {channel_id:?}, expected {actual:?}"
    )]
    ThresholdUnmet {
        channel_id: ChannelId,
        threshold: u16,
        actual: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channels {
    pub channels: rpds::HashTrieMapSync<ChannelId, ChannelState>,
    pub mint_eligible_channels: Vec<ChannelId>,
    pub frozen_notes: FrozenNotes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelState {
    // Channel Configuration
    pub accredited_keys: Arc<Keys>, // keys.len() <= ChannelKeyIndex::MAX
    pub configuration_threshold: u16, /* indicating how many keys are required to update
                                     * the
                                     * configuration */

    // Message Ordering
    pub tip_message: MsgId,

    // Decentralized Sequencing
    pub tip_slot: Slot,
    pub tip_sequencer: u16, /* indicating the actual sequencer position in the list of
                             * accredited keys */
    pub tip_sequencer_starting_slot: Slot,
    pub posting_timeframe: SlotTimeframe, // number of slots (0 = infinity)
    pub posting_timeout: SlotTimeout,     // number of slots (0 = no timeout)

    // Bridging
    pub floating_balance: Value,
    pub solvency: Value,
    pub frozen_note_map: rpds::HashTrieMapSync<(Epoch, ZkPublicKey), NoteId>,
    pub sequencers_zk_pks: Arc<ZkKeys>,
    pub withdrawal_nonce: u32,
    pub withdraw_threshold: ChannelKeyIndex, /* indicating how many keys are required to
                                              * withdraw
                                              * funds from the channel */
}

pub(crate) const DEFAULT_WITHDRAW_THRESHOLD: ChannelKeyIndex = 1;

impl Default for Channels {
    fn default() -> Self {
        Self::new()
    }
}

impl Channels {
    pub fn from_genesis(op: &InscriptionOp) -> Result<(Self, Events), Error> {
        let (ctx, events) = op.execute(InscriptionExecutionContext {
            channels: Self::default(),
            block_slot: Slot::default(),
        })?;
        Ok((ctx.channels, events))
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            channels: rpds::HashTrieMapSync::new_sync(),
            mint_eligible_channels: vec![],
            frozen_notes: FrozenNotes::new(),
        }
    }

    pub fn mint_frozen_notes(&self, epoch: Epoch) -> Result<(Self, Vec<Utxo>), Error> {
        let mut channels = self.clone();
        let mut minted_utxos = Vec::new();

        for channel_id in &self.mint_eligible_channels {
            if let Some(channel) = channels.channels.get_mut(channel_id) {
                let num_sequencers = channel.sequencers_zk_pks.len();
                let note_value = channel
                    .floating_balance
                    .checked_div(num_sequencers as Value)
                    .unwrap_or(0);

                if num_sequencers > 0 && note_value > 0 {
                    channel.floating_balance -= note_value * num_sequencers as Value;

                    // Get the replacement of the op_id
                    let op_id: Hash = {
                        let mut hasher = Hasher::new();
                        hasher.update(b"CHANNEL_BRIDGE_NOTES");
                        hasher.update(channel_id.as_ref());
                        hasher.update(epoch.into_inner().to_le_bytes());
                        hasher.finalize().into()
                    };

                    for (idx, pk) in channel.sequencers_zk_pks.iter().enumerate() {
                        let note = Note::new(note_value, *pk);
                        let utxo = Utxo::new(op_id, idx, note);
                        let note_id = utxo.id();

                        channels.frozen_notes = channels
                            .frozen_notes
                            .freeze(note, &note_id)
                            .map_err(Error::FrozenNotes)?;

                        channel.frozen_note_map =
                            channel.frozen_note_map.insert((epoch, *pk), note_id);

                        minted_utxos.push(utxo);
                    }
                }
            }
        }

        channels.mint_eligible_channels.clear();

        Ok((channels, minted_utxos))
    }

    #[must_use]
    pub fn channel_state(&self, channel_id: &ChannelId) -> Option<&ChannelState> {
        self.channels.get(channel_id)
    }

    #[must_use]
    pub const fn frozen_notes(&self) -> &FrozenNotes {
        &self.frozen_notes
    }
}

impl ChannelState {
    #[must_use]
    pub fn last_mint_epoch(&self) -> Option<Epoch> {
        self.frozen_note_map
            .iter()
            .map(|((epoch, _), _)| *epoch)
            .max()
    }

    // Returns the new sequencer index and its starting slot
    #[must_use]
    pub fn round_robin(&self, block_slot: Slot) -> (u16, Slot) {
        let elapsed_slot_since_last_tip = (block_slot - self.tip_slot).into_inner();
        let tip_sequencer_duration = (block_slot - self.tip_sequencer_starting_slot).into_inner();
        let posting_timeframe = u64::from(self.posting_timeframe.0);
        let posting_timeout = u64::from(self.posting_timeout.0);
        let num_sequencers = self.accredited_keys.len() as u64; // bounded by ChannelKeyIndex::MAX
        let tip_sequencer = u64::from(self.tip_sequencer);
        let is_timed_out = elapsed_slot_since_last_tip >= posting_timeout && posting_timeout != 0;
        let sequencers_timed_out = elapsed_slot_since_last_tip.checked_div(posting_timeout); // None if posting_timeout == 0
        let timeframe_elapsed = tip_sequencer_duration.checked_div(posting_timeframe); // None if timeframe == 0

        // Timeout-based rotation takes priority when timed out.
        // Falls back to timeframe-based rotation, then to the current sequencer.
        let index = sequencers_timed_out
            .filter(|_| is_timed_out)
            .or(timeframe_elapsed)
            .map_or(self.tip_sequencer, |slot| {
                ((tip_sequencer + slot) % num_sequencers) as u16
            });

        // Starting slot mirrors the same priority.
        let starting_slot = sequencers_timed_out
            .filter(|_| is_timed_out)
            .map(|sequencers_timed_out| self.tip_slot + sequencers_timed_out * posting_timeout)
            .or_else(|| {
                timeframe_elapsed.map(|timeframe_elapsed| {
                    self.tip_sequencer_starting_slot + timeframe_elapsed * posting_timeframe
                })
            })
            .unwrap_or(self.tip_sequencer_starting_slot);
        (index, starting_slot)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field as _;
    use lb_groth16::Fr;
    use lb_key_management_system_keys::keys::{Ed25519Key, UnsecuredZkKey, ZkKey};
    use lb_utils::blake_rng::RngCore as _;
    use rand::thread_rng;
    use rpds::HashTrieMapSync;

    use super::*;
    use crate::{
        events::{Event, EventPayload},
        mantle::{
            ledger::{Outputs, Utxos},
            ops::{
                OpId as _,
                channel::{
                    Ed25519PublicKey as PublicKey,
                    deposit::{DepositExecutionContext, DepositOp, Metadata},
                    withdraw::{ChannelWithdrawOp, WithdrawExecutionContext},
                },
            },
            tx::{GasPrices, MantleTxGasContext},
        },
        sdp::locked_notes::LockedNotes,
    };

    fn test_public_key(seed: u8) -> PublicKey {
        Ed25519Key::from_bytes(&[seed; 32]).public_key()
    }

    fn test_public_zk_key(seed: u8) -> ZkPublicKey {
        UnsecuredZkKey::new(Fr::from(seed)).to_public_key()
    }

    fn make_channel(
        tip_slot: u64,
        tip_sequencer: u16,
        tip_sequencer_starting_slot: u64,
        posting_timeframe: u32,
        posting_timeout: u32,
        num_keys: u8,
    ) -> ChannelState {
        ChannelState {
            tip_slot: Slot::new(tip_slot),
            tip_sequencer,
            tip_sequencer_starting_slot: Slot::new(tip_sequencer_starting_slot),
            posting_timeframe: SlotTimeframe(posting_timeframe),
            posting_timeout: SlotTimeout(posting_timeout),
            floating_balance: 0,
            solvency: 0,
            frozen_note_map: HashTrieMapSync::new_sync(),
            sequencers_zk_pks: ZkKeys::try_from(
                (0..num_keys).map(test_public_zk_key).collect::<Vec<_>>(),
            )
            .unwrap()
            .into(),
            withdrawal_nonce: 0,
            accredited_keys: Keys::try_from((0..num_keys).map(test_public_key).collect::<Vec<_>>())
                .unwrap()
                .into(),
            configuration_threshold: 0,
            tip_message: MsgId::root(),
            withdraw_threshold: 0,
        }
    }

    fn utxo(value: Value) -> (ZkKey, Utxo) {
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
        let mut utxo_tree = Utxos::new();
        for utxo in utxos {
            (utxo_tree, _) = utxo_tree.insert(utxo.id(), utxo);
        }
        utxo_tree
    }

    impl Channels {
        #[must_use]
        pub fn with_balance(channel_id: ChannelId, balance: Value) -> Self {
            Self {
                channels: HashTrieMapSync::new_sync().insert(
                    channel_id,
                    ChannelState {
                        accredited_keys: Keys::from(test_public_key(7)).into(),
                        configuration_threshold: 1,
                        tip_message: MsgId::root(),
                        tip_slot: Slot::default(),
                        tip_sequencer: 0,
                        tip_sequencer_starting_slot: Slot::default(),
                        posting_timeframe: 0u32.into(),
                        withdraw_threshold: 1,
                        withdrawal_nonce: 0,
                        posting_timeout: 0u32.into(),
                        floating_balance: balance,
                        solvency: balance,
                        frozen_note_map: HashTrieMapSync::new_sync(),
                        sequencers_zk_pks: ZkKeys::from(test_public_zk_key(7)).into(),
                    },
                ),
                mint_eligible_channels: vec![],
                frozen_notes: FrozenNotes::new(),
            }
        }
    }

    #[test]
    fn channels_to_gas_context_tracks_withdraw_thresholds() {
        let first_id = ChannelId::from([1u8; 32]);
        let second_id = ChannelId::from([2u8; 32]);
        let missing_id = ChannelId::from([0u8; 32]);

        let channels = Channels {
            channels: HashTrieMapSync::new_sync()
                .insert(
                    first_id,
                    ChannelState {
                        accredited_keys: Keys::from(test_public_key(11)).into(),
                        configuration_threshold: 1,
                        tip_message: MsgId::root(),
                        tip_slot: Slot::default(),
                        tip_sequencer: 0,
                        tip_sequencer_starting_slot: Slot::default(),
                        posting_timeframe: 0u32.into(),
                        withdraw_threshold: 1,
                        withdrawal_nonce: 0,
                        posting_timeout: 0u32.into(),
                        floating_balance: 5,
                        solvency: 5,
                        frozen_note_map: HashTrieMapSync::new_sync(),
                        sequencers_zk_pks: ZkKeys::from(test_public_zk_key(11)).into(),
                    },
                )
                .insert(
                    second_id,
                    ChannelState {
                        accredited_keys: Keys::from([test_public_key(22), test_public_key(23)])
                            .into(),
                        configuration_threshold: 1,
                        tip_message: MsgId::root(),
                        tip_slot: Slot::default(),
                        tip_sequencer: 0,
                        tip_sequencer_starting_slot: Slot::default(),
                        posting_timeframe: 0.into(),
                        withdraw_threshold: 2,
                        withdrawal_nonce: 0,
                        posting_timeout: 0.into(),
                        floating_balance: 9,
                        solvency: 9,
                        frozen_note_map: HashTrieMapSync::new_sync(),
                        sequencers_zk_pks: ZkKeys::from([
                            test_public_zk_key(22),
                            test_public_zk_key(23),
                        ])
                        .into(),
                    },
                ),
            mint_eligible_channels: vec![],
            frozen_notes: FrozenNotes::new(),
        };

        let gas_context = MantleTxGasContext::from_channels(&channels, GasPrices::new(0, 0));

        assert_eq!(gas_context.withdraw_threshold(&first_id), Some(1));
        assert_eq!(gas_context.withdraw_threshold(&second_id), Some(2));
        assert_eq!(gas_context.withdraw_threshold(&missing_id), None);
    }

    #[test]
    fn deposit_increases_channel_balance() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = Channels::with_balance(channel_id, 10);

        let (_, utxo) = utxo(6u64);

        let deposit_op = DepositOp {
            channel_id,
            inputs: [utxo.id()].into(),
            metadata: Metadata::empty(),
        };

        let utxo_tree = utxo_tree(vec![utxo]);

        let (updated, events) = deposit_op
            .execute(DepositExecutionContext {
                channels,
                locked_notes: LockedNotes::new(),
                utxos: utxo_tree,
                tx_hash: [0; 32].into(),
            })
            .expect("execution should succeed");

        assert_eq!(
            updated
                .channels
                .channel_state(&channel_id)
                .unwrap()
                .solvency,
            16
        );

        assert_eq!(events.len(), 1);
        let Event::Tx {
            tx_hash,
            op_id,
            payload,
        } = events.iter().next().cloned().unwrap()
        else {
            panic!("expected Tx event")
        };
        assert_eq!(tx_hash, [0; 32].into());
        assert_eq!(op_id, deposit_op.op_id());
        let EventPayload::Deposit {
            channel_id,
            amount,
            metadata,
        } = payload;
        assert_eq!(channel_id, deposit_op.channel_id);
        assert_eq!(amount, utxo.note.value);
        assert_eq!(metadata, deposit_op.metadata);
    }

    #[test]
    fn withdraw_decreases_channel_balance() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = Channels::with_balance(channel_id, 10);

        let (_, utxo) = utxo(6u64);

        let withdraw_op = ChannelWithdrawOp {
            channel_id,
            outputs: Outputs::new([Note {
                value: 6,
                pk: ZkPublicKey::zero(),
            }]),
            withdraw_nonce: 0,
        };

        let utxo_tree = utxo_tree(vec![utxo]);

        let (updated, events) = withdraw_op
            .execute(WithdrawExecutionContext {
                channels,
                utxos: utxo_tree,
                current_epoch: 0.into(),
            })
            .expect("execution should succeed");

        assert_eq!(
            updated
                .channels
                .channel_state(&channel_id)
                .unwrap()
                .solvency,
            4
        );
        assert!(events.is_empty());
    }

    #[test]
    fn withdraw_fails_with_insufficient_funds() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = Channels::with_balance(channel_id, 3);

        let (_, utxo) = utxo(6u64);

        let withdraw_op = ChannelWithdrawOp {
            channel_id,
            outputs: Outputs::new([Note {
                value: 6,
                pk: ZkPublicKey::zero(),
            }]),
            withdraw_nonce: 0,
        };

        let utxo_tree = utxo_tree(vec![utxo]);

        let result = withdraw_op.execute(WithdrawExecutionContext {
            channels,
            utxos: utxo_tree,
            current_epoch: 0.into(),
        });

        assert!(matches!(result, Err(Error::InsufficientFunds)));
    }

    #[test]
    fn withdraw_fails_for_missing_channel() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = Channels::new();
        let (_, utxo) = utxo(6u64);

        let withdraw_op = ChannelWithdrawOp {
            channel_id,
            outputs: Outputs::new([Note {
                value: 6,
                pk: ZkPublicKey::zero(),
            }]),
            withdraw_nonce: 0,
        };

        let utxo_tree = utxo_tree(vec![utxo]);

        let result = withdraw_op.execute(WithdrawExecutionContext {
            channels,
            utxos: utxo_tree,
            current_epoch: 0.into(),
        });

        assert!(matches!(result, Err(Error::ChannelNotFound { .. })));
    }

    // 1. Infinite timeframe (timeframe=0): sequencer holds indefinitely unless
    //    timed out
    #[test]
    fn infinite_timeframe_no_timeout_stays_forever() {
        let channel = make_channel(100, 2, 80, 0, 0, 5);
        assert_eq!(channel.round_robin(100.into()), (2, 80.into()));
        assert_eq!(channel.round_robin(999_999.into()), (2, 80.into()));
    }

    #[test]
    fn infinite_timeframe_not_yet_timed_out() {
        let channel = make_channel(100, 1, 90, 0, 50, 4);
        assert_eq!(channel.round_robin(130.into()), (1, 90.into()));
    }

    #[test]
    fn infinite_timeframe_timed_out() {
        let channel = make_channel(100, 1, 90, 0, 50, 4);
        assert_eq!(channel.round_robin(150.into()), (2, 150.into()));
    }

    #[test]
    fn infinite_timeframe_multiple_timeouts() {
        let channel = make_channel(100, 1, 90, 0, 50, 4);
        assert_eq!(channel.round_robin(220.into()), (3, 200.into()));
    }

    // 2. Normal timeframe rotation (no timeout triggered)
    #[test]
    fn timeframe_rotation_same_slot_no_advance() {
        let channel = make_channel(100, 0, 100, 10, 0, 3);
        assert_eq!(channel.round_robin(100.into()), (0, 100.into()));
    }

    #[test]
    fn timeframe_rotation_within_first_frame() {
        let channel = make_channel(100, 0, 100, 10, 0, 3);
        assert_eq!(channel.round_robin(105.into()), (0, 100.into()));
    }

    #[test]
    fn timeframe_rotation_exact_boundary() {
        let channel = make_channel(100, 0, 100, 10, 0, 3);
        assert_eq!(channel.round_robin(110.into()), (1, 110.into()));
    }

    #[test]
    fn timeframe_rotation_multiple_frames() {
        let channel = make_channel(100, 0, 100, 10, 0, 4);
        assert_eq!(channel.round_robin(125.into()), (2, 120.into()));
    }

    #[test]
    fn timeframe_rotation_wraps_around() {
        let channel = make_channel(100, 2, 100, 10, 0, 3);
        assert_eq!(channel.round_robin(110.into()), (0, 110.into()));
    }

    #[test]
    fn timeframe_rotation_full_cycle() {
        // 3 keys, 3 rotations => back to the same sequencer
        let channel = make_channel(100, 1, 100, 10, 0, 3);
        assert_eq!(channel.round_robin(130.into()), (1, 130.into()));
    }

    #[test]
    fn timeframe_rotation_starting_slot_offset() {
        let channel = make_channel(100, 0, 95, 10, 0, 3);
        assert_eq!(channel.round_robin(105.into()), (1, 105.into()));
    }

    // 3. Timed out sequencers
    #[test]
    fn timeout_exact_boundary() {
        let channel = make_channel(100, 0, 100, 10, 20, 4);
        assert_eq!(channel.round_robin(120.into()), (1, 120.into()));
    }

    #[test]
    fn timeout_skips_multiple_unresponsive_sequencers() {
        let channel = make_channel(100, 0, 100, 5, 10, 4);
        assert_eq!(channel.round_robin(135.into()), (3, 130.into()));
    }

    #[test]
    fn timeout_wraps_past_end_of_key_list() {
        let channel = make_channel(100, 2, 100, 5, 10, 3);
        assert_eq!(channel.round_robin(120.into()), (1, 120.into()));
    }

    #[test]
    fn timeout_wraps_full_cycle() {
        let channel = make_channel(100, 0, 100, 5, 10, 3);
        assert_eq!(channel.round_robin(130.into()), (0, 130.into()));
    }

    // 4. No timeout (timeout=0)
    #[test]
    fn no_timeout_rotates_by_timeframe_even_after_long_absence() {
        let channel = make_channel(100, 0, 100, 10, 0, 3);
        assert_eq!(channel.round_robin(1100.into()), (1, 1100.into()));
    }

    // 5. Just below the timeout threshold
    #[test]
    fn just_below_timeout_uses_timeframe_branch() {
        let channel = make_channel(100, 0, 100, 10, 20, 4);
        assert_eq!(channel.round_robin(119.into()), (1, 110.into()));
    }

    // 6. Single sequencer
    #[test]
    fn single_key_always_index_zero() {
        let channel = make_channel(100, 0, 100, 10, 20, 1);
        assert_eq!(channel.round_robin(100.into()).0, 0);
        assert_eq!(channel.round_robin(115.into()).0, 0);
        assert_eq!(channel.round_robin(130.into()).0, 0);
    }

    // 7. Two sequencers
    #[test]
    fn two_sequencers_alternate() {
        let channel = make_channel(100, 0, 100, 5, 0, 2);
        assert_eq!(channel.round_robin(100.into()).0, 0);
        assert_eq!(channel.round_robin(104.into()).0, 0);
        assert_eq!(channel.round_robin(105.into()).0, 1);
        assert_eq!(channel.round_robin(109.into()).0, 1);
        assert_eq!(channel.round_robin(110.into()).0, 0);
    }

    // 8. 50 sequencers
    #[test]
    fn fifty_sequencers_rotate_and_wrap() {
        let channel = make_channel(0, 0, 0, 5, 0, 50);

        // After 5 slots => sequencer 1
        assert_eq!(channel.round_robin(5.into()).0, 1);
        // After 5*49 = 245 slots => sequencer 49 (last)
        assert_eq!(channel.round_robin(245.into()).0, 49);
        // After 5*50 = 250 slots => wrap back to 0
        assert_eq!(channel.round_robin(250.into()).0, 0);
        // After 5*73 = 365 slots => (0+73)%50 = 23
        assert_eq!(channel.round_robin(365.into()).0, 23);
    }

    #[test]
    fn fifty_sequencers_cascading_timeouts() {
        let channel = make_channel(1000, 10, 1000, 5, 3, 50);
        assert_eq!(channel.round_robin(1090.into()), (40, 1090.into()));
    }

    // 9. State transition: after timeout, new sequencer gets a fresh baseline
    #[test]
    fn after_timeout_new_sequencer_gets_fresh_starting_slot() {
        let channel = make_channel(110, 1, 110, 15, 10, 3);
        assert_eq!(channel.round_robin(125.into()), (2, 120.into()));
        assert_eq!(channel.round_robin(135.into()), (0, 130.into()));
    }

    // 10. Zero elapsed (block_slot == tip_slot)
    #[test]
    fn zero_elapsed_no_change() {
        let channel = make_channel(100, 3, 95, 10, 20, 5);
        assert_eq!(channel.round_robin(100.into()), (3, 95.into()));
    }

    // --- mint_frozen_notes ---

    fn channels_with_mint_candidates(
        channel_id: ChannelId,
        floating_balance: Value,
        zk_pks: Vec<ZkPublicKey>,
    ) -> Channels {
        let mut channels = Channels::new();
        let n = zk_pks.len() as u8;
        channels.channels = channels.channels.insert(
            channel_id,
            ChannelState {
                accredited_keys: Keys::try_from((0..n).map(test_public_key).collect::<Vec<_>>())
                    .unwrap()
                    .into(),
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
                solvency: floating_balance,
                frozen_note_map: HashTrieMapSync::new_sync(),
                sequencers_zk_pks: ZkKeys::try_from(zk_pks).unwrap().into(),
            },
        );
        channels.mint_eligible_channels.push(channel_id);
        channels
    }

    #[test]
    fn mints_one_note_per_sequencer() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk0 = test_public_zk_key(0);
        let pk1 = test_public_zk_key(1);
        let epoch: Epoch = 3.into();

        let channels = channels_with_mint_candidates(channel_id, 13, vec![pk0, pk1]);

        let (updated, utxos) = channels.mint_frozen_notes(epoch).unwrap();

        assert_eq!(utxos.len(), 2);
        // floor(13 / 2) = 6
        assert!(utxos.iter().all(|u| u.note.value == 6));

        // Floating balance reduced by note_value * n_sequencers = 12
        assert_eq!(
            updated.channel_state(&channel_id).unwrap().floating_balance,
            1
        );

        // frozen_note_map has one entry per sequencer for this epoch
        let state = updated.channel_state(&channel_id).unwrap();
        assert!(state.frozen_note_map.contains_key(&(epoch, pk0)));
        assert!(state.frozen_note_map.contains_key(&(epoch, pk1)));

        for utxo in &utxos {
            assert!(updated.frozen_notes.contains(&utxo.id()));
        }

        // mint_eligible_channels cleared
        assert!(updated.mint_eligible_channels.is_empty());
    }

    #[test]
    fn skips_channel_with_no_sequencers() {
        let channel_id = ChannelId::from([0u8; 32]);
        let mut channels = Channels::new();
        channels.channels = channels.channels.insert(
            channel_id,
            ChannelState {
                accredited_keys: Keys::from(test_public_key(0)).into(),
                configuration_threshold: 1,
                tip_message: MsgId::root(),
                tip_slot: Slot::default(),
                tip_sequencer: 0,
                tip_sequencer_starting_slot: Slot::default(),
                posting_timeframe: 0.into(),
                posting_timeout: 0.into(),
                withdraw_threshold: 1,
                withdrawal_nonce: 0,
                floating_balance: 100,
                solvency: 100,
                frozen_note_map: HashTrieMapSync::new_sync(),
                sequencers_zk_pks: ZkKeys::try_from(vec![]).unwrap().into(),
            },
        );
        channels.mint_eligible_channels.push(channel_id);

        let (updated, utxos) = channels.mint_frozen_notes(1.into()).unwrap();

        assert!(utxos.is_empty());
        assert_eq!(
            updated.channel_state(&channel_id).unwrap().floating_balance,
            100
        );
        assert!(updated.mint_eligible_channels.is_empty());
    }

    #[test]
    fn skips_when_balance_smaller_than_sequencer_count() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = channels_with_mint_candidates(
            channel_id,
            1,
            vec![test_public_zk_key(0), test_public_zk_key(1)],
        );

        let (updated, utxos) = channels.mint_frozen_notes(1.into()).unwrap();

        assert!(utxos.is_empty());
        assert_eq!(
            updated.channel_state(&channel_id).unwrap().floating_balance,
            1
        );
        assert!(
            updated
                .channel_state(&channel_id)
                .unwrap()
                .frozen_note_map
                .is_empty()
        );
        assert!(updated.mint_eligible_channels.is_empty());
    }

    #[test]
    fn map_entries_match_returned_utxo_ids() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk0 = test_public_zk_key(0);
        let pk1 = test_public_zk_key(1);
        let epoch: Epoch = 5.into();

        let channels = channels_with_mint_candidates(channel_id, 10, vec![pk0, pk1]);
        let (updated, utxos) = channels.mint_frozen_notes(epoch).unwrap();

        let state = updated.channel_state(&channel_id).unwrap();

        // The note_id stored in frozen_note_map for each (epoch, pk) must exactly
        // match the id of the corresponding returned utxo.
        for utxo in &utxos {
            let pk = utxo.note.pk;
            let stored_note_id = state
                .frozen_note_map
                .get(&(epoch, pk))
                .copied()
                .expect("entry must be present for every sequencer pk");
            assert_eq!(stored_note_id, utxo.id());
        }
    }

    #[test]
    fn all_minted_notes_are_in_frozen_set() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pks = vec![
            test_public_zk_key(0),
            test_public_zk_key(1),
            test_public_zk_key(2),
        ];
        let channels = channels_with_mint_candidates(channel_id, 9, pks);
        let (updated, utxos) = channels.mint_frozen_notes(2.into()).unwrap();

        assert_eq!(utxos.len(), 3);
        for utxo in &utxos {
            assert!(updated.frozen_notes.contains(&utxo.id()));
        }
    }

    #[test]
    fn mint_eligible_channels_cleared_even_when_nothing_minted() {
        let channel_id = ChannelId::from([0u8; 32]);
        let channels = channels_with_mint_candidates(channel_id, 0, vec![test_public_zk_key(0)]);

        assert_eq!(channels.mint_eligible_channels.len(), 1);

        let (updated, utxos) = channels.mint_frozen_notes(1.into()).unwrap();

        assert!(utxos.is_empty());
        assert!(updated.mint_eligible_channels.is_empty());
    }

    #[test]
    fn silently_skips_missing_channel() {
        let present_id = ChannelId::from([0u8; 32]);
        let ghost_id = ChannelId::from([1u8; 32]);

        let mut channels =
            channels_with_mint_candidates(present_id, 10, vec![test_public_zk_key(0)]);
        // ghost_id is in mint_eligible_channels but has no entry in channels map
        channels.mint_eligible_channels.push(ghost_id);

        let (updated, utxos) = channels.mint_frozen_notes(1.into()).unwrap();

        // Only the present channel minted one note
        assert_eq!(utxos.len(), 1);
        assert!(updated.channel_state(&present_id).is_some());
        // ghost channel was skipped without error
        assert!(updated.channel_state(&ghost_id).is_none());
        assert!(updated.mint_eligible_channels.is_empty());
    }

    #[test]
    fn processes_all_eligible_channels() {
        let id_a = ChannelId::from([0u8; 32]);
        let id_b = ChannelId::from([1u8; 32]);
        let epoch: Epoch = 1.into();

        let mut channels = channels_with_mint_candidates(
            id_a,
            6,
            vec![test_public_zk_key(0), test_public_zk_key(1)],
        );

        channels.channels = channels.channels.insert(
            id_b,
            ChannelState {
                accredited_keys: Keys::from(test_public_key(2)).into(),
                configuration_threshold: 1,
                tip_message: MsgId::root(),
                tip_slot: Slot::default(),
                tip_sequencer: 0,
                tip_sequencer_starting_slot: Slot::default(),
                posting_timeframe: 0.into(),
                posting_timeout: 0.into(),
                withdraw_threshold: 1,
                withdrawal_nonce: 0,
                floating_balance: 9,
                solvency: 9,
                frozen_note_map: HashTrieMapSync::new_sync(),
                sequencers_zk_pks: ZkKeys::from(test_public_zk_key(2)).into(),
            },
        );
        channels.mint_eligible_channels.push(id_b);

        let (updated, utxos) = channels.mint_frozen_notes(epoch).unwrap();

        // Channel A: 2 sequencers, balance 6 → 2 notes of value 3
        let state_a = updated.channel_state(&id_a).unwrap();
        assert_eq!(state_a.floating_balance, 0);
        assert_eq!(state_a.frozen_note_map.size(), 2);

        // Channel B: 1 sequencer, balance 9 → 1 note of value 9
        let state_b = updated.channel_state(&id_b).unwrap();
        assert_eq!(state_b.floating_balance, 0);
        assert_eq!(state_b.frozen_note_map.size(), 1);

        assert_eq!(utxos.len(), 3);
        assert!(updated.mint_eligible_channels.is_empty());
    }

    #[test]
    fn note_ids_are_deterministic() {
        let channel_id = ChannelId::from([0u8; 32]);
        let epoch: Epoch = 1.into();
        let channels = channels_with_mint_candidates(
            channel_id,
            10,
            vec![test_public_zk_key(0), test_public_zk_key(1)],
        );

        let (_, utxos_first) = channels.mint_frozen_notes(epoch).unwrap();
        let (_, utxos_second) = channels.mint_frozen_notes(epoch).unwrap();

        assert_eq!(utxos_first.len(), utxos_second.len());
        for (a, b) in utxos_first.iter().zip(utxos_second.iter()) {
            assert_eq!(a.id(), b.id());
        }
    }

    #[test]
    fn frozen_notes_are_present_in_utxo_tree_after_insertion() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pks = vec![test_public_zk_key(0), test_public_zk_key(1)];
        let channels = channels_with_mint_candidates(channel_id, 10, pks);

        let (_, minted_utxos) = channels.mint_frozen_notes(1.into()).unwrap();

        // Insert minted UTXOs into a UTXO tree
        let mut tree = Utxos::new();
        for utxo in &minted_utxos {
            (tree, _) = tree.insert(utxo.id(), *utxo);
        }

        for utxo in &minted_utxos {
            let note_id = utxo.id();
            assert!(
                tree.utxos().contains_key(&note_id),
                "note {note_id:?} must be in the UTxO tree"
            );
        }
    }
}
