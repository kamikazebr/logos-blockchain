use lb_cryptarchia_engine::Epoch;
use serde::{Deserialize, Serialize};

use crate::{
    events::Events,
    mantle::{
        TxHash,
        channel::{Channels, Error},
        encoding::encode_channel_withdraw,
        ledger::{self, Operation, Outputs, Utxos},
        ops::{OpId, channel::ChannelId},
    },
    proofs::channel_multi_sig_proof::ChannelMultiSigProof,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelWithdrawOp {
    pub channel_id: ChannelId,
    pub outputs: Outputs,
    pub withdraw_nonce: u32,
}

impl OpId for ChannelWithdrawOp {
    fn op_bytes(&self) -> Vec<u8> {
        encode_channel_withdraw(self)
    }
}

pub struct WithdrawValidationContext<'a> {
    pub channels: &'a Channels,
    pub tx_hash: &'a TxHash,
    pub withdraw_sigs: &'a ChannelMultiSigProof,
}

pub struct WithdrawExecutionContext {
    pub channels: Channels,
    pub utxos: Utxos,
    pub current_epoch: Epoch,
}

impl Operation<WithdrawValidationContext<'_>> for ChannelWithdrawOp {
    type ExecutionContext<'a>
        = WithdrawExecutionContext
    where
        Self: 'a;
    type Error = Error;

    fn validate(&self, ctx: &WithdrawValidationContext<'_>) -> Result<(), Self::Error> {
        // Check that the outputs are valid
        self.outputs.validate()?;

        // Check that the channel exist
        if !ctx.channels.channels.contains_key(&self.channel_id) {
            return Err(Error::ChannelNotFound {
                channel_id: self.channel_id,
            });
        }

        // Check that the withdrawal nonce is correct
        let channel = ctx
            .channels
            .channels
            .get(&self.channel_id)
            .cloned()
            .expect("we checked that the channel exist above");
        if channel.withdrawal_nonce != self.withdraw_nonce {
            return Err(Error::InvalidWithdrawNonce);
        }

        // Check that the channel has enough funds
        let amount = self.outputs.amount()?;
        if amount > channel.solvency {
            return Err(Error::InsufficientFunds);
        }

        // Check that the indexes are unique and there is the same number of proof and
        // index. This is enforced by the proof structure that enforces it.

        // Check there is enough signatures
        let signatures = ctx.withdraw_sigs.signatures();
        if signatures.len() != channel.withdraw_threshold as usize {
            return Err(Error::ThresholdUnmet {
                channel_id: self.channel_id,
                threshold: channel.withdraw_threshold,
                actual: ctx.withdraw_sigs.signatures().len(),
            });
        }

        // Check the signatures
        for sig in signatures {
            if channel.accredited_keys[sig.channel_key_index as usize]
                .verify(ctx.tx_hash.as_signing_bytes().as_ref(), &sig.signature)
                .is_err()
            {
                return Err(Error::InvalidSignature);
            }
        }

        Ok(())
    }

    fn execute(
        &self,
        mut ctx: Self::ExecutionContext<'_>,
    ) -> Result<(Self::ExecutionContext<'_>, Events), Self::Error> {
        // Get the amount to withdraw
        let amount_withdraw = self.outputs.amount()?;

        let channel =
            ctx.channels
                .channels
                .get_mut(&self.channel_id)
                .ok_or(Error::ChannelNotFound {
                    channel_id: self.channel_id,
                })?;

        // If the floating balance alone doesn't cover the withdrawal, release frozen
        // notes epoch by epoch from the most recent one backward until it does.
        // Each released note is removed from the frozen set and the UTXO tree, and
        // its value is added back to the floating balance.
        let mut epoch_number = ctx.current_epoch;
        while amount_withdraw > channel.floating_balance {
            for pk in channel.sequencers_zk_pks.iter() {
                // Collect sequencers' note of the epoch_number
                let key = (epoch_number, *pk);
                if let Some(&note_id) = channel.frozen_note_map.get(&key) {
                    // Unfreeze the note
                    channel.frozen_note_map = channel.frozen_note_map.remove(&key);
                    let note = ctx
                        .channels
                        .frozen_notes
                        .unfreeze(&note_id)
                        .map_err(Error::FrozenNotes)?;

                    // Consume the note on the ledger
                    (ctx.utxos, _) = ctx
                        .utxos
                        .remove(&note_id)
                        .map_err(|_| Error::Inputs(ledger::InputsError::InexistingNote(note_id)))?;

                    // Increase the floating balance
                    channel.floating_balance = channel
                        .floating_balance
                        .checked_add(note.value)
                        .ok_or(Error::BalanceOverflow)?;
                }
            }

            // Decrease the epoch number and start again if it doesn't cover the withdrawal
            // amount
            epoch_number = Epoch::new(
                epoch_number
                    .into_inner()
                    .checked_sub(1)
                    .ok_or(Error::InsufficientFunds)?,
            );
        }

        // Decrease the balance of the channel and increase the withdrawal nonce
        channel.floating_balance = channel
            .floating_balance
            .checked_sub(amount_withdraw)
            .ok_or(Error::InsufficientFunds)?;
        channel.solvency = channel
            .solvency
            .checked_sub(amount_withdraw)
            .ok_or(Error::InsufficientFunds)?;
        channel.withdrawal_nonce = channel
            .withdrawal_nonce
            .checked_add(1)
            .ok_or(Error::WithdrawNonceOverflow)?;

        // Add the outputs to the ledger
        ctx.utxos = self.outputs.execute(ctx.utxos, self);

        Ok((ctx, Events::new()))
    }
}

#[cfg(test)]
mod tests {
    use lb_groth16::Fr;
    use lb_key_management_system_keys::keys::{Ed25519Key, UnsecuredZkKey, ZkPublicKey};
    use rpds::HashTrieMapSync;

    use super::*;
    use crate::mantle::{
        Note, Utxo,
        channel::{ChannelState, Channels},
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

    fn make_frozen_utxo(value: u64, pk: ZkPublicKey) -> Utxo {
        Utxo::new([1u8; 32], 0, Note::new(value, pk))
    }

    fn utxo_tree(utxos: Vec<Utxo>) -> Utxos {
        let mut tree = Utxos::new();
        for u in utxos {
            (tree, _) = tree.insert(u.id(), u);
        }
        tree
    }

    fn channel_with_frozen_note(
        channel_id: ChannelId,
        floating_balance: u64,
        frozen_value: u64,
        epoch: Epoch,
        pk: ZkPublicKey,
    ) -> (Channels, Utxo) {
        let frozen_utxo = make_frozen_utxo(frozen_value, pk);
        let note_id = frozen_utxo.id();

        let mut channels = Channels::new();
        channels.frozen_notes = channels
            .frozen_notes
            .freeze(Note::new(frozen_value, pk), &note_id)
            .unwrap();
        channels.channels = channels.channels.insert(
            channel_id,
            ChannelState {
                accredited_keys: Keys::from(ed_pk(0)).into(),
                configuration_threshold: 1,
                tip_message: MsgId::root(),
                tip_slot: Default::default(),
                tip_sequencer: 0,
                tip_sequencer_starting_slot: Default::default(),
                posting_timeframe: 0.into(),
                posting_timeout: 0.into(),
                withdraw_threshold: 1,
                withdrawal_nonce: 0,
                floating_balance,
                solvency: floating_balance + frozen_value,
                frozen_note_map: HashTrieMapSync::new_sync().insert((epoch, pk), note_id),
                sequencers_zk_pks: ZkKeys::from(pk).into(),
            },
        );
        (channels, frozen_utxo)
    }

    fn execute_withdraw(
        channels: Channels,
        utxos: Utxos,
        channel_id: ChannelId,
        amount: u64,
        epoch: Epoch,
    ) -> WithdrawExecutionContext {
        let pk = ZkPublicKey::zero();
        let op = ChannelWithdrawOp {
            channel_id,
            outputs: Outputs::new([Note::new(amount, pk)]),
            withdraw_nonce: channels
                .channel_state(&channel_id)
                .unwrap()
                .withdrawal_nonce,
        };
        op.execute(WithdrawExecutionContext {
            channels,
            utxos,
            current_epoch: epoch,
        })
        .unwrap()
        .0
    }

    #[test]
    fn withdraw_uses_floating_balance_first_without_touching_frozen_notes() {
        let channel_id = ChannelId::from([0u8; 32]);
        let epoch: Epoch = 1.into();
        let pk = zk_pk(0);
        let frozen_value = 10u64;
        let floating = 20u64;

        let (channels, frozen_utxo) =
            channel_with_frozen_note(channel_id, floating, frozen_value, epoch, pk);
        let note_id = frozen_utxo.id();
        let utxos = utxo_tree(vec![frozen_utxo]);

        // Withdraw 15, covered entirely by floating balance (20)
        let result = execute_withdraw(channels, utxos, channel_id, 15, epoch);

        let state = result.channels.channel_state(&channel_id).unwrap();
        assert_eq!(state.floating_balance, floating - 15);
        // Frozen note untouched
        assert!(state.frozen_note_map.contains_key(&(epoch, pk)));
        assert!(result.channels.frozen_notes.contains(&note_id));
    }

    #[test]
    fn withdraw_releases_frozen_notes_lifo() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk = zk_pk(0);
        let epoch_old: Epoch = 1.into();
        let epoch_new: Epoch = 2.into();

        // Two frozen notes at different epochs
        let utxo_old = Utxo::new([1u8; 32], 0, Note::new(10, pk));
        let utxo_new = Utxo::new([2u8; 32], 0, Note::new(10, pk));
        let id_old = utxo_old.id();
        let id_new = utxo_new.id();

        let mut channels = Channels::new();
        channels.frozen_notes = channels
            .frozen_notes
            .freeze(Note::new(10, pk), &id_old)
            .unwrap();
        channels.frozen_notes = channels
            .frozen_notes
            .freeze(Note::new(10, pk), &id_new)
            .unwrap();
        channels.channels = channels.channels.insert(
            channel_id,
            ChannelState {
                accredited_keys: Keys::from(ed_pk(0)).into(),
                configuration_threshold: 1,
                tip_message: MsgId::root(),
                tip_slot: Default::default(),
                tip_sequencer: 0,
                tip_sequencer_starting_slot: Default::default(),
                posting_timeframe: 0.into(),
                posting_timeout: 0.into(),
                withdraw_threshold: 1,
                withdrawal_nonce: 0,
                floating_balance: 0,
                solvency: 20,
                frozen_note_map: HashTrieMapSync::new_sync()
                    .insert((epoch_old, pk), id_old)
                    .insert((epoch_new, pk), id_new),
                sequencers_zk_pks: ZkKeys::from(pk).into(),
            },
        );
        let utxos = utxo_tree(vec![utxo_old, utxo_new]);

        // Withdraw 5: floating=0, so releases epoch_new first (most recent).
        // After releasing epoch_new (value 10): floating becomes 10 >= 5, loop stops.
        let result = execute_withdraw(channels, utxos, channel_id, 5, epoch_new);

        let state = result.channels.channel_state(&channel_id).unwrap();
        // epoch_new note consumed
        assert!(!state.frozen_note_map.contains_key(&(epoch_new, pk)));
        assert!(!result.channels.frozen_notes.contains(&id_new));
        // epoch_old note still present
        assert!(state.frozen_note_map.contains_key(&(epoch_old, pk)));
        assert!(result.channels.frozen_notes.contains(&id_old));
    }

    #[test]
    fn withdraw_partial_unfreeze_removes_only_consumed_entries_from_map() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk0 = zk_pk(0);
        let pk1 = zk_pk(1);
        let epoch: Epoch = 1.into();

        // Two sequencers, one epoch — two frozen notes
        let utxo0 = Utxo::new([1u8; 32], 0, Note::new(5, pk0));
        let utxo1 = Utxo::new([2u8; 32], 0, Note::new(5, pk1));
        let id0 = utxo0.id();
        let id1 = utxo1.id();

        let mut channels = Channels::new();
        channels.frozen_notes = channels.frozen_notes.freeze(Note::new(5, pk0), &id0).unwrap();
        channels.frozen_notes = channels.frozen_notes.freeze(Note::new(5, pk1), &id1).unwrap();
        channels.channels = channels.channels.insert(
            channel_id,
            ChannelState {
                accredited_keys: Keys::try_from(vec![ed_pk(0), ed_pk(1)]).unwrap().into(),
                configuration_threshold: 1,
                tip_message: MsgId::root(),
                tip_slot: Default::default(),
                tip_sequencer: 0,
                tip_sequencer_starting_slot: Default::default(),
                posting_timeframe: 0.into(),
                posting_timeout: 0.into(),
                withdraw_threshold: 1,
                withdrawal_nonce: 0,
                floating_balance: 0,
                solvency: 10,
                frozen_note_map: HashTrieMapSync::new_sync()
                    .insert((epoch, pk0), id0)
                    .insert((epoch, pk1), id1),
                sequencers_zk_pks: ZkKeys::try_from(vec![pk0, pk1]).unwrap().into(),
            },
        );
        let utxos = utxo_tree(vec![utxo0, utxo1]);

        // Withdraw 7: floating=0, release epoch 1 (both pk0 and pk1 unfrozen → +10)
        // → floating becomes 10, exits loop; pays 7, leaves 3 floating
        let result = execute_withdraw(channels, utxos, channel_id, 7, epoch);

        let state = result.channels.channel_state(&channel_id).unwrap();
        // Both entries from epoch 1 removed from the map
        assert_eq!(state.frozen_note_map.size(), 0);
        assert!(!result.channels.frozen_notes.contains(&id0));
        assert!(!result.channels.frozen_notes.contains(&id1));
        assert_eq!(state.floating_balance, 3);
    }

    #[test]
    fn withdraw_full_unfreeze_empties_frozen_note_map() {
        let channel_id = ChannelId::from([0u8; 32]);
        let pk = zk_pk(0);
        let epoch_old: Epoch = 1.into();
        let epoch_new: Epoch = 2.into();

        // Two epochs, 8 tokens each, floating = 0
        let utxo_old = Utxo::new([1u8; 32], 0, Note::new(8, pk));
        let utxo_new = Utxo::new([2u8; 32], 0, Note::new(8, pk));
        let id_old = utxo_old.id();
        let id_new = utxo_new.id();

        let mut channels = Channels::new();
        channels.frozen_notes = channels.frozen_notes.freeze(Note::new(8, pk), &id_old).unwrap();
        channels.frozen_notes = channels.frozen_notes.freeze(Note::new(8, pk), &id_new).unwrap();
        channels.channels = channels.channels.insert(
            channel_id,
            ChannelState {
                accredited_keys: Keys::from(ed_pk(0)).into(),
                configuration_threshold: 1,
                tip_message: MsgId::root(),
                tip_slot: Default::default(),
                tip_sequencer: 0,
                tip_sequencer_starting_slot: Default::default(),
                posting_timeframe: 0.into(),
                posting_timeout: 0.into(),
                withdraw_threshold: 1,
                withdrawal_nonce: 0,
                floating_balance: 0,
                solvency: 16,
                frozen_note_map: HashTrieMapSync::new_sync()
                    .insert((epoch_old, pk), id_old)
                    .insert((epoch_new, pk), id_new),
                sequencers_zk_pks: ZkKeys::from(pk).into(),
            },
        );
        let utxos = utxo_tree(vec![utxo_old, utxo_new]);

        // Withdraw 10: epoch_new releases 8 (total 8 < 10), epoch_old releases 8
        // (total 16 >= 10), both entries consumed
        let result = execute_withdraw(channels, utxos, channel_id, 10, epoch_new);

        let state = result.channels.channel_state(&channel_id).unwrap();
        assert_eq!(state.frozen_note_map.size(), 0);
        assert!(!result.channels.frozen_notes.contains(&id_old));
        assert!(!result.channels.frozen_notes.contains(&id_new));
    }

    #[test]
    fn withdraw_decreases_solvency_by_withdrawn_amount() {
        let channel_id = ChannelId::from([0u8; 32]);
        let epoch: Epoch = 1.into();
        let pk = zk_pk(0);
        let initial_solvency = 30u64;
        let withdraw_amount = 7u64;

        let (channels, frozen_utxo) =
            channel_with_frozen_note(channel_id, initial_solvency, 0, epoch, pk);
        let utxos = utxo_tree(vec![frozen_utxo]);

        let result = execute_withdraw(channels, utxos, channel_id, withdraw_amount, epoch);

        assert_eq!(
            result.channels.channel_state(&channel_id).unwrap().solvency,
            initial_solvency - withdraw_amount,
        );
    }
}
