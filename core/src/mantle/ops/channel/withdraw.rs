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
