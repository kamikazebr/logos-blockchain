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
                && channel.sequencers_zk_pks.len() < channel.floating_balance as usize
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
