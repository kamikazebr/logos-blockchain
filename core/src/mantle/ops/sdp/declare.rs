use lb_key_management_system_keys::keys::{Ed25519Signature, ZkPublicKey, ZkSignature};

use super::{MAX_DECLARATION_LOCATOR, SDPDeclareOp, SdpError};
use crate::{
    events::Events,
    mantle::{
        Note, TxHash,
        frozen_notes::FrozenNotes,
        ledger::{Declarations, Operation, Utxos},
    },
    sdp::{Declaration, MinStake, locked_notes::LockedNotes},
};

trait SDPDeclareValidationExt {
    fn validate(
        &self,
        note: Note,
        declarations: &Declarations,
        locked_notes: &LockedNotes,
        frozen_notes: &FrozenNotes,
        min_stake: &MinStake,
    ) -> Result<(), SdpError>;

    fn execute(
        &self,
        ctx: SDPDeclareExecutionContext,
    ) -> Result<(SDPDeclareExecutionContext, Events), SdpError>;
}

impl SDPDeclareValidationExt for SDPDeclareOp {
    fn validate(
        &self,
        note: Note,
        declarations: &Declarations,
        locked_notes: &LockedNotes,
        frozen_notes: &FrozenNotes,
        min_stake: &MinStake,
    ) -> Result<(), SdpError> {
        // Check that the declaration doesn't already exist
        if declarations.contains_key(&self.id()) {
            return Err(SdpError::DuplicateDeclaration(self.id()));
        }

        // Ensure it has no more than 8 locators.
        if self.locators.len() > MAX_DECLARATION_LOCATOR {
            return Err(SdpError::TooMuchLocators);
        }

        // Ensure the note isn't frozen
        if frozen_notes.contains(&self.locked_note_id) {
            return Err(SdpError::NoteFrozen {
                note_id: self.locked_note_id,
            });
        }

        // Ensure value of locked note is sufficient for joining the service.
        if note.value < min_stake.threshold {
            return Err(SdpError::NoteInsufficientValue {
                note_id: self.locked_note_id,
                value: note.value,
            });
        }

        // Ensure the note has not already been locked for this service.
        if locked_notes.is_locked_for_service(&self.locked_note_id, &self.service_type) {
            return Err(SdpError::NoteAlreadyUsedForService {
                note_id: self.locked_note_id,
                service_type: self.service_type,
            });
        }

        Ok(())
    }

    fn execute(
        &self,
        mut ctx: SDPDeclareExecutionContext,
    ) -> Result<(SDPDeclareExecutionContext, Events), SdpError> {
        let declaration_id = self.id();
        let declaration = Declaration::new(ctx.block_number, self);
        ctx.declarations = ctx.declarations.insert(declaration_id, declaration);
        let utxo = ctx
            .utxo_tree
            .utxos()
            .get(&self.locked_note_id)
            .expect("The operation should have been checked")
            .0;

        ctx.locked_notes = ctx
            .locked_notes
            .lock(
                &ctx.min_stake,
                self.service_type,
                utxo.note,
                &self.locked_note_id,
            )
            .map_err(|_| SdpError::UnexpectedError)?;

        Ok((ctx, Events::new()))
    }
}

pub struct SDPDeclareValidationContext<'a> {
    pub utxo_tree: &'a Utxos,
    pub locked_notes: &'a LockedNotes,
    pub frozen_notes: &'a FrozenNotes,
    pub tx_hash: &'a TxHash,
    pub declare_zk_sig: &'a ZkSignature,
    pub declare_eddsa_sig: &'a Ed25519Signature,
    pub declarations: &'a Declarations,
    pub min_stake: &'a MinStake,
}

pub struct SDPDeclareGenesisValidationContext<'a> {
    pub utxo_tree: &'a Utxos,
    pub locked_notes: &'a LockedNotes,
    pub frozen_notes: &'a FrozenNotes,
    pub declarations: &'a Declarations,
    pub min_stake: &'a MinStake,
}

pub struct SDPDeclareExecutionContext {
    pub utxo_tree: Utxos,
    pub block_number: u64,
    pub declarations: Declarations,
    pub locked_notes: LockedNotes,
    pub min_stake: MinStake,
}

impl Operation<SDPDeclareValidationContext<'_>> for SDPDeclareOp {
    type ExecutionContext<'a>
        = SDPDeclareExecutionContext
    where
        Self: 'a;
    type Error = SdpError;

    fn validate(&self, ctx: &SDPDeclareValidationContext<'_>) -> Result<(), Self::Error> {
        // Check that the note exist
        let Some((utxo, _)) = ctx.utxo_tree.utxos().get(&self.locked_note_id) else {
            return Err(SdpError::InexistingNote(self.locked_note_id));
        };

        // Ensure locked note exists and ownership over the locked note and `zk_id`
        let note = utxo.note;
        if !ZkPublicKey::verify_multi(
            &[note.pk, self.zk_id],
            &ctx.tx_hash.to_fr(),
            ctx.declare_zk_sig,
        ) {
            return Err(SdpError::InvalidZkSignature);
        }

        // Ensure ownership over the `provider_id`
        self.provider_id
            .0
            .verify(
                ctx.tx_hash.as_signing_bytes().as_ref(),
                ctx.declare_eddsa_sig,
            )
            .map_err(|_| SdpError::InvalidEddsaSignature)?;

        SDPDeclareValidationExt::validate(
            self,
            note,
            ctx.declarations,
            ctx.locked_notes,
            ctx.frozen_notes,
            ctx.min_stake,
        )
    }

    fn execute(
        &self,
        ctx: Self::ExecutionContext<'_>,
    ) -> Result<(Self::ExecutionContext<'_>, Events), Self::Error> {
        SDPDeclareValidationExt::execute(self, ctx)
    }
}

impl Operation<SDPDeclareGenesisValidationContext<'_>> for SDPDeclareOp {
    type ExecutionContext<'a>
        = SDPDeclareExecutionContext
    where
        Self: 'a;
    type Error = SdpError;

    fn validate(&self, ctx: &SDPDeclareGenesisValidationContext<'_>) -> Result<(), Self::Error> {
        // Check that the note exist
        let Some((utxo, _)) = ctx.utxo_tree.utxos().get(&self.locked_note_id) else {
            return Err(SdpError::InexistingNote(self.locked_note_id));
        };
        let note = utxo.note;

        SDPDeclareValidationExt::validate(
            self,
            note,
            ctx.declarations,
            ctx.locked_notes,
            ctx.frozen_notes,
            ctx.min_stake,
        )
    }

    fn execute(
        &self,
        ctx: Self::ExecutionContext<'_>,
    ) -> Result<(Self::ExecutionContext<'_>, Events), Self::Error> {
        SDPDeclareValidationExt::execute(self, ctx)
    }
}

#[cfg(test)]
mod tests {
    use lb_groth16::Fr;
    use lb_key_management_system_keys::keys::{Ed25519Key, UnsecuredZkKey};

    use super::*;
    use crate::{
        mantle::{NoteId, Utxo},
        sdp::{Locator, ProviderId, ServiceType},
    };

    fn make_frozen_note_in_utxo_tree() -> (Utxos, FrozenNotes, NoteId) {
        let pk = UnsecuredZkKey::new(Fr::from(0u64)).to_public_key();
        let note = Note::new(100, pk);
        let utxo = Utxo::new([0u8; 32], 0, note);
        let note_id = utxo.id();

        let mut utxos = Utxos::new();
        (utxos, _) = utxos.insert(note_id, utxo);
        let frozen_notes = FrozenNotes::new().freeze(note, &note_id).unwrap();

        (utxos, frozen_notes, note_id)
    }

    #[test]
    fn sdp_declare_rejects_frozen_note_as_collateral() {
        let (utxos, frozen_notes, note_id) = make_frozen_note_in_utxo_tree();

        let op = SDPDeclareOp {
            service_type: ServiceType::BlendNetwork,
            locators: "/ip4/1.1.1.1/udp/0".parse::<Locator>().unwrap().into(),
            provider_id: ProviderId(Ed25519Key::from_bytes(&[0u8; 32]).public_key()),
            zk_id: UnsecuredZkKey::new(Fr::from(0u64)).to_public_key(),
            locked_note_id: note_id,
        };

        let ctx = SDPDeclareGenesisValidationContext {
            utxo_tree: &utxos,
            locked_notes: &LockedNotes::new(),
            frozen_notes: &frozen_notes,
            declarations: &Declarations::new_sync(),
            min_stake: &MinStake {
                threshold: 1,
                timestamp: 0,
            },
        };

        assert_eq!(
            Operation::<SDPDeclareGenesisValidationContext>::validate(&op, &ctx),
            Err(SdpError::NoteFrozen { note_id }),
        );
    }
}
