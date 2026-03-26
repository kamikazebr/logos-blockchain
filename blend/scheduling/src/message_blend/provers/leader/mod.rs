use async_trait::async_trait;
use futures::stream::{self, Stream, StreamExt as _};
use lb_blend_message::crypto::{
    key_ext::Ed25519SecretKeyExt as _, proofs::PoQVerificationInputsMinusSigningKey,
};
use lb_blend_proofs::{
    quota::{
        VerifiedProofOfQuota,
        inputs::prove::{
            PrivateInputs, PublicInputs, private::ProofOfLeadershipQuotaInputs,
            public::LeaderInputs,
        },
    },
    selection::VerifiedProofOfSelection,
};
use lb_cryptarchia_engine::Epoch;
use lb_groth16::fr_to_bytes;
use lb_key_management_system_keys::keys::UnsecuredEd25519Key;
use tokio::{
    sync::mpsc,
    task::{JoinHandle, spawn_blocking},
    time::Instant,
};

use crate::message_blend::provers::{BlendLayerProof, ProofsGeneratorSettings};

#[cfg(test)]
mod tests;

const LOG_TARGET: &str = "blend::scheduling::proofs::leader";

/// A `PoQ` generator that deals only with leadership proofs, suitable for edge
/// nodes.
#[async_trait]
pub trait LeaderProofsGenerator<SecretInfoStream>: Sized {
    /// Instantiate a new generator with the provided public inputs and secret
    /// `PoL` values.
    fn new(settings: ProofsGeneratorSettings, private_inputs_stream: SecretInfoStream) -> Self;
    /// Signal an epoch transition in the middle of the current session, with
    /// new public and secret inputs.
    fn rotate_epoch(
        &mut self,
        new_epoch_public: LeaderInputs,
        new_private_inputs_stream: SecretInfoStream,
        new_epoch: Epoch,
    );
    /// Get the next leadership proof.
    async fn get_next_proof(&mut self) -> BlendLayerProof;
}

pub struct RealLeaderProofsGenerator {
    pub(super) settings: ProofsGeneratorSettings,
    proof_receiver: mpsc::Receiver<BlendLayerProof>,
    proof_generation_task_handle: JoinHandle<()>,
}

impl Drop for RealLeaderProofsGenerator {
    fn drop(&mut self) {
        self.proof_generation_task_handle.abort();
    }
}

#[async_trait]
impl<SecretInfoStream> LeaderProofsGenerator<SecretInfoStream> for RealLeaderProofsGenerator
where
    SecretInfoStream: Stream<Item = ProofOfLeadershipQuotaInputs> + Send + 'static,
{
    fn new(settings: ProofsGeneratorSettings, private_inputs_stream: SecretInfoStream) -> Self {
        let (proof_receiver, proof_generation_task_handle) = spawn_proof_generation(
            create_proof_stream(settings.public_inputs, private_inputs_stream),
            settings.public_inputs.leader.message_quota as usize,
        );

        Self {
            settings,
            proof_receiver,
            proof_generation_task_handle,
        }
    }

    fn rotate_epoch(
        &mut self,
        new_epoch_public: LeaderInputs,
        new_private_inputs_stream: SecretInfoStream,
        new_epoch: Epoch,
    ) {
        tracing::info!(target: LOG_TARGET, "Rotating epoch...");

        // On epoch rotation, we maintain the current session info and only change the
        // PoL relevant parts.
        self.settings.public_inputs.leader = new_epoch_public;
        self.settings.epoch = new_epoch;

        // Compute new proofs with the updated settings.
        self.generate_new_proofs_stream(new_private_inputs_stream);
    }

    async fn get_next_proof(&mut self) -> BlendLayerProof {
        let start = Instant::now();
        let proof = self
            .proof_receiver
            .recv()
            .await
            .expect("Underlying proof generation task should always yield items.");
        tracing::trace!(target: LOG_TARGET, "Generated leadership Blend layer proof with key nullifier {:?} addressed to node at index {:?} in {:?} ms.", hex::encode(fr_to_bytes(&proof.proof_of_quota.key_nullifier())), proof.proof_of_selection.expected_index(self.settings.membership_size), start.elapsed().as_millis());
        proof
    }
}

impl RealLeaderProofsGenerator {
    fn generate_new_proofs_stream<SecretInfoStream>(&mut self, secret_info_stream: SecretInfoStream)
    where
        SecretInfoStream: Stream<Item = ProofOfLeadershipQuotaInputs> + Send + 'static,
    {
        self.proof_generation_task_handle.abort();

        let (proof_receiver, generation_task) = spawn_proof_generation(
            create_proof_stream(self.settings.public_inputs, secret_info_stream),
            self.settings.public_inputs.leader.message_quota as usize,
        );
        self.proof_receiver = proof_receiver;
        self.proof_generation_task_handle = generation_task;
    }

    pub(super) const fn current_epoch(&self) -> Epoch {
        self.settings.epoch
    }
}

// Spawns a background task that eagerly drives the proof stream, sending
// generated proofs into a bounded channel. This ensures proofs are
// pre-generated and ready for immediate consumption, rather than being lazily
// produced only when polled as is the case with a buffered stream.
fn spawn_proof_generation(
    stream: impl Stream<Item = BlendLayerProof> + Send + 'static,
    buffer_size: usize,
) -> (mpsc::Receiver<BlendLayerProof>, JoinHandle<()>) {
    let (proof_sender, proof_receiver) = mpsc::channel(buffer_size);
    let handle = tokio::spawn(async move {
        tokio::pin!(stream);
        while let Some(proof) = stream.next().await {
            if proof_sender.send(proof).await.is_err() {
                break;
            }
        }
    });
    (proof_receiver, handle)
}

fn create_proof_stream<SecretInfoStream>(
    public_inputs: PoQVerificationInputsMinusSigningKey,
    secret_info_stream: SecretInfoStream,
) -> impl Stream<Item = BlendLayerProof>
where
    SecretInfoStream: Stream<Item = ProofOfLeadershipQuotaInputs>,
{
    let message_quota = public_inputs.leader.message_quota;
    tracing::debug!(target: LOG_TARGET, "Generating leadership quota proofs starting with public inputs: {public_inputs:?}.");

    secret_info_stream.flat_map(move |next_secret_info| {
        // For each winning slot, generate `message_quota` proofs.
        // TODO: Replace this logic with returning a single element that contains all
        // the needed proofs to send out `N` copies of the block proposal, where `N` is
        // the number of total copies of the message * number of encapsulations for each
        // copy.
        stream::iter(0..message_quota).then(move |message_release_index| {
            let public_inputs = public_inputs;

            async move {
                let leadership_proof = spawn_blocking(move || {
                    let ephemeral_signing_key = UnsecuredEd25519Key::generate_with_blake_rng();
                    let (proof_of_quota, secret_selection_randomness) = VerifiedProofOfQuota::new(
                        &PublicInputs {
                            signing_key: ephemeral_signing_key.public_key().into_inner(),
                            core: public_inputs.core,
                            leader: public_inputs.leader,
                            session: public_inputs.session,
                        },
                        PrivateInputs::new_proof_of_leadership_quota_inputs(
                            message_release_index,
                            next_secret_info,
                        ),
                    )
                    .expect("Leadership PoQ proof creation should not fail.");

                    let proof_of_selection =
                        VerifiedProofOfSelection::new(secret_selection_randomness);

                    BlendLayerProof {
                        proof_of_quota,
                        proof_of_selection,
                        ephemeral_signing_key,
                    }
                })
                .await
                .expect("Spawning task for leadership proof generation should not fail.");

                tracing::trace!(target: LOG_TARGET, "Generated leadership PoQ within the stream for message release index {message_release_index:?} with key nullifier {:?}  and public key {:?}.", hex::encode(fr_to_bytes(&leadership_proof.proof_of_quota.key_nullifier())), leadership_proof.ephemeral_signing_key.public_key());
                leadership_proof
            }
        })
    })
}
