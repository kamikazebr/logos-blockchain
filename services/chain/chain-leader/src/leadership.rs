use std::{
    fmt::{Debug, Display},
    sync::{Arc, RwLock},
};

use lb_core::{
    mantle::Utxo,
    proofs::leader_proof::{Groth16LeaderProof, LeaderPrivate, LeaderPublic},
};
use lb_cryptarchia_engine::{Epoch, Slot};
use lb_key_management_system_service::{
    backend::preload::KeyId, keys::Ed25519Key,
    operators::zk::leader::BuildPrivateInputsWithLeaderKey,
};
use lb_ledger::{EpochState, UtxoTree};
use lb_wallet_service::{UtxoWithKeyId, api::WalletApi};
use overwatch::services::AsServiceId;
use rand::rngs::OsRng;
use tokio::{
    sync::{broadcast, oneshot},
    task::JoinHandle,
    time::Instant,
};

use crate::{WinningPolInfo, kms::KmsAdapter};

/// Return a leadership proof and signing key if the current slot is a
/// winning one, and notifies consumers of winning slot info.
///
/// If the slot is not a winning one, it returns `None` and no consumer is
/// notified.
pub async fn build_proof_for<Wallet, Kms, RuntimeServiceId>(
    utxos: &[UtxoWithKeyId],
    latest_tree: &UtxoTree,
    epoch_state: &EpochState,
    slot: Slot,
    wallet: &WalletApi<Wallet, RuntimeServiceId>,
    kms: &Kms,
) -> Option<(Groth16LeaderProof, Ed25519Key)>
where
    Wallet: lb_wallet_service::api::WalletServiceData,
    Kms: KmsAdapter<RuntimeServiceId, KeyId = KeyId> + Sync,
    RuntimeServiceId: Debug + Display + Sync + AsServiceId<Wallet>,
{
    for UtxoWithKeyId { utxo, key_id } in utxos {
        let public_inputs = public_inputs_for_slot(epoch_state, slot, latest_tree);
        let winning = kms
            .check_winning_with_key(key_id.clone(), utxo, &public_inputs)
            .await;
        if winning {
            tracing::debug!(
                "leader for slot {:?}, {:?}/{:?}",
                slot,
                utxo.note.value,
                epoch_state.total_stake()
            );

            let voucher_cm = match wallet.generate_new_voucher().await {
                Ok(voucher_cm) => voucher_cm,
                Err(e) => {
                    tracing::error!("Failed to generate voucher: {e:?}");
                    continue;
                }
            };

            let private_inputs_result = kms
                .build_private_inputs_for_winning_utxo_and_slot(
                    key_id.clone(),
                    utxo,
                    epoch_state,
                    public_inputs,
                    latest_tree,
                )
                .await;
            let (private_inputs, leader_signing_key) = match private_inputs_result {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(
                        "Failed to build private inputs for winning utxo {:?} for {slot:?}: {e:?}",
                        utxo.id(),
                    );
                    continue;
                }
            };

            let res = tokio::task::spawn_blocking(move || {
                Groth16LeaderProof::prove(private_inputs, voucher_cm)
            })
            .await;
            match res {
                Ok(Ok(proof)) => return Some((proof, leader_signing_key)),
                Ok(Err(e)) => {
                    tracing::error!("Failed to build proof: {:?}", e);
                }
                Err(e) => {
                    tracing::error!("Failed to wait thread to build proof: {:?}", e);
                }
            }
        } else {
            tracing::trace!(
                "Not a leader for slot {:?}, {:?}/{:?}",
                slot,
                utxo.note.value,
                epoch_state.total_stake()
            );
        }
    }

    None
}

pub fn operator_for_private_inputs_arguments_for_winning_utxo_and_slot(
    utxo: &Utxo,
    epoch_state: &EpochState,
    public_inputs: LeaderPublic,
    latest_tree: &UtxoTree,
) -> Result<
    (
        BuildPrivateInputsWithLeaderKey,
        oneshot::Receiver<LeaderPrivate>,
        Ed25519Key,
    ),
    PrivateInputsError,
> {
    let (sender, receiver) = oneshot::channel();
    let aged_path = epoch_state
        .utxo_merkle_path(utxo)
        .ok_or(PrivateInputsError::AgedNoteNotFound)?;
    let latest_path = latest_tree
        .path(&utxo.id())
        .ok_or(PrivateInputsError::LatestNoteNotFound)?;
    // Generate a random one-time Ed25519 key for P_LEAD (as per PoL spec)
    let leader_signing_key = Ed25519Key::generate(&mut OsRng);
    let leader_pk = leader_signing_key.public_key();

    Ok((
        BuildPrivateInputsWithLeaderKey::new(
            sender,
            *utxo,
            public_inputs,
            aged_path,
            latest_path,
            leader_pk,
        ),
        receiver,
        leader_signing_key,
    ))
}

fn public_inputs_for_slot(
    epoch_state: &EpochState,
    slot: Slot,
    latest_tree: &UtxoTree,
) -> LeaderPublic {
    LeaderPublic::new(
        epoch_state.utxo_merkle_root(),
        latest_tree.root(),
        epoch_state.nonce,
        slot.into(),
        epoch_state.lottery_0,
        epoch_state.lottery_1,
    )
}

#[derive(thiserror::Error, Debug)]
pub enum PrivateInputsError {
    #[error("Aged note not found from merkle tree")]
    AgedNoteNotFound,
    #[error("Latest note not found from merkle tree")]
    LatestNoteNotFound,
}

/// A replay-capable broadcast channel for winning slot information.
///
/// Every sent item is appended to an internal log **and** broadcast to live
/// receivers. Late subscribers receive a snapshot of the full log together
/// with a live receiver.
///
/// The channel is reset on epoch changes.
pub struct EpochWinningSlotsChannel {
    log: RwLock<Vec<WinningPolInfo>>,
    sender: broadcast::Sender<WinningPolInfo>,
}

impl EpochWinningSlotsChannel {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            log: RwLock::new(Vec::new()),
            sender,
        }
    }

    /// Appends the item to the log and broadcasts it to live receivers.
    ///
    /// If no live receivers exist yet the item is still stored in the log and
    /// will be included in the snapshot returned by [`Self::subscribe`].
    pub fn send(&self, info: WinningPolInfo) {
        self.log
            .write()
            .expect("WinningSlotsChannel log poisoned")
            .push(info.clone());
        // Broadcast failure (no live receivers) is expected during startup
        // and is harmless — the data is safe in the log.
        drop(self.sender.send(info));
    }

    /// Returns a snapshot of all previously sent items together with a live
    /// broadcast receiver.
    ///
    /// The read-lock is held across both operations so every item is
    /// guaranteed to appear either in the snapshot **or** in the receiver,
    /// never both and never missed.
    pub fn subscribe(&self) -> (Vec<WinningPolInfo>, broadcast::Receiver<WinningPolInfo>) {
        let snapshot = self
            .log
            .read()
            .expect("WinningSlotsChannel log poisoned")
            .clone();
        let receiver = self.sender.subscribe();
        (snapshot, receiver)
    }

    /// Clears the log. Called when a new epoch starts.
    fn clear(&self) {
        self.log
            .write()
            .expect("WinningSlotsChannel log poisoned")
            .clear();
    }
}

/// Reacts to the first tick received and to the first tick of every new epoch
/// by spawning a background task that scans all slots in the epoch and sends
/// every winning slot to consumers via a broadcast channel.
///
/// The term *potential* means that winning slots are computed based on the
/// notes available at tick-processing time. A note may later be spent before
/// the slot is reached, in which case it will not actually win. This notifier
/// does not account for such cases.
pub struct PotentialWinningPoLSlotNotifier<'service> {
    ledger_config: &'service lb_ledger::Config,
    channel: Arc<EpochWinningSlotsChannel>,
    last_processed_epoch: Option<Epoch>,
    /// Handle to the background epoch-scanning task, if one is running.
    scan_handle: Option<JoinHandle<()>>,
}

impl<'service> PotentialWinningPoLSlotNotifier<'service> {
    pub(super) const fn new(
        ledger_config: &'service lb_ledger::Config,
        channel: Arc<EpochWinningSlotsChannel>,
    ) -> Self {
        Self {
            ledger_config,
            channel,
            last_processed_epoch: None,
            scan_handle: None,
        }
    }

    fn clear_old_epoch(&mut self) {
        // Cancel any in-progress scan from a previous epoch.
        if let Some(handle) = self.scan_handle.take() {
            handle.abort();
        }
        self.channel.clear();
    }

    /// Spawns a background task that scans every slot in the new epoch
    /// starting from `starting_slot` and sends all winning slot information
    /// to consumers. If a scan for a previous epoch is still running it is
    /// cancelled first.
    ///
    /// `starting_slot` allows skipping slots that have already elapsed when
    /// the service joins an epoch mid-way (e.g. after startup or IBD).
    pub(super) fn process_epoch<RuntimeServiceId>(
        &mut self,
        utxos: &[UtxoWithKeyId],
        latest_tree: &UtxoTree,
        epoch_state: &EpochState,
        starting_slot: Slot,
        kms: &(impl KmsAdapter<RuntimeServiceId, KeyId = KeyId> + Clone + Send + Sync + 'static),
    ) where
        RuntimeServiceId: Send + 'static,
    {
        if let Some(last_epoch) = self.last_processed_epoch {
            if last_epoch == epoch_state.epoch {
                tracing::trace!("Skipping already processed epoch.");
                return;
            } else if last_epoch > epoch_state.epoch {
                tracing::error!(
                    "Received an epoch smaller than the last processed one. This is invalid."
                );
                return;
            }
        }
        tracing::debug!("Processing new epoch: {:?}", epoch_state.epoch);

        // Cancel any in-progress scan from a previous epoch.
        self.clear_old_epoch();

        self.last_processed_epoch = Some(epoch_state.epoch);

        self.scan_handle = Some(tokio::spawn(scan_epoch_winning_slots(
            utxos.to_vec(),
            latest_tree.clone(),
            epoch_state.clone(),
            starting_slot,
            self.ledger_config.clone(),
            kms.clone(),
            Arc::clone(&self.channel),
        )));
    }
}

/// Scans all slots in the epoch and sends every winning slot to the broadcast
/// channel. Slots are scanned in order so that the nearest winning slots are
/// discovered and communicated to consumers first.
async fn scan_epoch_winning_slots<Kms, RuntimeServiceId>(
    utxos: Vec<UtxoWithKeyId>,
    latest_tree: UtxoTree,
    epoch_state: EpochState,
    starting_slot: Slot,
    ledger_config: lb_ledger::Config,
    kms: Kms,
    channel: Arc<EpochWinningSlotsChannel>,
) where
    Kms: KmsAdapter<RuntimeServiceId, KeyId = KeyId> + Sync,
{
    let epoch_starting_slot = ledger_config
        .epoch_config
        .starting_slot(&epoch_state.epoch, ledger_config.base_period_length())
        .into_inner();
    let epoch_end_slot = epoch_starting_slot
        .checked_add(ledger_config.epoch_length())
        .expect("Slot calculation overflow.");
    let scan_from = {
        let starting_inner = starting_slot.into_inner();
        if starting_inner < epoch_starting_slot {
            tracing::warn!(
                "Specified starting slot is before the start of the epoch. Using epoch starting slot as default."
            );
            epoch_starting_slot
        } else if starting_inner > epoch_end_slot {
            tracing::warn!(
                "Specified starting slot is after the end of the epoch. Using epoch last slot as default."
            );
            epoch_end_slot
        } else {
            starting_inner
        }
    };

    let start = Instant::now();
    let mut winning_count: u64 = 0;

    // Iterate slots (outer) then UTXOs (inner) so that the nearest winning
    // slots are found first. Slots before `starting_slot` are skipped — as they are
    // considered to have already elapsed.
    for slot_number in scan_from..epoch_end_slot {
        let slot: Slot = slot_number.into();
        let public_inputs = public_inputs_for_slot(&epoch_state, slot, &latest_tree);

        for UtxoWithKeyId { utxo, key_id } in &utxos {
            let winning = kms
                .check_winning_with_key(key_id.clone(), utxo, &public_inputs)
                .await;
            if !winning {
                continue;
            }

            // Note: We discard the signing key here since this is just for
            // pre-computing winning slots. The actual signing key will be
            // generated when building the proof.
            let private_inputs_result = kms
                .build_private_inputs_for_winning_utxo_and_slot(
                    key_id.clone(),
                    utxo,
                    &epoch_state,
                    public_inputs,
                    &latest_tree,
                )
                .await;
            let (leader_private, _) = match private_inputs_result {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(
                        "Failed to build private inputs for winning utxo {:?} for {slot:?}: {e:?}",
                        utxo.id(),
                    );
                    continue;
                }
            };

            channel.send((leader_private, public_inputs, epoch_state.epoch));
            winning_count += 1;
        }

        // Yield cooperatively every 100 slots to avoid starving other tasks.
        if slot_number % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }

    tracing::debug!(
        "Found {winning_count} winning slots for epoch {:?} in {:?} ms",
        epoch_state.epoch,
        start.elapsed().as_millis()
    );
}

#[cfg(test)]
mod pol_tests {
    use core::fmt;
    use std::{fmt::Formatter, num::NonZero, slice};

    use lb_core::{
        mantle::{
            ledger::{Note, Tx},
            ops::leader_claim::VoucherCm,
        },
        proofs::leader_proof::{LeaderProof as _, check_winning},
        sdp::{MinStake, ServiceParameters, ServiceType},
    };
    use lb_cryptarchia_engine::EpochConfig;
    use lb_groth16::{Fr, fr_from_bytes_unchecked};
    use lb_key_management_system_service::keys::{UnsecuredZkKey, ZkKey};
    use lb_ledger::mantle::sdp::{
        Config as SdpConfig, ServiceRewardsParameters, rewards::blend::RewardsParameters,
    };
    use lb_utils::math::{NonNegativeF64, NonNegativeRatio};
    use lb_wallet_service::{WalletMsg, WalletServiceSettings, api::WalletServiceData};
    use overwatch::services::{
        ServiceData,
        relay::OutboundRelay,
        state::{NoOperator, NoState},
    };
    use tokio::sync::mpsc;

    use super::*;

    /// Test that [`Leader::build_proof_for`] generates `PoL` which can be
    /// verified successfully.
    #[tokio::test]
    async fn test_build_proof_for() {
        let config = test_config();

        // Create secret key and leader
        let kms = DummyKms;
        let key_id = KeyId::from("0");
        let sk = UnsecuredZkKey::new(Fr::from(0u64));
        let pk = sk.to_public_key();

        // Create a UTXO
        let utxo = Tx::new(vec![], vec![Note::new(1000u64, pk)])
            .utxo_by_index(0)
            .unwrap();

        // Create aged/latest UTXO trees
        let aged_tree = UtxoTree::new().insert(utxo.id(), utxo).0;
        let latest_tree = UtxoTree::new().insert(utxo.id(), utxo).0;

        // Create EpochState
        let total_stake = utxo.note.value;
        let (lottery_0, lottery_1) = config
            .lottery_constants()
            .compute_lottery_values(total_stake);
        let epoch_state = EpochState {
            epoch: 1.into(),
            nonce: Fr::from(999u64),
            utxos: aged_tree.clone(),
            total_stake,
            lottery_0,
            lottery_1,
        };

        // Create dummy wallet service
        let wallet = DummyWallet::spawn();

        // Find a winning slot by calling `build_proof_for` until it succeeds
        let (proof, winning_slot) = find_winning_slot_and_build_proof(
            (0..1000).map(Slot::from),
            UtxoWithKeyId { utxo, key_id },
            &epoch_state,
            &latest_tree,
            &wallet,
            &kms,
        )
        .await
        .expect("should find a winning slot and build a proof");
        assert_eq!(proof.voucher_cm(), &dummy_voucher_cm());

        // Verify proof
        let public_inputs = LeaderPublic::new(
            aged_tree.root(),
            latest_tree.root(),
            epoch_state.nonce,
            winning_slot.into(),
            epoch_state.lottery_0,
            epoch_state.lottery_1,
        );
        assert!(
            proof.verify(&public_inputs),
            "proof verification should succeed"
        );
    }

    /// Find a winning slot by calling `build_proof_for` until it succeeds
    async fn find_winning_slot_and_build_proof(
        slots: impl Iterator<Item = Slot>,
        utxo: UtxoWithKeyId,
        epoch_state: &EpochState,
        latest_tree: &UtxoTree,
        wallet: &WalletApi<DummyWallet, TestRuntimeServiceId>,
        kms: &(impl KmsAdapter<TestRuntimeServiceId, KeyId = KeyId> + Sync),
    ) -> Option<(Groth16LeaderProof, Slot)> {
        for slot in slots {
            if let Some((proof, _signing_key)) = build_proof_for(
                slice::from_ref(&utxo),
                latest_tree,
                epoch_state,
                slot,
                wallet,
                kms,
            )
            .await
            {
                return Some((proof, slot));
            }
        }
        None
    }

    fn test_config() -> lb_ledger::Config {
        lb_ledger::Config {
            epoch_config: EpochConfig {
                epoch_stake_distribution_stabilization: NonZero::new(3u8).unwrap(),
                epoch_period_nonce_buffer: NonZero::new(3).unwrap(),
                epoch_period_nonce_stabilization: NonZero::new(4).unwrap(),
            },
            consensus_config: lb_cryptarchia_engine::Config::new(
                NonZero::new(5).unwrap(),
                NonNegativeRatio::new(1, 10.try_into().unwrap()),
                1f64.try_into().expect("1 > 0"),
            ),
            sdp_config: SdpConfig {
                service_params: Arc::new(
                    [(
                        ServiceType::BlendNetwork,
                        ServiceParameters {
                            lock_period: 10,
                            inactivity_period: 20,
                            retention_period: 100,
                            timestamp: 0,
                            session_duration: 10,
                        },
                    )]
                    .into(),
                ),
                service_rewards_params: ServiceRewardsParameters {
                    blend: RewardsParameters {
                        rounds_per_session: NonZero::new(10u64).unwrap(),
                        message_frequency_per_round: NonNegativeF64::try_from(1.0).unwrap(),
                        num_blend_layers: NonZero::new(3u64).unwrap(),
                        minimum_network_size: NonZero::new(1u64).unwrap(),
                        data_replication_factor: 0,
                        activity_threshold_sensitivity: 1,
                    },
                },
                min_stake: MinStake {
                    threshold: 1,
                    timestamp: 0,
                },
            },
            faucet_pk: None,
        }
    }

    struct DummyKms;

    #[async_trait::async_trait]
    impl KmsAdapter<TestRuntimeServiceId> for DummyKms {
        type KeyId = KeyId;

        async fn check_winning_with_key(
            &self,
            _: Self::KeyId,
            utxo: &Utxo,
            leader_public: &LeaderPublic,
        ) -> bool {
            let sk = ZkKey::new(Fr::from(0u64));
            check_winning(*utxo, *leader_public, &sk.to_public_key(), Fr::from(0u64))
        }

        async fn build_private_inputs_for_winning_utxo_and_slot(
            &self,
            _: Self::KeyId,
            utxo: &Utxo,
            epoch_state: &EpochState,
            public_inputs: LeaderPublic,
            latest_tree: &UtxoTree,
        ) -> Result<(LeaderPrivate, Ed25519Key), PrivateInputsError> {
            let aged_path = epoch_state
                .utxo_merkle_path(utxo)
                .ok_or(PrivateInputsError::AgedNoteNotFound)?;
            let latest_path = latest_tree
                .path(&utxo.id())
                .ok_or(PrivateInputsError::LatestNoteNotFound)?;
            // Generate a random one-time Ed25519 key for P_LEAD (as per PoL spec)
            let leader_signing_key = Ed25519Key::generate(&mut OsRng);
            let leader_pk = leader_signing_key.public_key();
            let leader_private = LeaderPrivate::new(
                public_inputs,
                *utxo,
                &aged_path,
                &latest_path,
                Fr::from(0u64),
                &leader_pk,
            );
            Ok((leader_private, leader_signing_key))
        }
    }

    struct DummyWallet;

    impl ServiceData for DummyWallet {
        type Settings = WalletServiceSettings;
        type State = NoState<Self::Settings>;
        type StateOperator = NoOperator<Self::State>;
        type Message = WalletMsg;
    }

    impl WalletServiceData for DummyWallet {
        type Kms = ();
        type Cryptarchia = ();
        type Tx = ();
        type Storage = ();
    }

    impl DummyWallet {
        fn spawn() -> WalletApi<Self, TestRuntimeServiceId> {
            let (msg_sender, mut msg_receiver) = mpsc::channel(10);

            tokio::spawn(async move {
                while let Some(msg) = msg_receiver.recv().await {
                    if let WalletMsg::GenerateNewVoucherSecret { resp_tx } = msg {
                        let _ = resp_tx.send(dummy_voucher_cm());
                    }
                }
            });

            WalletApi::<Self, TestRuntimeServiceId>::new(OutboundRelay::new(msg_sender))
        }
    }

    const DUMMY_VOUCHER_CM_BYTES: [u8; 32] = [99u8; 32];

    fn dummy_voucher_cm() -> VoucherCm {
        fr_from_bytes_unchecked(&DUMMY_VOUCHER_CM_BYTES).into()
    }

    #[derive(Debug)]
    struct TestRuntimeServiceId;

    impl AsServiceId<DummyWallet> for TestRuntimeServiceId {
        const SERVICE_ID: Self = Self;
    }

    impl Display for TestRuntimeServiceId {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "TestRuntimeServiceId")
        }
    }
}
