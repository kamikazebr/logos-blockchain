use core::{
    fmt::{Debug, Display},
    hash::Hash,
    time::Duration,
};

use futures::{Stream, StreamExt as _};
use lb_blend::{
    crypto::merkle::sort_nodes_and_build_merkle_tree,
    scheduling::{
        membership::{Membership, Node},
        stream::UninitializedFirstReadyStream,
    },
};
use lb_chain_service::{
    Epoch,
    api::{CryptarchiaServiceApi, CryptarchiaServiceData},
};
use lb_core::{
    mantle::Value,
    sdp::{ProviderId, ProviderInfo, ServiceType},
};
use lb_groth16::Fr;
use lb_key_management_system_service::keys::{Ed25519PublicKey, ZkPublicKey};
use lb_ledger::{EpochState, UtxoTree};
use lb_log_targets::blend;
use lb_time_service::{SlotTick, TimeService, TimeServiceMessage, backends::TimeBackend};
use overwatch::{overwatch::OverwatchHandle, services::AsServiceId};
use tokio::{sync::oneshot, time::sleep};
use tracing::{debug, warn};

use crate::membership::{MembershipInfo, ZkInfo, node_id};

const LOG_TARGET: &str = blend::service::EPOCH;

pub struct BlendMembershipEpochState<NodeId> {
    pub epoch: Epoch,
    pub nonce: Fr,
    pub utxos: UtxoTree,
    pub total_stake: Value,
    pub lottery_0: Fr,
    pub lottery_1: Fr,
    pub membership: MembershipInfo<NodeId>,
}

pub async fn get_epoch_membership_stream<
    ChainService,
    TimeRuntimeBackend,
    NodeId,
    RuntimeServiceId,
>(
    overwatch_handle: &OverwatchHandle<RuntimeServiceId>,
    signing_public_key: Ed25519PublicKey,
    zk_public_key: Option<ZkPublicKey>,
) -> Result<impl Stream<Item = BlendMembershipEpochState<NodeId>>, Box<dyn std::error::Error>>
where
    ChainService: CryptarchiaServiceData<Tx: Send + Sync>,
    TimeRuntimeBackend: TimeBackend + Send,
    NodeId: node_id::TryFrom + Clone + Hash + Eq,
    RuntimeServiceId: AsServiceId<ChainService>
        + AsServiceId<TimeService<TimeRuntimeBackend, RuntimeServiceId>>
        + Debug
        + Sync
        + Display,
{
    let epoch_info_stream =
        get_epoch_stream::<ChainService, TimeRuntimeBackend, RuntimeServiceId>(&overwatch_handle)
            .await?;
    Ok(epoch_info_stream.map(move |epoch_state| {
        let membership_info = membership_info_from_epoch_state::<NodeId>(
            &epoch_state,
            &signing_public_key,
            zk_public_key,
        );
        BlendMembershipEpochState {
            epoch: epoch_state.epoch,
            nonce: epoch_state.nonce,
            utxos: epoch_state.utxos,
            total_stake: epoch_state.total_stake,
            lottery_0: epoch_state.lottery_0,
            lottery_1: epoch_state.lottery_1,
            membership: membership_info,
        }
    }))
}

pub enum EpochMembershipEvent<NodeId> {
    /// A new epoch has started, carrying its membership state.
    NewEpoch(BlendMembershipEpochState<NodeId>),
    /// The transition period of the previous epoch has elapsed and its state
    /// can be safely discarded.
    PreviousEpochTransitionExpired,
}

pub fn add_epoch_transitions<NodeId, MembershipStream>(
    membership_stream: MembershipStream,
    transition_period: Duration,
) -> impl Stream<Item = EpochMembershipEvent<NodeId>>
where
    MembershipStream: Stream<Item = BlendMembershipEpochState<NodeId>> + Unpin,
{
    futures::stream::unfold(
        (membership_stream, None, false),
        move |(mut memberships, pending_timer, has_previous): (_, Option<_>, bool)| async move {
            if let Some(timer) = pending_timer {
                timer.await;
                return Some((
                    EpochMembershipEvent::PreviousEpochTransitionExpired,
                    (memberships, None, has_previous),
                ));
            }
            let membership = memberships.next().await?;
            // Start the transition timer immediately, so its deadline is
            // anchored to the moment the new epoch is observed rather than
            // to when the consumer next polls the stream.
            let next_timer = has_previous.then(|| Box::pin(sleep(transition_period)));
            Some((
                EpochMembershipEvent::NewEpoch(membership),
                (memberships, next_timer, true),
            ))
        },
    )
}

/// Subscribes to the slot clock and yields the [`EpochState`] once per epoch,
/// at the first slot tick observed for that epoch.
async fn get_epoch_stream<ChainService, TimeRuntimeBackend, RuntimeServiceId>(
    overwatch_handle: &OverwatchHandle<RuntimeServiceId>,
) -> Result<impl Stream<Item = EpochState>, Box<dyn std::error::Error>>
where
    ChainService: CryptarchiaServiceData<Tx: Send + Sync>,
    TimeRuntimeBackend: TimeBackend + Send,
    RuntimeServiceId: AsServiceId<ChainService>
        + AsServiceId<TimeService<TimeRuntimeBackend, RuntimeServiceId>>
        + Debug
        + Sync
        + Display,
{
    let chain_service = CryptarchiaServiceApi::<ChainService, RuntimeServiceId>::new(
        overwatch_handle
            .relay::<ChainService>()
            .await
            .map_err(|_| "Relay with chain service should be available.")?,
    );

    let slot_ticks = {
        let time_relay = overwatch_handle
            .relay::<TimeService<_, _>>()
            .await
            .map_err(|_| "Relay with time service should be available.")?;
        let (sender, receiver) = oneshot::channel();
        time_relay
            .send(TimeServiceMessage::Subscribe { sender })
            .await
            .map_err(|_| "Failed to subscribe to slot clock.")?;
        receiver
            .await
            .map_err(|_| "Should not fail to receive slot stream from time service.")?
    };

    Ok(slot_ticks
        .scan(None, move |last_epoch, SlotTick { epoch, slot }| {
            let is_new_epoch = Some(epoch) != *last_epoch;
            if is_new_epoch {
                *last_epoch = Some(epoch);
            }
            let chain_service = chain_service.clone();
            async move {
                if !is_new_epoch {
                    return Some(None);
                }
                match chain_service.get_epoch_state(slot).await {
                    Ok(Ok(epoch_state)) => Some(Some(epoch_state)),
                    Ok(Err(e)) => {
                        tracing::warn!(target: LOG_TARGET, "Chain service returned error for epoch state at slot {slot:?}: {e:?}");
                        Some(None)
                    }
                    Err(e) => {
                        tracing::warn!(target: LOG_TARGET, "Failed to query epoch state at slot {slot:?}: {e:?}");
                        Some(None)
                    }
                }
            }
        })
        .filter_map(async move |maybe| maybe))
}

fn membership_info_from_epoch_state<NodeId>(
    epoch_state: &EpochState,
    signing_public_key: &Ed25519PublicKey,
    maybe_zk_public_key: Option<ZkPublicKey>,
) -> MembershipInfo<NodeId>
where
    NodeId: node_id::TryFrom + Clone + Hash + Eq,
{
    let declarations = epoch_state.sdp.declarations();
    let mut nodes: Vec<ZkNode<NodeId>> = declarations
        .iter()
        .filter(|(service_type, _)| matches!(service_type, ServiceType::BlendNetwork))
        .flat_map(|(_, declarations)| declarations.values())
        .filter_map(|declaration| {
            let provider_info = ProviderInfo {
                locators: declaration.locators.clone(),
                zk_id: declaration.zk_id,
            };
            node_from_provider::<NodeId>(&declaration.provider_id, &provider_info)
        })
        .collect();

    let zk_info = if nodes.is_empty() {
        None
    } else {
        let zk_tree = sort_nodes_and_build_merkle_tree(&mut nodes, |ZkNode { zk_key, .. }| {
            zk_key.into_inner()
        })
        .expect("Should not fail to build Merkle tree of core nodes' zk public keys.");
        let core_and_path_selectors = maybe_zk_public_key.and_then(|zk_public_key| {
            let Some(proof) = zk_tree.get_proof_for_key(zk_public_key.as_fr()) else {
                debug!(
                    "Local node's ZK public key not found in membership Merkle tree: node is not a core member."
                );
                return None;
            };
            Some(proof)
        });
        Some(ZkInfo {
            core_and_path_selectors,
            root: zk_tree.root(),
        })
    };
    let membership_nodes = nodes
        .into_iter()
        .map(|ZkNode { node, .. }| node)
        .collect::<Vec<_>>();
    MembershipInfo {
        membership: Membership::new(&membership_nodes, signing_public_key),
        zk: zk_info,
        epoch_number: epoch_state.epoch().into_inner().into(),
    }
}

/// Builds a [`ZkNode`] from a [`ProviderId`] and a set of [`Locator`]s.
/// Returns [`None`] if the locators set is empty or if the provider ID cannot
/// be decoded.
fn node_from_provider<NodeId>(
    provider_id: &ProviderId,
    ProviderInfo { locators, zk_id }: &ProviderInfo,
) -> Option<ZkNode<NodeId>>
where
    NodeId: node_id::TryFrom,
{
    let provider_id = provider_id.0.as_bytes();
    // TODO: Once we provide a proper API for non-empty vectors, we can expose a
    // `first()` method that returns `&T` instead of `Option<&T>`, and remove this
    // `expect`.
    let address = locators
        .first()
        .expect("Locators set cannot be empty")
        .clone();
    let id = NodeId::try_from_provider_id(provider_id)
        .map_err(|e| {
            warn!("Failed to decode provider_id to node ID: {e:?}");
        })
        .ok()?;
    let public_key = Ed25519PublicKey::from_bytes(provider_id)
        .map_err(|e| {
            warn!("Failed to decode provider_id to public_key: {e:?}");
        })
        .ok()?;
    Some(ZkNode {
        node: Node {
            id,
            address: address.into_inner(),
            public_key,
        },
        zk_key: *zk_id,
    })
}

/// Wrapper around [`Node`] that includes its ZK public key.
#[derive(Debug, Clone)]
struct ZkNode<NodeId> {
    pub node: Node<NodeId>,
    pub zk_key: ZkPublicKey,
}

/// A staging type that initializes a [`SessionEventStream`] by consuming
/// the first [`Session`] from the underlying stream, expected to be yielded
/// within a short timeout.
pub struct UninitializedEpochEventStream<Stream> {
    stream: UninitializedFirstReadyStream<Stream>,
    transition_period: Duration,
}

impl<Stream> UninitializedEpochEventStream<Stream> {
    #[must_use]
    pub const fn new(epoch_stream: Stream, transition_period: Duration) -> Self {
        Self {
            stream: UninitializedFirstReadyStream::new(epoch_stream),
            transition_period,
        }
    }
}

impl<Stream, Epoch> UninitializedEpochEventStream<Stream>
where
    Stream: futures::Stream<Item = Epoch> + Unpin,
{
    /// Initializes a [`EpochEventStream`] by consuming the first [`Epoch`]
    /// from the underlying stream.
    ///
    /// It returns the first [`Epoch`] and the initialized
    /// [`EpochEventStream`], awaiting the first epoch for as long as
    /// necessary.
    /// It returns an error only if the underlying stream closes before yielding
    /// an epoch.
    pub async fn await_first_ready(
        self,
    ) -> Result<(Epoch, EpochEventStream<Stream>), FirstReadyStreamError> {
        let (first_epoch, remaining_stream) = self.stream.first().await?;
        Ok((
            first_epoch,
            EpochEventStream::new(remaining_stream, self.transition_period),
        ))
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use tokio::time::{Instant, interval};
    use tokio_stream::wrappers::IntervalStream;

    use super::*;

    #[tokio::test]
    async fn yield_two_events_alternately() {
        let session_duration = Duration::from_secs(1);
        let transition_period = Duration::from_millis(200);
        let time_tolerance = Duration::from_millis(100);

        let mut stream = SessionEventStream::new(
            Box::pin(IntervalStream::new(interval(session_duration))),
            transition_period,
        );

        // NewSession should be emitted immediately.
        let start_time = Instant::now();
        assert!(matches!(
            stream.next().await,
            Some(SessionEvent::NewSession(_))
        ));
        let elapsed = start_time.elapsed();
        let tolerance = Duration::from_millis(50);
        assert!(elapsed <= tolerance, "elapsed:{elapsed:?}");

        // TransitionEnd should be emitted after transition_period.
        let start_time = Instant::now();
        assert!(matches!(
            stream.next().await,
            Some(SessionEvent::TransitionPeriodExpired)
        ));
        let elapsed = start_time.elapsed();
        assert!(
            elapsed.abs_diff(transition_period) <= time_tolerance,
            "elapsed:{elapsed:?}, expected:{transition_period:?}",
        );

        // NewSession should be emitted after session_duration - transition_period.
        let start_time = Instant::now();
        assert!(matches!(
            stream.next().await,
            Some(SessionEvent::NewSession(_))
        ));
        let elapsed = start_time.elapsed();
        assert!(
            elapsed.abs_diff(session_duration.checked_sub(transition_period).unwrap())
                <= time_tolerance,
            "elapsed:{elapsed:?}, expected:{:?}",
            session_duration.checked_sub(transition_period).unwrap()
        );

        // TransitionEnd should be emitted after transition_period.
        let start_time = Instant::now();
        assert!(matches!(
            stream.next().await,
            Some(SessionEvent::TransitionPeriodExpired)
        ));
        let elapsed = start_time.elapsed();
        assert!(
            elapsed.abs_diff(transition_period) <= time_tolerance,
            "elapsed:{elapsed:?}, expected:{transition_period:?}",
        );
    }

    #[tokio::test]
    async fn transition_period_shorter_than_session() {
        let session_duration = Duration::from_millis(500);
        let transition_period = Duration::from_millis(600);
        let time_tolerance = Duration::from_millis(50);

        let mut stream = SessionEventStream::new(
            Box::pin(IntervalStream::new(interval(session_duration))),
            transition_period,
        );

        // NewSession should be emitted immediately.
        let start_time = Instant::now();
        assert!(matches!(
            stream.next().await,
            Some(SessionEvent::NewSession(_))
        ));
        let elapsed = start_time.elapsed();
        assert!(elapsed <= time_tolerance, "elapsed:{elapsed:?}");

        // NewSession should be emitted again after session_duration.
        let start_time = Instant::now();
        assert!(matches!(
            stream.next().await,
            Some(SessionEvent::NewSession(_))
        ));
        let elapsed = start_time.elapsed();
        assert!(
            elapsed.abs_diff(session_duration) <= time_tolerance,
            "elapsed:{elapsed:?}, expected:{session_duration:?}",
        );
    }

    #[tokio::test]
    async fn first_ready_stream_yields_first_item_immediately() {
        // Use an underlying stream that yields the first item nearly immediately.
        let stream = UninitializedFirstReadyStream::new(
            IntervalStream::new(interval(Duration::from_secs(1)))
                .enumerate()
                .map(|(i, _)| i),
        );

        let (first, mut stream) = stream.first().await.expect("first item should be yielded");
        assert_eq!(first, 0);
        // Next items are yielded normally.
        assert_eq!(stream.next().await, Some(1));
        assert_eq!(stream.next().await, Some(2));
    }
}
