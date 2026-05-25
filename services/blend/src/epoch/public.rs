use core::{
    fmt::{Debug, Display},
    hash::Hash,
};

use futures::{Stream, StreamExt as _};
use lb_blend::{
    crypto::merkle::sort_nodes_and_build_merkle_tree,
    scheduling::membership::{Membership, Node},
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
use tokio::sync::oneshot;
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
