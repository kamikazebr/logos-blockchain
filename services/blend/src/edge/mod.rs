pub mod backends;
mod handlers;
pub(crate) mod service_components;
pub mod settings;
#[cfg(test)]
mod tests;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    time::Duration,
};

use backends::BlendBackend;
use futures::{Stream, StreamExt as _};
use lb_blend::{
    message::crypto::proofs::PoQVerificationInputsMinusSigningKey,
    proofs::quota::inputs::prove::public::{CoreInputs, LeaderInputs},
    scheduling::{
        message_blend::provers::leader::LeaderProofsGenerator,
        session::{SessionEvent, UninitializedEpochEventStream},
        stream::UninitializedFirstReadyStream,
    },
};
use lb_chain_service::{
    Epoch,
    api::{CryptarchiaServiceApi, CryptarchiaServiceData},
};
use lb_core::codec::SerializeOp as _;
use lb_key_management_system_service::{
    api::KmsServiceApi, keys::KeyOperators,
    operators::ed25519::exfiltrate_secret_key::LeakSecretKeyOperator,
};
use lb_log_targets::blend;
use lb_services_utils::wait_until_services_are_ready;
use lb_time_service::{SlotTick, TimeService, TimeServiceMessage};
use overwatch::{
    OpaqueServiceResourcesHandle,
    overwatch::OverwatchHandle,
    services::{
        AsServiceId, ServiceCore, ServiceData,
        resources::ServiceResourcesHandle,
        state::{NoOperator, NoState},
    },
};
use serde::{Serialize, de::DeserializeOwned};
pub(crate) use service_components::ServiceComponents;
use settings::StartingBlendConfig;
use tokio::sync::oneshot;
use tracing::{debug, error, info};

use crate::{
    edge::{
        handlers::{Error, MessageHandler},
        settings::RunningBlendConfig,
    },
    epoch::{
        private::{PolEpochInfo, PolInfoProvider as PolInfoProviderTrait},
        public::{
            BlendMembershipEpochState, EpochMembershipEvent, add_epoch_transitions,
            get_epoch_membership_stream,
        },
    },
    epoch_info::{ChainApi, EpochEvent, EpochHandler, PolEpochInfo},
    kms::PreloadKmsService,
    membership::{self, MembershipInfo, node_id},
    message::{NetworkInfo, NetworkMessage, ServiceMessage},
};

const LOG_TARGET: &str = blend::service::EDGE;

type RunningSettings<Backend, NodeId, RuntimeServiceId> =
    RunningBlendConfig<<Backend as BlendBackend<NodeId, RuntimeServiceId>>::Settings>;

type EpochInfoAndHandler<Backend, NodeId, ProofsGenerator, RuntimeServiceId> = (
    PolEpochInfo,
    MessageHandler<Backend, NodeId, ProofsGenerator, RuntimeServiceId>,
);

pub struct BlendService<
    Backend,
    NodeId,
    BroadcastSettings,
    MembershipAdapter,
    ProofsGenerator,
    TimeBackend,
    ChainService,
    PolInfoProvider,
    RuntimeServiceId,
> where
    Backend: BlendBackend<NodeId, RuntimeServiceId>,
    NodeId: Clone,
{
    service_resources_handle: OpaqueServiceResourcesHandle<Self, RuntimeServiceId>,
    _phantom: PhantomData<(
        MembershipAdapter,
        ProofsGenerator,
        TimeBackend,
        ChainService,
        PolInfoProvider,
    )>,
}

impl<
    Backend,
    NodeId,
    BroadcastSettings,
    MembershipAdapter,
    ProofsGenerator,
    TimeBackend,
    ChainService,
    PolInfoProvider,
    RuntimeServiceId,
> ServiceData
    for BlendService<
        Backend,
        NodeId,
        BroadcastSettings,
        MembershipAdapter,
        ProofsGenerator,
        TimeBackend,
        ChainService,
        PolInfoProvider,
        RuntimeServiceId,
    >
where
    Backend: BlendBackend<NodeId, RuntimeServiceId>,
    NodeId: Clone,
{
    type Settings = StartingBlendConfig<Backend::Settings>;
    type State = NoState<Self::Settings>;
    type StateOperator = NoOperator<Self::State>;
    type Message = ServiceMessage<BroadcastSettings, NodeId>;
}

#[expect(clippy::too_many_lines, reason = "TODO: Address this at some point.")]
#[async_trait::async_trait]
impl<
    Backend,
    NodeId,
    BroadcastSettings,
    MembershipAdapter,
    ProofsGenerator,
    TimeBackend,
    ChainService,
    PolInfoProvider,
    RuntimeServiceId,
> ServiceCore<RuntimeServiceId>
    for BlendService<
        Backend,
        NodeId,
        BroadcastSettings,
        MembershipAdapter,
        ProofsGenerator,
        TimeBackend,
        ChainService,
        PolInfoProvider,
        RuntimeServiceId,
    >
where
    Backend: BlendBackend<NodeId, RuntimeServiceId> + Send + Sync,
    NodeId: Clone + Debug + Eq + Hash + Send + Sync + node_id::TryFrom + 'static,
    BroadcastSettings: Serialize + DeserializeOwned + Send,
    MembershipAdapter: membership::Adapter<NodeId = NodeId, Error: Send + Sync + 'static> + Send,
    membership::ServiceMessage<MembershipAdapter>: Send + Sync + 'static,
    ProofsGenerator: LeaderProofsGenerator + Send,
    TimeBackend: lb_time_service::backends::TimeBackend + Send,
    ChainService: CryptarchiaServiceData<Tx: Send + Sync>,
    PolInfoProvider: PolInfoProviderTrait<RuntimeServiceId, Stream: Send + Unpin + 'static> + Send,
    RuntimeServiceId: AsServiceId<<MembershipAdapter as membership::Adapter>::Service>
        + AsServiceId<Self>
        + AsServiceId<TimeService<TimeBackend, RuntimeServiceId>>
        + AsServiceId<ChainService>
        + AsServiceId<PreloadKmsService<RuntimeServiceId>>
        + Display
        + Debug
        + Clone
        + Send
        + Sync
        + Unpin
        + 'static,
{
    fn init(
        service_resources_handle: OpaqueServiceResourcesHandle<Self, RuntimeServiceId>,
        _initial_state: Self::State,
    ) -> Result<Self, overwatch::DynError> {
        Ok(Self {
            service_resources_handle,
            _phantom: PhantomData,
        })
    }

    async fn run(mut self) -> Result<(), overwatch::DynError> {
        let Self {
            service_resources_handle:
                ServiceResourcesHandle {
                    inbound_relay,
                    overwatch_handle,
                    settings_handle,
                    status_updater,
                    ..
                },
            ..
        } = self;

        let settings = settings_handle.notifier().get_updated_settings();

        wait_until_services_are_ready!(
            &overwatch_handle,
            Some(Duration::from_mins(1)),
            TimeService<_, _>,
            <MembershipAdapter as membership::Adapter>::Service,
            PreloadKmsService<_>
        )
        .await?;

        let kms = KmsServiceApi::<PreloadKmsService<_>, RuntimeServiceId>::new(
            overwatch_handle.relay::<PreloadKmsService<_>>().await?,
        );

        // TODO: This will go once we do not need to pass the secret key anymore, i.e.,
        // when we have libp2p integration with KMS.
        let non_ephemeral_signing_key = {
            let (sender, receiver) = oneshot::channel();
            kms.execute(
                settings.non_ephemeral_signing_key_id,
                KeyOperators::Ed25519(Box::new(LeakSecretKeyOperator::new(sender))),
            )
            .await
            .expect("Failed to interact with KMS to fetch non-ephemeral signing key.");
            receiver
                .await
                .expect("Failed to retrieve non-ephemeral signing key from KMS.")
        };
        let local_node_id =
            NodeId::try_from_provider_id(&non_ephemeral_signing_key.public_key().to_bytes())
                .expect("non-ephemeral signing key should decode into a valid node id");

        // Initialize membership stream for session and core-related public PoQ inputs.
        let epoch_stream =
            get_epoch_membership_stream::<ChainService, NodeId, TimeBackend, RuntimeServiceId>(
                &overwatch_handle,
                non_ephemeral_signing_key.public_key(),
                None,
            )
            .await
            .expect("Failed to retrieve epoch membership stream.");

        let messages_to_blend_stream = Box::pin(inbound_relay.filter_map(async |msg| {
            match msg {
                ServiceMessage::Blend(message) => Some(
                    NetworkMessage::<BroadcastSettings>::to_bytes(&message)
                        .expect("NetworkMessage should be able to be serialized")
                        .to_vec(),
                ),
                ServiceMessage::GetNetworkInfo { reply } => {
                    drop(reply.send(Some(NetworkInfo {
                        node_id: local_node_id.clone(),
                        core_info: None,
                    })));
                    None
                }
            }
        }));

        run::<Backend, _, ProofsGenerator, PolInfoProvider, _>(
            UninitializedFirstReadyStream::new(epoch_stream),
            messages_to_blend_stream,
            RunningSettings::<Backend, _, _> {
                backend: settings.backend,
                cover: settings.cover,
                non_ephemeral_signing_key,
                num_blend_layers: settings.num_blend_layers,
                minimum_network_size: settings.minimum_network_size,
                time: settings.time,
                data_replication_factor: settings.data_replication_factor,
            },
            &overwatch_handle,
            || {
                status_updater.notify_ready();
                info!(
                    target: LOG_TARGET,
                    "Service '{}' is ready.",
                    <RuntimeServiceId as AsServiceId<Self>>::SERVICE_ID
                );
            },
        )
        .await
        .map_err(|e| {
            error!(target: LOG_TARGET, "Edge blend service is being terminated with error: {e:?}");
            e.into()
        })
    }
}

/// Run the event loop of the service.
///
/// The event loop handles three types of events:
/// - **Session changes**: resets the message handler with the new session but
///   the current epoch info. If the handler was shut down (waiting for secret
///   epoch info), it stays shut down.
/// - **Clock ticks (epoch transitions)**: on a new epoch, shuts down the
///   message handler until secret `PoL` info for that epoch is received. If
///   secret info was already provided for the new epoch, the handler is kept.
/// - **Secret `PoL` info**: always (re)creates the message handler with the new
///   epoch's public and private inputs, preserving the current session.
///
/// Returns an [`Error`] if a new membership does not satisfy the edge node
/// condition.
///
/// # Panics
/// - If the initial membership is not yielded immediately from the session
///   stream.
#[expect(
    clippy::cognitive_complexity,
    reason = "TODO: address this in a dedicated refactor"
)]
async fn run<Backend, NodeId, ProofsGenerator, PolInfoProvider, RuntimeServiceId>(
    epoch_stream: impl Stream<Item = BlendMembershipEpochState<NodeId>>,
    mut incoming_message_stream: impl Stream<Item = Vec<u8>> + Send + Unpin,
    settings: RunningSettings<Backend, NodeId, RuntimeServiceId>,
    overwatch_handle: &OverwatchHandle<RuntimeServiceId>,
    notify_ready: impl Fn(),
) -> Result<(), Error>
where
    Backend: BlendBackend<NodeId, RuntimeServiceId> + Sync + Send,
    NodeId: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    ProofsGenerator: LeaderProofsGenerator + Send,
    PolInfoProvider: PolInfoProviderTrait<RuntimeServiceId, Stream: Unpin>,
    RuntimeServiceId: Clone + Send + Sync,
{
    notify_ready();

    let mut secret_pol_info_stream = PolInfoProvider::subscribe(overwatch_handle)
        .await
        .expect("Should not fail to subscribe to secret PoL info stream.");

    let mut current_secret_info_epoch_and_message_handler: Option<(
        Epoch,
        MessageHandler<Backend, NodeId, ProofsGenerator, RuntimeServiceId>,
    )> = None;

    loop {
        tokio::select! {
            Some(BlendMembershipEpochState { epoch, .. }) = epoch_stream.next() => {
                if let Some((current_epoch, _)) = current_secret_info_epoch_and_message_handler.as_ref() && current_epoch < *epoch {
                    debug!(target: LOG_TARGET, "Epoch transition detected. Current epoch: {current_epoch}, new epoch: {epoch}. Shutting down message handler until new secret PoL info is received for the new epoch.");
                    *current_secret_info_epoch_and_message_handler = None;
                }
            }
            Some(message) = incoming_message_stream.next() => {
                // TODO: Investigate why secret PoL info at times arrives after the block proposal.
                let Some(handler) = current_message_handler.as_mut() else {
                    tracing::warn!(target: LOG_TARGET, "Received a message to blend, but no active message handler is available to process it because the secret PoL info for the current epoch is not yet available. Ignoring the message.");
                    continue;
                };
                let message_copies = settings.data_replication_factor.checked_add(1).unwrap();
                for _ in 0..message_copies {
                    handler.handle_message_to_blend(message.clone()).await;
                }
            }
            Some(new_secret_pol_info) = secret_pol_info_stream.next() => {
                current_secret_info_epoch_and_message_handler = handle_new_secret_epoch_info(new_secret_pol_info, settings.clone(), overwatch_handle);
            }
        }
    }
}

/// Processes new secret `PoL` info.
///
/// Always creates a new message handler using the new epoch's public and
/// private inputs from the `PoL` info, while preserving the current session.
fn handle_new_secret_epoch_info<Backend, NodeId, ProofsGenerator, RuntimeServiceId>(
    new_pol_epoch_info: PolEpochInfo<NodeId>,
    settings: RunningSettings<Backend, NodeId, RuntimeServiceId>,
    overwatch_handle: &OverwatchHandle<RuntimeServiceId>,
) -> Option<(
    Epoch,
    MessageHandler<Backend, NodeId, ProofsGenerator, RuntimeServiceId>,
)>
where
    Backend: BlendBackend<NodeId, RuntimeServiceId>,
    NodeId: Clone + Eq + Hash + Send + 'static,
    ProofsGenerator: LeaderProofsGenerator,
    RuntimeServiceId: Clone,
{
    let Some(zk_root) = current_membership_info.zk.as_ref().map(|zk| zk.root) else {
        return None;
    };

    let current_membership = current_membership_info.membership.clone();
    let new_public_inputs = PoQVerificationInputsMinusSigningKey {
        leader: LeaderInputs {
            lottery_0: new_pol_epoch_info.poq_public_inputs.lottery_0,
            lottery_1: new_pol_epoch_info.poq_public_inputs.lottery_1,
            pol_epoch_nonce: new_pol_epoch_info.poq_public_inputs.epoch_nonce,
            pol_ledger_aged: new_pol_epoch_info.poq_public_inputs.aged_root,
            message_quota: settings.session_leadership_quota(),
        },
        core: CoreInputs {
            quota: settings.cover.epoch_core_quota(
                settings.num_blend_layers,
                &settings.time,
                current_membership.size(),
            ),
            zk_root,
        },
    };
    Some((new_pol_epoch_info.poq_public_inputs.epoch, MessageHandler::try_new_with_edge_condition_check(
        settings,
        current_membership,
        new_public_inputs,
        new_pol_epoch_info.poq_private_inputs,
        overwatch_handle.clone(),
        new_pol_epoch_info.epoch,
    ).expect("Should not fail to re-create message handler on epoch rotation after private inputs are set.")))
}
