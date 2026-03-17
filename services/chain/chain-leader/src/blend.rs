use std::marker::PhantomData;

use lb_blend_service::message::{NetworkMessage, ServiceMessage};
use lb_chain_service_common::NetworkMessage as ChainNetworkMessage;
use lb_core::{block::Proposal, codec::SerializeOp as _};
use overwatch::services::{ServiceData, relay::OutboundRelay};
use tracing::error;

use crate::LOG_TARGET;

pub struct BlendAdapter<BlendService>
where
    BlendService: ServiceData + lb_blend_service::ServiceComponents,
{
    relay: OutboundRelay<<BlendService as ServiceData>::Message>,
    broadcast_settings: BlendService::BroadcastSettings,
    _phantom: PhantomData<BlendService>,
}

impl<BlendService> BlendAdapter<BlendService>
where
    BlendService: ServiceData + lb_blend_service::ServiceComponents,
{
    pub const fn new(
        relay: OutboundRelay<<BlendService as ServiceData>::Message>,
        broadcast_settings: BlendService::BroadcastSettings,
    ) -> Self {
        Self {
            relay,
            broadcast_settings,
            _phantom: PhantomData,
        }
    }
}

impl<BlendService> BlendAdapter<BlendService>
where
    BlendService: ServiceData<Message = ServiceMessage<BlendService::BroadcastSettings>>
        + lb_blend_service::ServiceComponents
        + Sync,
    <BlendService as ServiceData>::Message: Send,
    BlendService::BroadcastSettings: Clone + Sync,
{
    pub async fn blend_proposal(&self, proposal: Proposal) {
        self.send_to_blend(ServiceMessage::Blend(NetworkMessage {
            message: ChainNetworkMessage::to_bytes(&ChainNetworkMessage::Proposal(proposal))
                .expect("NetworkMessage should be able to be serialized")
                .to_vec(),
            broadcast_settings: self.broadcast_settings.clone(),
        }))
        .await;
    }

    // Temporary workaround until Blend moves from block-based scheduling to
    // slot-based scheduling. In the meanwhile, we force the first block of each
    // new epoch to be broadcasted in clear.
    // TODO: Remove this once Blend moves to slot-based scheduling.
    pub async fn broadcast_proposal(&self, proposal: Proposal) {
        self.send_to_blend(ServiceMessage::Broadcast(NetworkMessage {
            message: ChainNetworkMessage::to_bytes(&ChainNetworkMessage::Proposal(proposal))
                .expect("NetworkMessage should be able to be serialized")
                .to_vec(),
            broadcast_settings: self.broadcast_settings.clone(),
        }))
        .await;
    }

    async fn send_to_blend(&self, message: ServiceMessage<BlendService::BroadcastSettings>) {
        if let Err((e, _)) = self.relay.send(message).await {
            error!(target: LOG_TARGET, "Failed to relay proposal to blend service: {e:?}");
        }
    }
}
