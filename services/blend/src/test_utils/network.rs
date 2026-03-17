use async_trait::async_trait;
use lb_network_service::{NetworkService, backends::NetworkBackend};
use overwatch::{
    overwatch::OverwatchHandle,
    services::{ServiceData, relay::OutboundRelay},
};
use tokio_stream::wrappers::BroadcastStream;

use crate::network::NetworkAdapter;

pub struct TestNetworkBackend;

#[async_trait::async_trait]
impl<RuntimeServiceId> NetworkBackend<RuntimeServiceId> for TestNetworkBackend {
    type Settings = ();
    type Message = Vec<u8>;
    type PubSubEvent = ();
    type ChainSyncEvent = ();

    fn new((): Self::Settings, _: OverwatchHandle<RuntimeServiceId>) -> Self {
        Self
    }

    async fn process(&self, _: Self::Message) {}

    async fn subscribe_to_pubsub(&mut self) -> BroadcastStream<Self::PubSubEvent> {
        unimplemented!()
    }

    async fn subscribe_to_chainsync(&mut self) -> BroadcastStream<Self::ChainSyncEvent> {
        unimplemented!()
    }
}

pub struct TestNetworkAdapter;

#[async_trait]
impl<RuntimeServiceId> NetworkAdapter<RuntimeServiceId> for TestNetworkAdapter {
    type Backend = TestNetworkBackend;
    type BroadcastSettings = ();

    fn new(
        _network_relay: OutboundRelay<
            <NetworkService<Self::Backend, RuntimeServiceId> as ServiceData>::Message,
        >,
    ) -> Self {
        Self
    }

    async fn broadcast(&self, _message: Vec<u8>, _broadcast_settings: Self::BroadcastSettings) {}
}
