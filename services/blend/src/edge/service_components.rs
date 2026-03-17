use crate::{
    edge::{BlendService, backends::BlendBackend},
    network::NetworkAdapter,
};

/// Exposes associated types for external modules that depend on
/// [`BlendService`], without requiring them to specify its generic parameters.
pub trait ServiceComponents {
    /// Settings for broadcasting messages that have passed through the blend
    /// network.
    type BroadcastSettings;
    /// Adapter for membership service.
    type MembershipAdapter;
    type ProofsGenerator;
    type BackendSettings;
}

impl<
    Backend,
    NodeId,
    MembershipAdapter,
    ProofsGenerator,
    TimeBackend,
    ChainService,
    PolInfoProvider,
    Network,
    RuntimeServiceId,
> ServiceComponents
    for BlendService<
        Backend,
        NodeId,
        MembershipAdapter,
        ProofsGenerator,
        TimeBackend,
        ChainService,
        PolInfoProvider,
        Network,
        RuntimeServiceId,
    >
where
    Backend: BlendBackend<NodeId, RuntimeServiceId>,
    Network: NetworkAdapter<RuntimeServiceId>,
    NodeId: Clone,
{
    type BackendSettings = Backend::Settings;
    type BroadcastSettings = Network::BroadcastSettings;
    type MembershipAdapter = MembershipAdapter;
    type ProofsGenerator = ProofsGenerator;
}
