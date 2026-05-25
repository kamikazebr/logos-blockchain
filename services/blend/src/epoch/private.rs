use core::fmt::{self, Debug, Formatter};

use async_trait::async_trait;
use futures::Stream;
use lb_blend::proofs::quota::inputs::prove::private::ProofOfLeadershipQuotaInputs;
use lb_chain_service::Epoch;
use lb_core::proofs::leader_proof::LeaderPublic;
use overwatch::overwatch::OverwatchHandle;

use crate::epoch::public::BlendMembershipEpochState;

/// Secret `PoL` info associated to an epoch, as returned by the `PoL` info
/// provider.
#[derive(Clone)]
pub struct PolEpochInfo<NodeId> {
    pub poq_public_inputs: BlendMembershipEpochState<NodeId>,
    pub poq_private_inputs: ProofOfLeadershipQuotaInputs,
}

impl<NodeId> Debug for PolEpochInfo<NodeId> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolEpochInfo")
            .field("poq_public_inputs", &self.poq_public_inputs)
            .field("poq_private_inputs", &"<redacted>")
            .finish()
    }
}

#[async_trait]
pub trait PolInfoProvider<NodeId, RuntimeServiceId> {
    type Stream: Stream<Item = PolEpochInfo<NodeId>>;

    async fn subscribe(
        overwatch_handle: &OverwatchHandle<RuntimeServiceId>,
    ) -> Option<Self::Stream>;
}
