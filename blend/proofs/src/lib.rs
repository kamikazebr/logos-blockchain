use lb_blend_crypto::{ZkHash, ZkHasher};
use lb_key_management_system_keys::keys::UnsecuredEd25519Key;
pub use lb_poq::CorePathAndSelectors;

use crate::{quota::VerifiedProofOfQuota, selection::VerifiedProofOfSelection};

pub mod quota;
pub mod selection;

trait ZkHashExt {
    fn hash(&self) -> ZkHash;
}

impl<T> ZkHashExt for T
where
    T: AsRef<[ZkHash]>,
{
    fn hash(&self) -> ZkHash {
        let mut hasher = ZkHasher::new();
        hasher.update(self.as_ref());
        hasher.finalize()
    }
}

trait ZkCompressExt {
    fn compress(&self) -> ZkHash;
}

impl ZkCompressExt for [ZkHash; 2] {
    fn compress(&self) -> ZkHash {
        let mut hasher = ZkHasher::new();
        hasher.compress(self);
        hasher.finalize()
    }
}

impl ZkCompressExt for &[ZkHash; 2] {
    fn compress(&self) -> ZkHash {
        let mut hasher = ZkHasher::new();
        hasher.compress(self);
        hasher.finalize()
    }
}

/// A single proof to be attached to one layer of a Blend message.
pub struct BlendLayerProof {
    /// `PoQ`
    pub proof_of_quota: VerifiedProofOfQuota,
    /// `PoSel`
    pub proof_of_selection: VerifiedProofOfSelection,
    /// Ephemeral key used to sign the message layer's payload.
    pub ephemeral_signing_key: UnsecuredEd25519Key,
}
