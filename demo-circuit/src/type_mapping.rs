pub use cctp_primitives::type_mapping::*;
use primitives::{
    crh::bowe_hopwood::BoweHopwoodPedersenCRH,
    signature::{
    schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrSignature,
    },
}, vrf::ecvrf::*};
use crate::constants::VRFWindow;

pub const SCHNORR_PK_SIZE: usize = GROUP_COMPRESSED_SIZE;
pub const SCHNORR_SK_SIZE: usize = SCALAR_FIELD_SIZE;
pub const SCHNORR_SIG_SIZE: usize = 2 * FIELD_SIZE;

pub const VRF_PK_SIZE: usize = GROUP_COMPRESSED_SIZE;
pub const VRF_SK_SIZE: usize = SCALAR_FIELD_SIZE;
pub const VRF_PROOF_SIZE: usize = GROUP_COMPRESSED_SIZE + 2 * FIELD_SIZE;

pub type Error = Box<dyn std::error::Error>;

pub type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<FieldElement, Projective, FieldHash>;
pub type SchnorrSig = FieldBasedSchnorrSignature<FieldElement, Projective>;
pub type SchnorrPk = Affine;
pub type SchnorrSk = ScalarFieldElement;

pub type GroupHash = BoweHopwoodPedersenCRH<Projective, VRFWindow>;

pub type VRFScheme = FieldBasedEcVrf<FieldElement, Projective, FieldHash, GroupHash>;
pub type VRFProof = FieldBasedEcVrfProof<FieldElement, Projective>;
pub type VRFPk = Affine;
pub type VRFSk = ScalarFieldElement;