use crate::constants::VRFWindow;
use algebra::{
    fields::ed25519::{fq::Fq as ed25519Fq, fr::Fr as ed25519Fr},
    FpParameters, PrimeField,
};
pub use cctp_primitives::type_mapping::*;
use primitives::{
    crh::bowe_hopwood::BoweHopwoodPedersenCRH,
    signature::schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme,
    },
    vrf::ecvrf::*,
    FieldBasedBinaryMHTPath,
};
use r1cs_crypto::schnorr::field_based_schnorr::{
    FieldBasedSchnorrPkGadget, FieldBasedSchnorrSigGadget, FieldBasedSchnorrSigVerificationGadget,
};
use r1cs_crypto::{
    field_based_mht::{FieldBasedBinaryMerkleTreePathGadget, FieldBasedMerkleTreeGadget},
    TweedleFrPoseidonHashGadget, TweedleFrDensityOptimizedPoseidonHashGadget,
};
use r1cs_std::{
    fields::fp::FpGadget, groups::nonnative::GroupAffineNonNativeGadget,
    instantiated::tweedle::TweedleDumGadget as CurveGadget,
};

pub const SCHNORR_PK_SIZE: usize = GROUP_COMPRESSED_SIZE;
pub const SCHNORR_SK_SIZE: usize = SCALAR_FIELD_SIZE;
pub const SCHNORR_SIG_SIZE: usize = 2 * FIELD_SIZE;

pub const VRF_PK_SIZE: usize = GROUP_COMPRESSED_SIZE;
pub const VRF_SK_SIZE: usize = SCALAR_FIELD_SIZE;
pub const VRF_PROOF_SIZE: usize = GROUP_COMPRESSED_SIZE + 2 * FIELD_SIZE;

pub type Error = Box<dyn std::error::Error>;

pub type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<FieldElement, G2Projective, FieldHash>;
pub type SchnorrSig = FieldBasedSchnorrSignature<FieldElement, G2Projective>;
pub type SchnorrPk = G2;
pub type SchnorrSk = ScalarFieldElement;

pub type GroupHash = BoweHopwoodPedersenCRH<G2Projective, VRFWindow>;

pub type VRFScheme = FieldBasedEcVrf<FieldElement, G2Projective, FieldHash, GroupHash>;
pub type VRFProof = FieldBasedEcVrfProof<FieldElement, G2Projective>;
pub type VRFPk = G2;
pub type VRFSk = ScalarFieldElement;
pub(crate) type FieldElementGadget = FpGadget<FieldElement>;
pub(crate) type FieldHashGadget = TweedleFrDensityOptimizedPoseidonHashGadget;

// Kept for backward compatibility of Threshold Circuit V1
pub(crate) type UnoptimizedFieldHashGadget = TweedleFrPoseidonHashGadget;

pub type GingerMHTBinaryPath = FieldBasedBinaryMHTPath<GingerMHTParams>;
#[allow(unused)]
pub(crate) type GingerMHTGagdet =
    FieldBasedMerkleTreeGadget<GingerMHTParams, FieldHashGadget, FieldElement>;
pub(crate) type GingerMHTBinaryGadget =
    FieldBasedBinaryMerkleTreePathGadget<GingerMHTParams, FieldHashGadget, FieldElement>;

// Simulated types
pub type SimulatedScalarFieldElement = ed25519Fr;
pub const SIMULATED_SCALAR_FIELD_MODULUS_BITS: usize =
    <SimulatedScalarFieldElement as PrimeField>::Params::MODULUS_BITS as usize;

pub const SIMULATED_SCALAR_FIELD_REPR_SHAVE_BITS: usize =
    <SimulatedScalarFieldElement as PrimeField>::Params::REPR_SHAVE_BITS as usize;

pub const SIMULATED_SCALAR_FIELD_BYTE_SIZE: usize =
    (SIMULATED_SCALAR_FIELD_MODULUS_BITS + SIMULATED_SCALAR_FIELD_REPR_SHAVE_BITS) / 8;

pub type SimulatedFieldElement = ed25519Fq;
pub const SIMULATED_FIELD_BYTE_SIZE: usize =
    ((<SimulatedFieldElement as PrimeField>::Params::MODULUS_BITS
        + <SimulatedFieldElement as PrimeField>::Params::REPR_SHAVE_BITS)
        / 8) as usize;

pub type SimulatedSWGroup = algebra::curves::ed25519::SWEd25519Affine;
pub type SimulatedTEGroup = algebra::curves::ed25519::TEEd25519Affine;
pub type SimulatedCurveParameters = algebra::curves::ed25519::Ed25519Parameters;
pub(crate) type ECPointSimulationGadget =
    GroupAffineNonNativeGadget<SimulatedCurveParameters, FieldElement, SimulatedFieldElement>;

//Sig types
pub(crate) type SchnorrSigGadget = FieldBasedSchnorrSigGadget<FieldElement, G2Projective>;
pub(crate) type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    FieldElement,
    G2Projective,
    CurveGadget,
    FieldHash,
    FieldHashGadget,
>;
pub(crate) type UnoptimizedSchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    FieldElement,
    G2Projective,
    CurveGadget,
    FieldHash,
    UnoptimizedFieldHashGadget,
>;
pub(crate) type SchnorrPkGadget =
    FieldBasedSchnorrPkGadget<FieldElement, G2Projective, CurveGadget>;
