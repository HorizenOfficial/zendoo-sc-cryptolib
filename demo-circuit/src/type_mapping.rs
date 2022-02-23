use algebra::{
    fields::ed25519::{fq::Fq as ed25519Fq, fr::Fr as ed25519Fr},
    FpParameters, PrimeField,
};
use r1cs_crypto::{
    field_based_mht::FieldBasedBinaryMerkleTreePathGadget,
    TweedleFrDensityOptimizedPoseidonHashGadget,
};
use r1cs_std::{fields::fp::FpGadget, groups::nonnative::GroupAffineNonNativeGadget};
use super::*;

pub type FieldElementGadget = FpGadget<FieldElement>;
pub type FieldHashGadget = TweedleFrDensityOptimizedPoseidonHashGadget;
pub type GingerMHTBinaryPath = GingerMHTPath;
pub type GingerMHTBinaryGadget =
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
pub type ECPointSimulationGadget =
    GroupAffineNonNativeGadget<SimulatedCurveParameters, FieldElement, SimulatedFieldElement>;
