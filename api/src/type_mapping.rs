use algebra::{
    fields::{
        tweedle::{Fq as ScalarFieldElement, Fr},
    },
    curves::{
        tweedle::{
            dum::{
                Projective as Projective,
                Affine as Affine
            },
            dee::Affine as PCAffine
        },
    },
    BigInteger256
};

use primitives::{crh::{
    poseidon::parameters::tweedle::{TweedleFrPoseidonHash as PoseidonHash, TweedleFrBatchPoseidonHash as BatchFieldHash},
    bowe_hopwood::{
        BoweHopwoodPedersenCRH,
    },
}, merkle_tree::field_based_mht::{
    // smt::{BigMerkleTree, LazyBigMerkleTree, Coord, OperationLeaf},
    optimized::FieldBasedOptimizedMHT,
    parameters::tweedle_fr::TWEEDLE_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS,
    FieldBasedMerkleTreePrecomputedEmptyConstants,
    FieldBasedMerkleTreeParameters, BatchFieldBasedMerkleTreeParameters,
    FieldBasedBinaryMHTPath,
}, signature::{
    schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrSignature,
    },
}, vrf::{ecvrf::*}/*, ActionLeaf*/};

use marlin::*;
use blake2::Blake2s;
use poly_commit::ipa_pc::InnerProductArgPC;
use demo_circuit::{
    constants::{
        VRFWindow,
    },
};

pub type FieldBigInteger = BigInteger256;
pub type FieldElement = Fr;

// #[derive(Clone)]
// struct MarlinNoLCNoZk;
//
// impl MarlinConfig for MarlinNoLCNoZk {
//     const LC_OPT: bool = false;
//     const ZK: bool = false;
// }

pub type IPAPC = InnerProductArgPC<PCAffine, Blake2s>;
// type MarlinInst = Marlin<Fr, IPAPC, Blake2s, MarlinNoLCNoZk>;
pub type MarlinInst = Marlin<Fr, IPAPC, Blake2s>;

pub const FIELD_SIZE: usize = 32; //Field size in bytes
pub const SCALAR_FIELD_SIZE: usize = FIELD_SIZE;// 32
pub const G_SIZE: usize = 96;

pub const SCHNORR_PK_SIZE: usize = G_SIZE; // 96
pub const SCHNORR_SK_SIZE: usize = SCALAR_FIELD_SIZE; // 32
pub const SCHNORR_SIG_SIZE: usize = 2 * FIELD_SIZE; // 64

pub const VRF_PK_SIZE: usize = G_SIZE; // 96
pub const VRF_SK_SIZE: usize = SCALAR_FIELD_SIZE; // 32
pub const VRF_PROOF_SIZE: usize = G_SIZE + 2 * FIELD_SIZE; // 160

pub type Error = Box<dyn std::error::Error>;

pub type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<FieldElement, Projective, FieldHash>;
pub type SchnorrSig = FieldBasedSchnorrSignature<FieldElement, Projective>;
pub type SchnorrPk = Affine;
pub type SchnorrSk = ScalarFieldElement;

pub type FieldHash = PoseidonHash;

pub type SCProof = Proof<Fr, IPAPC>;

pub type GroupHash = BoweHopwoodPedersenCRH<Projective, VRFWindow>;

pub type VRFScheme = FieldBasedEcVrf<FieldElement, Projective, FieldHash, GroupHash>;
pub type VRFProof = FieldBasedEcVrfProof<FieldElement, Projective>;
pub type VRFPk = Affine;
pub type VRFSk = ScalarFieldElement;

#[derive(Debug, Clone)]
pub struct GingerMerkleTreeParameters;

impl FieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type Data = FieldElement;
    type H = FieldHash;
    const MERKLE_ARITY: usize = 2;
    const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> =
        Some(MHT_PARAMETERS);
}

impl BatchFieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type BH = BatchFieldHash;
}

pub type GingerMHTPath = FieldBasedBinaryMHTPath<GingerMerkleTreeParameters>;
pub type GingerMHT = FieldBasedOptimizedMHT<GingerMerkleTreeParameters>;