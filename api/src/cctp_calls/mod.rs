use demo_circuit::*;
use r1cs_core::debug_circuit;
use rand::rngs::OsRng;

use cctp_primitives::{
    proving_system::{
        error::ProvingSystemError,
        init::get_g1_committer_key,
        verifier::verify_zendoo_proof,
        ProvingSystem, ZendooProof, ZendooProverKey, ZendooVerifierKey,
    },
    utils::commitment_tree::DataAccumulator,
};

pub mod cert;
pub mod csw;