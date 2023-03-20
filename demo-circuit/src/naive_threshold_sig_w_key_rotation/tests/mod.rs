mod first_cert;
mod next_cert;
mod utils;
mod verify;

use cctp_primitives::{
    proving_system::init::{get_g1_committer_key, load_g1_committer_key},
    utils::commitment_tree::hash_vec,
};
use primitives::schnorr::field_based_schnorr::FieldBasedSchnorrPk;
use primitives::{
    schnorr::field_based_schnorr::FieldBasedSchnorrSignature, FieldBasedHash,
    FieldBasedSignatureScheme,
};
use r1cs_core::debug_circuit;
use rand::thread_rng;
use serial_test::serial;
use utils::*;

use crate::{
    common::{WithdrawalCertificateData, NULL_CONST},
    create_msg_to_sign,
    type_mapping::*,
};
use rand::Rng;

use crate::{MAX_SEGMENT_SIZE, SUPPORTED_SEGMENT_SIZE};

use super::{data_structures::ValidatorKeysUpdates, NaiveThresholdSignatureWKeyRotation};

pub const VALIDATORS_SIZE: usize = 6;
pub const MAX_PKS: usize = VALIDATORS_SIZE;
