
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use cctp_primitives::{type_mapping::Digest as Hash, proving_system::init::{load_g1_committer_key, get_g1_committer_key}, type_mapping::CoboundaryMarlin, utils::serialization::serialize_to_buffer};

use crate::{MAX_SEGMENT_SIZE, SUPPORTED_SEGMENT_SIZE, naive_threshold_sig::NaiveThresholdSignature, naive_threshold_sig_w_key_rotation::NaiveThresholdSignatureWKeyRotation, blaze_csw::constraints::CeasedSidechainWithdrawalCircuit};
use digest::Digest;
use serial_test::*;

// Blake2s digest of all circuits' (pk, vk)

// Base: zendoo-sc-cryptolib v0.5.0
const CSW_PK_DIGEST: &str = "59bf77a13f149f77ecae088ff2900ac9ff200dfc6c32d22d1e021e316cd34b33";
const CSW_VK_DIGEST: &str = "80f11e13d9c40bbaccca90083ed1dba52f0384435a4a9b3ebfad4bd551221d67";

const THRESHOLD_V1_PK_DIGEST: &str = "b9701b189eb1e265dd128b236a3ec4979984b76a288101aac7c4074062bdf349";
const THRESHOLD_V1_VK_DIGEST: &str = "00f26e9ab058d46bc39f0c0383c22981a64a3c946e22dda5eae3c4c050f401a3";

// Base: zendoo-sc-cryptolib v0.6.0
const THRESHOLD_V2_PK_DIGEST: &str = "8e5987aba3c5a7ec44bc8b666ba2c720b4cbc857336dbbb052a7fe84b78119e2";
const THRESHOLD_V2_VK_DIGEST: &str = "43478bf7f66e2e64f5d55e00ba8352a627bfafb9eebdb475501d4837d43734a9";

// Common parameters to be used for regression
const NUM_KEYS: usize = 6;
const NUM_CUSTOM_FIELDS: u32 = 4;
const NUM_BLOCKS: u32 = 10;
const CONSTANT_PRESENT: bool = true;

#[derive(Debug, EnumIter)]
enum Circuits {
    ThresholdV1,
    ThresholdV2,
    CSW,
}

/// Get a setup instance of the circuit corresponding to 'circuit_type', compute the digest of (pk, vk)
/// and compare it with the hardcoded one
fn compute_and_compare_circuits_digests(circuit_type: Circuits) {
    let ck = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();

    // Get actual and reference (pk, vk) pairs
    let (params, comp_pk, comp_vk) = match circuit_type {
        Circuits::ThresholdV1 => {
            let c = NaiveThresholdSignature::get_instance_for_setup(NUM_KEYS, NUM_CUSTOM_FIELDS as usize);
            (CoboundaryMarlin::index(&ck, c).unwrap(), THRESHOLD_V1_PK_DIGEST, THRESHOLD_V1_VK_DIGEST)
        },
        Circuits::ThresholdV2 => {
            let c = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(NUM_KEYS, NUM_CUSTOM_FIELDS);
            (CoboundaryMarlin::index(&ck, c).unwrap(), THRESHOLD_V2_PK_DIGEST, THRESHOLD_V2_VK_DIGEST)
        },
        Circuits::CSW => {
            let c = CeasedSidechainWithdrawalCircuit::get_instance_for_setup(NUM_BLOCKS, NUM_CUSTOM_FIELDS, CONSTANT_PRESENT);
            (CoboundaryMarlin::index(&ck, c).unwrap(), CSW_PK_DIGEST, CSW_VK_DIGEST)
        },
    };

    // Serialize them
    let actual_pk_bytes = serialize_to_buffer(&params.0, Some(true)).unwrap();
    let actual_vk_bytes = serialize_to_buffer(&params.1, Some(true)).unwrap();

    // Compute their digests
    let actual_pk_digest = hex::encode(Hash::digest(actual_pk_bytes.as_slice()));
    let actual_vk_digest = hex::encode(Hash::digest(actual_vk_bytes.as_slice()));

    // Assert they have not changed
    assert_eq!(actual_pk_digest, comp_pk, "Regression test failed for {:?} circuit proving key", circuit_type);
    assert_eq!(actual_vk_digest, comp_vk, "Regression test failed for {:?} circuit verification key", circuit_type);

}

#[serial]
#[test]
fn no_changes_from_previous_version() {
    // Create DLOG keys
    let _ = load_g1_committer_key(MAX_SEGMENT_SIZE - 1);

    // Assert no changes for each circuit compared to the previous version
    Circuits::iter().for_each(|circ_type| compute_and_compare_circuits_digests(circ_type))
}