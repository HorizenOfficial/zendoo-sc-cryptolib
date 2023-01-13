use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use cctp_primitives::{
    proving_system::init::{get_g1_committer_key, load_g1_committer_key},
    type_mapping::CoboundaryMarlin,
    type_mapping::Digest as Hash,
    utils::serialization::serialize_to_buffer,
};

use crate::{
    blaze_csw::constraints::CeasedSidechainWithdrawalCircuit,
    naive_threshold_sig::NaiveThresholdSignature,
    naive_threshold_sig_w_key_rotation::NaiveThresholdSignatureWKeyRotation, MAX_SEGMENT_SIZE,
    SUPPORTED_SEGMENT_SIZE,
};
use digest::Digest;
use serial_test::*;

// Blake2s digest of all circuits' (pk, vk)

// Base: zendoo-sc-cryptolib v0.5.0
const CSW_PK_DIGEST: &str = "33513c70bbd25a853ffe73e8d44f5569ee44351397c57c5761fa52aac5ce63dd";
const CSW_VK_DIGEST: &str = "dcb3aabfe0a2c962963d41f48ebda0eb15cf1fa2ebbd63dd450dffa135c2ccd8";
const CSW_NO_CONST_PK_DIGEST: &str = 
    "d786bf80bb5f50244fa25a852075714e1fd4012f11ebefe0b33b082fc67679b8";
const CSW_NO_CONST_VK_DIGEST: &str =
    "bc6c5f7327a3668513351b35191112e9053d2df9643b0708da32230338dd5451";

const THRESHOLD_V1_PK_DIGEST: &str =
    "b9701b189eb1e265dd128b236a3ec4979984b76a288101aac7c4074062bdf349";
const THRESHOLD_V1_VK_DIGEST: &str =
    "00f26e9ab058d46bc39f0c0383c22981a64a3c946e22dda5eae3c4c050f401a3";

// Base: zendoo-sc-cryptolib v0.6.0
const THRESHOLD_V2_PK_DIGEST: &str =
    "d3a70ab2990ae2b625b632d684049c19cd019237f49c419d9feb013b7cd5a373";
//"8e5987aba3c5a7ec44bc8b666ba2c720b4cbc857336dbbb052a7fe84b78119e2";
const THRESHOLD_V2_VK_DIGEST: &str =
    "0792d70d039a46dd6a29b2f87897e39c0ffc31c1f5d19b5db01a50a72a3f94db";
//    "43478bf7f66e2e64f5d55e00ba8352a627bfafb9eebdb475501d4837d43734a9";

// Common parameters to be used for regression
const NUM_KEYS: usize = 6;
const NUM_CUSTOM_FIELDS: u32 = 4;
const NUM_BLOCKS: u32 = 5;

#[derive(Debug, EnumIter)]
enum Circuits {
    ThresholdV1,
    ThresholdV2,
    CSWConstant,
    CSWNoConstant,
}

/// Get a setup instance of the circuit corresponding to 'circuit_type', compute the digest of (pk, vk)
/// and compare it with the hardcoded one
fn compute_and_compare_circuits_digests(circuit_type: Circuits) {
    let ck = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();

    // Get actual and reference (pk, vk) pairs
    let (params, comp_pk, comp_vk) = match circuit_type {
        Circuits::ThresholdV1 => {
            let c = NaiveThresholdSignature::get_instance_for_setup(
                NUM_KEYS,
                NUM_CUSTOM_FIELDS as usize,
            );
            (
                CoboundaryMarlin::index(&ck, c).unwrap(),
                THRESHOLD_V1_PK_DIGEST,
                THRESHOLD_V1_VK_DIGEST,
            )
        }
        Circuits::ThresholdV2 => {
            let c = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(
                NUM_KEYS,
                NUM_CUSTOM_FIELDS,
            );
            (
                CoboundaryMarlin::index(&ck, c).unwrap(),
                THRESHOLD_V2_PK_DIGEST,
                THRESHOLD_V2_VK_DIGEST,
            )
        }
        Circuits::CSWConstant => {
            let c = CeasedSidechainWithdrawalCircuit::get_instance_for_setup(
                NUM_BLOCKS,
                NUM_CUSTOM_FIELDS,
                true,
            );
            (
                CoboundaryMarlin::index(&ck, c).unwrap(),
                CSW_PK_DIGEST,
                CSW_VK_DIGEST,
            )
        }
        Circuits::CSWNoConstant => {
            let c = CeasedSidechainWithdrawalCircuit::get_instance_for_setup(
                NUM_BLOCKS,
                NUM_CUSTOM_FIELDS,
                false,
            );
            (
                CoboundaryMarlin::index(&ck, c).unwrap(),
                CSW_NO_CONST_PK_DIGEST,
                CSW_NO_CONST_VK_DIGEST,
            )
        }
    };

    // Serialize them
    let actual_pk_bytes = serialize_to_buffer(&params.0, Some(true)).unwrap();
    let actual_vk_bytes = serialize_to_buffer(&params.1, Some(true)).unwrap();

    // Compute their digests
    let actual_pk_digest = hex::encode(Hash::digest(actual_pk_bytes.as_slice()));
    let actual_vk_digest = hex::encode(Hash::digest(actual_vk_bytes.as_slice()));

    // Assert they have not changed
    assert_eq!(
        actual_pk_digest, comp_pk,
        "Regression test failed for {:?} circuit proving key",
        circuit_type
    );
    assert_eq!(
        actual_vk_digest, comp_vk,
        "Regression test failed for {:?} circuit verification key",
        circuit_type
    );
}

#[serial]
#[test]
fn no_changes_in_circuits_from_previous_version() {
    // Create DLOG keys
    let _ = load_g1_committer_key(MAX_SEGMENT_SIZE - 1);

    // Assert no changes for each circuit compared to the previous version
    Circuits::iter().for_each(|circ_type| compute_and_compare_circuits_digests(circ_type))
}
