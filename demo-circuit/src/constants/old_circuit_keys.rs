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
const CSW_PK_DIGEST: &str = "191f3d52680d5223f623dd15d5eccef6e5d61c3084bcbbbc0a4d93fec2a1a16f";
const CSW_VK_DIGEST: &str = "200d698d865dd49f8f6920200d94272c8ed0e837ef34c615d14ac8801a4b5c94";
const CSW_NO_CONST_PK_DIGEST: &str =
    "3437a211f2cdb7f5a1f821c230f70ba04d3f4a98c877af24ec772e605c38c62a";
const CSW_NO_CONST_VK_DIGEST: &str =
    "e8f459cca702f05b473080c214f3e9bfcc01684e16e41a83f122619d8b2dff0f";

const THRESHOLD_V1_PK_DIGEST: &str =
    "c9eb18711e1b30e5f1a0733bff004efcd6507e81c4509ee71dcb0c367396ad29";
const THRESHOLD_V1_VK_DIGEST: &str =
    "821dd1bb16309d12e8075492e2da685c15caef0920b1ec0579fda86d873029b8";

// Base: zendoo-sc-cryptolib v0.6.0
const THRESHOLD_V2_PK_DIGEST: &str =
    "80c9220c01cc3efdb052080d6bd6096cc8a456e96fc50e971e1830f10f7f5a68";
const THRESHOLD_V2_VK_DIGEST: &str =
    "4a9b672b36c97bb0fc2f2308085f1dc259a7b3e11c39bde1db7b7ed5f1afa429";

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
    Circuits::iter().for_each(compute_and_compare_circuits_digests)
}
