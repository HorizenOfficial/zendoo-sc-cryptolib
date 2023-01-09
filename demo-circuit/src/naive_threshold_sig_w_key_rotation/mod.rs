use algebra::{Field, PrimeField, ToBits};

use primitives::{
    crh::FieldBasedHash, signature::schnorr::field_based_schnorr::FieldBasedSchnorrSignature,
    FieldBasedSignatureScheme,
};

use crate::create_msg_to_sign;
use crate::{
    common::data_structures::{WithdrawalCertificateData, NULL_CONST},
    type_mapping::*,
};

use cctp_primitives::{
    proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH,
    utils::{commitment_tree::hash_vec, get_cert_data_hash_from_bt_root_and_custom_fields_hash},
};
use data_structures::ValidatorKeysUpdates;

pub mod constraints;
pub mod data_structures;
#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct NaiveThresholdSignatureWKeyRotation {
    // Witnesses
    /// Validators' signatures on the current withdrawal certificate
    wcert_signatures: Vec<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,

    /// Validators' key changes and the corresponding signatures
    validator_keys_updates: ValidatorKeysUpdates,

    /// Current WithdrawalCertificate
    withdrawal_certificate: WithdrawalCertificateData,

    /// Previous WithdrawalCertificate
    prev_withdrawal_certificate: WithdrawalCertificateData,

    /// Minimum number of valid signatures for the certificate to be considered valid
    threshold: FieldElement,

    /// Used for the threshold check
    b: Vec<bool>,

    /// Merkle root of the genesis validators' keys tree
    genesis_validator_keys_tree_root: FieldElement,

    /// If the circuit is being instantiated for the first certificate
    is_first_certificate: bool,

    /// Number of valid validators' signatures on the certificate
    valid_signatures: usize,

    // Public inputs
    /// The SC constant declared in MC and published in the genesis block
    /// It is currently computed as H(MR(genesis_validators_keys)||threshold)
    genesis_constant: FieldElement,

    /// Hash of the previous certificate data, supposed to be set to phantom
    /// if the circuit is for the first certificate
    prev_cert_data_hash: FieldElement,

    /// Hash of the current certificate data
    cert_data_hash: FieldElement,
}

impl NaiveThresholdSignatureWKeyRotation {
    pub fn get_instance_for_setup(max_pks: usize, custom_fields_len: u32) -> Self {
        //Instantiating supported number of pks and sigs
        let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
        let withdrawal_certificate = WithdrawalCertificateData::get_default(custom_fields_len);

        // Create parameters for our circuit
        NaiveThresholdSignatureWKeyRotation {
            validator_keys_updates: ValidatorKeysUpdates::get_instance_for_setup(max_pks, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id),
            wcert_signatures: vec![NULL_CONST.null_sig; max_pks],
            withdrawal_certificate: withdrawal_certificate.clone(),
            prev_withdrawal_certificate: withdrawal_certificate,
            threshold: FieldElement::zero(),
            b: vec![false; log_max_pks + 1],
            genesis_validator_keys_tree_root: FieldElement::zero(),
            is_first_certificate: false,
            genesis_constant: FieldElement::zero(),
            cert_data_hash: FieldElement::zero(),
            prev_cert_data_hash: FieldElement::zero(),
            valid_signatures: 0,
        }
    }

    pub fn new(
        validator_keys_updates: ValidatorKeysUpdates,
        wcert_signatures: Vec<Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>>,
        mut withdrawal_certificate: WithdrawalCertificateData,
        prev_withdrawal_certificate: Option<WithdrawalCertificateData>,
        threshold: u64,
        genesis_validator_keys_tree_root: FieldElement,
    ) -> Result<Self, Error> {
        assert!(
            !withdrawal_certificate.custom_fields.is_empty(),
            "custom_fields < 1"
        );
        assert_eq!(
            wcert_signatures.len(),
            validator_keys_updates.max_pks,
            "wcert_signatures.len != max_pks"
        );
        assert_eq!(
            validator_keys_updates.max_pks,
            validator_keys_updates.signing_keys.len()
        );
        assert_eq!(
            validator_keys_updates.max_pks,
            validator_keys_updates.master_keys.len()
        );
        assert_eq!(
            validator_keys_updates.max_pks,
            validator_keys_updates.updated_signing_keys.len()
        );
        assert_eq!(
            validator_keys_updates.max_pks,
            validator_keys_updates.updated_master_keys.len()
        );

        let is_first_certificate = prev_withdrawal_certificate.is_none();

        let threshold = FieldElement::from(threshold);
        //Compute genesis_constant (merkle tree of validator keys hashed with the threshold)
        let genesis_constant = FieldHash::init_constant_length(2, None)
                .update(genesis_validator_keys_tree_root)
                .update(threshold)
                .finalize()?;

        let msg_signed = create_msg_to_sign(
            &withdrawal_certificate.ledger_id,
            withdrawal_certificate.epoch_id,
            &withdrawal_certificate.mcb_sc_txs_com,
            withdrawal_certificate.btr_min_fee,
            withdrawal_certificate.ft_min_amount,
            &withdrawal_certificate.bt_root,
            Some(withdrawal_certificate.custom_fields.clone()),
        )?;

        // Iterate over sigs, check and count number of valid signatures,
        // and replace with NULL_CONST.null_sig the None ones
        let mut wcert_signatures_adjusted =
            vec![NULL_CONST.null_sig; validator_keys_updates.max_pks];
        let mut valid_signatures = 0usize;

        for (i, opt_sig) in wcert_signatures.iter().enumerate() {
            if let Some(sig) = opt_sig {
                let is_verified = SchnorrSigScheme::verify(
                    &validator_keys_updates.signing_keys[i],
                    msg_signed,
                    sig,
                )
                .map_err(|e| format!("Unable to verify signature {}: {:?}", i, e))?;
                if is_verified {
                    valid_signatures += 1;
                }
                wcert_signatures_adjusted[i] = *sig;
            }
        }

        //Convert b to the needed bool vector
        let b_bool = {
            let log_max_pks = (validator_keys_updates.max_pks.next_power_of_two() as u64)
                .trailing_zeros() as usize;
            //Compute b as v-t and convert it to field element
            let b_bits = (FieldElement::from(valid_signatures as u64) - threshold).write_bits();
            let to_skip = FieldElement::size_in_bits() - (log_max_pks + 1);
            b_bits[to_skip..].to_vec()
        };

        withdrawal_certificate.quality = valid_signatures as u64;
        //Compute cert_data_hash
        let custom_fields_hash = hash_vec(withdrawal_certificate.custom_fields.clone())?;
        let cert_data_hash = get_cert_data_hash_from_bt_root_and_custom_fields_hash(
            &withdrawal_certificate.ledger_id,
            withdrawal_certificate.epoch_id,
            withdrawal_certificate.quality,
            withdrawal_certificate.bt_root,
            Some(custom_fields_hash),
            &withdrawal_certificate.mcb_sc_txs_com,
            withdrawal_certificate.btr_min_fee,
            withdrawal_certificate.ft_min_amount,
        )?;

        //Compute prev_cert_data_hash, if a previous certificate is present
        let prev_cert_data_hash = match prev_withdrawal_certificate {
            Some(ref prev_cert) => {
                let prev_custom_fields_hash = hash_vec(prev_cert.custom_fields.clone())?;
                get_cert_data_hash_from_bt_root_and_custom_fields_hash(
                    &prev_cert.ledger_id,
                    prev_cert.epoch_id,
                    prev_cert.quality,
                    prev_cert.bt_root,
                    Some(prev_custom_fields_hash),
                    &prev_cert.mcb_sc_txs_com,
                    prev_cert.btr_min_fee,
                    prev_cert.ft_min_amount,
                )?
            }
            None => PHANTOM_CERT_DATA_HASH,
        };

        let prev_withdrawal_certificate =
            prev_withdrawal_certificate.unwrap_or_else(|| {
                WithdrawalCertificateData::get_default(
                    withdrawal_certificate.custom_fields.len() as u32
                )
            });

        Ok(Self {
            validator_keys_updates,
            wcert_signatures: wcert_signatures_adjusted,
            withdrawal_certificate,
            prev_withdrawal_certificate,
            threshold,
            b: b_bool,
            genesis_constant,
            genesis_validator_keys_tree_root,
            is_first_certificate,
            cert_data_hash,
            prev_cert_data_hash,
            valid_signatures,
        })
    }

    pub fn get_valid_signatures(&self) -> usize {
        self.valid_signatures
    }
}
