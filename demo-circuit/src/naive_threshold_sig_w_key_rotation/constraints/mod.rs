use algebra::Field;
use cctp_primitives::proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH;
use r1cs_crypto::{crh::FieldBasedHashGadget, signature::FieldBasedSigGadget, FieldHasherGadget};

use r1cs_std::{
    alloc::AllocGadget,
    bits::{boolean::Boolean, FromBitsGadget},
    eq::EqGadget,
    fields::FieldGadget,
    prelude::ConstantGadget,
    select::CondSelectGadget,
};

use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};

use super::NaiveThresholdSignatureWKeyRotation;
use crate::{
    common::constraints::{MessageSigningDataGadget, WithdrawalCertificateDataGadget},
    naive_threshold_sig_w_key_rotation::constraints::data_structures::ValidatorKeysUpdatesGadget,
    type_mapping::*,
};
use crate::naive_threshold_sig_w_key_rotation::data_structures::VALIDATOR_HASH_SALT;

pub mod data_structures;

impl ConstraintSynthesizer<FieldElement> for NaiveThresholdSignatureWKeyRotation {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // *************************** Check preconditions ********************************
        let max_pks = self.validator_keys_updates.max_pks;
        let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
        assert_eq!(max_pks, self.validator_keys_updates.signing_keys.len());
        assert_eq!(max_pks, self.validator_keys_updates.master_keys.len());
        assert_eq!(
            max_pks,
            self.validator_keys_updates.updated_signing_keys.len()
        );
        assert_eq!(
            max_pks,
            self.validator_keys_updates.updated_master_keys.len()
        );
        assert_eq!(
            max_pks,
            self.validator_keys_updates
                .updated_signing_keys_sk_signatures
                .len()
        );
        assert_eq!(
            max_pks,
            self.validator_keys_updates
                .updated_signing_keys_mk_signatures
                .len()
        );
        assert_eq!(
            max_pks,
            self.validator_keys_updates
                .updated_master_keys_sk_signatures
                .len()
        );
        assert_eq!(
            max_pks,
            self.validator_keys_updates
                .updated_master_keys_mk_signatures
                .len()
        );
        assert_eq!(max_pks, self.wcert_signatures.len());
        assert_eq!(log_max_pks + 1, self.b.len());
        assert!(!self.withdrawal_certificate.custom_fields.is_empty());
        assert!(!self.prev_withdrawal_certificate.custom_fields.is_empty());

        // *************************** Allocate/derive common data for checks below ***************************

        // Alloc current certificate data
        let withdrawal_certificate_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc wcert data"), || {
                Ok(self.withdrawal_certificate.clone())
            })?;

        // Alloc prev_wcert
        let prev_withdrawal_certificate_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc prev wcert data"), || {
                Ok(self.prev_withdrawal_certificate.clone())
            })?;

        // We let the prover set the value of this flag, but he will be forced to pick the correct one.
        let is_first_certificate_g =
            Boolean::alloc(cs.ns(|| "alloc is_first_certificate"), || {
                Ok(self.is_first_certificate)
            })?;

        // Alloc validators keys updates
        let validators_keys_updates_g =
            ValidatorKeysUpdatesGadget::alloc(cs.ns(|| "alloc validator keys updates"), || {
                Ok(self.validator_keys_updates.clone())
            })?;

        // Alloc the root of the genesis_validator_keys_tree
        let genesis_validator_keys_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc genesis_validator_keys_tree_root"), || {
                Ok(self.genesis_validator_keys_tree_root)
            })?;

        // *************************** Check certificate's signatures >= threshold ***************************

        // Derive the preimage of the message to be signed, i.e. certificate_data_without_quality
        let message_g = MessageSigningDataGadget::from(&withdrawal_certificate_g);

        // Allocate threshold
        let threshold_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc threshold"), || Ok(self.threshold))?;

        // Allocate signatures
        let mut sigs_g = Vec::with_capacity(max_pks);

        for (i, sig) in self.wcert_signatures.iter().enumerate() {
            let sig_g = SchnorrSigGadget::alloc(cs.ns(|| format!("alloc_sig_{}", i)), || Ok(sig))?;
            sigs_g.push(sig_g);
        }

        // Alloc the b's
        let mut bs_g = Vec::with_capacity(log_max_pks + 1);
        for (i, b) in self.b.iter().enumerate() {
            let b_g = Boolean::alloc(cs.ns(|| format!("alloc b_{}", i)), || Ok(b))?;
            bs_g.push(b_g);
        }

        // Pack the b's into a field element
        let b_field = FieldElementGadget::from_bits(
            cs.ns(|| "pack the b's into a field element"),
            bs_g.as_slice(),
        )?;

        // Convert quality to FE
        let cert_quality_fe_g = {
            let mut bits = withdrawal_certificate_g.quality_g.to_bits_le();
            bits.reverse();

            FieldElementGadget::from_bits(cs.ns(|| "cert_quality_fe_g"), bits.as_slice())
        }?;

        // Enforce msg_to_sign
        let msg_hash_g = message_g.enforce_hash(cs.ns(|| "enforce msg signed"), None)?;

        // Check signatures validity
        let mut verdicts = Vec::with_capacity(max_pks);

        //Check signatures verification verdict on message
        for (i, (pk_g, sig_g)) in validators_keys_updates_g
            .signing_keys_g
            .iter()
            .zip(sigs_g.iter())
            .enumerate()
        {
            let v = SchnorrVrfySigGadget::enforce_signature_verdict(
                cs.ns(|| format!("check_sig_verdict_{}", i)),
                pk_g,
                sig_g,
                msg_hash_g.clone(),
            )?;
            verdicts.push(v);
        }

        //Count valid signatures
        let mut valid_signatures =
            FieldElementGadget::zero(cs.ns(|| "alloc valid signatures count"))?;
        for (i, v) in verdicts.iter().enumerate() {
            valid_signatures = valid_signatures.conditionally_add_constant(
                cs.ns(|| format!("add_verdict_{}", i)),
                v,
                FieldElement::one(),
            )?;
        }

        // Enforce quality
        valid_signatures
            .enforce_equal(cs.ns(|| "valid_signatures == quality"), &cert_quality_fe_g)?;

        //Enforce threshold
        valid_signatures
            .sub(cs.ns(|| "valid_signatures - threshold"), &threshold_g)?
            .enforce_equal(cs.ns(|| "threshold check"), &b_field)?;

        // *************************** Check genesis constant ***************************

        // Expose genesis_constant as public input
        let expected_genesis_constant_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc constant as input"), || {
                Ok(self.genesis_constant)
            })?;

        // Check genesis constant
        let genesis_constant_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(MR(genesis_pks), threshold)"),
            &[
                genesis_validator_keys_tree_root_g.clone(),
                threshold_g,
            ],
        )?;

        genesis_constant_g.enforce_equal(
            cs.ns(|| "genesis_constant: expected == actual"),
            &expected_genesis_constant_g,
        )?;

        // ******************Check certificate(s) hashes******************

        // Enforce previous cert_data hash
        let mut prev_cert_data_hash_g = prev_withdrawal_certificate_g
            .enforce_hash(cs.ns(|| "enforce prev_wcert_hash"), None)?;

        // Enforce current cert_data hash
        let cert_data_hash_g =
            withdrawal_certificate_g.enforce_hash(cs.ns(|| "enforce cert data hash"), None)?;

        // Expose cert_data_hash as public input
        let expected_cert_data_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc input sc_wcert_hash"), || {
                Ok(self.cert_data_hash)
            })?;

        // Expose previous cert_data_hash as public input
        let expected_prev_cert_data_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc input sc_prev_wcert_hash"), || {
                Ok(self.prev_cert_data_hash)
            })?;

        // Inputize hashes
        // if (sc_prev_wcert_hash != NULL)
        //     require(sc_prev_wcert_hash == H(prev_wcert))
        let phantom_cert_data_hash_g = FieldElementGadget::from_value(
            cs.ns(|| "hardcode phantom hash"),
            &PHANTOM_CERT_DATA_HASH,
        );

        // The verifier will always pass the correct public input, so the prover is forced to always
        // pick the right value for is_first_certificate_g
        prev_cert_data_hash_g = FieldElementGadget::conditionally_select(
            cs.ns(|| "prev_cert_data_hash = PHANTOM if is_first_certificate"),
            &is_first_certificate_g,
            &phantom_cert_data_hash_g,
            &prev_cert_data_hash_g,
        )?;

        expected_prev_cert_data_hash_g.enforce_equal(
            cs.ns(|| "require(sc_prev_wcert_hash == H(prev_wcert)"),
            &prev_cert_data_hash_g,
        )?;

        // require(sc_wcert_hash == H(wcert))
        expected_cert_data_hash_g.enforce_equal(
            cs.ns(|| "require(sc_wcert_hash == H(wcert)"),
            &cert_data_hash_g,
        )?;

        // *************************** Verify signatures of updated validators keys ***************************
        // Enforce new root using the updated keys
        let (new_validators_keys_root, new_validators_keys_leaves) = validators_keys_updates_g
            .enforce_upd_validators_keys_root(cs.ns(|| "enforce new root"))?;

        validators_keys_updates_g.check_keys_updates(
            cs.ns(|| "check key changes"),
            new_validators_keys_leaves.as_slice(),
            VALIDATOR_HASH_SALT,
            &withdrawal_certificate_g.epoch_id_g,
            &withdrawal_certificate_g.ledger_id_g
        )?;

        // *************************** Check validators merkle roots ***************************

        // Get expected actual root from the previous certificate
        let expected_current_validators_keys_root =
            &prev_withdrawal_certificate_g.custom_fields_g[0];

        // Enforce actual root
        let (current_validators_keys_root, _) = validators_keys_updates_g
            .enforce_curr_validators_keys_root(cs.ns(|| "enforce current root"))?;

        // if (sc_prev_wcert_hash != NULL)
        //     require(prev_wcert.custom_fields.scb_validators_keys_root == current_validators_keys_root)
        current_validators_keys_root.conditional_enforce_equal(
            cs.ns(|| "enforce current root equals the one in prev cert if present"),
            &expected_current_validators_keys_root,
            &is_first_certificate_g.not(),
        )?;

        // else
        //     require(genesis_validator_keys_root == validators_keys_root)
        current_validators_keys_root.conditional_enforce_equal(
            cs.ns(|| "enforce current root equals genesis one if prev cert is not present"),
            &genesis_validator_keys_tree_root_g,
            &is_first_certificate_g,
        )?;

        // Get the expected new root from certificate
        let expected_new_validators_keys_root = &withdrawal_certificate_g.custom_fields_g[0];

        // require(wcert.custom_fields.scb_validators_keys_root == new_validators_keys_root)
        new_validators_keys_root.enforce_equal(
            cs.ns(|| "enforce new root equals the one in curr cert"),
            expected_new_validators_keys_root,
        )?;

        Ok(())
    }
}
