use std::borrow::Borrow;

use cctp_primitives::type_mapping::{FieldElement, GingerMHTParams};
use primitives::FieldBasedMerkleTreeParameters;
use r1cs_core::{ConstraintSystemAbstract, Namespace, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget};
use r1cs_std::{FromBitsGadget, prelude::{AllocGadget, ConstantGadget, EqGadget}, to_field_gadget_vec::ToConstraintFieldGadget};
use r1cs_std::uint32::UInt32;
use r1cs_std::uint8::UInt8;

use crate::{
    naive_threshold_sig_w_key_rotation::data_structures::ValidatorKeysUpdates, FieldElementGadget,
    FieldHashGadget, SchnorrPkGadget, SchnorrSigGadget, SchnorrVrfySigGadget,
};
use crate::naive_threshold_sig_w_key_rotation::data_structures::{MASTER_KEY_DOMAIN_TAG, SIGNING_KEY_DOMAIN_TAG};

/// Starting from all the leaves in the Merkle Tree, reconstructs and returns
/// the Merkle Root. NOTE: This works iff Merkle Tree has been created by passing
/// all leaves (i.e. padding_tree = null).
/// TODO: move to ginger-lib
pub(crate) fn enforce_root_from_leaves<CS: ConstraintSystemAbstract<FieldElement>>(
    mut cs: CS,
    leaves: &[FieldElementGadget],
    height: usize,
) -> Result<FieldElementGadget, SynthesisError> {
    if leaves.len() != 2_usize.checked_pow(height as u32).ok_or(
        SynthesisError::Other(format!("Height of the Merkle Tree should be at most {}, found {}", 0_usize.count_zeros(), height))
    )? {
        return Err(SynthesisError::Other(
            "Leaves number must be a power of 2".to_owned(),
        ));
    }

    let mut prev_level_nodes = leaves.to_vec();
    //Iterate over all levels except the root
    for level in 0..height {
        let mut curr_level_nodes = vec![];

        //Iterate over all nodes in a level. We assume their number to be even (e.g a power of two)

        for (i, nodes) in prev_level_nodes.chunks(2).enumerate() {
            //Compute parent hash
            let parent_hash = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("hash_children_pair_{}_of_level_{}", i, level)),
                &[nodes[0].clone(), nodes[1].clone()],
            )?;
            curr_level_nodes.push(parent_hash);
        }
        prev_level_nodes = curr_level_nodes;
    }
    //At this point, we should have only the root in prev_level_nodes
    //Enforce equality with the root
    debug_assert!(prev_level_nodes.len() == 1);

    Ok(prev_level_nodes[0].clone())
}

#[derive(Clone)]
pub struct ValidatorKeysUpdatesGadget {
    /// Current validators' signing keys: (sk1, sk2, sk3,...)
    pub(crate) signing_keys_g: Vec<SchnorrPkGadget>,

    /// Current validators' master keys: (mk1, mk2, mk3, ...)
    pub(crate) master_keys_g: Vec<SchnorrPkGadget>,

    /// New validators' signing keys: (sk1', sk2', sk3',...)
    /// If the i-th signing key was not changed, then signing_keys_g[i] = updated_signing_keys_g[i]
    pub(crate) updated_signing_keys_g: Vec<SchnorrPkGadget>,

    /// New validators' master keys: (mk1', mk2', mk3', ...)
    /// If the i-th master key was not changed, then master_keys_g[i] = updated_master_keys_g[i]
    pub(crate) updated_master_keys_g: Vec<SchnorrPkGadget>,

    /// Signatures made with old signing keys on the new ones, if they were changed.
    /// If the i-th signing key was not changed, then updated_signing_keys_sk_signatures_g[i] = NULL_SIG
    pub(crate) updated_signing_keys_sk_signatures_g: Vec<SchnorrSigGadget>,

    /// Signatures made with current master keys on the new signing keys, if they were changed.
    /// If the i-th signing key was not changed, then updated_signing_keys_mk_signatures_g[i] = NULL_SIG
    pub(crate) updated_signing_keys_mk_signatures_g: Vec<SchnorrSigGadget>,

    /// Signatures made with current signing keys on the new master keys, if they were changed.
    /// If the i-th master key was not changed, then updated_master_keys_sk_signatures_g[i] = NULL_SIG
    pub(crate) updated_master_keys_sk_signatures_g: Vec<SchnorrSigGadget>,

    /// Signatures made with old master keys on the new ones, if they were changed.
    /// If the i-th master key was not changed, then updated_master_keys_mk_signatures_g[i] = NULL_SIG
    pub(crate) updated_master_keys_mk_signatures_g: Vec<SchnorrSigGadget>,

    max_pks: usize,
}

impl ValidatorKeysUpdatesGadget {
    fn enforce_validators_key_root<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        max_pks: usize,
        sig_keys_g: &[SchnorrPkGadget],
        master_keys_g: &[SchnorrPkGadget],
    ) -> Result<(FieldElementGadget, Vec<FieldElementGadget>), SynthesisError> {
        let height = (max_pks.next_power_of_two() * 2).trailing_zeros() as usize;
        let null_leaf_g: FieldElementGadget = ConstantGadget::from_value(
            cs.ns(|| "hardcoded NULL_LEAF"),
            &GingerMHTParams::ZERO_NODE_CST.unwrap().nodes[0],
        );

        let mut validator_mktree_leaves_g = Vec::with_capacity(max_pks);

        for (i, (signing_key_g, master_key_g)) in sig_keys_g.iter().zip(master_keys_g).enumerate() {
            // Enforce signing key hash
            let signing_key_fe_g = signing_key_g.to_field_gadget_elements(
                cs.ns(|| format!("alloc_fe gadget elems for skey_{}", i)),
            )?;
            let signing_key_fe_hash_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(skey_{})", i)),
                signing_key_fe_g.as_slice(),
            )?;

            // Add it to the tree
            validator_mktree_leaves_g.push(signing_key_fe_hash_g);

            // Enforce master key hash
            let master_key_fe_g = master_key_g.to_field_gadget_elements(
                cs.ns(|| format!("alloc_fe gadget elems for mkey_{}", i)),
            )?;
            let master_key_fe_hash_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(mkey_{})", i)),
                master_key_fe_g.as_slice(),
            )?;

            // Add it to the tree
            validator_mktree_leaves_g.push(master_key_fe_hash_g);
        }

        // pad the vector up to the length 2^height, to use in the enforce_root_from_leaves function
        validator_mktree_leaves_g.resize(2_usize.checked_pow(height as u32).ok_or(
            SynthesisError::Other(format!("Height of the Merkle Tree should be at most {}, found {}", 0_usize.count_zeros(), height))
        )?, null_leaf_g);

        // Starting from all the leaves in the Merkle Tree, reconstructs and returns
        // the Merkle Root. NOTE: This works iff Merkle Tree has been created by passing
        // all leaves (i.e. padding_tree = null).
        let root_g = enforce_root_from_leaves(
            cs.ns(|| "enforce root from all leaves"),
            &validator_mktree_leaves_g,
            height,
        )?;

        Ok((root_g, validator_mktree_leaves_g))
    }

    /// Enforce merkle root of current validators keys. Return the enforced Merkle root and the leaves
    pub fn enforce_curr_validators_keys_root<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        cs: CS,
    ) -> Result<(FieldElementGadget, Vec<FieldElementGadget>), SynthesisError> {
        Self::enforce_validators_key_root(
            cs,
            self.max_pks,
            self.signing_keys_g.as_slice(),
            self.master_keys_g.as_slice(),
        )
    }

    /// Enforce merkle root of updated validators keys. Return the enforced Merkle root and the leaves
    pub fn enforce_upd_validators_keys_root<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        cs: CS,
    ) -> Result<(FieldElementGadget, Vec<FieldElementGadget>), SynthesisError> {
        Self::enforce_validators_key_root(
            cs,
            self.max_pks,
            self.updated_signing_keys_g.as_slice(),
            self.updated_master_keys_g.as_slice(),
        )
    }

    /// Checks validity of signatures in case of change for any public key
    pub fn check_keys_updates<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        new_validators_keys_leaves: &[FieldElementGadget],
        salt: u8,
        epoch_id: &UInt32,
        ledger_id: &FieldElementGadget,
    ) -> Result<(), SynthesisError> {

        let secret_key_tag = UInt8::constant(SIGNING_KEY_DOMAIN_TAG);
        let master_key_tag = UInt8::constant(MASTER_KEY_DOMAIN_TAG);
        let salt = UInt8::constant(salt);

        let salt_bits = salt.into_bits_be();
        let epoch_bits = epoch_id.clone().into_bits_be();
        let get_key_domain_fe = |mut cs: Namespace<FieldElement, CS::Root>, domain: UInt8| {
            let mut domain_bits = domain.into_bits_be();
            domain_bits.extend_from_slice(&salt_bits);
            domain_bits.extend_from_slice(&epoch_bits);
            FieldElementGadget::from_bits(cs.ns(|| "domain to field element value"), &domain_bits)
        };

        let mut secret_key_domain_bits = secret_key_tag.into_bits_be();
        secret_key_domain_bits.extend_from_slice(&salt_bits);
        secret_key_domain_bits.extend_from_slice(&epoch_bits);

        let secret_key_domain = get_key_domain_fe(cs.ns(|| "secret key domain"), secret_key_tag)?;
        let master_key_domain = get_key_domain_fe(cs.ns(|| "master key domain"), master_key_tag)?;

        for i in 0..self.max_pks {
            // ******* check signing keys updates *********

            // msg_to_sign = H(H(updated_signing_keys[i])||'s'||CONST_SALT||epoch_id||ledger_id);
            let hash_payload_g = vec![
                new_validators_keys_leaves[2 * i].clone(),
                secret_key_domain.clone(),
                ledger_id.clone(),
            ];

            let upd_sig_msg_to_sign_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(H(skey_{})||'s'||CONST_SALT||epoch_id||ledger_id)", i)),
                hash_payload_g.as_slice(),
            )?;

            // if (updated_signing_keys[i] != signing_keys[i])
            let should_enforce_s = self.updated_signing_keys_g[i]
                .is_eq(
                    cs.ns(|| format!("enforce if updated_signing_keys != signing_keys_{}", i)),
                    &self.signing_keys_g[i],
                )?
                .not();

            // verify_signature(msg_to_sign, sk_sig, signing_keys[i])
            SchnorrVrfySigGadget::conditionally_enforce_signature_verification(
                cs.ns(|| {
                    format!(
                        "check updated signing key should be signed old signing key {}",
                        i
                    )
                }),
                &self.signing_keys_g[i],
                &self.updated_signing_keys_sk_signatures_g[i],
                upd_sig_msg_to_sign_g.clone(),
                &should_enforce_s,
            )?;

            // verify_signature(msg_to_sign, mk_sig, master_keys[i])
            SchnorrVrfySigGadget::conditionally_enforce_signature_verification(
                cs.ns(|| {
                    format!(
                        "check updated signing key should be signed old master key {}",
                        i
                    )
                }),
                &self.master_keys_g[i],
                &self.updated_signing_keys_mk_signatures_g[i],
                upd_sig_msg_to_sign_g,
                &should_enforce_s,
            )?;

            // ******* check master keys updates *********

            // msg_to_sign = H(H(updated_master_keys[i])||'m'||CONST_SALT||epoch_id||ledger_id);
            let hash_payload_g = vec![
                new_validators_keys_leaves[(2 * i) + 1].clone(),
                master_key_domain.clone(),
                ledger_id.clone(),
            ];

            let upd_master_msg_to_sign_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(H(mkey_{})||'m'||CONST_SALT||epoch_id||ledger_id)", i)),
                hash_payload_g.as_slice(),
            )?;

            // if (updated_master_keys[i] != master_keys[i])
            let should_enforce_s = self.updated_master_keys_g[i]
                .is_eq(
                    cs.ns(|| format!("enforce if updated_master_keys != master_keys_{}", i)),
                    &self.master_keys_g[i],
                )?
                .not();

            // verify_signature(msg_to_sign, sk_sig, signing_keys[i])
            SchnorrVrfySigGadget::conditionally_enforce_signature_verification(
                cs.ns(|| {
                    format!(
                        "check updated master key should be signed old signing key {}",
                        i
                    )
                }),
                &self.signing_keys_g[i],
                &self.updated_master_keys_sk_signatures_g[i],
                upd_master_msg_to_sign_g.clone(),
                &should_enforce_s,
            )?;

            // verify_signature(msg_to_sign, mk_sig, master_keys[i])
            SchnorrVrfySigGadget::conditionally_enforce_signature_verification(
                cs.ns(|| {
                    format!(
                        "check updated master key should be signed old master key {}",
                        i
                    )
                }),
                &self.master_keys_g[i],
                &self.updated_master_keys_mk_signatures_g[i],
                upd_master_msg_to_sign_g,
                &should_enforce_s,
            )?;
        }

        Ok(())
    }
}

impl AllocGadget<ValidatorKeysUpdates, FieldElement> for ValidatorKeysUpdatesGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<ValidatorKeysUpdates>,
    {
        let (
            signing_keys,
            master_keys,
            updated_signing_keys,
            updated_master_keys,
            updated_signing_keys_sk_signatures,
            updated_signing_keys_mk_signatures,
            updated_master_keys_sk_signatures,
            updated_master_keys_mk_signatures,
            max_pks,
        ) = match f() {
            Ok(validators_keys_updates) => {
                let validators_keys_updates = validators_keys_updates.borrow().clone();
                (
                    Ok(validators_keys_updates.signing_keys),
                    Ok(validators_keys_updates.master_keys),
                    Ok(validators_keys_updates.updated_signing_keys),
                    Ok(validators_keys_updates.updated_master_keys),
                    Ok(validators_keys_updates.updated_signing_keys_sk_signatures),
                    Ok(validators_keys_updates.updated_signing_keys_mk_signatures),
                    Ok(validators_keys_updates.updated_master_keys_sk_signatures),
                    Ok(validators_keys_updates.updated_master_keys_mk_signatures),
                    Ok(validators_keys_updates.max_pks),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let signing_keys_g =
            Vec::<SchnorrPkGadget>::alloc(cs.ns(|| "alloc signing_keys"), || signing_keys)?;

        let master_keys_g =
            Vec::<SchnorrPkGadget>::alloc(cs.ns(|| "alloc master_keys"), || master_keys)?;

        let updated_signing_keys_g =
            Vec::<SchnorrPkGadget>::alloc(cs.ns(|| "alloc updated_signing_keys"), || {
                updated_signing_keys
            })?;

        let updated_master_keys_g =
            Vec::<SchnorrPkGadget>::alloc(cs.ns(|| "alloc updated_master_keys"), || {
                updated_master_keys
            })?;

        let updated_signing_keys_sk_signatures_g = Vec::<SchnorrSigGadget>::alloc(
            cs.ns(|| "alloc updated_signing_keys_sk_signatures"),
            || updated_signing_keys_sk_signatures,
        )?;

        let updated_signing_keys_mk_signatures_g = Vec::<SchnorrSigGadget>::alloc(
            cs.ns(|| "alloc updated_signing_keys_mk_signatures"),
            || updated_signing_keys_mk_signatures,
        )?;

        let updated_master_keys_sk_signatures_g = Vec::<SchnorrSigGadget>::alloc(
            cs.ns(|| "alloc updated_master_keys_sk_signatures"),
            || updated_master_keys_sk_signatures,
        )?;

        let updated_master_keys_mk_signatures_g = Vec::<SchnorrSigGadget>::alloc(
            cs.ns(|| "alloc updated_master_keys_mk_signatures"),
            || updated_master_keys_mk_signatures,
        )?;

        let new_instance = Self {
            signing_keys_g,
            master_keys_g,
            updated_signing_keys_g,
            updated_master_keys_g,
            updated_signing_keys_sk_signatures_g,
            updated_signing_keys_mk_signatures_g,
            updated_master_keys_sk_signatures_g,
            updated_master_keys_mk_signatures_g,
            max_pks: max_pks?,
        };

        Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<ValidatorKeysUpdates>,
    {
        unimplemented!()
    }
}
