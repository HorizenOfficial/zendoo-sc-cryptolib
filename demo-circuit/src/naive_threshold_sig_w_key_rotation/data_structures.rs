use algebra::{Field, ToConstraintField};
use cctp_primitives::type_mapping::{
    FieldElement, FieldHash, G2Projective, GingerMHT, GingerMHTParams,
};
use primitives::{
    schnorr::field_based_schnorr::{FieldBasedSchnorrPk, FieldBasedSchnorrSignature},
    FieldBasedHash, FieldBasedMerkleTree, FieldBasedMerkleTreeParameters,
};

use crate::{common::NULL_CONST, Error};

pub const VALIDATOR_HASH_SALT: u8 = 0u8;

//TODO: It would be nice using a constant generic here
#[derive(Clone)]
pub struct ValidatorKeysUpdates {
    /// Current validators' signing keys: (sk1, sk2, sk3,...)
    pub(crate) signing_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,

    /// Current validators' master keys: (mk1, mk2, mk3, ...)
    pub(crate) master_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,

    /// New validators' signing keys: (sk1', sk2', sk3',...)
    /// If the i-th signing key was not changed, then signing_keys[i] = updated_signing_keys[i]
    pub(crate) updated_signing_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,

    /// New validators' master keys: (mk1', mk2', mk3', ...)
    /// If the i-th master key was not changed, then master_keys[i] = updated_master_keys[i]
    pub(crate) updated_master_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,

    /// Signatures made with old signing keys on the new ones, if they were changed.
    /// If the i-th signing key was not changed, then updated_signing_keys_sk_signatures[i] = NULL_SIG
    pub(crate) updated_signing_keys_sk_signatures:
        Vec<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,

    /// Signatures made with current master keys on the new signing keys, if they were changed.
    /// If the i-th signing key was not changed, then updated_signing_keys_mk_signatures[i] = NULL_SIG
    pub(crate) updated_signing_keys_mk_signatures:
        Vec<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,

    /// Signatures made with current signing keys on the new master keys, if they were changed.
    /// If the i-th master key was not changed, then updated_master_keys_sk_signatures[i] = NULL_SIG
    pub(crate) updated_master_keys_sk_signatures:
        Vec<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,

    /// Signatures made with old master keys on the new ones, if they were changed.
    /// If the i-th master key was not changed, then updated_master_keys_mk_signatures[i] = NULL_SIG
    pub(crate) updated_master_keys_mk_signatures:
        Vec<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,

    /// Maximum number of pks
    pub(crate) max_pks: usize,

    pub(crate) epoch_id: u32,

    pub(crate) ledger_id: FieldElement,
}

impl ValidatorKeysUpdates {
    pub fn get_instance_for_setup(max_pks: usize, epoch_id: u32, ledger_id: FieldElement) -> Self {
        Self {
            signing_keys: vec![NULL_CONST.null_pk; max_pks],
            master_keys: vec![NULL_CONST.null_pk; max_pks],
            updated_signing_keys: vec![NULL_CONST.null_pk; max_pks],
            updated_master_keys: vec![NULL_CONST.null_pk; max_pks],
            updated_signing_keys_sk_signatures: vec![NULL_CONST.null_sig; max_pks],
            updated_signing_keys_mk_signatures: vec![NULL_CONST.null_sig; max_pks],
            updated_master_keys_sk_signatures: vec![NULL_CONST.null_sig; max_pks],
            updated_master_keys_mk_signatures: vec![NULL_CONST.null_sig; max_pks],
            max_pks,
            epoch_id,
            ledger_id,
        }
    }

    pub fn new(
        signing_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,
        master_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,
        updated_signing_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,
        updated_master_keys: Vec<FieldBasedSchnorrPk<G2Projective>>,
        updated_signing_keys_sk_signatures: Vec<
            Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,
        >,
        updated_signing_keys_mk_signatures: Vec<
            Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,
        >,
        updated_master_keys_sk_signatures: Vec<
            Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,
        >,
        updated_master_keys_mk_signatures: Vec<
            Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>,
        >,
        max_pks: usize,
        epoch_id: u32,
        ledger_id: FieldElement,
    ) -> Self {
        assert_eq!(
            signing_keys.len(),
            updated_signing_keys.len(),
            "signing_keys.len != updated_signing_keys.len"
        );
        assert_eq!(
            master_keys.len(),
            updated_master_keys.len(),
            "master_keys.len != updated_master_keys.len"
        );
        assert_eq!(max_pks, signing_keys.len());
        assert_eq!(max_pks, master_keys.len());
        assert_eq!(max_pks, updated_signing_keys_sk_signatures.len());
        assert_eq!(max_pks, updated_signing_keys_mk_signatures.len());
        assert_eq!(max_pks, updated_master_keys_sk_signatures.len());
        assert_eq!(max_pks, updated_master_keys_mk_signatures.len());

        let updated_signing_keys_sk_signatures_adjusted = updated_signing_keys_sk_signatures
            .into_iter()
            .map(|opt_sig| opt_sig.unwrap_or_else(|| NULL_CONST.null_sig))
            .collect();

        let updated_signing_keys_mk_signatures_adjusted = updated_signing_keys_mk_signatures
            .into_iter()
            .map(|opt_sig| opt_sig.unwrap_or_else(|| NULL_CONST.null_sig))
            .collect();

        let updated_master_keys_sk_signatures_adjusted = updated_master_keys_sk_signatures
            .into_iter()
            .map(|opt_sig| opt_sig.unwrap_or_else(|| NULL_CONST.null_sig))
            .collect();

        let updated_master_keys_mk_signatures_adjusted = updated_master_keys_mk_signatures
            .into_iter()
            .map(|opt_sig| opt_sig.unwrap_or_else(|| NULL_CONST.null_sig))
            .collect();

        Self {
            signing_keys,
            master_keys,
            updated_signing_keys,
            updated_master_keys,
            updated_signing_keys_sk_signatures: updated_signing_keys_sk_signatures_adjusted,
            updated_signing_keys_mk_signatures: updated_signing_keys_mk_signatures_adjusted,
            updated_master_keys_sk_signatures: updated_master_keys_sk_signatures_adjusted,
            updated_master_keys_mk_signatures: updated_master_keys_mk_signatures_adjusted,
            max_pks,
            epoch_id,
            ledger_id,
        }
    }

    pub(crate) fn get_validators_key_root(
        max_pks: usize,
        sig_keys: &[FieldBasedSchnorrPk<G2Projective>],
        master_keys: &[FieldBasedSchnorrPk<G2Projective>],
        epoch_id: u32,
        ledger_id: FieldElement,
    ) -> Result<FieldElement, Error> {
        let height = ((max_pks.next_power_of_two() * 2) as f64).log2() as usize;
        let null_leaf: FieldElement = GingerMHTParams::ZERO_NODE_CST.unwrap().nodes[0];
        let mut tree = GingerMHT::init(height, 1 << height)?;

        let get_key_hash = |pk: &FieldBasedSchnorrPk<G2Projective>, domain: FieldElement| -> Result<FieldElement, Error> {
            let pk_fe = pk.0.to_field_elements()?;

            let mut h = FieldHash::init_constant_length(pk_fe.len() + 2, None);
            pk_fe.into_iter().for_each(|fe| {
                h.update(fe);
            });
            h.update(domain);
            h.update(ledger_id);
            h.finalize()
        };

        let mut bytes = [0u8; 32];
        bytes[0] = 's' as u8;
        bytes[1] = VALIDATOR_HASH_SALT;
        bytes[2..6].copy_from_slice(&epoch_id.to_be_bytes());
        // Safe to unwrap since it won't overflow
        let sk_domain = FieldElement::from_random_bytes(&bytes).unwrap();
        bytes[0] = 'm' as u8;
        let mk_domain = FieldElement::from_random_bytes(&bytes).unwrap();

        for i in 0..max_pks.next_power_of_two() {
            if i < sig_keys.len() {
                // Compute curr pks hash and append them to curr tree
                let signing_key_hash = get_key_hash(&sig_keys[i], sk_domain)?;
                let master_key_hash = get_key_hash(&master_keys[i], mk_domain)?;

                tree.append(signing_key_hash)?;
                tree.append(master_key_hash)?;
            } else {
                // Pad trees with null leaves if max_pks is not a power of two
                tree.append(null_leaf)?;
                tree.append(null_leaf)?;
            }
        }

        // Finalize the trees and get the root
        tree.finalize_in_place()?;
        tree.root()
            .ok_or_else(|| Box::<dyn std::error::Error>::from("cannot get merkle root"))
    }

    /// Create merkle tree root of current validators keys
    pub fn get_curr_validators_keys_root(&self) -> Result<FieldElement, Error> {
        Self::get_validators_key_root(
            self.max_pks,
            self.signing_keys.as_slice(),
            self.master_keys.as_slice(),
            self.epoch_id,
            self.ledger_id,
        )
    }

    /// Create merkle tree root of updated validators keys
    pub fn get_upd_validators_keys_root(&self) -> Result<FieldElement, Error> {
        Self::get_validators_key_root(
            self.max_pks,
            self.updated_signing_keys.as_slice(),
            self.updated_master_keys.as_slice(),
            self.epoch_id,
            self.ledger_id,
        )
    }

    pub fn get_max_pks(&self) -> usize {
        self.max_pks
    }

    pub fn get_epoch_id(&self) -> u32 {
        self.epoch_id
    }

    pub fn get_ledger_id(&self) -> FieldElement {
        self.ledger_id
    }
}
