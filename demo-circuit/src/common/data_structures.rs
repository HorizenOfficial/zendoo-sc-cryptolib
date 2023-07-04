use crate::constants::NaiveThresholdSigParams;
use cctp_primitives::{
    type_mapping::{Error, FieldElement},
    utils::{
        commitment_tree::hash_vec, data_structures::BackwardTransfer, get_bt_merkle_root,
        get_cert_data_hash_from_bt_root_and_custom_fields_hash,
    },
};

use lazy_static::*;

/// Minumum number of custom fields
pub const MIN_CUSTOM_FIELDS: usize = 3;
/// The position of Message Root Hash in the custom fields: See ZenIP-42205
pub const MSG_ROOT_HASH_CUSTOM_FIELDS_POS: usize = 1;
/// The position of Max Quality Cert Hash in the custom fields: See ZenIP-42205
pub const MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS: usize = 2;

lazy_static! {
    pub static ref NULL_CONST: NaiveThresholdSigParams = NaiveThresholdSigParams::new();
}

#[derive(Clone, Debug)]
/// The content of a withdrawal certificate
pub struct WithdrawalCertificateData {
    pub ledger_id: FieldElement,
    pub epoch_id: u32,
    /// Merkle root hash of all BTs from the certificate
    pub bt_root: FieldElement,
    pub quality: u64,
    /// Reference to the state of the mainchain-to-sidechain transaction history.
    /// Declares to which extent the sidechain processed forward transactions.
    pub mcb_sc_txs_com: FieldElement,
    pub ft_min_amount: u64,
    pub btr_min_fee: u64,
    pub custom_fields: Vec<FieldElement>,
}

impl WithdrawalCertificateData {
    /// Creates a Withdrawal Certificate that can be used for generating/verifying proofs
    pub fn new(
        ledger_id: FieldElement,
        epoch_id: u32,
        bt_list: Vec<BackwardTransfer>,
        quality: u64,
        mcb_sc_txs_com: FieldElement,
        ft_min_amount: u64,
        btr_min_fee: u64,
        custom_fields: Vec<FieldElement>,
    ) -> Self {
        Self {
            ledger_id,
            epoch_id,
            bt_root: get_bt_merkle_root(if bt_list.is_empty() {
                None
            } else {
                Some(&bt_list)
            })
            .unwrap(),
            quality,
            mcb_sc_txs_com,
            ft_min_amount,
            btr_min_fee,
            custom_fields,
        }
    }

    pub fn hash(&self) -> Result<FieldElement, Error> {
        let custom_fields_hash = if self.custom_fields.len() > 0 {
            Some(hash_vec(self.custom_fields.clone())?)
        } else {
            None
        };
        get_cert_data_hash_from_bt_root_and_custom_fields_hash(
            &self.ledger_id,
            self.epoch_id,
            self.quality,
            self.bt_root,
            custom_fields_hash,
            &self.mcb_sc_txs_com,
            self.btr_min_fee,
            self.ft_min_amount,
        )
    }

    pub(crate) fn get_default(num_custom_fields: u32) -> Self {
        Self {
            ledger_id: FieldElement::default(),
            epoch_id: 0,
            bt_root: get_bt_merkle_root(None).unwrap(),
            quality: 0,
            mcb_sc_txs_com: FieldElement::default(),
            ft_min_amount: 0,
            btr_min_fee: 0,
            custom_fields: vec![FieldElement::default(); num_custom_fields as usize],
        }
    }
}
