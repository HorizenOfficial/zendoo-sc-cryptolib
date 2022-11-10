use crate::constants::NaiveThresholdSigParams;
use cctp_primitives::{
    type_mapping::FieldElement,
    utils::{data_structures::BackwardTransfer, get_bt_merkle_root},
};

use lazy_static::*;

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
    /// Carries the reference to the sidechain state. (Currently the reference is
    /// split over two field elements)
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
