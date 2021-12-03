use algebra::ToConstraintField;
use cctp_primitives::{
    type_mapping::FieldElement,
    utils::{
        commitment_tree::DataAccumulator, data_structures::BackwardTransfer, get_bt_merkle_root,
    },
};
use primitives::{FieldBasedHash, FieldHasher};

use crate::{
    type_mapping::*, GingerMHTBinaryPath, PHANTOM_PUBLIC_KEY_BITS, PHANTOM_SECRET_KEY_BITS,
    SC_PUBLIC_KEY_LENGTH, SC_TX_HASH_LENGTH, constants::constants::BoxType,
};

// Must replace old one
pub struct WithdrawalCertificateDataNew {
    pub sc_id: FieldElement,
    pub epoch_number: u32,
    pub bt_root: FieldElement,
    pub quality: u64,
    pub mcb_sc_txs_com: FieldElement,
    pub ft_min_amount: u64,
    pub btr_min_fee: u64,
    pub custom_fields: Vec<FieldElement>,
}

impl WithdrawalCertificateDataNew {
    pub fn new(
        sc_id: FieldElement,
        epoch_number: u32,
        bt_list: Vec<BackwardTransfer>,
        quality: u64,
        mcb_sc_txs_com: FieldElement,
        ft_min_amount: u64,
        btr_min_fee: u64,
        custom_fields: Vec<FieldElement>,
    ) -> Self {
        Self {
            sc_id,
            epoch_number,
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
}

#[derive(Clone)]
pub struct WithdrawalCertificateData {
    // sys_data [START]
    pub ledger_id: FieldElement,
    pub epoch_id: FieldElement,
    pub bt_list_hash: FieldElement, // Merkle root hash of all BTs from the certificate (recall that MC hashes all complex proof_data params from the certificate)
    pub quality: FieldElement,
    pub mcb_sc_txs_com: FieldElement,
    pub ft_min_amount: FieldElement,
    pub btr_min_fee: FieldElement,
    // sys_data [END]

    // proof_data [START]
    pub scb_new_mst_root: FieldElement, // proof_data [END]
}

#[derive(Clone)]
pub struct CswUtxoOutputData {
    pub spending_pub_key: [bool; SIMULATED_FIELD_BYTE_SIZE * 8],
    pub amount: u64,
    pub nonce: u64,
    pub custom_hash: [bool; FIELD_SIZE * 8],
}

impl Default for CswUtxoOutputData {
    fn default() -> Self {
        Self {
            spending_pub_key: PHANTOM_PUBLIC_KEY_BITS,
            amount: 0,
            nonce: 0,
            custom_hash: [false; FIELD_SIZE * 8],
        }
    }
}

impl ToConstraintField<FieldElement> for CswUtxoOutputData {
    fn to_field_elements(&self) -> Result<Vec<FieldElement>, Error> {
        DataAccumulator::init()
            .update_with_bits(self.spending_pub_key.to_vec())?
            .update(self.amount)?
            .update(self.nonce)?
            .update_with_bits(self.custom_hash.to_vec())?
            .get_field_elements()
    }
}

impl FieldHasher<FieldElement, FieldHash> for CswUtxoOutputData {
    fn hash(&self, personalization: Option<&[FieldElement]>) -> Result<FieldElement, Error> {
        let self_fes = self.to_field_elements()?;
        let mut h = FieldHash::init_constant_length(self_fes.len() + 1, personalization);
        self_fes.into_iter().for_each(|fe| {
            h.update(fe);
        });
        h.update(FieldElement::from(BoxType::CoinBox as u8));
        h.finalize()
    }
}

// TODO: is it ok to consider "phantom" the default instance of this struct?
#[derive(Clone)]
pub struct CswUtxoInputData {
    pub output: CswUtxoOutputData,
    pub secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
}

impl Default for CswUtxoInputData {
    fn default() -> Self {
        Self {
            output: CswUtxoOutputData::default(),
            secret_key: PHANTOM_SECRET_KEY_BITS,
        }
    }
}

// TODO: is it ok to consider "phantom" the default instance of this struct?
#[derive(Clone, Default)]
pub struct CswFtOutputData {
    pub amount: u64,
    pub receiver_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    pub payback_addr_data_hash: [u8; MC_PK_SIZE],
    pub tx_hash: [u8; SC_TX_HASH_LENGTH],
    pub out_idx: u32,
}

#[derive(Clone)]
pub struct CswSysData {
    pub genesis_constant: Option<FieldElement>, // Passed directly by the MC. It is a constant declared during SC creation that commits to various SC params. In the current SNARK design it isn't used (but might be usefull for other sidechains), so just ignored in the circuit. Note that it is the same constant as for WCert proof.
    pub mcb_sc_txs_com_end: FieldElement, // Passed directly by MC. The cumulative SCTxsCommitment hash taken from the MC block where the SC was ceased (needed to recover FTs in reverted epochs).
    pub sc_last_wcert_hash: FieldElement, // hash of the last confirmed WCert (excluding reverted) for this sidechain (calculated directly by MC). Note that it should be a hash of WithdrawalCertificateData
    pub amount: u64,                      // taken from CSW and passed directly by the MC
    pub nullifier: FieldElement,          // taken from CSW and passed directly by the MC
    pub receiver: [u8; MC_PK_SIZE], // the receiver is fixed by the proof, otherwise someone will be able to front-run the tx and steel the proof. Note that we actually don't need to do anything with the receiver in the circuit, it's enough just to have it as a public input
}

impl CswSysData {
    pub fn new(
        genesis_constant: Option<FieldElement>,
        mcb_sc_txs_com_end: Option<FieldElement>,
        sc_last_wcert_hash: Option<FieldElement>,
        amount: u64,
        nullifier: FieldElement,
        receiver: [u8; MC_PK_SIZE],
    ) -> Self {
        Self {
            genesis_constant,
            mcb_sc_txs_com_end: mcb_sc_txs_com_end.unwrap_or_default(),
            sc_last_wcert_hash: sc_last_wcert_hash.unwrap_or_default(),
            amount,
            nullifier,
            receiver,
        }
    }
}

#[derive(Clone)]
pub struct CswUtxoProverData {
    pub input: CswUtxoInputData, // unspent output we are trying to withdraw
    pub mst_path_to_output: GingerMHTBinaryPath, // path to output in the MST of the known state
}

#[derive(Clone)]
pub struct CswFtProverData {
    pub ft_output: CswFtOutputData, // FT output in the MC block
    pub ft_input_secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS], // secret key that authorizes ft_input spending
    pub mcb_sc_txs_com_start: FieldElement, // Cumulative ScTxsCommittment taken from the last MC block of the last confirmed (not reverted) epoch
    pub merkle_path_to_sc_hash: GingerMHTBinaryPath, // Merkle path to a particular sidechain in the ScTxsComm tree
    pub ft_tree_path: GingerMHTBinaryPath, // path to the ft_input_hash in the FT Merkle tree included in ScTxsComm tree
    pub sc_creation_commitment: FieldElement,
    pub scb_btr_tree_root: FieldElement, // root hash of the BTR tree included in ScTxsComm tree
    pub wcert_tree_root: FieldElement,   // root hash of the Wcert tree included in ScTxsComm tree
    pub sc_txs_com_hashes: Vec<FieldElement>, // contains all ScTxsComm cumulative hashes on the way from `mcb_sc_txs_com_start` to `mcb_sc_txs_com_end`
                                              // RANGE_SIZE is a number of blocks between `mcb_sc_txs_com_start` and `mcb_sc_txs_com_end`.
                                              // It seems it can be a constant as the number of blocks between the last confirmed block and SC ceasing block should be fixed for a particular sidechain
                                              // witnesses [END]
}

#[derive(Clone)]
pub struct CswProverData {
    // public inputs
    pub sys_data: CswSysData,

    // witnesses
    pub last_wcert: WithdrawalCertificateData, // the last confirmed wcert in the MC
    pub utxo_data: CswUtxoProverData,
    pub ft_data: CswFtProverData,
}
