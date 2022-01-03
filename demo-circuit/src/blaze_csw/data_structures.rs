use algebra::ToConstraintField;
use cctp_primitives::{
    commitment_tree::{sidechain_tree_alive::FWT_MT_HEIGHT, CMT_MT_HEIGHT},
    proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH,
    type_mapping::FieldElement,
    utils::{
        commitment_tree::DataAccumulator, data_structures::BackwardTransfer, get_bt_merkle_root,
    },
};
use primitives::{FieldBasedHash, FieldBasedMerkleTreePath, FieldHasher};

use crate::{
    constants::constants::BoxType, type_mapping::*, GingerMHTBinaryPath, MST_MERKLE_TREE_HEIGHT,
    SC_CUSTOM_HASH_LENGTH, SC_PUBLIC_KEY_LENGTH,
    SC_TX_HASH_LENGTH, CSW_PHANTOM_PUB_KEY_BYTES,
};

#[derive(Clone, Debug)]
pub struct WithdrawalCertificateData {
    pub ledger_id: FieldElement,
    pub epoch_id: u32,
    pub bt_root: FieldElement, // Merkle root hash of all BTs from the certificate (recall that MC hashes all complex proof_data params from the certificate)
    pub quality: u64,
    pub mcb_sc_txs_com: FieldElement,
    pub ft_min_amount: u64,
    pub btr_min_fee: u64,
    pub custom_fields: Vec<FieldElement>,
}

impl WithdrawalCertificateData {
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
            bt_root: FieldElement::default(),
            quality: 0,
            mcb_sc_txs_com: FieldElement::default(),
            ft_min_amount: 0,
            btr_min_fee: 0,
            custom_fields: vec![FieldElement::default(); num_custom_fields as usize],
        }
    }

    pub(crate) fn get_phantom(num_custom_fields: u32) -> Self {
        WithdrawalCertificateData::get_default(num_custom_fields)
    }
}

impl PartialEq for WithdrawalCertificateData {
    fn eq(&self, other: &Self) -> bool {
        self.ledger_id == other.ledger_id
            && self.epoch_id == other.epoch_id
            && self.bt_root == other.bt_root
            && self.quality == other.quality
            && self.mcb_sc_txs_com == other.mcb_sc_txs_com
            && self.ft_min_amount == other.ft_min_amount
            && self.btr_min_fee == other.btr_min_fee
            && self.custom_fields == other.custom_fields
    }
}

#[derive(Clone, Default)]
pub struct CswUtxoOutputData {
    pub spending_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    pub amount: u64,
    pub nonce: u64,
    pub custom_hash: [u8; SC_CUSTOM_HASH_LENGTH],
}

impl CswUtxoOutputData {
    pub fn get_phantom() -> Self {
        Self {
            spending_pub_key: CSW_PHANTOM_PUB_KEY_BYTES,
            amount: 0,
            nonce: 0,
            custom_hash: [0; SC_CUSTOM_HASH_LENGTH],
        }
    }
}

impl PartialEq for CswUtxoOutputData {
    fn eq(&self, other: &Self) -> bool {
        self.spending_pub_key == other.spending_pub_key
            && self.amount == other.amount
            && self.nonce == other.nonce
            && self.custom_hash == other.custom_hash
    }
}

impl ToConstraintField<FieldElement> for CswUtxoOutputData {
    fn to_field_elements(&self) -> Result<Vec<FieldElement>, Error> {
        DataAccumulator::init()
            .update(&self.spending_pub_key[..])?
            .update(self.amount)?
            .update(self.nonce)?
            .update(&self.custom_hash[..])?
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

#[derive(Clone)]
pub struct CswUtxoInputData {
    pub output: CswUtxoOutputData,
    pub secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
}

impl CswUtxoInputData {
    pub fn get_phantom() -> Self {
        Self {
            output: CswUtxoOutputData::get_phantom(),
            secret_key: [true; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
        }
    }
}

impl Default for CswUtxoInputData {
    fn default() -> Self {
        Self {
            output: CswUtxoOutputData::default(),
            secret_key: [false; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
        }
    }
}

impl PartialEq for CswUtxoInputData {
    fn eq(&self, other: &Self) -> bool {
        self.output == other.output && self.secret_key == other.secret_key
    }
}

#[derive(Clone, Default)]
pub struct CswFtOutputData {
    pub amount: u64,
    pub receiver_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    pub payback_addr_data_hash: [u8; MC_PK_SIZE],
    pub tx_hash: [u8; SC_TX_HASH_LENGTH],
    pub out_idx: u32,
}

impl CswFtOutputData {
    pub fn get_phantom() -> Self {
        Self {
            amount: 0,
            receiver_pub_key: CSW_PHANTOM_PUB_KEY_BYTES,
            payback_addr_data_hash: [0; MC_PK_SIZE],
            tx_hash: [0; SC_TX_HASH_LENGTH],
            out_idx: 0,
        }
    }
}

impl PartialEq for CswFtOutputData {
    fn eq(&self, other: &Self) -> bool {
        self.amount == other.amount
            && self.receiver_pub_key == other.receiver_pub_key
            && self.payback_addr_data_hash == other.payback_addr_data_hash
            && self.tx_hash == other.tx_hash
            && self.out_idx == other.out_idx
    }
}

#[derive(Clone, Default)]
pub struct CswSysData {
    pub mcb_sc_txs_com_end: FieldElement, // Passed directly by MC. The cumulative SCTxsCommitment hash taken from the MC block where the SC was ceased (needed to recover FTs in reverted epochs).
    pub sc_last_wcert_hash: FieldElement, // hash of the last confirmed WCert (excluding reverted) for this sidechain (calculated directly by MC). Note that it should be a hash of WithdrawalCertificateData
    pub amount: u64,                      // taken from CSW and passed directly by the MC
    pub nullifier: FieldElement,          // taken from CSW and passed directly by the MC
    pub receiver: [u8; MC_PK_SIZE], // the receiver is fixed by the proof, otherwise someone will be able to front-run the tx and steel the proof.
                                    // Note that we actually don't need to do anything with the receiver in the circuit, it's enough just to have it as a public input
}

impl CswSysData {
    pub fn new(
        mcb_sc_txs_com_end: Option<FieldElement>,
        sc_last_wcert_hash: Option<FieldElement>,
        amount: u64,
        nullifier: FieldElement,
        receiver: [u8; MC_PK_SIZE],
    ) -> Self {
        Self {
            mcb_sc_txs_com_end: mcb_sc_txs_com_end.unwrap_or(FieldElement::default()),
            sc_last_wcert_hash: sc_last_wcert_hash.unwrap_or(PHANTOM_CERT_DATA_HASH),
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

impl CswUtxoProverData {
    pub fn get_phantom() -> Self {
        Self {
            input: CswUtxoInputData::get_phantom(),
            mst_path_to_output: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                MST_MERKLE_TREE_HEIGHT
            ]),
        }
    }
}

impl Default for CswUtxoProverData {
    fn default() -> Self {
        Self {
            input: CswUtxoInputData::default(),
            mst_path_to_output: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                MST_MERKLE_TREE_HEIGHT
            ]),
        }
    }
}

impl PartialEq for CswUtxoProverData {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input && self.mst_path_to_output == other.mst_path_to_output
    }
}

#[derive(Clone)]
pub struct CswFtProverData {
    pub ft_output: CswFtOutputData, // FT output in the MC block
    pub ft_input_secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS], // secret key that authorizes ft_input spending.
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

impl CswFtProverData {

    pub(crate) fn get_default(commitment_hashes_number: u32) -> Self {
        Self {
            ft_output: CswFtOutputData::default(),
            ft_input_secret_key: [false; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
            mcb_sc_txs_com_start: FieldElement::default(),
            merkle_path_to_sc_hash: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                CMT_MT_HEIGHT
            ]),
            ft_tree_path: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                FWT_MT_HEIGHT
            ]),
            sc_creation_commitment: FieldElement::default(),
            scb_btr_tree_root: FieldElement::default(),
            wcert_tree_root: FieldElement::default(),
            sc_txs_com_hashes: vec![FieldElement::default(); commitment_hashes_number as usize],
        }
    }

    pub(crate) fn get_phantom(commitment_hashes_number: u32) -> Self {
        Self {
            ft_output: CswFtOutputData::get_phantom(),
            ft_input_secret_key: [true; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
            mcb_sc_txs_com_start: FieldElement::default(),
            merkle_path_to_sc_hash: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                CMT_MT_HEIGHT
            ]),
            ft_tree_path: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                FWT_MT_HEIGHT
            ]),
            sc_creation_commitment: FieldElement::default(),
            scb_btr_tree_root: FieldElement::default(),
            wcert_tree_root: FieldElement::default(),
            sc_txs_com_hashes: vec![FieldElement::default(); commitment_hashes_number as usize],
        }
    }
}

impl PartialEq for CswFtProverData {
    fn eq(&self, other: &Self) -> bool {
        self.ft_output == other.ft_output
            && self.ft_input_secret_key == other.ft_input_secret_key
            && self.mcb_sc_txs_com_start == other.mcb_sc_txs_com_start
            && self.merkle_path_to_sc_hash == other.merkle_path_to_sc_hash
            && self.ft_tree_path == other.ft_tree_path
            && self.sc_creation_commitment == other.sc_creation_commitment
            && self.scb_btr_tree_root == other.scb_btr_tree_root
            && self.wcert_tree_root == other.wcert_tree_root
            && self.sc_txs_com_hashes == other.sc_txs_com_hashes
    }
}

#[derive(Clone)]
pub struct CswProverData {
    pub sys_data: CswSysData,
    pub last_wcert: WithdrawalCertificateData, // the last confirmed wcert in the MC
    pub utxo_data: CswUtxoProverData,
    pub ft_data: CswFtProverData,
}

impl CswProverData {

    pub(crate) fn get_default(range_size: u32, num_custom_fields: u32) -> Self {
        Self {
            sys_data: CswSysData::default(),
            last_wcert: WithdrawalCertificateData::get_default(num_custom_fields),
            utxo_data: CswUtxoProverData::default(),
            ft_data: CswFtProverData::get_default(range_size),
        }
    }
}
