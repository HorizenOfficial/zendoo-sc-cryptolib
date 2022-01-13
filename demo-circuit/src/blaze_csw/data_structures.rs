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
    type_mapping::*, GingerMHTBinaryPath, MST_MERKLE_TREE_HEIGHT, SC_CUSTOM_HASH_LENGTH,
    SC_PUBLIC_KEY_LENGTH, SC_TX_HASH_LENGTH,
};

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

#[derive(Clone, Default)]
/// The relevant public data on a utxo
pub struct CswUtxoOutputData {
    pub spending_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    pub amount: u64,
    pub nonce: u64,
    pub custom_hash: [u8; SC_CUSTOM_HASH_LENGTH],
}

impl ToConstraintField<FieldElement> for CswUtxoOutputData {
    fn to_field_elements(&self) -> Result<Vec<FieldElement>, Error> {
        DataAccumulator::init()
            .update(&self.spending_pub_key[..])
            .map_err(|e| {
                format!(
                    "Unable to update DataAccumulator with speding_pub_key: {:?}",
                    e
                )
            })?
            .update(self.amount)
            .map_err(|e| format!("Unable to update DataAccumulator with amount: {:?}", e))?
            .update(self.nonce)
            .map_err(|e| format!("Unable to update DataAccumulator with nonce: {:?}", e))?
            .update(&self.custom_hash[..])
            .map_err(|e| format!("Unable to update DataAccumulator with custom_hash: {:?}", e))?
            .get_field_elements()
    }
}

impl FieldHasher<FieldElement, FieldHash> for CswUtxoOutputData {
    fn hash(&self, personalization: Option<&[FieldElement]>) -> Result<FieldElement, Error> {
        let self_fes = self.to_field_elements().map_err(|e| {
            format!(
                "Unable to convert CswUtxoOutputData into FieldElements: {:?}",
                e
            )
        })?;
        let mut h = FieldHash::init_constant_length(self_fes.len(), personalization);
        self_fes.into_iter().for_each(|fe| {
            h.update(fe);
        });
        h.finalize()
    }
}

// The relevant witness data for proving ownership of a utxo
#[derive(Clone)]
pub struct CswUtxoInputData {
    pub output: CswUtxoOutputData,
    pub secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
}

impl Default for CswUtxoInputData {
    fn default() -> Self {
        Self {
            output: CswUtxoOutputData::default(),
            secret_key: [false; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
        }
    }
}

/// The relevant public data of a forward transaction
#[derive(Clone, Default)]
pub struct CswFtOutputData {
    pub amount: u64,
    pub receiver_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    pub payback_addr_data_hash: [u8; MC_PK_SIZE],
    pub tx_hash: [u8; SC_TX_HASH_LENGTH],
    pub out_idx: u32,
}

/// The relevant public data of a ceased sidechain withdrawal
#[derive(Clone, Default)]
pub struct CswSysData {
    /// The last hash of the history of Sc_Tx_Commitments
    pub mcb_sc_txs_com_end: FieldElement,
    /// The hash of the last accepted withdrawal certificate 
    pub sc_last_wcert_hash: FieldElement,
    /// amount of the csw
    pub amount: u64,
    /// nullifier for the csw, a unique reference to its utxo/ft                    
    pub nullifier: FieldElement,
    /// recipient address of the csw
    pub receiver: [u8; MC_PK_SIZE], 
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
            mcb_sc_txs_com_end: mcb_sc_txs_com_end.unwrap_or_default(),
            sc_last_wcert_hash: sc_last_wcert_hash.unwrap_or(PHANTOM_CERT_DATA_HASH),
            amount,
            nullifier,
            receiver,
        }
    }
}

/// The witness data needed for a utxo withdrawal proof. 
/// Contains the utxo and secret key, and the witnesses for proving membership
/// to the last sidechain state accepted by the mainchain.
#[derive(Clone)]
pub struct CswUtxoProverData {
    /// unspent output we are trying to withdraw
    pub input: CswUtxoInputData, 
    /// Merkle path to last state accepted sidechain state, which 
    /// is extracted from the `custom_fields` of the withdrawal certificate
    pub mst_path_to_output: GingerMHTBinaryPath, 
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

/// The witnesses needed for a forward transaction withdrawal proof.
/// Consists of the forward transaction and its secret key, plus additional
/// witness data for proving the ft being member of the mainchain-to-sidechain
/// history maintained by the mainchain (by means of the Sc_Txs_Commitments).
#[derive(Clone)]
pub struct CswFtProverData {
    /// The forward transaction output
    pub ft_output: CswFtOutputData, 
    /// The secret key for the ft's recipient address
    pub ft_input_secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS], 
    /// The Sc_Txs_Commitment at the start of the time window the withdrawal proof refers to.
    /// (The end is provided via public inputs)
    pub mcb_sc_txs_com_start: FieldElement,
    /// The complete hash chain of the Sc_Txs_Commitments 
    pub sc_txs_com_hashes: Vec<FieldElement>,
    //   
    //  Witness data for proving the ft being member of an Sc_Txs_Commitment. 
    //
    /// The Merkle path for the sidechain-specific root within the Sc_Txs_Commitment.
    pub merkle_path_to_sc_hash: GingerMHTBinaryPath, // Merkle path to a particular sidechain in the ScTxsComm tree
    /// The Merkle path for the ft to its sidechain-specific root within the Sc_Txs_Commitment
    pub ft_tree_path: GingerMHTBinaryPath, // path to the ft_input_hash in the FT Merkle tree included in ScTxsComm tree
    /// for completing the Merkle Path from the ft_tree root to the sidechain-specific root:
    /// The sidechain creation commitment.
    pub sc_creation_commitment: FieldElement,
    /// for completing the Merkle Path from the ft_tree root to the sidechain-specific root:
    /// The backward transfer request commitment.
    pub scb_btr_tree_root: FieldElement, 
    /// for completing the Merkle Path from the ft_tree root to the sidechain-specific root:
    /// The withdrawal certificate commitment.
    pub wcert_tree_root: FieldElement,   
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
}

/// The complete witness data for creating a csw proof.
#[derive(Clone)]
pub struct CswProverData {
    pub sys_data: CswSysData,
    pub last_wcert: WithdrawalCertificateData, // the last confirmed wcert in the MC
    pub utxo_data: CswUtxoProverData,
    pub ft_data: CswFtProverData,
}
