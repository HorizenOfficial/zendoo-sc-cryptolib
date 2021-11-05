use cctp_primitives::type_mapping::{FieldElement, FieldHash, GingerMHTPath, MC_PK_SIZE};

pub struct WithdrawalCertificateData {
    // sys_data [START]
    pub ledger_id: FieldHash,
    pub epoch_id: FieldElement,
    pub bt_list_hash: FieldHash,        // Merkle root hash of all BTs from the certificate (recall that MC hashes all complex proof_data params from the certificate)
    pub quality: FieldElement,
    pub mcb_sc_txs_com: FieldHash,
    pub ft_min_fee: FieldElement,
    pub btr_min_fee: FieldElement,
    // sys_data [END]

    // proof_data [START]
    pub scb_new_mst_root: FieldElement
    // proof_data [END]
}

pub struct CswUtxoInputData {
    // output [START]
    pub spending_pub_key: [u8; 32],
    pub amount: FieldElement,
    pub nonce: FieldElement,
    pub custom_hash: FieldElement,
    // output [END]

    pub secret_key: [u8; 32]
}

pub struct CswFtInputData {
    pub amount: FieldElement,
    pub receiver_pub_key: [u8; 32],
    pub payback_addr_data_hash: FieldHash,
    pub tx_hash: FieldHash,
    pub out_idx: FieldElement,
}

pub struct CswProverData {
    // public inputs [START]

    // sys_data [START]
    pub genesis_constant: FieldElement,     // Passed directly by the MC. It is a constant declared during SC creation that commits to various SC params. In the current SNARK design it isn't used (but might be usefull for other sidechains), so just ignored in the circuit. Note that it is the same constant as for WCert proof.
    pub mcb_sc_txs_com_end: FieldHash,      // Passed directly by MC. The cumulative SCTxsCommitment hash taken from the MC block where the SC was ceased (needed to recover FTs in reverted epochs).
    pub sc_last_wcert_hash: FieldHash,      // hash of the last confirmed WCert (excluding reverted) for this sidechain (calculated directly by MC). Note that it should be a hash of WithdrawalCertificateData
    pub amount: FieldElement,               // taken from CSW and passed directly by the MC
    pub nullifier: FieldHash,               // taken from CSW and passed directly by the MC
    pub receiver: [u8; MC_PK_SIZE],         // the receiver is fixed by the proof, otherwise someone will be able to front-run the tx and steel the proof. Note that we actually don't need to do anything with the receiver in the circuit, it's enough just to have it as a public input
    // sys_data [END]

    // public inputs [END]

    // witnesses [START]
    pub last_wcert: WithdrawalCertificateData,  // the last confirmed wcert in the MC

    // either `input` or `ft_input` must be non NULL
    pub input: CswUtxoInputData,                // unspent output we are trying to withdraw
    pub mst_path_to_output: FieldHash,          // path to output in the MST of the known state
    pub ft_input: CswFtInputData,               // FT output in the MC block
    pub ft_input_secret_key: [u8; 32],          // secret key that authorizes ft_input spending
    pub mcb_sc_txs_com_start: FieldHash,        // Cumulative ScTxsCommittment taken from the last MC block of the last confirmed (not reverted) epoch
    pub merkle_path_to_sc_hash: GingerMHTPath,  // Merkle path to a particular sidechain in the ScTxsComm tree
    pub ft_tree_path: GingerMHTPath,            // path to the ft_input_hash in the FT Merkle tree included in ScTxsComm tree
    pub scb_btr_tree_root: FieldHash,           // root hash of the BTR tree included in ScTxsComm tree
    pub wcert_tree_root: FieldHash,             // root hash of the Wcert tree included in ScTxsComm tree
    pub sc_txs_com_hashes: Vec<FieldHash>,      // contains all ScTxsComm cumulative hashes on the way from `mcb_sc_txs_com_start` to `mcb_sc_txs_com_end` 
                                                // RANGE_SIZE is a number of blocks between `mcb_sc_txs_com_start` and `mcb_sc_txs_com_end`. 
                                                // It seems it can be a constant as the number of blocks between the last confirmed block and SC ceasing block should be fixed for a particular sidechain
    // witnesses [END]
}