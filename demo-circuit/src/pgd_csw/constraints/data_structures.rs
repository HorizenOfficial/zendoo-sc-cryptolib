use std::borrow::Borrow;

use cctp_primitives::type_mapping::FieldElement;
use r1cs_core::{ConstraintSystemAbstract, SynthesisError};
use r1cs_std::{FromGadget, prelude::{AllocGadget, UInt8}};

use crate::{CswFtInputData, CswProverData, CswUtxoInputData, FieldElementGadget, GingerMHTBinaryGadget, WithdrawalCertificateData, constants::constants::CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER};

pub struct WithdrawalCertificateDataGadget {
    ledger_id_g: FieldElementGadget,
    epoch_id_g: FieldElementGadget,
    bt_list_hash_g: FieldElementGadget,
    quality_g: FieldElementGadget,
    mcb_sc_txs_com_g: FieldElementGadget,
    ft_min_fee_g: FieldElementGadget,
    btr_min_fee_g: FieldElementGadget,
    scb_new_mst_root_g: FieldElementGadget
}

impl WithdrawalCertificateDataGadget {
    pub fn get_ledger_id_g(&self) -> &FieldElementGadget { &self.ledger_id_g }
    pub fn get_epoch_id_g(&self) -> &FieldElementGadget { &self.epoch_id_g }
    pub fn get_bt_list_hash_g(&self) -> &FieldElementGadget { &self.bt_list_hash_g }
    pub fn get_quality_g(&self) -> &FieldElementGadget { &self.quality_g }
    pub fn get_mcb_sc_txs_com_g(&self) -> &FieldElementGadget { &self.mcb_sc_txs_com_g }
    pub fn get_ft_min_fee_g(&self) -> &FieldElementGadget { &self.ft_min_fee_g }
    pub fn get_btr_min_fee_g(&self) -> &FieldElementGadget { &self.btr_min_fee_g }
    pub fn get_scb_new_mst_root_g(&self) -> &FieldElementGadget { &self.scb_new_mst_root_g }
}

impl AllocGadget<WithdrawalCertificateData, FieldElement> for WithdrawalCertificateDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<WithdrawalCertificateData> {
            let (ledger_id,
                 epoch_id,
                 bt_list_hash,
                 quality,
                 mcb_sc_txs_com,
                 ft_min_fee,
                 btr_min_fee,
                 scb_new_mst_root) = match f() {
                Ok(certificate_data) => {
                    let certificate_data = certificate_data.borrow().clone();
                    (
                        Ok(certificate_data.ledger_id),
                        Ok(certificate_data.epoch_id),
                        Ok(certificate_data.bt_list_hash),
                        Ok(certificate_data.quality),
                        Ok(certificate_data.mcb_sc_txs_com),
                        Ok(certificate_data.ft_min_fee),
                        Ok(certificate_data.btr_min_fee),
                        Ok(certificate_data.scb_new_mst_root)
                    )
                },
                _ => (
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing)
                )
            };

            let ledger_id_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc ledger id"),
                || ledger_id
            )?;
    
            let epoch_id_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc epoch id"),
                || epoch_id
            )?;
    
            let bt_list_hash_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc bt list hash"),
                || bt_list_hash
            )?;
    
            let quality_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc quality"),
                || quality
            )?;
    
            let mcb_sc_txs_com_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc mcb sc txs com"),
                || mcb_sc_txs_com
            )?;
    
            let ft_min_fee_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc ft min fee"),
                || ft_min_fee
            )?;
    
            let btr_min_fee_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc btr min fee"),
                || btr_min_fee
            )?;
    
            let scb_new_mst_root_g = FieldElementGadget::alloc_input(
                cs.ns(|| "alloc scb new mst root"),
                || scb_new_mst_root
            )?;
    
            let new_instance = Self {
                ledger_id_g,
                epoch_id_g,
                bt_list_hash_g,
                quality_g,
                mcb_sc_txs_com_g,
                ft_min_fee_g,
                btr_min_fee_g,
                scb_new_mst_root_g
            };
    
            Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(_cs: CS, _f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<WithdrawalCertificateData> {
        unimplemented!()
    }   
}

pub struct CswUtxoInputDataGadget {
    spending_pub_key_g: Vec::<UInt8>,
    amount_g: FieldElementGadget,
    nonce_g: FieldElementGadget,
    custom_hash_g: FieldElementGadget,
    secret_key_g: Vec::<UInt8>
}

impl CswUtxoInputDataGadget {
    pub fn get_spending_pub_key_g(&self) -> &Vec::<UInt8> { &self.spending_pub_key_g }
    pub fn get_amount_g(&self) -> &FieldElementGadget { &self.amount_g }
    pub fn get_nonce_g(&self) -> &FieldElementGadget { &self.nonce_g }
    pub fn get_custom_hash_g(&self) -> &FieldElementGadget { &self.custom_hash_g }
    pub fn get_secret_key_g(&self) -> &Vec::<UInt8> { &self.secret_key_g }
}

impl AllocGadget<CswUtxoInputData, FieldElement> for CswUtxoInputDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoInputData> {
            let (spending_pub_key,
                 amount,
                 nonce,
                 custom_hash,
                 secret_key) = match f() {
                Ok(csw_utxo_input_data) => {
                    let csw_utxo_input_data = csw_utxo_input_data.borrow().clone();
                    (
                        Ok(csw_utxo_input_data.spending_pub_key),
                        Ok(csw_utxo_input_data.amount),
                        Ok(csw_utxo_input_data.nonce),
                        Ok(csw_utxo_input_data.custom_hash),
                        Ok(csw_utxo_input_data.secret_key)
                    )
                },
                _ => (
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing)
                )
            };

            let spending_pub_key_g = Vec::<UInt8>::alloc(
                cs.ns(|| "alloc spending pub key"),
                || spending_pub_key
            )?;

            let amount_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc amount"),
                || amount
            )?;

            let nonce_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc nonce"),
                || nonce
            )?;

            let custom_hash_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc custom hash"),
                || custom_hash
            )?;

            let secret_key_g = Vec::<UInt8>::alloc(
                cs.ns(|| "alloc secret key"),
                || secret_key
            )?;
    
            let new_instance = Self {
                spending_pub_key_g,
                amount_g,
                nonce_g,
                custom_hash_g,
                secret_key_g
            };
    
            Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(_cs: CS, _f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoInputData> {
        unimplemented!()
    }   
}

pub struct CswFtInputDataGadget {
    amount_g: FieldElementGadget,
    receiver_pub_key_g: Vec::<UInt8>,
    payback_addr_data_hash_g: FieldElementGadget,
    tx_hash_g: FieldElementGadget,
    out_idx_g: FieldElementGadget
}

impl CswFtInputDataGadget {
    pub fn get_amount_g(&self) -> &FieldElementGadget { &self.amount_g }
    pub fn get_receiver_pub_key_g(&self) -> &Vec::<UInt8> { &self.receiver_pub_key_g }
    pub fn get_payback_addr_data_hash_g(&self) -> &FieldElementGadget { &self.payback_addr_data_hash_g }
    pub fn get_tx_hash_g(&self) -> &FieldElementGadget { &self.tx_hash_g }
    pub fn get_out_idx_g(&self) -> &FieldElementGadget { &self.out_idx_g }
}

impl AllocGadget<CswFtInputData, FieldElement> for CswFtInputDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtInputData> {
            let (amount,
                 receiver_pub_key,
                 payback_addr_data_hash,
                 tx_hash,
                 out_idx) = match f() {
                Ok(csw_ft_input_data) => {
                    let csw_ft_input_data = csw_ft_input_data.borrow().clone();
                    (
                        Ok(csw_ft_input_data.amount),
                        Ok(csw_ft_input_data.receiver_pub_key),
                        Ok(csw_ft_input_data.payback_addr_data_hash),
                        Ok(csw_ft_input_data.tx_hash),
                        Ok(csw_ft_input_data.out_idx)
                    )
                },
                _ => (
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing),
                    Err(SynthesisError::AssignmentMissing)
                )
            };

            let amount_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc amount"),
                || amount
            )?;

            let receiver_pub_key_g = Vec::<UInt8>::alloc(
                cs.ns(|| "alloc receiver pub key"),
                || receiver_pub_key
            )?;

            let payback_addr_data_hash_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc payback addr data hash"),
                || payback_addr_data_hash
            )?;

            let tx_hash_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc tx hash"),
                || tx_hash
            )?;

            let out_idx_g = FieldElementGadget::alloc(
                cs.ns(|| "alloc out idx"),
                || out_idx
            )?;

            let new_instance = Self {
                amount_g,
                receiver_pub_key_g,
                payback_addr_data_hash_g,
                tx_hash_g,
                out_idx_g
            };

            Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(_cs: CS, _f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtInputData> {
            unimplemented!()
    }   
}

pub struct CswProverDataGadget {

    // public inputs [START]
    genesis_constant_g: FieldElementGadget,
    mcb_sc_txs_com_end_g: FieldElementGadget,
    sc_last_wcert_hash_g: FieldElementGadget,
    amount_g: FieldElementGadget,
    nullifier_g: FieldElementGadget,
    receiver_g: FieldElementGadget,
    // public inputs [END]

    // witnesses [START]
    last_wcert_g: WithdrawalCertificateDataGadget,
    input_g: CswUtxoInputDataGadget,
    mst_path_to_output_g: GingerMHTBinaryGadget,
    ft_input_g: CswFtInputDataGadget,
    ft_input_secret_key_g: Vec<UInt8>,
    mcb_sc_txs_com_start_g: FieldElementGadget,
    merkle_path_to_sc_hash_g: GingerMHTBinaryGadget,
    ft_tree_path_g: GingerMHTBinaryGadget,
    scb_btr_tree_root_g: FieldElementGadget,
    wcert_tree_root_g: FieldElementGadget,
    sc_txs_com_hashes_g: Vec<FieldElementGadget>
    // witnesses [END]
}

impl CswProverDataGadget {
    pub fn get_genesis_constant_g(&self) -> &FieldElementGadget { &self.genesis_constant_g }
    pub fn get_mcb_sc_txs_com_end_g(&self) -> &FieldElementGadget { &self.mcb_sc_txs_com_end_g }
    pub fn get_sc_last_wcert_hash_g(&self) -> &FieldElementGadget { &self.sc_last_wcert_hash_g }
    pub fn get_amount_g(&self) -> &FieldElementGadget { &self.amount_g }
    pub fn get_nullifier_g(&self) -> &FieldElementGadget { &self.nullifier_g }
    pub fn get_receiver_g(&self) -> &FieldElementGadget { &self.receiver_g }
    pub fn get_last_wcert_g(&self) -> &WithdrawalCertificateDataGadget { &self.last_wcert_g }
    pub fn get_input_g(&self) -> &CswUtxoInputDataGadget { &self.input_g }
    pub fn get_mst_path_to_output_g(&self) -> &GingerMHTBinaryGadget { &self.mst_path_to_output_g }
    pub fn get_ft_input_g(&self) -> &CswFtInputDataGadget { &self.ft_input_g }
    pub fn get_ft_input_secret_key_g(&self) -> &Vec<UInt8> { &self.ft_input_secret_key_g }
    pub fn get_mcb_sc_txs_com_start_g(&self) -> &FieldElementGadget { &self.mcb_sc_txs_com_start_g }
    pub fn get_merkle_path_to_sc_hash_g(&self) -> &GingerMHTBinaryGadget { &self.merkle_path_to_sc_hash_g }
    pub fn get_ft_tree_path_g(&self) -> &GingerMHTBinaryGadget { &self.ft_tree_path_g }
    pub fn get_scb_btr_tree_root_g(&self) -> &FieldElementGadget { &self.scb_btr_tree_root_g }
    pub fn get_wcert_tree_root_g(&self) -> &FieldElementGadget { &self.wcert_tree_root_g }
    pub fn get_sc_txs_com_hashes_g(&self) -> &Vec<FieldElementGadget> { &self.sc_txs_com_hashes_g }
}

impl FromGadget<CswProverData, FieldElement> for CswProverDataGadget where {

    fn from<CS: ConstraintSystemAbstract<FieldElement>>(
        data: CswProverData,
        mut cs: CS,
    ) -> Result<Self, SynthesisError> {

        let genesis_constant_g = FieldElementGadget::alloc_input(
            cs.ns(|| "alloc genesis constant"),
            || Ok(data.genesis_constant)
        )?;

        let mcb_sc_txs_com_end_g = FieldElementGadget::alloc_input(
            cs.ns(|| "alloc mcb sc txs com end"),
            || Ok(data.mcb_sc_txs_com_end)
        )?;

        let sc_last_wcert_hash_g = FieldElementGadget::alloc_input(
            cs.ns(|| "alloc sc last wcert hash"),
            || Ok(data.sc_last_wcert_hash)
        )?;

        let amount_g = FieldElementGadget::alloc_input(
            cs.ns(|| "alloc amount"),
            || Ok(data.amount)
        )?;

        let nullifier_g = FieldElementGadget::alloc_input(
            cs.ns(|| "alloc nullifier"),
            || Ok(data.nullifier)
        )?;

        let receiver_g = FieldElementGadget::alloc_input(
            cs.ns(|| "alloc receiver"),
            || Ok(data.receiver)
        )?;

        let last_wcert_g = WithdrawalCertificateDataGadget::alloc(
            cs.ns(|| "alloc last wcert"),
            || Ok(data.last_wcert.clone())
        )?;

        let input_g = CswUtxoInputDataGadget::alloc(
            cs.ns(|| "alloc input"),
            || Ok(data.input.clone())
        )?;

        let mst_path_to_output_g = GingerMHTBinaryGadget::alloc(
            cs.ns(|| "alloc mst path to output"),
            || Ok(data.mst_path_to_output.clone())
        )?;

        let ft_input_g = CswFtInputDataGadget::alloc(
            cs.ns(|| "alloc ft input"),
            || Ok(data.ft_input.clone())
        )?;

        let ft_input_secret_key_g = Vec::<UInt8>::alloc(
            cs.ns(|| "alloc ft input secret key"),
            || Ok(data.ft_input_secret_key)
        )?;

        let mcb_sc_txs_com_start_g = FieldElementGadget::alloc(
            cs.ns(|| "alloc mcb sc txs com start"),
            || Ok(data.mcb_sc_txs_com_start)
        )?;

        let merkle_path_to_sc_hash_g = GingerMHTBinaryGadget::alloc(
            cs.ns(|| "alloc merkle path to sc hash"),
            || Ok(&data.merkle_path_to_sc_hash)
        )?;

        let ft_tree_path_g = GingerMHTBinaryGadget::alloc(
            cs.ns(|| "alloc ft tree path"),
            || Ok(data.ft_tree_path.clone())
        )?;

        let scb_btr_tree_root_g = FieldElementGadget::alloc(
            cs.ns(|| "alloc scb btr tree root"),
            || Ok(data.scb_btr_tree_root)
        )?;

        let wcert_tree_root_g = FieldElementGadget::alloc(
            cs.ns(|| "alloc wcert tree root"),
            || Ok(data.wcert_tree_root)
        )?;

        assert!(data.sc_txs_com_hashes.len() == CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER);
        let mut sc_txs_com_hashes_g = Vec::with_capacity(CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER);

        for index in 0..data.sc_txs_com_hashes.len() {
            let sc_txs_com_hash_g = FieldElementGadget::alloc(
                cs.ns(|| format!("alloc sc txs com hash {}", index)),
                || Ok(data.sc_txs_com_hashes[index])
            )?;
            sc_txs_com_hashes_g.push(sc_txs_com_hash_g);
        }

        let new_instance = Self {
            genesis_constant_g,
            mcb_sc_txs_com_end_g,
            sc_last_wcert_hash_g,
            amount_g,
            nullifier_g,
            receiver_g,
            last_wcert_g,
            input_g,
            mst_path_to_output_g,
            ft_input_g,
            ft_input_secret_key_g,
            mcb_sc_txs_com_start_g,
            merkle_path_to_sc_hash_g,
            ft_tree_path_g,
            scb_btr_tree_root_g,
            wcert_tree_root_g,
            sc_txs_com_hashes_g,
        };

        Ok(new_instance)
    }

}