use algebra::Field;
use cctp_primitives::type_mapping::FieldElement;
use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedMerkleTreePathGadget};
use r1cs_std::{
    alloc::AllocGadget,
    alloc::ConstantGadget,
    boolean::{AllocatedBit, Boolean},
    fields::FieldGadget,
    prelude::EqGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    FromGadget,
};

use crate::{
    constants::constants::{BoxType, CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER},
    CswProverData, FieldElementGadget, FieldHashGadget,
};

use self::data_structures::CswProverDataGadget;

pub mod data_structures;

#[derive(Clone)]
pub struct CeasedSidechainWithdrawalCircuit {
    sidechain_id: FieldElement,
    csw_data: CswProverData,
}

impl CeasedSidechainWithdrawalCircuit {
    pub fn new(sidechain_id: FieldElement, csw_data: CswProverData) -> Self {
        CeasedSidechainWithdrawalCircuit {
            sidechain_id,
            csw_data,
        }
    }
}

impl ConstraintSynthesizer<FieldElement> for CeasedSidechainWithdrawalCircuit {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let true_boolean_g = Boolean::from(
            AllocatedBit::alloc(cs.ns(|| "Alloc constant True gadget"), || Ok(true)).unwrap(),
        );

        let sidechain_id_g =
            FieldElementGadget::from_value(cs.ns(|| "sidechain_id_g"), &self.sidechain_id);

        let csw_data_g = <CswProverDataGadget as FromGadget<CswProverData, FieldElement>>::from(
            self.csw_data,
            cs.ns(|| "alloc csw data"),
        )?;

        // val last_wcert_hash = H(last_wcert)
        // TODO: define how to calculate the hash of a certificate
        let last_wcert_g = csw_data_g.last_wcert_g.clone();
        let last_wcert_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(last_wcert)"),
            &[
                last_wcert_g.ledger_id_g.clone(),
                last_wcert_g.epoch_id_g.clone(),
                last_wcert_g.bt_list_hash_g.clone(),
                last_wcert_g.quality_g.clone(),
                last_wcert_g.mcb_sc_txs_com_g.clone(),
                last_wcert_g.ft_min_fee_g.clone(),
                last_wcert_g.btr_min_fee_g.clone(),
                last_wcert_g.scb_new_mst_root_g.clone(),
            ],
        )?;

        let should_enforce_utxo_withdrawal_g = csw_data_g
            .input_g
            .is_phantom(cs.ns(|| "should_enforce_utxo_withdrawal"))?
            .not();

        let should_enforce_ft_withdrawal_g = csw_data_g
            .ft_input_g
            .is_phantom(cs.ns(|| "should_enforce_ft_withdrawal"))?
            .not();

        // enforce that the CSW if for either UTXO or FT
        // and that exactly one of the two is not NULL
        let utxo_xor_ft_withdrawal_g = Boolean::xor(
            cs.ns(|| "(input != NULL) XOR (ft_input != NULL)"),
            &should_enforce_utxo_withdrawal_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        utxo_xor_ft_withdrawal_g.enforce_equal(
            cs.ns(|| "enforce that the CSW if for either UTXO or FT"),
            &true_boolean_g,
        )?;

        // require(sc_last_wcert_hash == last_wcert_hash)
        last_wcert_hash_g.enforce_equal(
            cs.ns(|| "enforce sc_last_wcert_hash == last_wcert_hash"),
            &csw_data_g.sc_last_wcert_hash_g.clone(),
        )?;

        // UTXO widthdrawal [START]

        // val outputHash = H(input.output | BoxType.Coin)
        let box_type_coin_g = FieldElementGadget::from(
            cs.ns(|| "alloc BoxType.Coin constant"),
            &FieldElement::from(BoxType::CoinBox as u8),
        );

        let mut output_hash_elements_g = csw_data_g
            .input_g
            .output_g
            .to_field_gadget_elements(cs.ns(|| "alloc output hash elements"))?;

        output_hash_elements_g.push(box_type_coin_g);
        assert_eq!(output_hash_elements_g.len(), 6);

        let output_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(input.output)"),
            &output_hash_elements_g,
        )?;

        // 1 Check output presence in the known state
        // mst_root = reconstruct_merkle_root_hash(outputHash, mst_path_to_output)
        let mst_root_g = csw_data_g.mst_path_to_output_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(outputHash, mst_path_to_output)"),
            &output_hash_g,
        )?;

        // require(last_wcert.proof_data.scb_new_mst_root == mst_root)
        mst_root_g.conditional_enforce_equal(
            cs.ns(|| "last_wcert.proof_data.scb_new_mst_root == mst_root"),
            &csw_data_g.last_wcert_g.scb_new_mst_root_g,
            &should_enforce_utxo_withdrawal_g,
        )?;

        // 2 Check nullifier
        // require(nullifier == outputHash)
        output_hash_g.conditional_enforce_equal(
            cs.ns(|| "require(nullifier == outputHash)"),
            &csw_data_g.nullifier_g,
            &should_enforce_utxo_withdrawal_g,
        )?;

        // 3 Check amount and signature
        // require(input.output.amount == sys_data.amount)
        csw_data_g
            .input_g
            .output_g
            .amount_g
            .conditional_enforce_equal(
                cs.ns(|| "input.output.amount == sys_data.amount"),
                &csw_data_g.amount_g,
                &should_enforce_utxo_withdrawal_g,
            )?;

        // TODO: check secret key ownership

        // UTXO widthdrawal [END]

        // FT withdrawal [START]

        // val ft_input_hash = H(ft_input)
        let ft_input_hash_input_elements = csw_data_g
            .ft_input_g
            .to_field_gadget_elements(cs.ns(|| "alloc ft_input_hash input elements"))?;

        let ft_input_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(ft_input)"),
            &ft_input_hash_input_elements,
        )?;

        // val scb_ft_tree_root = reconstruct_merkle_root_hash(ft_input_hash, ft_tree_path)
        let scb_ft_tree_root_g = csw_data_g.ft_tree_path_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(ft_input_hash, ft_tree_path)"),
            &ft_input_hash_g,
        )?;

        // val txs_hash = H(scb_ft_tree_root | scb_btr_tree_root | wcert_tree_root)     // Q: what about sc_creation_tx that may be included in txs_hash? Should we add NULL instead?
        let txs_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(scb_ft_tree_root | scb_btr_tree_root | wcert_tree_root)"),
            &[
                scb_ft_tree_root_g,
                csw_data_g.scb_btr_tree_root_g.clone(),
                csw_data_g.wcert_tree_root_g.clone(),
            ],
        )?;

        // val sc_hash = H(txs_hash | THIS_SIDECHAIN_ID)
        let sc_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(txs_hash | THIS_SIDECHAIN_ID)"),
            &[txs_hash_g, sidechain_id_g],
        )?;

        // val sc_txs_com_tree_root = reconstruct_merkle_root_hash(sc_hash, merkle_path_to_scHash)
        let sc_txs_com_tree_root_g = csw_data_g.merkle_path_to_sc_hash_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(sc_hash, merkle_path_to_scHash)"),
            &sc_hash_g,
        )?;

        // var sc_txs_com_cumulative = mcb_sc_txs_com_start
        let mut sc_txs_com_cumulative_g = csw_data_g.mcb_sc_txs_com_start_g;

        // var cnt = 0
        let counter_g = FieldElementGadget::from_value(
            cs.ns(|| "alloc initial counter"),
            &FieldElement::from(0u8),
        );

        // TODO: define CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER as creation parameter
        for i in 0..CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER {
            // if (sc_txs_com_tree_root == sc_txs_com_hashes[i]) { cnt++ }
            let should_increase_counter = sc_txs_com_tree_root_g.is_eq(
                cs.ns(|| format!("sc_txs_com_tree_root == sc_txs_com_hashes[{}]", i)),
                &csw_data_g.sc_txs_com_hashes_g[i],
            )?;

            // cnt++
            counter_g.conditionally_add_constant(
                cs.ns(|| format!("cnt++ [{}]", i)),
                &should_increase_counter,
                FieldElement::one(),
            )?;

            // sc_txs_com_cumulative = H(sc_txs_com_cumulative, sc_txs_com_hashes[i])
            sc_txs_com_cumulative_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(sc_txs_com_cumulative, sc_txs_com_hashes[{}])", i)),
                &[
                    sc_txs_com_cumulative_g,
                    csw_data_g.sc_txs_com_hashes_g[i].clone(),
                ],
            )?;
        }

        // require(cnt == 1)   // We must have exactly one match
        let constant_one_g =
            FieldElementGadget::from_value(cs.ns(|| "alloc constant 1"), &FieldElement::from(1u8));
        counter_g.conditional_enforce_equal(
            cs.ns(|| "require(cnt == 1)"),
            &constant_one_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // require(mcb_sc_txs_com_end = sc_txs_com_cumulative)
        csw_data_g.mcb_sc_txs_com_end_g.conditional_enforce_equal(
            cs.ns(|| "mcb_sc_txs_com_end = sc_txs_com_cumulative"),
            &sc_txs_com_cumulative_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // require(ft_input.amount == sys_data.amount)
        csw_data_g.ft_input_g.amount_g.conditional_enforce_equal(
            cs.ns(|| "ft_input.amount == sys_data.amount"),
            &csw_data_g.amount_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // require(true == verify_signature(ft_input_hash, ft_input_sig, ft_input.receiver_metadata.receiver_pub_key))
        // TODO: as soon as the related gadget is available, implement this as proof of ownership of a secret key

        // require(nullifier == ft_input_hash)
        csw_data_g.nullifier_g.conditional_enforce_equal(
            cs.ns(|| "nullifier == ft_input_hash"),
            &ft_input_hash_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // FT withdrawal [END]

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{convert::TryInto, ops::AddAssign};

    use algebra::ToConstraintField;
    use cctp_primitives::{
        proving_system::init::{get_g1_committer_key, load_g1_committer_key},
        type_mapping::{CoboundaryMarlin, FieldElement, GingerMHT, MC_PK_SIZE},
        utils::poseidon_hash::get_poseidon_hash_constant_length,
    };
    use primitives::{bytes_to_bits, FieldBasedHash, FieldBasedMerkleTree};
    use r1cs_core::debug_circuit;

    use crate::{
        constants::constants::{BoxType, CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER},
        read_field_element_from_buffer_with_padding, CswFtInputData, CswProverData,
        CswUtxoInputData, CswUtxoOutputData, GingerMHTBinaryPath, WithdrawalCertificateData,
        MST_MERKLE_TREE_HEIGHT, SC_PUBLIC_KEY_LENGTH, SC_SECRET_KEY_LENGTH,
    };

    use super::CeasedSidechainWithdrawalCircuit;

    fn generate_test_csw_prover_data() -> CswProverData {
        let utxo_input_data = CswUtxoInputData {
            output: CswUtxoOutputData {
                spending_pub_key: [9; SC_PUBLIC_KEY_LENGTH],
                amount: FieldElement::from(10u8),
                nonce: FieldElement::from(11u8),
                custom_hash: FieldElement::from(12u8),
            },
            secret_key: [13; SC_SECRET_KEY_LENGTH],
        };

        let mut mst = GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();

        let mut mst_leaf_inputs = bytes_to_bits(&utxo_input_data.output.spending_pub_key)
            .to_field_elements()
            .unwrap();

        // Since the spending_pub_key is 32 bytes long, it cannot fit into a single field element.
        assert_eq!(mst_leaf_inputs.len(), 2);

        mst_leaf_inputs.extend(&[
            utxo_input_data.output.amount,
            utxo_input_data.output.nonce,
            utxo_input_data.output.custom_hash,
            FieldElement::from(BoxType::CoinBox as u8),
        ]);

        assert_eq!(mst_leaf_inputs.len(), 6);

        let mut mst_leaf = get_poseidon_hash_constant_length(mst_leaf_inputs.len(), None);

        mst_leaf_inputs.into_iter().for_each(|fe| {
            mst_leaf.update(fe);
        });

        let mst_leaf_hash = mst_leaf.finalize().unwrap();

        mst.append(mst_leaf_hash).unwrap();
        mst.finalize_in_place().unwrap();

        let mst_path: GingerMHTBinaryPath = mst.get_merkle_path(0).unwrap().try_into().unwrap();

        let cert_data = WithdrawalCertificateData {
            ledger_id: FieldElement::from(1u8),
            epoch_id: FieldElement::from(2u8),
            bt_list_hash: FieldElement::from(3u8),
            quality: FieldElement::from(4u8),
            mcb_sc_txs_com: FieldElement::from(5u8),
            ft_min_fee: FieldElement::from(6u8),
            btr_min_fee: FieldElement::from(7u8),
            scb_new_mst_root: mst.root().unwrap(),
        };

        let computed_last_wcert_hash = get_poseidon_hash_constant_length(8, None)
            .update(cert_data.ledger_id)
            .update(cert_data.epoch_id)
            .update(cert_data.bt_list_hash)
            .update(cert_data.quality)
            .update(cert_data.mcb_sc_txs_com)
            .update(cert_data.ft_min_fee)
            .update(cert_data.btr_min_fee)
            .update(cert_data.scb_new_mst_root)
            .finalize()
            .unwrap();

        let csw_prover_data = CswProverData {
            genesis_constant: FieldElement::from(14u8),
            mcb_sc_txs_com_end: FieldElement::from(15u8),
            sc_last_wcert_hash: computed_last_wcert_hash,
            amount: utxo_input_data.output.amount,
            nullifier: mst_leaf_hash,
            receiver: read_field_element_from_buffer_with_padding(&[19; MC_PK_SIZE]).unwrap(),
            last_wcert: cert_data,
            input: utxo_input_data,
            mst_path_to_output: mst_path,
            ft_input: CswFtInputData::default(),
            ft_input_secret_key: [20; SC_SECRET_KEY_LENGTH],
            mcb_sc_txs_com_start: FieldElement::from(21u8),
            merkle_path_to_sc_hash: GingerMHTBinaryPath::default(),
            ft_tree_path: GingerMHTBinaryPath::default(),
            scb_btr_tree_root: FieldElement::from(22u8),
            wcert_tree_root: FieldElement::from(23u8),
            sc_txs_com_hashes: vec![
                FieldElement::from(24u8);
                CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER
            ],
        };

        csw_prover_data
    }

    #[test]
    fn test_csw_circuit() {
        let sidechain_id = FieldElement::from(77u8);
        let csw_prover_data = generate_test_csw_prover_data();
        let circuit = CeasedSidechainWithdrawalCircuit::new(sidechain_id, csw_prover_data.clone());

        let failing_constraint = debug_circuit(circuit.clone()).unwrap();
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());

        load_g1_committer_key(1 << 17, 1 << 15).unwrap();
        let ck_g1 = get_g1_committer_key().unwrap();
        let params = CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circuit.clone()).unwrap();

        let proof = CoboundaryMarlin::prove(
            &params.0.clone(),
            ck_g1.as_ref().unwrap(),
            circuit,
            false,
            None,
        )
        .unwrap();

        let mut public_inputs = vec![
            csw_prover_data.genesis_constant,
            csw_prover_data.mcb_sc_txs_com_end,
            csw_prover_data.sc_last_wcert_hash,
            FieldElement::from(csw_prover_data.amount),
            csw_prover_data.nullifier,
            csw_prover_data.receiver,
            csw_prover_data.last_wcert.scb_new_mst_root,
        ];

        // Check that the proof gets correctly verified
        assert!(CoboundaryMarlin::verify(
            &params.1.clone(),
            ck_g1.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());

        // Change one public input and check that the proof fails
        public_inputs[0].add_assign(&FieldElement::from(1u8));
        assert!(!CoboundaryMarlin::verify(
            &params.1.clone(),
            ck_g1.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());
    }
}