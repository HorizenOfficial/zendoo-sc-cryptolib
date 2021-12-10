use algebra::{AffineCurve, Field};
use cctp_primitives::type_mapping::FieldElement;
use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedMerkleTreePathGadget};
use r1cs_std::{
    alloc::AllocGadget,
    alloc::ConstantGadget,
    boolean::{AllocatedBit, Boolean},
    fields::{nonnative::nonnative_field_gadget::NonNativeFieldGadget, FieldGadget},
    groups::GroupGadget,
    prelude::EqGadget,
    select::CondSelectGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    FromBitsGadget, FromGadget,
};

use crate::{
    constants::constants::{BoxType, CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER},
    type_mapping::*,
    CswFtProverData, CswProverData, CswSysData, CswUtxoProverData, FieldElementGadget,
    FieldHashGadget, WithdrawalCertificateData, PHANTOM_FIELD_ELEMENT,
};

use self::data_structures::CswProverDataGadget;

pub mod data_structures;

#[derive(Clone)]
pub struct CeasedSidechainWithdrawalCircuit {
    sidechain_id: FieldElement,
    csw_data: CswProverData,
    range_size: u32,
    num_custom_fields: u32,
}

impl CeasedSidechainWithdrawalCircuit {
    pub fn new(
        _sidechain_id: FieldElement,
        _sys_data: CswSysData,
        _last_wcert: Option<WithdrawalCertificateData>,
        _utxo_data: Option<CswUtxoProverData>,
        _ft_data: Option<CswFtProverData>,
        _range_size: u32,
        _num_custom_fields: u32,
    ) -> Self {
        unimplemented!();
    }

    // For testing, if useful
    pub fn from_prover_data(
        sidechain_id: FieldElement,
        csw_data: CswProverData,
        range_size: u32,
        num_custom_fields: u32,
    ) -> Self {
        CeasedSidechainWithdrawalCircuit {
            sidechain_id,
            csw_data,
            range_size,
            num_custom_fields,
        }
    }

    pub fn get_instance_for_setup(_range_size: u32, _num_custom_fields: u32) -> Self {
        unimplemented!();
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

        // val last_wcert_hash = H(last_wcert) [START]
        let last_wcert_g = csw_data_g.last_wcert_g.clone();

        let last_wcert_epoch_id_fe_g = {
            let bits = last_wcert_g.epoch_id_g.clone().into_bits_be();
            FieldElementGadget::from_bits(
                cs.ns(|| "last_wcert_epoch_id_fe_g"),
                bits.as_slice()
            )
        }?;

        let last_wcert_quality_fe_g = {
            let mut bits = last_wcert_g.quality_g.to_bits_le();
            bits.reverse();

            FieldElementGadget::from_bits(
                cs.ns(|| "last_wcert_quality_fe_g"),
                bits.as_slice()
            )
        }?;

        let mut last_wcert_btr_fee_bits_g = last_wcert_g.btr_min_fee_g.to_bits_le();
        last_wcert_btr_fee_bits_g.reverse();

        let mut last_wcert_ft_fee_bits_g = last_wcert_g.ft_min_amount_g.to_bits_le();
        last_wcert_ft_fee_bits_g.reverse();

        let mut last_wcert_fee_bits_g = last_wcert_btr_fee_bits_g;
        last_wcert_fee_bits_g.append(&mut last_wcert_ft_fee_bits_g);

        let last_wcert_fee_fe_g =
            FieldElementGadget::from_bits(cs.ns(|| "last_wcert_fee_fe_g"), &last_wcert_fee_bits_g)?;

        let temp_last_wcert_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(last_wcert without custom fields)"),
            &[
                last_wcert_g.ledger_id_g.clone(),
                last_wcert_epoch_id_fe_g,
                last_wcert_g.bt_list_root_g.clone(),
                last_wcert_quality_fe_g,
                last_wcert_g.mcb_sc_txs_com_g.clone(),
                last_wcert_fee_fe_g,
            ],
        )?;

        // Alloc custom_fields and enforce their hash, if they are present
        let last_wcert_custom_fields_hash_g = if last_wcert_g.custom_fields_g.len() > 0 {
            let custom_fields_hash_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H(custom_fields)"),
                last_wcert_g.custom_fields_g.as_slice(),
            )?;
            Some(custom_fields_hash_g)
        } else {
            None
        };

        let preimage = if last_wcert_custom_fields_hash_g.is_some() {
            vec![
                last_wcert_custom_fields_hash_g.unwrap(),
                temp_last_wcert_hash_g,
            ]
        } else {
            vec![temp_last_wcert_hash_g]
        };

        let last_wcert_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H([custom_fields], cert_data_hash)"),
            preimage.as_slice(),
        )?;

        // val last_wcert_hash = H(last_wcert) [END]

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

        let should_enforce_wcert_hash = last_wcert_g
            .is_phantom(
                cs.ns(|| "should_enforce_wcert_hash"),
                self.num_custom_fields,
            )?
            .not();

        // if last_wcert != NULL
        // require(sc_last_wcert_hash == last_wcert_hash)
        last_wcert_hash_g.conditional_enforce_equal(
            cs.ns(|| "enforce sc_last_wcert_hash == last_wcert_hash"),
            &csw_data_g.sc_last_wcert_hash_g.clone(),
            &should_enforce_wcert_hash,
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

        debug_assert_eq!(output_hash_elements_g.len(), 3);
        output_hash_elements_g.push(box_type_coin_g);

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

        if last_wcert_g.custom_fields_g.len() > 0 {
            // require(last_wcert.proof_data.scb_new_mst_root == mst_root)
            // Note that scb_new_mst_root is now the first element of the custom fields vector
            mst_root_g.conditional_enforce_equal(
                cs.ns(|| "last_wcert.proof_data.scb_new_mst_root == mst_root"),
                &last_wcert_g.custom_fields_g[0],
                &should_enforce_utxo_withdrawal_g,
            )?;
        }

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
        let sc_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(scb_ft_tree_root | scb_btr_tree_root | wcert_tree_root | ledgerId)"),
            &[
                scb_ft_tree_root_g.clone(),
                csw_data_g.scb_btr_tree_root_g.clone(),
                csw_data_g.wcert_tree_root_g.clone(),
                sidechain_id_g.clone(),
            ],
        )?;

        // val sc_txs_com_tree_root = reconstruct_merkle_root_hash(sc_hash, merkle_path_to_scHash)
        let sc_txs_com_tree_root_g = csw_data_g.merkle_path_to_sc_hash_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(sc_hash, merkle_path_to_scHash)"),
            &sc_hash_g,
        )?;

        // var sc_txs_com_cumulative = mcb_sc_txs_com_start
        let mut sc_txs_com_cumulative_g = csw_data_g.mcb_sc_txs_com_start_g;

        // var cnt = 0
        let mut counter_g = FieldElementGadget::from_value(
            cs.ns(|| "alloc initial counter"),
            &FieldElement::from(0u8),
        );

        // Alloc phantom field element
        let phantom_g = FieldElementGadget::from_value(cs.ns(|| "Break"), &PHANTOM_FIELD_ELEMENT);

        // TODO: define CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER as creation parameter
        for i in 0..CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER {
            // if (sc_txs_com_tree_root == sc_txs_com_hashes[i]) { cnt++ }
            let should_increase_counter = sc_txs_com_tree_root_g.is_eq(
                cs.ns(|| format!("sc_txs_com_tree_root == sc_txs_com_hashes[{}]", i)),
                &csw_data_g.sc_txs_com_hashes_g[i],
            )?;

            // cnt++
            counter_g = counter_g.conditionally_add_constant(
                cs.ns(|| format!("cnt++ [{}]", i)),
                &should_increase_counter,
                FieldElement::one(),
            )?;

            // sc_txs_com_cumulative = H(sc_txs_com_cumulative, sc_txs_com_hashes[i])
            let temp_sc_txs_com_cumulative = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(sc_txs_com_cumulative, sc_txs_com_hashes[{}])", i)),
                &[
                    sc_txs_com_cumulative_g.clone(),
                    csw_data_g.sc_txs_com_hashes_g[i].clone(),
                ],
            )?;

            // Ignore NULL hashes
            let should_ignore_hash = csw_data_g.sc_txs_com_hashes_g[i].is_eq(
                cs.ns(|| format!("sc_txs_com_hashes[{}] == PHANTOM", i)),
                &phantom_g,
            )?;

            sc_txs_com_cumulative_g = FieldElementGadget::conditionally_select(
                cs.ns(|| format!("Conditionally select hash at iteration {}", i)),
                &should_ignore_hash,
                &sc_txs_com_cumulative_g,
                &temp_sc_txs_com_cumulative,
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

        // FT withdrawal [END]

        // The following and last section contains checks that has to be performed for both UTXO and FT withdrawal,
        // to avoid duplication of code we rely on a conditional select.

        // 2 Check nullifier
        // require(nullifier == outputHash) [for UTXO]
        // OR
        // require(nullifier == ft_input_hash) [for FT]
        let computed_nullifier_hash = FieldElementGadget::conditionally_select(
            cs.ns(|| "Conditionally select computed nullifier"),
            &should_enforce_utxo_withdrawal_g,
            &output_hash_g,
            &ft_input_hash_g,
        )?;

        computed_nullifier_hash.enforce_equal(
            cs.ns(|| "require(nullifier == outputHash)"),
            &csw_data_g.nullifier_g,
        )?;

        // 3 Check amount
        // require(input.output.amount == sys_data.amount)
        // or
        // require(ft_input.amount == sys_data.amount)
        let mut utxo_amount_big_endian_bits_g = csw_data_g.input_g.output_g.amount_g.to_bits_le();
        utxo_amount_big_endian_bits_g.reverse();

        let utxo_input_amount_g = FieldElementGadget::from_bits(
            cs.ns(|| "read utxo input amount"),
            &utxo_amount_big_endian_bits_g,
        )?;

        let mut ft_amount_big_endian_bits_g = csw_data_g.ft_input_g.amount_g.to_bits_le();
        ft_amount_big_endian_bits_g.reverse();

        let ft_input_amount_g = FieldElementGadget::from_bits(
            cs.ns(|| "read ft input amount"),
            &ft_amount_big_endian_bits_g,
        )?;

        let selected_input_amount_g = FieldElementGadget::conditionally_select(
            cs.ns(|| "select input amount"),
            &should_enforce_utxo_withdrawal_g,
            &utxo_input_amount_g,
            &ft_input_amount_g,
        )?;

        selected_input_amount_g.enforce_equal(
            cs.ns(|| "input.amount == sys_data.amount"),
            &csw_data_g.amount_g,
        )?;

        // Check secret key ownership
        let mut public_key_bits_g = Vec::<Boolean>::with_capacity(SIMULATED_FIELD_BYTE_SIZE * 8);

        // Conditionally select the public key
        // TODO: to save some constraints it would be possible to optmize the conditionally select
        // by reading the public key from FieldElements.
        for i in 0..SIMULATED_FIELD_BYTE_SIZE * 8 {
            let public_key_bit_g = Boolean::conditionally_select(
                cs.ns(|| format!("read public key bit {}", i)),
                &should_enforce_utxo_withdrawal_g,
                &csw_data_g.input_g.output_g.spending_pub_key_g[i],
                &csw_data_g.ft_input_g.receiver_pub_key_g[i],
            )?;
            public_key_bits_g.push(public_key_bit_g);
        }

        // Get the Boolean corresponding to the sign of the x coordinate
        let pk_x_sign_bit_g = public_key_bits_g[0];

        // Read a NonNativeFieldGadget(ed25519Fq) from the other Booleans
        let pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement> =
            NonNativeFieldGadget::from_bits(
                cs.ns(|| "alloc pk y coordinate"),
                &public_key_bits_g[1..],
            )?;

        let mut secret_key_bits_g =
            Vec::<Boolean>::with_capacity(SIMULATED_SCALAR_FIELD_MODULUS_BITS);

        // Conditionally select the secret key
        for i in 0..SIMULATED_SCALAR_FIELD_MODULUS_BITS {
            let secret_key_bit_g = Boolean::conditionally_select(
                cs.ns(|| format!("read secret key bit {}", i)),
                &should_enforce_utxo_withdrawal_g,
                &csw_data_g.input_g.secret_key_g[i],
                &csw_data_g.ft_input_secret_key_g[i],
            )?;
            secret_key_bits_g.push(secret_key_bit_g);
        }

        secret_key_bits_g.reverse();

        // Compute public key from secret key
        let current_public_key_g = ECPointSimulationGadget::mul_bits_fixed_base(
            &SimulatedGroup::prime_subgroup_generator().into_projective(),
            cs.ns(|| "G^sk"),
            &secret_key_bits_g,
        )?;

        let x_sign = current_public_key_g
            .x
            .is_odd(cs.ns(|| "public key x coordinate is odd"))?;

        // Enforce x_sign is the same
        x_sign.enforce_equal(
            cs.ns(|| "Enforce x_sign == pk_x_sign_bit_g"),
            &pk_x_sign_bit_g,
        )?;

        // Enforce y_coordinate is the same
        current_public_key_g.y.enforce_equal(
            cs.ns(|| "Enforce y coordinate is equal"),
            &pk_y_coordinate_g,
        )?;

        Ok(())
    }
}

// #[cfg(test)]
// mod test {
//     use algebra::{
//         fields::ed25519::fr::Fr as ed25519Fr, Group, ProjectiveCurve, ToBits, UniformRand,
//     };
//     use cctp_primitives::{
//         proving_system::init::{get_g1_committer_key, load_g1_committer_key},
//         type_mapping::{CoboundaryMarlin, FieldElement, GingerMHT, MC_PK_SIZE},
//         utils::{
//             commitment_tree::DataAccumulator, poseidon_hash::get_poseidon_hash_constant_length,
//         },
//     };
//     use primitives::{bytes_to_bits, FieldBasedHash, FieldBasedMerkleTree};
//     use r1cs_core::debug_circuit;
//     use rand::rngs::OsRng;
//     use std::{convert::TryInto, ops::AddAssign};

//     use crate::{
//         constants::constants::{BoxType, CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER},
//         read_field_element_from_buffer_with_padding, CswFtOutputData, CswProverData,
//         CswUtxoInputData, CswUtxoOutputData, GingerMHTBinaryPath, WithdrawalCertificateData,
//         MC_RETURN_ADDRESS_BYTES, MST_MERKLE_TREE_HEIGHT,
//     };

//     use super::*;

//     type SimulatedScalarFieldElement = ed25519Fr;

//     enum CswType {
//         UTXO,
//         FT,
//     }

//     fn generate_key_pair() -> (Vec<bool>, Vec<bool>) {
//         let rng = &mut OsRng::default();

//         // Generate the secret key
//         let secret = SimulatedScalarFieldElement::rand(rng);

//         // Compute GENERATOR^SECRET_KEY
//         let public_key = SimulatedGroup::prime_subgroup_generator()
//             .into_projective()
//             .mul(&secret)
//             .into_affine();

//         // Store the sign (last bit) of the X coordinate
//         let x_sign = if public_key.x.is_odd() { true } else { false };

//         // Extract the public key bytes as Y coordinate
//         let y_coordinate = public_key.y;

//         // Use the last (null) bit of the public key to store the sign of the X coordinate
//         // Before this operation, the last bit of the public key (Y coordinate) is always 0 due to the field modulus
//         let mut pk_bits = vec![x_sign];
//         pk_bits.append(&mut y_coordinate.write_bits());

//         let secret_bits = secret.write_bits();

//         (secret_bits, pk_bits)
//     }

//     fn compute_mst_tree_data(
//         utxo_input_data: CswUtxoInputData,
//     ) -> (FieldElement, FieldElement, GingerMHTBinaryPath) {
//         let mut mst = GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();

//         let mut mst_leaf_accumulator = DataAccumulator::init();
//         mst_leaf_accumulator
//             .update_with_bits(utxo_input_data.output.spending_pub_key.to_vec())
//             .unwrap();
//         mst_leaf_accumulator
//             .update(utxo_input_data.output.amount)
//             .unwrap();
//         mst_leaf_accumulator
//             .update(utxo_input_data.output.nonce)
//             .unwrap();
//         mst_leaf_accumulator
//             .update_with_bits(utxo_input_data.output.custom_hash.to_vec())
//             .unwrap();

//         let mut mst_leaf_inputs = mst_leaf_accumulator.get_field_elements().unwrap();
//         debug_assert_eq!(mst_leaf_inputs.len(), 3);
//         mst_leaf_inputs.push(FieldElement::from(BoxType::CoinBox as u8));

//         let mut poseidon_hash = get_poseidon_hash_constant_length(mst_leaf_inputs.len(), None);

//         mst_leaf_inputs.into_iter().for_each(|leaf_input| {
//             poseidon_hash.update(leaf_input);
//         });

//         let mst_leaf_hash = poseidon_hash.finalize().unwrap();

//         mst.append(mst_leaf_hash).unwrap();
//         mst.finalize_in_place().unwrap();

//         let mst_path: GingerMHTBinaryPath = mst.get_merkle_path(0).unwrap().try_into().unwrap();

//         let mst_root = mst.root().unwrap();

//         (mst_root, mst_leaf_hash, mst_path)
//     }

//     fn compute_cert_data(
//         custom_fields: Vec<FieldElement>,
//     ) -> (WithdrawalCertificateData, FieldElement) {
//         let cert_data = WithdrawalCertificateData {
//             ledger_id: FieldElement::from(1u8),
//             epoch_id: 2u32,
//             bt_root: FieldElement::from(3u8),
//             quality: 4u64,
//             mcb_sc_txs_com: FieldElement::from(5u8),
//             ft_min_amount: 6u64,
//             btr_min_fee: 7u64,
//             custom_fields: custom_fields,
//         };

//         let fees_field_elements = DataAccumulator::init()
//             .update(cert_data.btr_min_fee)
//             .unwrap()
//             .update(cert_data.ft_min_amount)
//             .unwrap()
//             .get_field_elements()
//             .unwrap();

//         debug_assert_eq!(fees_field_elements.len(), 1);

//         let temp_computed_last_wcert_hash = get_poseidon_hash_constant_length(6, None)
//             .update(cert_data.ledger_id)
//             .update(FieldElement::from(cert_data.epoch_id))
//             .update(cert_data.bt_root)
//             .update(FieldElement::from(cert_data.quality))
//             .update(cert_data.mcb_sc_txs_com)
//             .update(fees_field_elements[0])
//             .finalize()
//             .unwrap();

//         let mut poseidon_hash =
//             get_poseidon_hash_constant_length(cert_data.custom_fields.len(), None);

//         cert_data.custom_fields.iter().for_each(|custom_field| {
//             poseidon_hash.update(*custom_field);
//         });

//         let computed_custom_fields_hash = poseidon_hash.finalize().unwrap();

//         let computed_last_wcert_hash = if cert_data.custom_fields.is_empty() {
//             get_poseidon_hash_constant_length(1, None)
//                 .update(temp_computed_last_wcert_hash)
//                 .finalize()
//                 .unwrap()
//         } else {
//             get_poseidon_hash_constant_length(2, None)
//                 .update(computed_custom_fields_hash)
//                 .update(temp_computed_last_wcert_hash)
//                 .finalize()
//                 .unwrap()
//         };

//         (cert_data, computed_last_wcert_hash)
//     }

//     fn generate_test_utxo_csw_data(
//         num_custom_fields: usize,
//         secret_key_bits: Vec<bool>,
//         public_key_bits: Vec<bool>,
//     ) -> CswProverData {
//         let utxo_input_data = CswUtxoInputData {
//             output: CswUtxoOutputData {
//                 spending_pub_key: public_key_bits.try_into().unwrap(),
//                 amount: 10,
//                 nonce: 11,
//                 custom_hash: bytes_to_bits(&[12; FIELD_SIZE]).try_into().unwrap(),
//             },
//             secret_key: secret_key_bits.try_into().unwrap(),
//         };

//         let (mst_root, mst_leaf_hash, mst_path) = compute_mst_tree_data(utxo_input_data.clone());

//         // To generate valid test data we need at least one custom field to store the MST root
//         debug_assert!(num_custom_fields > 0);
//         let mut custom_fields = vec![mst_root];

//         for _ in 0..num_custom_fields - 1 {
//             custom_fields.push(PHANTOM_FIELD_ELEMENT);
//         }

//         let (cert_data, last_wcert_hash) = compute_cert_data(custom_fields);

//         let csw_prover_data = CswProverData {
//             genesis_constant: FieldElement::from(14u8),
//             mcb_sc_txs_com_end: FieldElement::from(15u8),
//             sc_last_wcert_hash: last_wcert_hash,
//             amount: FieldElement::from(utxo_input_data.output.amount),
//             nullifier: mst_leaf_hash,
//             receiver: read_field_element_from_buffer_with_padding(&[0; MC_PK_SIZE]).unwrap(),
//             last_wcert: cert_data,
//             input: utxo_input_data.clone(),
//             mst_path_to_output: mst_path,
//             ft_input: CswFtOutputData::default(),
//             ft_input_secret_key: [false; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
//             mcb_sc_txs_com_start: PHANTOM_FIELD_ELEMENT,
//             merkle_path_to_sc_hash: GingerMHTBinaryPath::default(),
//             ft_tree_path: GingerMHTBinaryPath::default(),
//             scb_btr_tree_root: PHANTOM_FIELD_ELEMENT,
//             wcert_tree_root: PHANTOM_FIELD_ELEMENT,
//             sc_txs_com_hashes: vec![
//                 PHANTOM_FIELD_ELEMENT;
//                 CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER
//             ],
//         };

//         csw_prover_data
//     }

//     fn generate_ft_tree_data(
//         ft_input_data: CswFtOutputData,
//     ) -> (FieldElement, GingerMHTBinaryPath, FieldElement) {
//         let mut ft_input_hash_accumulator = DataAccumulator::init();
//         ft_input_hash_accumulator
//             .update(ft_input_data.amount)
//             .unwrap();
//         ft_input_hash_accumulator
//             .update_with_bits(ft_input_data.receiver_pub_key.to_vec())
//             .unwrap();
//         ft_input_hash_accumulator
//             .update_with_bits(ft_input_data.payback_addr_data_hash.to_vec())
//             .unwrap();
//         ft_input_hash_accumulator
//             .update_with_bits(ft_input_data.tx_hash.to_vec())
//             .unwrap();
//         ft_input_hash_accumulator
//             .update(ft_input_data.out_idx)
//             .unwrap();

//         let ft_input_hash_elements = ft_input_hash_accumulator.get_field_elements().unwrap();

//         let mut poseidon_hash =
//             get_poseidon_hash_constant_length(ft_input_hash_elements.len(), None);
//         ft_input_hash_elements.into_iter().for_each(|leaf_input| {
//             poseidon_hash.update(leaf_input);
//         });

//         let ft_input_hash = poseidon_hash.finalize().unwrap();

//         // TODO: set a proper height for the FT tree
//         let mut ft_tree =
//             GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
//         ft_tree.append(ft_input_hash).unwrap();
//         ft_tree.finalize_in_place().unwrap();

//         let ft_tree_path = ft_tree.get_merkle_path(0).unwrap().try_into().unwrap();
//         let ft_tree_root = ft_tree.root().unwrap();

//         (ft_input_hash, ft_tree_path, ft_tree_root)
//     }

//     fn generate_test_ft_csw_data(
//         sidechain_id: FieldElement,
//         num_custom_fields: usize,
//         secret_key_bits: Vec<bool>,
//         public_key_bits: Vec<bool>,
//     ) -> CswProverData {
//         let ft_input_data = CswFtOutputData {
//             amount: 100,
//             receiver_pub_key: public_key_bits.try_into().unwrap(),
//             payback_addr_data_hash: bytes_to_bits(&[101; MC_RETURN_ADDRESS_BYTES])
//                 .try_into()
//                 .unwrap(),
//             tx_hash: bytes_to_bits(&[102; FIELD_SIZE]).try_into().unwrap(),
//             out_idx: 103,
//         };

//         let (ft_input_hash, ft_tree_path, ft_tree_root) =
//             generate_ft_tree_data(ft_input_data.clone());

//         let scb_btr_tree_root = FieldElement::from(22u8);
//         let wcert_tree_root = FieldElement::from(23u8);

//         let sc_hash = get_poseidon_hash_constant_length(4, None)
//             .update(ft_tree_root)
//             .update(scb_btr_tree_root)
//             .update(wcert_tree_root)
//             .update(sidechain_id)
//             .finalize()
//             .unwrap();

//         // TODO: set a proper height for the SC tree
//         let mut sc_tree =
//             GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
//         sc_tree.append(sc_hash).unwrap();
//         sc_tree.finalize_in_place().unwrap();

//         let sc_tree_path = sc_tree.get_merkle_path(0).unwrap().try_into().unwrap();
//         let sc_tree_root = sc_tree.root().unwrap();

//         let mut csw_prover_data = CswProverData {
//             genesis_constant: PHANTOM_FIELD_ELEMENT,
//             mcb_sc_txs_com_end: PHANTOM_FIELD_ELEMENT,
//             sc_last_wcert_hash: PHANTOM_FIELD_ELEMENT,
//             amount: FieldElement::from(ft_input_data.amount),
//             nullifier: ft_input_hash,
//             receiver: read_field_element_from_buffer_with_padding(&[0; MC_PK_SIZE]).unwrap(),
//             last_wcert: WithdrawalCertificateData::get_phantom_data(num_custom_fields),
//             input: CswUtxoInputData::default(),
//             mst_path_to_output: GingerMHTBinaryPath::default(),
//             ft_input: ft_input_data,
//             ft_input_secret_key: secret_key_bits.try_into().unwrap(),
//             mcb_sc_txs_com_start: FieldElement::from(21u8),
//             merkle_path_to_sc_hash: sc_tree_path,
//             ft_tree_path: ft_tree_path,
//             scb_btr_tree_root: scb_btr_tree_root,
//             wcert_tree_root: wcert_tree_root,
//             sc_txs_com_hashes: vec![
//                 PHANTOM_FIELD_ELEMENT;
//                 CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER
//             ],
//         };

//         csw_prover_data.sc_txs_com_hashes[0] = sc_tree_root;

//         let mut mcb_sc_txs_com_end = csw_prover_data.mcb_sc_txs_com_start;

//         csw_prover_data
//             .sc_txs_com_hashes
//             .iter()
//             .for_each(|sc_txs_com_hash| {
//                 if !sc_txs_com_hash.eq(&PHANTOM_FIELD_ELEMENT) {
//                     mcb_sc_txs_com_end = get_poseidon_hash_constant_length(2, None)
//                         .update(mcb_sc_txs_com_end)
//                         .update(*sc_txs_com_hash)
//                         .finalize()
//                         .unwrap();
//                 }
//             });

//         csw_prover_data.mcb_sc_txs_com_end = mcb_sc_txs_com_end;

//         csw_prover_data
//     }

//     fn generate_test_csw_prover_data(
//         csw_type: CswType,
//         sidechain_id: FieldElement,
//         num_custom_fields: usize,
//     ) -> CswProverData {
//         let (secret_key, public_key) = generate_key_pair();

//         match csw_type {
//             CswType::UTXO => generate_test_utxo_csw_data(num_custom_fields, secret_key, public_key),
//             CswType::FT => {
//                 generate_test_ft_csw_data(sidechain_id, num_custom_fields, secret_key, public_key)
//             }
//         }
//     }

//     fn test_csw_circuit(csw_type: CswType) {
//         let sidechain_id = FieldElement::from(77u8);
//         let num_custom_fields = 1;
//         let csw_prover_data =
//             generate_test_csw_prover_data(csw_type, sidechain_id, num_custom_fields);
//         let circuit = CeasedSidechainWithdrawalCircuit::new(
//             sidechain_id,
//             num_custom_fields,
//             csw_prover_data.clone(),
//         );

//         let failing_constraint = debug_circuit(circuit.clone()).unwrap();
//         println!("Failing constraint: {:?}", failing_constraint);
//         assert!(failing_constraint.is_none());

//         load_g1_committer_key(1 << 17, 1 << 15).unwrap();
//         let ck_g1 = get_g1_committer_key().unwrap();
//         let params = CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circuit.clone()).unwrap();

//         let proof = CoboundaryMarlin::prove(
//             &params.0.clone(),
//             ck_g1.as_ref().unwrap(),
//             circuit,
//             false,
//             None,
//         )
//         .unwrap();

//         let mut public_inputs = vec![
//             csw_prover_data.genesis_constant,
//             csw_prover_data.mcb_sc_txs_com_end,
//             csw_prover_data.sc_last_wcert_hash,
//             FieldElement::from(csw_prover_data.amount),
//             csw_prover_data.nullifier,
//             csw_prover_data.receiver,
//         ];

//         // Check that the proof gets correctly verified
//         assert!(CoboundaryMarlin::verify(
//             &params.1.clone(),
//             ck_g1.as_ref().unwrap(),
//             public_inputs.as_slice(),
//             &proof
//         )
//         .unwrap());

//         // Change one public input and check that the proof fails
//         public_inputs[0].add_assign(&FieldElement::from(1u8));
//         assert!(!CoboundaryMarlin::verify(
//             &params.1.clone(),
//             ck_g1.as_ref().unwrap(),
//             public_inputs.as_slice(),
//             &proof
//         )
//         .unwrap());
//     }

//     #[test]
//     fn test_csw_circuit_utxo() {
//         test_csw_circuit(CswType::UTXO);
//     }

//     #[test]
//     fn test_csw_circuit_ft() {
//         test_csw_circuit(CswType::FT);
//     }
// }
