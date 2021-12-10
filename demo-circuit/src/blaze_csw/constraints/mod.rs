use std::convert::TryInto;

use algebra::AffineCurve;
use cctp_primitives::type_mapping::FieldElement;
use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::FieldHasherGadget;
use r1cs_std::{
    alloc::AllocGadget,
    boolean::Boolean,
    fields::nonnative::nonnative_field_gadget::NonNativeFieldGadget,
    groups::GroupGadget,
    prelude::EqGadget,
    select::CondSelectGadget,
    FromBitsGadget,
};

use crate::{
    type_mapping::*,
    CswFtProverData, CswProverData, CswSysData, CswUtxoProverData, FieldElementGadget,
    WithdrawalCertificateData,
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

    /// Enforce 'secret_key_bits_g' are indeed the ones behind 'public_key_bits_g'.
    fn enforce_pk_ownership<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        secret_key_bits_g: &[Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
        public_key_bits_g: &[Boolean; SIMULATED_FIELD_BYTE_SIZE]
    ) -> Result<(), SynthesisError> {

        // Get the Boolean corresponding to the sign of the x coordinate
        let pk_x_sign_bit_g = public_key_bits_g[0];

        // Read a NonNativeFieldGadget(ed25519Fq) from the other Booleans
        let pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement> =
            NonNativeFieldGadget::from_bits(
                cs.ns(|| "alloc pk y coordinate"),
                &public_key_bits_g[1..],
            )?;

        // Compute public key from secret key
        let current_public_key_g = ECPointSimulationGadget::mul_bits_fixed_base(
            &SimulatedGroup::prime_subgroup_generator().into_projective(),
            cs.ns(|| "G^sk"),
            secret_key_bits_g,
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

impl ConstraintSynthesizer<FieldElement> for CeasedSidechainWithdrawalCircuit {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Alloc sidechain id
        let sidechain_id_g = FieldElementGadget::alloc(
            cs.ns(|| "alloc sidechain_id_g"),
            || Ok(&self.sidechain_id)
        )?;

        // Alloc all witness data
        let csw_data_g = CswProverDataGadget::alloc(
            cs.ns(|| "alloc csw data"),
            || Ok(&self.csw_data),
        )?;

        // Decide whether to enforce utxo or ft withdrawal
        let should_enforce_utxo_withdrawal_g = csw_data_g
            .utxo_data_g
            .input_g
            .is_phantom(cs.ns(|| "should_enforce_utxo_withdrawal"))?
            .not();

        let should_enforce_ft_withdrawal_g = csw_data_g
            .ft_data_g
            .ft_output_g
            .is_phantom(cs.ns(|| "should_enforce_ft_withdrawal"))?
            .not();

        
        //TODO: Are these needed ?
        {
            // enforce that the CSW if for either UTXO or FT
            // and that exactly one of the two is not NULL
            let utxo_xor_ft_withdrawal_g = Boolean::xor(
                cs.ns(|| "(input != NULL) XOR (ft_input != NULL)"),
                &should_enforce_utxo_withdrawal_g,
                &should_enforce_ft_withdrawal_g,
            )?;

            utxo_xor_ft_withdrawal_g.enforce_equal(
                cs.ns(|| "enforce that the CSW if for either UTXO or FT"),
                &Boolean::Constant(true),
            )?;
        }

        let should_enforce_wcert_hash = csw_data_g.last_wcert_g
            .is_phantom(
                cs.ns(|| "should_enforce_wcert_hash"),
                self.num_custom_fields,
            )?
            .not();

        // if last_wcert != NULL
        // enforce(sys_data.sc_last_wcert_hash == H(last_wcert))
        
        let last_wcert_hash_g = csw_data_g.last_wcert_g.enforce_hash(
            cs.ns(|| "enforce last_wcert_hash"),
            None
        )?;

        last_wcert_hash_g.conditional_enforce_equal(
            cs.ns(|| "enforce sc_last_wcert_hash == last_wcert_hash"),
            &csw_data_g.sys_data_g.sc_last_wcert_hash_g.clone(),
            &should_enforce_wcert_hash,
        )?;

        // Enforce UTXO widthdrawal if required

        if !csw_data_g.last_wcert_g.custom_fields_g.is_empty() {

            assert_eq!(csw_data_g.last_wcert_g.custom_fields_g.len(), 2);

            // Reconstruct scb_new_mst_root from custom fields
            let scb_new_mst_root = {
                let mut first_half = (&csw_data_g)
                    .last_wcert_g
                    .custom_fields_g[0]
                    .to_bits_with_length_restriction(
                        cs.ns(|| "first custom field half to bits"),
                        8 * (FIELD_SIZE - FIELD_SIZE/2)
                    )?;

                let mut second_half = (&csw_data_g)
                    .last_wcert_g
                    .custom_fields_g[1]
                    .to_bits_with_length_restriction(
                        cs.ns(|| "first custom field half to bits"),
                        8 * (FIELD_SIZE - FIELD_SIZE/2)
                    )?;
                
                first_half.append(&mut second_half);

                // TODO: This won't work as from_bits gadget pack until CAPACITY but,
                //       most likely, since it's a hash, this will have full modulus
                //       bit length. We need another from_bits variant that packs up until
                //      modulus bits.
                //     @PaoloT: Comment this piece and restore one custom fields if you want to test/debug
                //              in the mean time. 
                FieldElementGadget::from_bits(
                    cs.ns(|| "read scb_new_mst_root from bits"),
                    first_half.as_slice()
                )
            }?;

            csw_data_g.utxo_data_g.conditionally_enforce_utxo_withdrawal(
                cs.ns(|| "enforce utxo withdrawal"),
                &scb_new_mst_root,
                &csw_data_g.sys_data_g.nullifier_g,
                &csw_data_g.sys_data_g.amount_g,
                &should_enforce_utxo_withdrawal_g,
            )?;
        }

        // Enforce FT withdrawal if required

        csw_data_g.ft_data_g.conditionally_enforce_ft_withdrawal(
            cs.ns(|| "conditionally enforce ft withdrawal"),
            &sidechain_id_g,
            self.range_size,
            &csw_data_g.sys_data_g.mcb_sc_txs_com_end_g,
            &csw_data_g.sys_data_g.nullifier_g,
            &csw_data_g.sys_data_g.amount_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // We check the public key ownership just once for both, choosing the appropriate public key
        // and secret key, as it is an expensive check, we want to do it just once.
        // NOTE: We could've done the same for nullifier and amount checks, but we didn't in order
        //       to have cleaner code (we lose only 2 constraints anyway)

        // Check secret key ownership
        let mut public_key_bits_g = Vec::<Boolean>::with_capacity(SIMULATED_FIELD_BYTE_SIZE * 8);

        // Conditionally select the public key
        // TODO: to save some constraints it would be possible to optmize the conditionally select
        // by reading the public key from FieldElements.
        for i in 0..SIMULATED_FIELD_BYTE_SIZE * 8 {
            let public_key_bit_g = Boolean::conditionally_select(
                cs.ns(|| format!("read public key bit {}", i)),
                &should_enforce_utxo_withdrawal_g,
                &csw_data_g.utxo_data_g.input_g.output_g.spending_pub_key_g[i],
                &csw_data_g.ft_data_g.ft_output_g.receiver_pub_key_g[i],
            )?;
            public_key_bits_g.push(public_key_bit_g);
        }

        let mut secret_key_bits_g =
            Vec::<Boolean>::with_capacity(SIMULATED_SCALAR_FIELD_MODULUS_BITS);

        // Conditionally select the secret key
        for i in 0..SIMULATED_SCALAR_FIELD_MODULUS_BITS {
            let secret_key_bit_g = Boolean::conditionally_select(
                cs.ns(|| format!("read secret key bit {}", i)),
                &should_enforce_utxo_withdrawal_g,
                &csw_data_g.utxo_data_g.input_g.secret_key_g[i],
                &csw_data_g.ft_data_g.ft_input_secret_key_g[i],
            )?;
            secret_key_bits_g.push(secret_key_bit_g);
        }

        secret_key_bits_g.reverse();

        // Enforce pk ownership
        Self::enforce_pk_ownership(
            cs.ns(|| "enforce pk ownership"),
            secret_key_bits_g.as_slice().try_into().unwrap(),
            public_key_bits_g.as_slice().try_into().unwrap()
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

//         let sys_data = CswSysData {
//             genesis_constant: FieldElement::from(14u8),
//             mcb_sc_txs_com_end: FieldElement::from(15u8),
//             sc_last_wcert_hash: last_wcert_hash,
//             amount: FieldElement::from(utxo_input_data.output.amount),
//             nullifier: mst_leaf_hash,
//             receiver: read_field_element_from_buffer_with_padding(&[0; MC_PK_SIZE]).unwrap(),
//         };

//         let utxo_data = CswUtxoProverData {
//             input: utxo_input_data.clone(),
//             mst_path_to_output: mst_path,
//         };

//         let ft_data = CswFtProverData {
//             ft_output: CswFtOutputData::default(),
//             ft_input_secret_key: [false; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
//             mcb_sc_txs_com_start: PHANTOM_FIELD_ELEMENT,
//             merkle_path_to_sc_hash: GingerMHTBinaryPath::default(),
//             ft_tree_path: GingerMHTBinaryPath::default(),
//             sc_creation_commitment: PHANTOM_FIELD_ELEMENT,
//             scb_btr_tree_root: PHANTOM_FIELD_ELEMENT,
//             wcert_tree_root: PHANTOM_FIELD_ELEMENT,
//             sc_txs_com_hashes: vec![
//                 PHANTOM_FIELD_ELEMENT;
//                 CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER
//             ],
//         };

//         let csw_prover_data = CswProverData {
//             sys_data,
//             last_wcert: cert_data,
//             utxo_data,
//             ft_data,
//         };

//         csw_prover_data
//     }

//     fn generate_ft_tree_data(
//         ft_input_data: CswFtOutputData,
//     ) -> (FieldElement, GingerMHTBinaryPath, FieldElement) {
//         let mut ft_output_hash_accumulator = DataAccumulator::init();
//         ft_output_hash_accumulator
//             .update(ft_input_data.amount)
//             .unwrap();
//         ft_output_hash_accumulator
//             .update_with_bits(ft_input_data.receiver_pub_key.to_vec())
//             .unwrap();
//         ft_output_hash_accumulator
//             .update_with_bits(ft_input_data.payback_addr_data_hash.to_vec())
//             .unwrap();
//         ft_output_hash_accumulator
//             .update_with_bits(ft_input_data.tx_hash.to_vec())
//             .unwrap();
//         ft_output_hash_accumulator
//             .update(ft_input_data.out_idx)
//             .unwrap();

//         let ft_output_hash_elements = ft_output_hash_accumulator.get_field_elements().unwrap();

//         let mut poseidon_hash =
//             get_poseidon_hash_constant_length(ft_output_hash_elements.len(), None);
//         ft_output_hash_elements.into_iter().for_each(|leaf_input| {
//             poseidon_hash.update(leaf_input);
//         });

//         let ft_output_hash = poseidon_hash.finalize().unwrap();

//         // TODO: set a proper height for the FT tree
//         let mut ft_tree =
//             GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
//         ft_tree.append(ft_output_hash).unwrap();
//         ft_tree.finalize_in_place().unwrap();

//         let ft_tree_path = ft_tree.get_merkle_path(0).unwrap().try_into().unwrap();
//         let ft_tree_root = ft_tree.root().unwrap();

//         (ft_output_hash, ft_tree_path, ft_tree_root)
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

//         let (ft_output_hash, ft_tree_path, ft_tree_root) =
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
//             nullifier: ft_output_hash,
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
