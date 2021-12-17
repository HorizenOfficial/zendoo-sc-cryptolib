use algebra::{AffineCurve, PrimeField};
use cctp_primitives::{
    type_mapping::FieldElement,
    utils::commitment_tree::{hash_vec, DataAccumulator},
};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldHasherGadget};
use r1cs_std::{
    alloc::AllocGadget, boolean::Boolean,
    fields::nonnative::nonnative_field_gadget::NonNativeFieldGadget, groups::GroupGadget,
    prelude::EqGadget, select::CondSelectGadget, FromBitsGadget,
};

use crate::{
    type_mapping::*, CswFtProverData, CswProverData, CswSysData, CswUtxoProverData,
    FieldElementGadget, WithdrawalCertificateData, PHANTOM_FIELD_ELEMENT,
};

use self::data_structures::CswProverDataGadget;

pub mod data_structures;

#[derive(Clone)]
pub struct CeasedSidechainWithdrawalCircuit {
    // Setup params
    range_size: u32,
    num_custom_fields: u32,

    // Witnesses
    sidechain_id: FieldElement,
    csw_data: CswProverData,

    // Public inputs
    constant: Option<FieldElement>,
    csw_sys_data_hash: FieldElement,
}

impl CeasedSidechainWithdrawalCircuit {
    fn compute_csw_sys_data_hash(
        sys_data: &CswSysData,
        sidechain_id: FieldElement,
    ) -> Result<FieldElement, Error> {
        let mut sys_data_hash_inputs = DataAccumulator::init()
            .update(sys_data.amount)?
            .update(&sys_data.receiver[..])?
            .get_field_elements()?;

        debug_assert!(sys_data_hash_inputs.len() == 1);

        sys_data_hash_inputs.extend_from_slice(&[
            sidechain_id,
            sys_data.nullifier,
            sys_data.sc_last_wcert_hash,
            sys_data.mcb_sc_txs_com_end,
        ]);

        hash_vec(sys_data_hash_inputs)
    }

    pub fn new(
        sidechain_id: FieldElement,
        constant: Option<FieldElement>,
        sys_data: CswSysData,
        last_wcert: Option<WithdrawalCertificateData>,
        utxo_data: Option<CswUtxoProverData>,
        ft_data: Option<CswFtProverData>,
        range_size: u32,
        num_custom_fields: u32,
    ) -> Result<Self, Error> {
        // Compute csw sys_data hash
        let csw_sys_data_hash = Self::compute_csw_sys_data_hash(&sys_data, sidechain_id)?;

        // Handle all cases
        let csw_data = match (last_wcert, utxo_data, ft_data) {
            // SC Utxo withdraw
            (Some(last_wcert), Some(utxo_data), None) => Ok(CswProverData {
                sys_data,
                last_wcert,
                utxo_data,
                ft_data: CswFtProverData::get_phantom(range_size),
            }),
            // FT withdraw, with last_wcert present
            (Some(last_wcert), None, Some(ft_data)) => Ok(CswProverData {
                sys_data,
                last_wcert,
                utxo_data: CswUtxoProverData::default(),
                ft_data,
            }),
            // FT withdraw, with last_wcert not present
            (None, None, Some(ft_data)) => Ok(CswProverData {
                sys_data,
                last_wcert: WithdrawalCertificateData::get_phantom(num_custom_fields),
                utxo_data: CswUtxoProverData::default(),
                ft_data,
            }),
            // Attempt to withdraw a sc utxo without having specified a last_wcert
            (None, Some(_), _) => Err(Error::from(
                "Attempt to withdraw SC Utxo without specifying last WCert",
            )),
            // Attempt to withdraw both a sc utxo and a ft
            (_, Some(_), Some(_)) => Err(Error::from(
                "Cannot create a CSW proof for retrieving both a SC UTXO and a FT",
            )),
            // Any other combination is not admissable
            _ => Err(Error::from("Unexpected inputs combination")),
        }?;

        Ok(Self {
            range_size,
            num_custom_fields,
            sidechain_id,
            csw_data,
            constant,
            csw_sys_data_hash,
        })
    }

    // For testing, if useful
    pub fn from_prover_data(
        sidechain_id: FieldElement,
        constant: Option<FieldElement>,
        csw_data: CswProverData,
        range_size: u32,
        num_custom_fields: u32,
    ) -> Result<Self, Error> {
        let csw_sys_data_hash = Self::compute_csw_sys_data_hash(&csw_data.sys_data, sidechain_id)?;

        Ok(CeasedSidechainWithdrawalCircuit {
            sidechain_id,
            csw_data,
            range_size,
            num_custom_fields,
            constant,
            csw_sys_data_hash,
        })
    }

    pub fn get_instance_for_setup(
        range_size: u32,
        num_custom_fields: u32,
        is_constant_present: bool,
    ) -> Self {
        Self {
            range_size,
            num_custom_fields,
            sidechain_id: PHANTOM_FIELD_ELEMENT,
            csw_data: CswProverData::get_phantom(range_size, num_custom_fields),
            constant: if is_constant_present {
                Some(PHANTOM_FIELD_ELEMENT)
            } else {
                None
            },
            csw_sys_data_hash: PHANTOM_FIELD_ELEMENT,
        }
    }

    /// Extract the sign of the x coordinate and the y coordinate itself from
    /// 'public_key_bits_g', assuming to be passed in BE form.
    fn get_x_sign_and_y_coord_from_pk_bits<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        public_key_bits_g: &[Boolean; SIMULATED_FIELD_BYTE_SIZE * 8],
    ) -> Result<
        (
            Boolean,
            NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
        ),
        SynthesisError,
    > {
        // Get the Boolean corresponding to the sign of the x coordinate
        let pk_x_sign_bit_g = public_key_bits_g[0];

        // Read a NonNativeFieldGadget(ed25519Fq) from the other Booleans
        let pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement> =
            NonNativeFieldGadget::from_bits(
                cs.ns(|| "alloc pk y coordinate"),
                &public_key_bits_g[1..],
            )?;

        Ok((pk_x_sign_bit_g, pk_y_coordinate_g))
    }

    /// Enforce ownership of the public key in the Sc Utxo/FT by enforcing its derivation from the secret key.
    fn enforce_pk_ownership<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        csw_data_g: &CswProverDataGadget,
        should_enforce_utxo_withdrawal_g: &Boolean,
    ) -> Result<(), SynthesisError> {
        // Get public_key_y_coord and x sign from both sc utxo and ft and select the correct one
        let (pk_x_sign_bit_g, pk_y_coordinate_g) = {
            let (utxo_pk_x_sign_bit_g, utxo_pk_y_coordinate_g) =
                Self::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "unpack utxo pk bits"),
                    &csw_data_g.utxo_data_g.input_g.output_g.spending_pub_key_g,
                )?;

            let (ft_pk_x_sign_bit_g, ft_pk_y_coordinate_g) =
                Self::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "unpack ft pk bits"),
                    &csw_data_g.ft_data_g.ft_output_g.receiver_pub_key_g,
                )?;

            let selected_pk_x_sign_bit_g = Boolean::conditionally_select(
                cs.ns(|| "select x sign bit"),
                &should_enforce_utxo_withdrawal_g,
                &utxo_pk_x_sign_bit_g,
                &ft_pk_x_sign_bit_g,
            )?;

            let selected_pk_y_coordinate_g = NonNativeFieldGadget::conditionally_select(
                cs.ns(|| "select pk_y_coordinate_g"),
                &should_enforce_utxo_withdrawal_g,
                &utxo_pk_y_coordinate_g,
                &ft_pk_y_coordinate_g,
            )?;

            (selected_pk_x_sign_bit_g, selected_pk_y_coordinate_g)
        };

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

        // We assume secret key bits to be in Big Endian form. TODO: Check endianness
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

impl ConstraintSynthesizer<FieldElement> for CeasedSidechainWithdrawalCircuit {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Alloc sidechain id
        let sidechain_id_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc sidechain_id_g"), || Ok(&self.sidechain_id))?;

        // Alloc all witness data
        let csw_data_g =
            CswProverDataGadget::alloc(cs.ns(|| "alloc csw data"), || Ok(&self.csw_data))?;

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

        let should_enforce_wcert_hash = csw_data_g
            .last_wcert_g
            .is_phantom(
                cs.ns(|| "should_enforce_wcert_hash"),
                self.num_custom_fields,
            )?
            .not();

        // if last_wcert != NULL
        // enforce(sys_data.sc_last_wcert_hash == H(last_wcert))
        let last_wcert_hash_g = csw_data_g
            .last_wcert_g
            .enforce_hash(cs.ns(|| "enforce last_wcert_hash"), None)?;

        last_wcert_hash_g.conditional_enforce_equal(
            cs.ns(|| "enforce sc_last_wcert_hash == last_wcert_hash"),
            &csw_data_g.sys_data_g.sc_last_wcert_hash_g,
            &should_enforce_wcert_hash,
        )?;

        // Enforce UTXO widthdrawal if required

        if !csw_data_g.last_wcert_g.custom_fields_g.is_empty() {
            // We use two custom fields (with half of the bits set) to store a single Field Element
            assert_eq!(
                csw_data_g.last_wcert_g.custom_fields_g.len(),
                self.num_custom_fields as usize
            );
            assert!(self.num_custom_fields >= 2);

            // Reconstruct scb_new_mst_root from firt 2 custom fields
            let scb_new_mst_root = {
                use algebra::Field;
                use r1cs_std::fields::FieldGadget;

                // Compute 2^128 in the field
                let pow = FieldElement::one().double().pow(&[128u64]);

                // Combine the two custom fields as custom_fields[0] + (2^128) * custom_fields[1]
                // We assume here that the 2 FieldElements were originally truncated at the 128th bit .
                // Note that the prover is able to find multiple custom_fields[0], custom_fields[1]
                // leading to the same result but this will change the certificate hash, binded to
                // the sys_data_hash public input, for which he would need to find a collision,
                // and this is unfeasible.
                let first_half = &csw_data_g.last_wcert_g.custom_fields_g[0];
                let second_half = csw_data_g.last_wcert_g.custom_fields_g[1]
                    .mul_by_constant(cs.ns(|| "2^128 * custom_fields[1]"), &pow)?;

                first_half.add(
                    cs.ns(|| "custom_fields[0] + (2^128) * custom_fields[1]"),
                    &second_half,
                )
            }?;

            csw_data_g
                .utxo_data_g
                .conditionally_enforce_utxo_withdrawal(
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

        Self::enforce_pk_ownership(
            cs.ns(|| "enforce pk ownership"),
            &csw_data_g,
            &should_enforce_utxo_withdrawal_g,
        )?;

        // Let's build up the public inputs

        // Allocate constant as public input if needed and don't use it
        if self.constant.is_some() {
            let _ = FieldElementGadget::alloc_input(cs.ns(|| "alloc constant as input"), || {
                Ok(self.constant.unwrap())
            })?;
        }

        // Deserialize a FieldElement out of amount_g and receiver_g
        let amount_and_receiver_fe_g = {
            let mut amount_and_receiver_bits_g = csw_data_g
                .sys_data_g
                .amount_g
                .to_bits_with_length_restriction(
                    cs.ns(|| "amount to bits"),
                    FieldElement::size_in_bits() - 64,
                )?;

            let mut receiver_g_bits = csw_data_g.sys_data_g.receiver_g;
            receiver_g_bits.reverse();

            amount_and_receiver_bits_g.extend_from_slice(&receiver_g_bits[..]);

            FieldElementGadget::from_bits(
                cs.ns(|| "read field element out of amount and bits"),
                amount_and_receiver_bits_g.as_slice(),
            )
        }?;

        // Enforce sys_data_hash computation
        let sys_data_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "compute sys data hash"),
            &[
                amount_and_receiver_fe_g,
                sidechain_id_g,
                csw_data_g.sys_data_g.nullifier_g.clone(),
                csw_data_g.sys_data_g.sc_last_wcert_hash_g.clone(),
                csw_data_g.sys_data_g.mcb_sc_txs_com_end_g,
            ],
        )?;

        // Alloc it as public input
        let expected_sys_data_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc input sys_data_hash_g"), || {
                Ok(self.csw_sys_data_hash)
            })?;

        // Enforce equality
        expected_sys_data_hash_g.enforce_equal(
            cs.ns(|| "expected_sys_data_hash == actual_sys_data_hash"),
            &sys_data_hash_g,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        fields::ed25519::fr::Fr as ed25519Fr, Field, Group, ProjectiveCurve,
        UniformRand,
    };
    use cctp_primitives::{
        commitment_tree::{
            hashers::{hash_cert, hash_fwt},
            sidechain_tree_alive::FWT_MT_HEIGHT,
            CMT_MT_HEIGHT,
        },
        proving_system::init::{get_g1_committer_key, load_g1_committer_key},
        type_mapping::{CoboundaryMarlin, FieldElement, GingerMHT, MC_PK_SIZE},
        utils::{
            get_bt_merkle_root, poseidon_hash::get_poseidon_hash_constant_length,
            serialization::serialize_to_buffer,
        },
    };
    use primitives::{bytes_to_bits, FieldBasedHash, FieldBasedMerkleTree, FieldHasher};
    use r1cs_core::debug_circuit;
    use rand::{rngs::OsRng, thread_rng, Rng};
    use std::convert::TryInto;

    use crate::{
        utils::split_field_element_at_index, CswFtOutputData, CswProverData, CswUtxoInputData,
        CswUtxoOutputData, GingerMHTBinaryPath, WithdrawalCertificateData, MC_RETURN_ADDRESS_BYTES,
        MST_MERKLE_TREE_HEIGHT, PHANTOM_FIELD_ELEMENT, SC_TX_HASH_LENGTH,
    };

    use super::*;

    type SimulatedScalarFieldElement = ed25519Fr;

    enum CswType {
        UTXO,
        FT,
    }

    fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
        let rng = &mut OsRng::default();

        // Generate the secret key
        let secret = SimulatedScalarFieldElement::rand(rng);

        // Compute GENERATOR^SECRET_KEY
        let public_key = SimulatedGroup::prime_subgroup_generator()
            .into_projective()
            .mul(&secret)
            .into_affine();

        // Store the sign (last bit) of the X coordinate
        // The value is left-shifted to be used later in an OR operation
        let x_sign = if public_key.x.is_odd() { 1 << 7 } else { 0u8 };

        // Extract the public key bytes as Y coordinate
        let y_coordinate = public_key.y;
        let mut pk_bytes = serialize_to_buffer(&y_coordinate, None).unwrap();

        // Use the last (null) bit of the public key to store the sign of the X coordinate
        // Before this operation, the last bit of the public key (Y coordinate) is always 0 due to the field modulus
        let len = pk_bytes.len();
        pk_bytes[len - 1] |= x_sign;

        // Reverse each pk byte
        for i in 0..pk_bytes.len() {
            pk_bytes[i] = pk_bytes[i].reverse_bits();
        }

        pk_bytes.reverse();

        let mut secret_bytes = serialize_to_buffer(&secret, None).unwrap();

        // Reverse each sk byte
        for i in 0..secret_bytes.len() {
            secret_bytes[i] = secret_bytes[i].reverse_bits();
        }

        secret_bytes.reverse();

        (secret_bytes, pk_bytes)
    }

    fn compute_mst_tree_data(
        utxo_output_data: CswUtxoOutputData,
    ) -> (FieldElement, FieldElement, GingerMHTBinaryPath) {
        let mut mst = GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();

        let mst_leaf_hash = utxo_output_data.hash(None).unwrap();

        mst.append(mst_leaf_hash).unwrap();
        mst.finalize_in_place().unwrap();

        let mst_path: GingerMHTBinaryPath = mst.get_merkle_path(0).unwrap().try_into().unwrap();

        let mst_root = mst.root().unwrap();

        (mst_root, mst_leaf_hash, mst_path)
    }

    fn compute_cert_data(
        custom_fields: Vec<FieldElement>,
    ) -> (WithdrawalCertificateData, FieldElement) {
        let rng = &mut thread_rng();
        let cert_data = WithdrawalCertificateData {
            ledger_id: FieldElement::rand(rng),
            epoch_id: rng.gen(),
            bt_root: get_bt_merkle_root(None).unwrap(),
            quality: rng.gen(),
            mcb_sc_txs_com: FieldElement::rand(rng),
            ft_min_amount: rng.gen(),
            btr_min_fee: rng.gen(),
            custom_fields,
        };

        let custom_fields_ref = {
            if cert_data.custom_fields.is_empty() {
                None
            } else {
                Some(
                    cert_data
                        .custom_fields
                        .iter()
                        .collect::<Vec<&FieldElement>>(),
                )
            }
        };

        let computed_last_wcert_hash = hash_cert(
            &cert_data.ledger_id,
            cert_data.epoch_id,
            cert_data.quality,
            None,
            custom_fields_ref,
            &cert_data.mcb_sc_txs_com,
            cert_data.btr_min_fee,
            cert_data.ft_min_amount,
        )
        .unwrap();

        (cert_data, computed_last_wcert_hash)
    }

    fn generate_test_utxo_csw_data(
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        secret_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> CswProverData {
        let rng = &mut thread_rng();
        let utxo_input_data = CswUtxoInputData {
            output: CswUtxoOutputData {
                spending_pub_key: bytes_to_bits(&public_key_bytes).try_into().unwrap(),
                amount: rng.gen(),
                nonce: rng.gen(),
                custom_hash: bytes_to_bits(&rng.gen::<[u8; FIELD_SIZE]>())
                    .try_into()
                    .unwrap(),
            },
            secret_key: bytes_to_bits(&secret_key_bytes)[SIMULATED_SCALAR_FIELD_REPR_SHAVE_BITS..]
                .try_into()
                .unwrap(),
        };

        let (mst_root, mst_leaf_hash, mst_path) =
            compute_mst_tree_data(utxo_input_data.output.clone());

        let custom_fields = {
            if num_custom_fields == 0 {
                vec![]
            } else {
                // To generate valid test data we need at least 2 custom field to store the MST root
                debug_assert!(num_custom_fields >= 2);

                // Split mst_root in 2

                let mut custom_fields = {
                    let (mst_root_1, mst_root_2) =
                        split_field_element_at_index(&mst_root, FIELD_SIZE / 2).unwrap();
                    vec![mst_root_1, mst_root_2]
                };

                for _ in 0..num_custom_fields - 2 {
                    custom_fields.push(PHANTOM_FIELD_ELEMENT);
                }

                custom_fields
            }
        };

        let (cert_data, last_wcert_hash) = compute_cert_data(custom_fields);

        let utxo_data = CswUtxoProverData {
            input: utxo_input_data.clone(),
            mst_path_to_output: mst_path,
        };

        let rng = &mut thread_rng();
        let sys_data = CswSysData {
            mcb_sc_txs_com_end: FieldElement::rand(rng),
            sc_last_wcert_hash: last_wcert_hash,
            amount: utxo_input_data.output.amount,
            nullifier: mst_leaf_hash,
            receiver: (0..MC_PK_SIZE)
                .map(|_| rng.gen())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        };

        let csw_prover_data = CswProverData {
            sys_data,
            last_wcert: cert_data,
            utxo_data,
            ft_data: CswFtProverData::get_phantom(num_commitment_hashes),
        };

        csw_prover_data
    }

    fn generate_ft_tree_data(
        ft_output_data: CswFtOutputData,
    ) -> (FieldElement, GingerMHTBinaryPath, FieldElement) {
        let ft_input_hash = hash_fwt(
            ft_output_data.amount,
            &ft_output_data.receiver_pub_key,
            &ft_output_data.payback_addr_data_hash,
            &ft_output_data.tx_hash,
            ft_output_data.out_idx,
        )
        .unwrap();

        let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
        ft_tree.append(ft_input_hash).unwrap();
        ft_tree.finalize_in_place().unwrap();

        let ft_tree_path = ft_tree.get_merkle_path(0).unwrap().try_into().unwrap();
        let ft_tree_root = ft_tree.root().unwrap();

        (ft_input_hash, ft_tree_path, ft_tree_root)
    }

    fn generate_test_ft_csw_data(
        sidechain_id: FieldElement,
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        secret_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> CswProverData {
        let rng = &mut thread_rng();

        let ft_output_data = CswFtOutputData {
            amount: rng.gen(),
            receiver_pub_key: public_key_bytes.try_into().unwrap(),
            payback_addr_data_hash: (0..MC_RETURN_ADDRESS_BYTES)
                .map(|_| rng.gen())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
            tx_hash: rng.gen::<[u8; SC_TX_HASH_LENGTH]>(),
            out_idx: rng.gen(),
        };

        let (ft_output_hash, ft_tree_path, ft_tree_root) =
            generate_ft_tree_data(ft_output_data.clone());

        let scb_btr_tree_root = FieldElement::rand(rng);
        let wcert_tree_root = FieldElement::rand(rng);

        let sc_hash = get_poseidon_hash_constant_length(4, None)
            .update(ft_tree_root)
            .update(scb_btr_tree_root)
            .update(wcert_tree_root)
            .update(sidechain_id)
            .finalize()
            .unwrap();

        let mut sc_tree = GingerMHT::init(CMT_MT_HEIGHT, 1 << CMT_MT_HEIGHT).unwrap();
        sc_tree.append(sc_hash).unwrap();
        sc_tree.finalize_in_place().unwrap();

        let sc_tree_path: GingerMHTBinaryPath =
            sc_tree.get_merkle_path(0).unwrap().try_into().unwrap();
        let sc_tree_root = sc_tree.root().unwrap();

        let mut ft_data = CswFtProverData {
            ft_output: ft_output_data,
            ft_input_secret_key: bytes_to_bits(&secret_key_bytes)
                [SIMULATED_SCALAR_FIELD_REPR_SHAVE_BITS..]
                .try_into()
                .unwrap(),
            mcb_sc_txs_com_start: PHANTOM_FIELD_ELEMENT,
            merkle_path_to_sc_hash: sc_tree_path,
            ft_tree_path,
            sc_creation_commitment: PHANTOM_FIELD_ELEMENT,
            scb_btr_tree_root,
            wcert_tree_root,
            sc_txs_com_hashes: vec![PHANTOM_FIELD_ELEMENT; num_commitment_hashes as usize],
        };

        ft_data.sc_txs_com_hashes[0] = sc_tree_root;

        let mut mcb_sc_txs_com_end = ft_data.mcb_sc_txs_com_start;

        ft_data
            .sc_txs_com_hashes
            .iter()
            .for_each(|sc_txs_com_hash| {
                if !sc_txs_com_hash.eq(&PHANTOM_FIELD_ELEMENT) {
                    mcb_sc_txs_com_end = get_poseidon_hash_constant_length(2, None)
                        .update(mcb_sc_txs_com_end)
                        .update(*sc_txs_com_hash)
                        .finalize()
                        .unwrap();
                }
            });

        let sys_data = CswSysData {
            mcb_sc_txs_com_end,
            sc_last_wcert_hash: PHANTOM_FIELD_ELEMENT,
            amount: ft_data.ft_output.amount,
            nullifier: ft_output_hash,
            receiver: rng.gen::<[u8; MC_PK_SIZE]>(),
        };

        let csw_prover_data = CswProverData {
            sys_data,
            last_wcert: WithdrawalCertificateData::get_phantom(num_custom_fields),
            utxo_data: CswUtxoProverData::default(),
            ft_data,
        };

        csw_prover_data
    }

    fn generate_test_csw_prover_data(
        csw_type: CswType,
        sidechain_id: FieldElement,
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        secret_key_bytes: Option<Vec<u8>>,
        public_key_bytes: Option<Vec<u8>>,
    ) -> CswProverData {
        let (secret_key, public_key) = {
            if secret_key_bytes.is_none() || public_key_bytes.is_none() {
                generate_key_pair()
            } else {
                (secret_key_bytes.unwrap(), public_key_bytes.unwrap())
            }
        };

        match csw_type {
            CswType::UTXO => generate_test_utxo_csw_data(
                num_custom_fields,
                num_commitment_hashes,
                secret_key,
                public_key,
            ),
            CswType::FT => generate_test_ft_csw_data(
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                secret_key,
                public_key,
            ),
        }
    }

    fn test_csw_circuit(
        debug_only: bool,
        sidechain_id: FieldElement,
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        constant: Option<FieldElement>,
        csw_prover_data: CswProverData,
        public_inputs: Option<Vec<FieldElement>>,
    ) -> Option<String> {
        let circuit = CeasedSidechainWithdrawalCircuit::from_prover_data(
            sidechain_id,
            constant,
            csw_prover_data.clone(),
            num_commitment_hashes,
            num_custom_fields,
        )
        .unwrap();

        let failing_constraint = debug_circuit(circuit.clone()).unwrap();

        if !debug_only {
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

            let current_public_inputs = {
                if public_inputs.is_none() {
                    let mut tmp_public_inputs = Vec::new();

                    if constant.is_some() {
                        tmp_public_inputs.push(constant.unwrap());
                    }

                    let csw_sys_data_hash =
                        CeasedSidechainWithdrawalCircuit::compute_csw_sys_data_hash(
                            &csw_prover_data.sys_data,
                            sidechain_id,
                        )
                        .unwrap();

                    tmp_public_inputs.push(csw_sys_data_hash);
                    tmp_public_inputs
                } else {
                    public_inputs.unwrap()
                }
            };

            // Check that the proof gets correctly verified
            assert!(CoboundaryMarlin::verify(
                &params.1.clone(),
                ck_g1.as_ref().unwrap(),
                current_public_inputs.as_slice(),
                &proof
            )
            .unwrap());

            // Change one public input each time and check that the proof fails
            for i in 0..current_public_inputs.len() {
                let mut wrong_public_inputs = current_public_inputs.clone();
                wrong_public_inputs[i].double_in_place();

                assert!(!CoboundaryMarlin::verify(
                    &params.1.clone(),
                    ck_g1.as_ref().unwrap(),
                    wrong_public_inputs.as_slice(),
                    &proof
                )
                .unwrap());
            }
        }

        failing_constraint
    }

    fn generate_circuit_test_data() -> (FieldElement, u32, u32, Option<FieldElement>, bool) {
        let rng = &mut thread_rng();
        let sidechain_id = FieldElement::rand(rng);
        let num_custom_fields = 2;
        let num_commitment_hashes = 10;
        let constant = Some(FieldElement::rand(rng));
        let debug_only = true;

        (
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            debug_only,
        )
    }

    #[test]
    fn test_csw_circuit_utxo() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, _) =
            generate_circuit_test_data();

        let debug_only = false;

        let csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    fn test_csw_circuit_ft() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, _) =
            generate_circuit_test_data();

        let debug_only = false;

        let csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    fn test_csw_circuit_utxo_wrong_cert_hash() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        csw_prover_data
            .sys_data
            .sc_last_wcert_hash
            .double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("enforce sc_last_wcert_hash == last_wcert_hash"));
    }

    #[test]
    fn test_csw_circuit_utxo_without_certificate() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        csw_prover_data.last_wcert = WithdrawalCertificateData::get_phantom(num_custom_fields);

        let custom_fields_ref = csw_prover_data
            .last_wcert
            .custom_fields
            .iter()
            .collect::<Vec<&FieldElement>>();

        let computed_last_wcert_hash = hash_cert(
            &csw_prover_data.last_wcert.ledger_id,
            csw_prover_data.last_wcert.epoch_id,
            csw_prover_data.last_wcert.quality,
            None,
            Some(custom_fields_ref),
            &csw_prover_data.last_wcert.mcb_sc_txs_com,
            csw_prover_data.last_wcert.btr_min_fee,
            csw_prover_data.last_wcert.ft_min_amount,
        )
        .unwrap();

        csw_prover_data.sys_data.sc_last_wcert_hash = computed_last_wcert_hash;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("last_wcert.proof_data.scb_new_mst_root == mst_root"));
    }

    #[test]
    fn test_csw_circuit_utxo_wrong_mst_path() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Try to pass a path to the right leaf moved from position 0 to position 1
        let moved_mst_path = {
            let mut mst =
                GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
            let mst_leaf_hash = csw_prover_data.utxo_data.input.output.hash(None).unwrap();
            mst.append(FieldElement::zero()).unwrap();
            mst.append(mst_leaf_hash).unwrap();
            mst.finalize_in_place().unwrap();
            mst.get_merkle_path(1).unwrap().try_into().unwrap()
        };

        csw_prover_data.utxo_data.mst_path_to_output = moved_mst_path;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data.clone(),
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("last_wcert.proof_data.scb_new_mst_root == mst_root"));

        // Try to pass a path to the wrong leaf
        let wrong_mst_path = {
            let mut mst =
                GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
            let mst_leaf_hash = csw_prover_data.utxo_data.input.output.hash(None).unwrap();
            mst.append(mst_leaf_hash).unwrap();
            mst.finalize_in_place().unwrap();
            mst.get_merkle_path(1).unwrap().try_into().unwrap()
        };

        csw_prover_data.utxo_data.mst_path_to_output = wrong_mst_path;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("last_wcert.proof_data.scb_new_mst_root == mst_root"));
    }

    #[test]
    fn test_csw_circuit_utxo_wrong_nullifier() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the nullifier
        csw_prover_data.sys_data.nullifier.double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("require(nullifier == outputHash)"));
    }

    #[test]
    fn test_csw_circuit_utxo_wrong_amount() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the amount
        csw_prover_data.sys_data.amount += 1;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("input.amount == sys_data.amount"));
    }

    #[test]
    fn test_csw_circuit_utxo_wrong_public_key_x_sign() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        // Change the first bit, the check over the X sign should fail
        let (secret_key, mut public_key) = generate_key_pair();
        public_key[0] ^= 1;

        let csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            Some(secret_key),
            Some(public_key),
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("Enforce x_sign == pk_x_sign_bit_g"));
    }

    #[test]
    fn test_csw_circuit_utxo_wrong_public_key_y_coordinate() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        // Change any random bit of the public key (not the first one)
        let (random_byte, random_bit) = {
            let random_number = thread_rng().gen_range(1..SIMULATED_FIELD_BYTE_SIZE * 8);
            (random_number / 8, random_number % 8)
        };

        let (secret_key, mut public_key) = generate_key_pair();
        public_key[random_byte] ^= 1 << random_bit;

        let csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            Some(secret_key),
            Some(public_key),
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("Enforce y coordinate is equal"));
    }

    #[test]
    fn test_csw_circuit_utxo_without_constant() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, _, _) =
            generate_circuit_test_data();

        let debug_only = false;
        let constant = None;

        let csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    fn test_csw_circuit_utxo_without_custom_fields() {
        let (sidechain_id, _, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let num_custom_fields = 0;

        let csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    fn test_csw_circuit_utxo_with_wrong_custom_fields() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        assert!(!csw_prover_data.last_wcert.custom_fields.is_empty());
        csw_prover_data.last_wcert.custom_fields[0].double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("enforce sc_last_wcert_hash == last_wcert_hash"));
    }

    #[test]
    fn test_csw_circuit_ft_wrong_amount() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the amount
        csw_prover_data.sys_data.amount += 1;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("input.amount == sys_data.amount"));
    }

    #[test]
    fn test_csw_circuit_ft_wrong_nullifier() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the nullifier
        csw_prover_data.sys_data.nullifier.double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("require(nullifier == outputHash)"));
    }

    #[test]
    fn test_csw_circuit_ft_with_certificate() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let rng = &mut thread_rng();
        let (cert_data, last_wcert_hash) =
            compute_cert_data(vec![FieldElement::rand(rng), FieldElement::rand(rng)]);

        csw_prover_data.last_wcert = cert_data;

        // The test should fail since we didn't update the last wcert
        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data.clone(),
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("enforce sc_last_wcert_hash == last_wcert_hash/conditional_equals"));

        csw_prover_data.sys_data.sc_last_wcert_hash = last_wcert_hash;

        // The test should now pass
        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data.clone(),
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    fn test_csw_circuit_ft_wrong_ft_path() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Try to pass a path to the right leaf moved from position 0 to position 1
        let moved_ft_path = {
            let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
            ft_tree.append(FieldElement::zero()).unwrap();
            ft_tree.append(csw_prover_data.sys_data.nullifier).unwrap();
            ft_tree.finalize_in_place().unwrap();

            ft_tree.get_merkle_path(1).unwrap().try_into().unwrap()
        };

        csw_prover_data.ft_data.ft_tree_path = moved_ft_path;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data.clone(),
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));

        // Try to pass a path to the wrong leaf
        let wrong_ft_path = {
            let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
            ft_tree.append(csw_prover_data.sys_data.nullifier).unwrap();
            ft_tree.finalize_in_place().unwrap();

            ft_tree.get_merkle_path(1).unwrap().try_into().unwrap()
        };

        csw_prover_data.ft_data.ft_tree_path = wrong_ft_path;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
    }

    #[test]
    fn test_csw_circuit_ft_wrong_sc_hash_path() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Try to pass a path to the right leaf moved from position 0 to position 1
        let ft_tree_root = {
            let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
            ft_tree.append(csw_prover_data.sys_data.nullifier).unwrap();
            ft_tree.finalize_in_place().unwrap();
            ft_tree.root().unwrap()
        };

        let sc_moved_tree_path: GingerMHTBinaryPath = {
            let sc_hash = get_poseidon_hash_constant_length(4, None)
                .update(ft_tree_root)
                .update(csw_prover_data.ft_data.scb_btr_tree_root)
                .update(csw_prover_data.ft_data.wcert_tree_root)
                .update(sidechain_id)
                .finalize()
                .unwrap();

            let mut sc_tree = GingerMHT::init(CMT_MT_HEIGHT, 1 << CMT_MT_HEIGHT).unwrap();
            sc_tree.append(FieldElement::zero()).unwrap();
            sc_tree.append(sc_hash).unwrap();
            sc_tree.finalize_in_place().unwrap();

            sc_tree.get_merkle_path(1).unwrap().try_into().unwrap()
        };

        csw_prover_data.ft_data.merkle_path_to_sc_hash = sc_moved_tree_path;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data.clone(),
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));

        // Try to pass a path to the wrong leaf
        let wrong_sc_path = {
            let sc_hash = get_poseidon_hash_constant_length(4, None)
                .update(ft_tree_root)
                .update(csw_prover_data.ft_data.scb_btr_tree_root)
                .update(csw_prover_data.ft_data.wcert_tree_root)
                .update(sidechain_id)
                .finalize()
                .unwrap();

            let mut sc_tree = GingerMHT::init(CMT_MT_HEIGHT, 1 << CMT_MT_HEIGHT).unwrap();
            sc_tree.append(sc_hash).unwrap();
            sc_tree.finalize_in_place().unwrap();

            sc_tree.get_merkle_path(1).unwrap().try_into().unwrap()
        };

        csw_prover_data.ft_data.merkle_path_to_sc_hash = wrong_sc_path;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
    }

    #[test]
    fn test_csw_circuit_ft_missing_com_tx() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let mut csw_prover_data = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Remove the SC_TREE_ROOT as the first element of the commitment hashes
        csw_prover_data.ft_data.sc_txs_com_hashes[0] = PHANTOM_FIELD_ELEMENT;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            csw_prover_data,
            None,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
    }
}
