use algebra::PrimeField;
use cctp_primitives::{
    type_mapping::FieldElement,
    utils::commitment_tree::{hash_vec, DataAccumulator},
};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::FieldBasedHashGadget;
use r1cs_std::{alloc::AllocGadget, boolean::Boolean, eq::EqGadget, FromBitsGadget};

use crate::{
    common::data_structures::WithdrawalCertificateData, type_mapping::*, FieldElementGadget,
};

use self::data_structures::{CswProverDataGadget, ScPublicKeyGadget};
use super::data_structures::{CswFtProverData, CswProverData, CswSysData, CswUtxoProverData};

pub mod data_structures;

#[derive(Clone)]
pub struct CeasedSidechainWithdrawalCircuit {
    /// The range size (number of MC blocks) for a ft withdrawal
    range_size: u32,
    num_custom_fields: u32,
    sidechain_id: FieldElement,
    /// The (pre-images of the) public inputs
    sys_data: CswSysData,
    // Witnesses for the prover
    /// The last accepted withdrawal certificate. If not present, chosen default
    /// by the circuit.
    last_wcert: Option<WithdrawalCertificateData>,
    /// Witnesses for a utxo withdrawal. If present the circuit runs in utxo proving
    /// mode. If not present, ft proving mode is selected.
    utxo_data: Option<CswUtxoProverData>,
    /// Witnesses for an ft withdrawal.
    ft_data: Option<CswFtProverData>,

    /// public input 1: currently not used
    constant: Option<FieldElement>,
    /// public input 2: the hash of sys_data, the actual public input of the circuit.
    csw_sys_data_hash: FieldElement,
}

impl CeasedSidechainWithdrawalCircuit {
    fn compute_csw_sys_data_hash(
        sys_data: &CswSysData,
        sidechain_id: FieldElement,
    ) -> Result<FieldElement, Error> {
        let mut sys_data_hash_inputs = DataAccumulator::init()
            .update(sys_data.amount)
            .map_err(|e| {
                format!(
                    "Unable to update DataAccumulator with sys_data.amount: {:?}",
                    e
                )
            })?
            .update(&sys_data.receiver[..])
            .map_err(|e| {
                format!(
                    "Unable to update DataAccumulator with sys_data.receiver: {:?}",
                    e
                )
            })?
            .get_field_elements()
            .map_err(|e| format!("Unable to finalize DataAccumulator: {:?}", e))?;

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
        let csw_sys_data_hash = Self::compute_csw_sys_data_hash(&sys_data, sidechain_id)
            .map_err(|e| format!("Unable to compute csw_sys_data_hash: {:?}", e))?;

        // Handle exceptional cases
        let _ = match (last_wcert.is_some(), utxo_data.is_some(), ft_data.is_some()) {
            // Attempt to withdraw a sc utxo without having specified a last_wcert
            (false, true, _) => Err(Error::from(
                "Attempt to withdraw SC Utxo without specifying last WCert",
            )),
            // Attempt to withdraw both a sc utxo and a ft
            (_, true, true) => Err(Error::from(
                "Cannot create a CSW proof for retrieving both a SC UTXO and a FT",
            )),
            // Attempt to withdraw neither a sc utxo neither a ft
            (_, false, false) => Err(Error::from(
                "Cannot create a CSW proof for retrieving nothing",
            )),
            _ => Ok(()),
        }?;

        Ok(Self {
            range_size,
            num_custom_fields,
            sidechain_id,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
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
            sidechain_id: FieldElement::default(),
            sys_data: CswSysData::default(),
            last_wcert: None,
            utxo_data: None,
            ft_data: None,
            constant: if is_constant_present {
                Some(FieldElement::default())
            } else {
                None
            },
            csw_sys_data_hash: FieldElement::default(),
        }
    }
}

impl ConstraintSynthesizer<FieldElement> for CeasedSidechainWithdrawalCircuit {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Decide whether to enforce utxo or ft withdrawal.
        let should_enforce_utxo_withdrawal_g =
            Boolean::alloc(cs.ns(|| "should_enforce_utxo_withdrawal"), || {
                Ok(self.utxo_data.is_some())
            })?;

        let should_enforce_ft_withdrawal_g = should_enforce_utxo_withdrawal_g.not();

        // Alloc sidechain id
        let sidechain_id_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc sidechain_id_g"), || Ok(&self.sidechain_id))?;

        // Alloc all witness data
        let (csw_data_g, actual_range_size) = {
            let mut csw_data = CswProverData {
                sys_data: self.sys_data.clone(),
                last_wcert: self.last_wcert.clone().unwrap_or_else(|| {
                    WithdrawalCertificateData::get_default(self.num_custom_fields)
                }),
                utxo_data: self.utxo_data.clone().unwrap_or_default(),
                ft_data: self
                    .ft_data
                    .clone()
                    .unwrap_or_else(|| CswFtProverData::get_default(self.range_size)),
            };

            // Get the actual number of sc_txs_com_hashes
            let actual_range_size = csw_data.ft_data.sc_txs_com_hashes.len() as u32;

            // Pad to reach maximum one (in case it wasn't)
            if actual_range_size < self.range_size {
                csw_data
                    .ft_data
                    .sc_txs_com_hashes
                    .resize(self.range_size as usize, FieldElement::default())
            }

            (
                CswProverDataGadget::alloc(cs.ns(|| "alloc csw data"), || Ok(csw_data))?,
                actual_range_size,
            )
        };

        // Enforce UTXO widthdrawal if required
        csw_data_g
            .utxo_data_g
            .conditionally_enforce_utxo_withdrawal(
                cs.ns(|| "enforce utxo withdrawal"),
                &csw_data_g.last_wcert_g,
                &csw_data_g.sys_data_g.sc_last_wcert_hash_g,
                &csw_data_g.sys_data_g.nullifier_g,
                &csw_data_g.sys_data_g.amount_g,
                &should_enforce_utxo_withdrawal_g,
            )?;

        // Enforce FT withdrawal if required
        csw_data_g.ft_data_g.conditionally_enforce_ft_withdrawal(
            cs.ns(|| "conditionally enforce ft withdrawal"),
            &sidechain_id_g,
            self.range_size,
            actual_range_size,
            &csw_data_g.sys_data_g.mcb_sc_txs_com_end_g,
            &csw_data_g.sys_data_g.nullifier_g,
            &csw_data_g.sys_data_g.amount_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // We check the public key ownership just once for both, choosing the appropriate public key
        // and secret key, as it is an expensive check, we want to do it just once.
        // NOTE: We could've done the same for nullifier and amount checks, but we didn't in order
        //       to have cleaner code (we lose only 2 constraints anyway)

        ScPublicKeyGadget::enforce_pk_ownership(
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

            assert!(
                FieldElement::size_in_bits() > amount_and_receiver_bits_g.len(),
                "Field size is not enough to pack amount and receiver bits"
            );

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
    use algebra::{Field, ToBits, UniformRand};
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
    use primitives::{FieldBasedHash, FieldBasedMerkleTree, FieldHasher};
    use r1cs_core::debug_circuit;
    use rand::{thread_rng, Rng};
    use std::{convert::TryInto, ops::AddAssign};

    use crate::{
        blaze_csw::{
            data_structures::{CswFtOutputData, CswUtxoInputData, CswUtxoOutputData},
            deserialize_fe_unchecked, split_field_element_at_index,
        },
        common::data_structures::WithdrawalCertificateData,
        constants::personalizations::BoxType,
        GingerMHTBinaryPath, MAX_SEGMENT_SIZE, MC_RETURN_ADDRESS_BYTES, MST_MERKLE_TREE_HEIGHT,
        SC_PUBLIC_KEY_LENGTH, SC_TX_HASH_LENGTH, SUPPORTED_SEGMENT_SIZE,
    };

    use super::*;

    use serial_test::*;

    enum CswType {
        UTXO,
        FT,
    }

    fn get_test_key_pair() -> (
        [u8; SC_PUBLIC_KEY_LENGTH],
        [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
    ) {
        let test_sc_secrets = vec![
            "50d5e4c0b15402013941a3c525c6af85e7ab8a2da39a59707211ddd53def965e",
            "70057ef1805240ab9bf2772c0e25a3b57c5911e7dca4120f8e265d750ed77346",
            "1089ba2f1bee0bbc8f2270541bb22595026fe7d828033845d5ed82f31386b65d",
            "305510ff60436930d09ccb8e2321211967aadfe904f30ccb13f600786f9e297a",
            "c80155e642065ca1cc575f69fa658f837b880df76771a335f40ce27240735443",
            "50e8a8b680918c1840bedfa1650e53f94c8823e81f6efd24d9e37fedfab9344f",
            "98b4a1c05a44708014a895d27923c7c20f3260e1bc9f2d5edcd6996e4d017944",
            "b840b87072d095849d433ec11ddd49b138f1823dae16268dcbe46d8035635e74",
            "b07b2199ad9258449889686423a3c9382cf428355ac348bce40c9d639edf6759",
            "302fcad55ae4b8f54ab3ab01eaf171873d38676075dff601e4b12a377c7c217d",
            "001d2489d7b8caab450822ee6393d0b9324da8af67fda2b2cba19b46f64de852",
            "3811067e9f19d35b2f7487eeb08076a9c4a459dec10791095ebae03bb613f375",
        ];

        let test_sc_te_public_keys = vec![
            "f165e1e5f7c290e52f2edef3fbab60cbae74bfd3274f8e5ee1de3345c954a166",
            "8f80338eef733ec67c601349c4a8251393b28deb722cfd0a91907744a26d3dab",
            "cc1983469486418cd66dcdc8664677c263487b736840cfd1532e144386fa7610",
            "88166617f91bc145b243c2ae6e1088f1208bf17311cca74dbf032fee25b219e0",
            "6f97404947a00311785785217b1759b002cbae16da26e0801f0dcbe4e00d5f45",
            "fb7a8589cbe59427b2e9c91a5091bf43cf2080f1d4f1947af0d214ca825076f0",
            "30da57cda802def8dfd764812f2e3c82eb2871b2a14e3bb634f2195ef733796d",
            "622c8cb09b558fecfc60ce1ec4b1e3014fe04f4628e06cad58ce9ded4d192a2d",
            "3733056f59780d2f17adf073582634940c6ae57d530345d28e9b6b7cf1d3dcfb",
            "423cb2cdd87b3e612517cf77e68d918914b0705d8937ef7e25b24a53620bc9d1",
            "f5206f3569998819efc57e83e8521110e9414c8dca8c5e96c173366e9acd958f",
            "f1785d4d2f6017ad7a25f795db5beb48d38d6f8cd44dcc3b7f321b8e2a5352fd",
        ];

        let rng = &mut thread_rng();
        let random_idx = rng.gen_range(0..test_sc_secrets.len());

        let (test_sc_secret, test_sc_public_key) = (
            test_sc_secrets[random_idx],
            test_sc_te_public_keys[random_idx],
        );

        // Parse pk LE bits
        let pk_bytes = hex::decode(test_sc_public_key).unwrap();

        // Parse sk LE bits
        let sk_bytes = hex::decode(test_sc_secret).unwrap();
        let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

        // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
        let mut sk_bits = sk.write_bits();
        sk_bits.reverse();

        (pk_bytes.try_into().unwrap(), sk_bits.try_into().unwrap())
    }

    fn compute_mst_tree_data(
        utxo_output_data: CswUtxoOutputData,
    ) -> (FieldElement, FieldElement, GingerMHTBinaryPath) {
        let mut mst = GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();

        let mst_leaf_hash = utxo_output_data
            .hash(Some(&[FieldElement::from(BoxType::CoinBox as u8)]))
            .unwrap();

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
        secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
        spending_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    ) -> (
        CswSysData,
        Option<WithdrawalCertificateData>,
        Option<CswUtxoProverData>,
        Option<CswFtProverData>,
    ) {
        let rng = &mut thread_rng();
        let utxo_input_data = CswUtxoInputData {
            output: CswUtxoOutputData {
                spending_pub_key,
                amount: rng.gen(),
                nonce: rng.gen(),
                custom_hash: rng.gen::<[u8; FIELD_SIZE]>(),
            },
            secret_key,
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
                    custom_fields.push(FieldElement::default());
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
        let sys_data = CswSysData::new(
            Some(FieldElement::rand(rng)),
            Some(last_wcert_hash),
            utxo_input_data.output.amount,
            mst_leaf_hash,
            rng.gen::<[u8; MC_PK_SIZE]>(),
        );

        (sys_data, Some(cert_data), Some(utxo_data), None)
    }

    fn generate_ft_tree_data(
        ft_output_data: CswFtOutputData,
    ) -> (FieldElement, GingerMHTBinaryPath, FieldElement) {
        let mut receiver_pub_key = ft_output_data.receiver_pub_key;
        receiver_pub_key.reverse();

        let ft_input_hash = hash_fwt(
            ft_output_data.amount,
            &receiver_pub_key,
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
        num_commitment_hashes: u32,
        ft_input_secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
        receiver_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
    ) -> (
        CswSysData,
        Option<WithdrawalCertificateData>,
        Option<CswUtxoProverData>,
        Option<CswFtProverData>,
    ) {
        let rng = &mut thread_rng();

        let ft_output_data = CswFtOutputData {
            amount: rng.gen(),
            receiver_pub_key,
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
        let sc_creation_commitment = FieldElement::rand(rng);

        let sc_hash = get_poseidon_hash_constant_length(5, None)
            .update(ft_tree_root)
            .update(scb_btr_tree_root)
            .update(wcert_tree_root)
            .update(sc_creation_commitment)
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
            ft_input_secret_key,
            mcb_sc_txs_com_start: FieldElement::default(),
            merkle_path_to_sc_hash: sc_tree_path,
            ft_tree_path,
            sc_creation_commitment,
            scb_btr_tree_root,
            wcert_tree_root,
            sc_txs_com_hashes: vec![FieldElement::default(); num_commitment_hashes as usize],
        };

        // Sample a random idx in which putting the sc_tree_root
        let random_idx = rng.gen_range(0..num_commitment_hashes) as usize;
        ft_data.sc_txs_com_hashes[random_idx] = sc_tree_root;

        let mut mcb_sc_txs_com_end = ft_data.mcb_sc_txs_com_start;

        ft_data
            .sc_txs_com_hashes
            .iter()
            .enumerate()
            .for_each(|(i, sc_txs_com_hash)| {
                if i < num_commitment_hashes as usize {
                    mcb_sc_txs_com_end = get_poseidon_hash_constant_length(2, None)
                        .update(mcb_sc_txs_com_end)
                        .update(*sc_txs_com_hash)
                        .finalize()
                        .unwrap();
                }
            });

        let sys_data = CswSysData::new(
            Some(mcb_sc_txs_com_end),
            None,
            ft_data.ft_output.amount,
            ft_output_hash,
            rng.gen::<[u8; MC_PK_SIZE]>(),
        );

        (sys_data, None, None, Some(ft_data))
    }

    fn generate_test_csw_prover_data(
        csw_type: CswType,
        sidechain_id: FieldElement,
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        secret_key: Option<[bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS]>,
        public_key: Option<[u8; SC_PUBLIC_KEY_LENGTH]>,
    ) -> (
        CswSysData,
        Option<WithdrawalCertificateData>,
        Option<CswUtxoProverData>,
        Option<CswFtProverData>,
    ) {
        let (public_key, secret_key) =
            if let (Some(public_key), Some(secret_key)) = (public_key, secret_key) {
                (public_key, secret_key)
            } else {
                get_test_key_pair()
            };

        match csw_type {
            CswType::UTXO => generate_test_utxo_csw_data(num_custom_fields, secret_key, public_key),
            CswType::FT => generate_test_ft_csw_data(
                sidechain_id,
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
        max_num_commitment_hashes: u32,
        constant: Option<FieldElement>,
        sys_data: CswSysData,
        last_wcert: Option<WithdrawalCertificateData>,
        utxo_data: Option<CswUtxoProverData>,
        ft_data: Option<CswFtProverData>,
    ) -> Option<String> {
        let circuit = CeasedSidechainWithdrawalCircuit::new(
            sidechain_id,
            constant,
            sys_data.clone(),
            last_wcert,
            utxo_data,
            ft_data,
            max_num_commitment_hashes,
            num_custom_fields,
        )
        .unwrap();

        let failing_constraint = debug_circuit(circuit.clone()).unwrap();

        if !debug_only {
            let _ = load_g1_committer_key(MAX_SEGMENT_SIZE - 1);
            let ck_g1 = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();
            assert_eq!(ck_g1.comm_key.len(), SUPPORTED_SEGMENT_SIZE);

            let setup_circuit = CeasedSidechainWithdrawalCircuit::get_instance_for_setup(
                max_num_commitment_hashes,
                num_custom_fields,
                constant.is_some(),
            );
            let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
            let rng = &mut thread_rng();

            let proof =
                CoboundaryMarlin::prove(&params.0, &ck_g1, circuit, true, Some(rng)).unwrap();

            let current_public_inputs = {
                let mut tmp_public_inputs = Vec::new();

                if let Some(constant) = constant {
                    tmp_public_inputs.push(constant);
                }

                let csw_sys_data_hash =
                    CeasedSidechainWithdrawalCircuit::compute_csw_sys_data_hash(
                        &sys_data,
                        sidechain_id,
                    )
                    .unwrap();

                tmp_public_inputs.push(csw_sys_data_hash);
                tmp_public_inputs
            };

            // Check that the proof gets correctly verified
            assert!(CoboundaryMarlin::verify(
                &params.1,
                &ck_g1,
                current_public_inputs.as_slice(),
                &proof
            )
            .unwrap());

            // Change one public input each time and check that the proof fails
            for i in 0..current_public_inputs.len() {
                let mut wrong_public_inputs = current_public_inputs.clone();
                wrong_public_inputs[i].add_assign(FieldElement::one());

                assert!(!CoboundaryMarlin::verify(
                    &params.1.clone(),
                    &ck_g1,
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
    #[serial]
    fn complete_test_csw_circuit_utxo() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, _) =
            generate_circuit_test_data();

        let debug_only = false;

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
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
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    #[serial]
    fn complete_test_csw_circuit_ft() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, _) =
            generate_circuit_test_data();

        let debug_only = false;

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
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
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_wrong_cert_hash() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        sys_data.sc_last_wcert_hash.double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );

        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("enforce sc_last_wcert_hash == last_wcert_hash"));
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_without_certificate() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, _, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let empty_cert = WithdrawalCertificateData::get_default(num_custom_fields);

        let custom_fields_ref = empty_cert
            .custom_fields
            .iter()
            .collect::<Vec<&FieldElement>>();

        let computed_last_wcert_hash = hash_cert(
            &empty_cert.ledger_id,
            empty_cert.epoch_id,
            empty_cert.quality,
            None,
            Some(custom_fields_ref),
            &empty_cert.mcb_sc_txs_com,
            empty_cert.btr_min_fee,
            empty_cert.ft_min_amount,
        )
        .unwrap();

        sys_data.sc_last_wcert_hash = computed_last_wcert_hash;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            Some(empty_cert),
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("last_wcert.proof_data.scb_new_mst_root == mst_root"));
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_wrong_mst_path() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        {
            let mut utxo_data = utxo_data.clone().unwrap();

            // Try to pass a path to the right leaf moved from position 0 to position 1
            let moved_mst_path = {
                let mut mst =
                    GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
                let mst_leaf_hash = utxo_data
                    .input
                    .output
                    .hash(Some(&[FieldElement::from(BoxType::CoinBox as u8)]))
                    .unwrap();
                mst.append(FieldElement::zero()).unwrap();
                mst.append(mst_leaf_hash).unwrap();
                mst.finalize_in_place().unwrap();
                mst.get_merkle_path(1).unwrap().try_into().unwrap()
            };

            utxo_data.mst_path_to_output = moved_mst_path;

            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data.clone(),
                last_wcert.clone(),
                Some(utxo_data),
                ft_data.clone(),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint
                .unwrap()
                .contains("last_wcert.proof_data.scb_new_mst_root == mst_root"));
        }

        {
            let mut utxo_data = utxo_data.unwrap();

            // Try to pass a path to the wrong leaf
            let wrong_mst_path = {
                let mut mst =
                    GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
                let mst_leaf_hash = utxo_data
                    .input
                    .output
                    .hash(Some(&[FieldElement::from(BoxType::CoinBox as u8)]))
                    .unwrap();
                mst.append(mst_leaf_hash).unwrap();
                mst.finalize_in_place().unwrap();
                mst.get_merkle_path(1).unwrap().try_into().unwrap()
            };

            utxo_data.mst_path_to_output = wrong_mst_path;

            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data,
                last_wcert,
                Some(utxo_data),
                ft_data,
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint
                .unwrap()
                .contains("last_wcert.proof_data.scb_new_mst_root == mst_root"));
        }
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_wrong_nullifier() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the nullifier
        sys_data.nullifier.double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("require(nullifier == outputHash)"));
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_wrong_amount() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the amount
        sys_data.amount += 1;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("input.amount == sys_data.amount"));
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_wrong_public_key_x_sign() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        // Change the first bit
        let (mut public_key, secret_key) = get_test_key_pair();
        public_key[0] ^= 1;

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
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
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(
            failing_constraint
                .unwrap()
                .contains("enforce pk ownership/enforce ownership inner") // Might fail for multiple reasons, so let's be a bit more general here.
        );
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_wrong_public_key_y_coordinate() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        // Generate random (but valid) point and take its y coordinate
        let random_bytes = {
            let random_y = SimulatedTEGroup::rand(&mut thread_rng()).y;
            serialize_to_buffer(&random_y, None).unwrap()
        };

        let (_, secret_key) = get_test_key_pair();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            Some(secret_key),
            Some(random_bytes.try_into().unwrap()),
        );

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("enforce pk ownership/enforce ownership inner/expected_pk == actual_pk/enforce condition/conditional_equals"));
    }

    #[test]
    #[serial]
    fn complete_test_csw_circuit_utxo_without_constant() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, _, _) =
            generate_circuit_test_data();

        let debug_only = false;

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
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
            None,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    #[serial]
    #[should_panic]
    fn test_csw_circuit_utxo_without_custom_fields() {
        let (sidechain_id, _, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let num_custom_fields = 0;

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
    }

    #[test]
    #[serial]
    fn test_csw_circuit_utxo_with_wrong_custom_fields() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::UTXO,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let mut last_wcert = last_wcert.unwrap();

        assert!(!last_wcert.custom_fields.is_empty());
        last_wcert.custom_fields[0].double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            Some(last_wcert),
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("enforce utxo withdrawal/last_wcert.proof_data.scb_new_mst_root == mst_root/conditional_equals"));
    }

    #[test]
    #[serial]
    fn test_csw_circuit_ft_wrong_amount() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the amount
        sys_data.amount += 1;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("input.amount == sys_data.amount"));
    }

    #[test]
    #[serial]
    fn test_csw_circuit_ft_wrong_nullifier() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of the nullifier
        sys_data.nullifier.double_in_place();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint
            .unwrap()
            .contains("require(nullifier == outputHash)"));
    }

    #[test]
    #[serial]
    fn complete_test_csw_circuit_ft_wrong_phantom_certificate_hash() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (sys_data, _, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        // Change the value of sc_last_wcert_hash
        {
            let mut sys_data = sys_data.clone();
            sys_data.sc_last_wcert_hash.double_in_place();

            // Certificate hash is not enforced when withdrawing a FT so the constraint system should pass anyway
            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data,
                None,
                utxo_data.clone(),
                ft_data.clone(),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint.is_none());
        }

        // However, if the prover supplies a wrong value for the public input when creating a proof, its verification should fail
        // (due to non-malleability property of our proving system)
        // Let's use our test routine that creates and verify a proof (passing also wrong public inputs)
        // to assert this (should crash if proof verification passes despite wrong public input)
        let debug_only = false;

        {
            let _ = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data,
                None,
                utxo_data,
                ft_data,
            );
        }
    }

    // Same test as before but we use a real certificate this time, just to show that nothing changes
    #[test]
    #[serial]
    fn complete_test_csw_circuit_ft_wrong_certificate_hash() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (mut sys_data, _, utxo_data, ft_data) = generate_test_csw_prover_data(
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

        {
            // We didn't update sys_data, so it's the wrong value for certificate hash; but the
            // certificate hash is not enforced when withdrawing a FT so the constraint system should pass anyway
            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data.clone(),
                Some(cert_data.clone()),
                utxo_data.clone(),
                ft_data.clone(),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint.is_none());
        }

        // However, if the prover supplies a wrong value for the public input when creating a proof, its verification should fail
        // (due to non-malleability property of our proving system)
        // Let's use our test routine that creates and verify a proof (passing also wrong public inputs)
        // to assert this (should crash if proof verification passes despite wrong public input)
        let debug_only = false;
        {
            // Assign correct value to sys_data so that the positive test passes
            sys_data.sc_last_wcert_hash = last_wcert_hash;

            let _ = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data,
                Some(cert_data),
                utxo_data,
                ft_data,
            );
        }
    }

    #[test]
    #[serial]
    fn test_csw_circuit_ft_wrong_ft_path() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        {
            let mut ft_data = ft_data.clone().unwrap();

            // Try to pass a path to the right leaf moved from position 0 to position 1
            let moved_ft_path = {
                let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
                ft_tree.append(FieldElement::zero()).unwrap();
                ft_tree.append(sys_data.nullifier).unwrap();
                ft_tree.finalize_in_place().unwrap();

                ft_tree.get_merkle_path(1).unwrap().try_into().unwrap()
            };

            ft_data.ft_tree_path = moved_ft_path;

            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data.clone(),
                last_wcert.clone(),
                utxo_data.clone(),
                Some(ft_data),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
        }

        {
            let mut ft_data = ft_data.unwrap();

            // Try to pass a path to the wrong leaf
            let wrong_ft_path = {
                let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
                ft_tree.append(sys_data.nullifier).unwrap();
                ft_tree.finalize_in_place().unwrap();

                ft_tree.get_merkle_path(1).unwrap().try_into().unwrap()
            };

            ft_data.ft_tree_path = wrong_ft_path;

            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data,
                last_wcert,
                utxo_data,
                Some(ft_data),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
        }
    }

    #[test]
    #[serial]
    fn test_csw_circuit_ft_wrong_sc_hash_path() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let ft_data = ft_data.unwrap();

        let ft_tree_root = {
            let mut ft_tree = GingerMHT::init(FWT_MT_HEIGHT, 1 << FWT_MT_HEIGHT).unwrap();
            ft_tree.append(sys_data.nullifier).unwrap();
            ft_tree.finalize_in_place().unwrap();
            ft_tree.root().unwrap()
        };

        let sc_hash = get_poseidon_hash_constant_length(5, None)
            .update(ft_tree_root)
            .update(ft_data.scb_btr_tree_root)
            .update(ft_data.wcert_tree_root)
            .update(ft_data.sc_creation_commitment)
            .update(sidechain_id)
            .finalize()
            .unwrap();

        {
            let mut ft_data = ft_data.clone();

            // Try to pass a path to the right leaf moved from position 0 to position 1
            let sc_moved_tree_path: GingerMHTBinaryPath = {
                let mut sc_tree = GingerMHT::init(CMT_MT_HEIGHT, 1 << CMT_MT_HEIGHT).unwrap();
                sc_tree.append(FieldElement::zero()).unwrap();
                sc_tree.append(sc_hash).unwrap();
                sc_tree.finalize_in_place().unwrap();

                sc_tree.get_merkle_path(1).unwrap().try_into().unwrap()
            };

            ft_data.merkle_path_to_sc_hash = sc_moved_tree_path;

            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data.clone(),
                last_wcert.clone(),
                utxo_data.clone(),
                Some(ft_data),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
        }

        {
            let mut ft_data = ft_data;
            // Try to pass a path to the wrong leaf
            let wrong_sc_path = {
                let mut sc_tree = GingerMHT::init(CMT_MT_HEIGHT, 1 << CMT_MT_HEIGHT).unwrap();
                sc_tree.append(sc_hash).unwrap();
                sc_tree.finalize_in_place().unwrap();

                sc_tree.get_merkle_path(1).unwrap().try_into().unwrap()
            };

            ft_data.merkle_path_to_sc_hash = wrong_sc_path;

            let failing_constraint = test_csw_circuit(
                debug_only,
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                constant,
                sys_data,
                last_wcert,
                utxo_data,
                Some(ft_data),
            );
            println!("Failing constraint: {:?}", failing_constraint);
            assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
        }
    }

    #[test]
    #[serial]
    fn test_csw_circuit_ft_missing_com_tx() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, debug_only) =
            generate_circuit_test_data();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            None,
            None,
        );

        let mut ft_data = ft_data.unwrap();
        let elem_idx_to_reset = ft_data
            .sc_txs_com_hashes
            .iter()
            .position(|&elem| elem != FieldElement::default())
            .unwrap();

        // Remove the SC_TREE_ROOT as the first element of the commitment hashes
        ft_data.sc_txs_com_hashes[elem_idx_to_reset] = FieldElement::default();

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            Some(ft_data),
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.unwrap().contains("require(cnt == 1)"));
    }

    #[test]
    #[serial]
    fn complete_test_csw_circuit_ft_few_tx_com_hashes() {
        let (sidechain_id, num_custom_fields, num_commitment_hashes, constant, _) =
            generate_circuit_test_data();

        let (sys_data, last_wcert, utxo_data, ft_data) = generate_test_csw_prover_data(
            CswType::FT,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes / 2,
            None,
            None,
        );

        let debug_only = false;

        let failing_constraint = test_csw_circuit(
            debug_only,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
            constant,
            sys_data,
            last_wcert,
            utxo_data,
            ft_data,
        );
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());
    }

    #[test]
    #[ignore]
    fn print_circuit_info() {
        use cctp_primitives::proving_system::{compute_proof_vk_size, ProvingSystem};

        let max_proof_plus_vk_size = 9 * 1024;
        let range_sizes = (19..=20).map(|num| num * 100);

        for range_size in range_sizes {
            println!("**********************************************************");
            println!(
                "Num hashes: {} (Num epochs: {})",
                range_size,
                range_size / 2
            );

            let circ =
                CeasedSidechainWithdrawalCircuit::get_instance_for_setup(range_size, 2, false);
            let index = CoboundaryMarlin::get_index_info(circ).unwrap();
            println!(
                "Padded num_constraints-num_variables: {}, |H| = {}",
                std::cmp::max(
                    index.index_info.num_constraints,
                    index.index_info.num_witness + index.index_info.num_inputs
                ),
                std::cmp::max(
                    index.index_info.num_constraints,
                    index.index_info.num_witness + index.index_info.num_inputs
                )
                .next_power_of_two()
            );
            println!(
                "Num non zero = {}, |K| = {}",
                index.index_info.num_non_zero,
                index.index_info.num_non_zero.next_power_of_two()
            );
            let (proof_size, vk_size) = compute_proof_vk_size(
                1 << 18,
                index.index_info,
                true,
                ProvingSystem::CoboundaryMarlin,
            );
            println!("Proof size: {}", proof_size);
            println!("Vk size: {}", vk_size);
            println!("Proof + vk size: {}", proof_size + vk_size);
            if proof_size + vk_size > max_proof_plus_vk_size {
                println!("Circuit is too complex. Max proof + vk size exceeded");
            }
        }
    }
}
