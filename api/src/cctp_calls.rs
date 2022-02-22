use algebra::{AffineCurve, ProjectiveCurve, ToConstraintField, UniformRand};
use demo_circuit::{
    constants::VRFParams, constraints::CeasedSidechainWithdrawalCircuit, naive_threshold_sig::*,
    type_mapping::*, CswFtProverData, CswSysData, CswUtxoProverData, WithdrawalCertificateData,
};
use lazy_static::*;
use primitives::{
    crh::{bowe_hopwood::BoweHopwoodPedersenParameters, FieldBasedHash},
    signature::{schnorr::field_based_schnorr::FieldBasedSchnorrPk, FieldBasedSignatureScheme},
    vrf::{ecvrf::FieldBasedEcVrfPk, FieldBasedVrf},
};
use r1cs_core::debug_circuit;
use rand::{rngs::OsRng, SeedableRng};
use rand_xorshift::XorShiftRng;

use cctp_primitives::{
    proving_system::{
        error::ProvingSystemError,
        init::get_g1_committer_key,
        verifier::{
            ceased_sidechain_withdrawal::CSWProofUserInputs,
            certificate::CertificateProofUserInputs, verify_zendoo_proof,
        },
        ProvingSystem, ZendooProof, ZendooProverKey, ZendooVerifierKey,
    },
    utils::{
        commitment_tree::DataAccumulator, data_structures::BackwardTransfer, get_bt_merkle_root,
        serialization::*,
    },
};

use std::path::Path;

//*****************************Naive threshold sig circuit related functions************************

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(
    pks: &[SchnorrPk],
    threshold: u64,
) -> Result<FieldElement, Error> {
    let threshold_field = FieldElement::from(threshold);

    // pks must always be all present
    let mut h = FieldHash::init_constant_length(pks.len(), None);
    pks.iter().for_each(|pk| {
        h.update(pk.x);
    });
    let pks_hash = h
        .finalize()
        .map_err(|e| format!("Unable to compute pks hash: {:?}", e))?;

    let pks_threshold_hash = FieldHash::init_constant_length(2, None)
        .update(pks_hash)
        .update(threshold_field)
        .finalize()
        .map_err(|e| format!("Unable to compute pks_treshold_hash: {:?}", e))?;

    Ok(pks_threshold_hash)
}

//Compute and return (MR(bt_list), H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount, [H(custom_fields)]))
pub fn compute_msg_to_sign(
    sc_id: &FieldElement,
    epoch_number: u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
    bt_list: Vec<BackwardTransfer>,
    custom_fields: Option<Vec<FieldElement>>,
) -> Result<(FieldElement, FieldElement), Error> {
    let epoch_number = FieldElement::from(epoch_number);

    //Compute bt_list merkle_root
    let bt_list_opt = if !bt_list.is_empty() {
        Some(bt_list.as_slice())
    } else {
        None
    };
    let mr_bt = get_bt_merkle_root(bt_list_opt)
        .map_err(|e| format!("Backward transfer Merkle Root computation failed: {:?}", e))?;

    let fees_field_element = {
        let fes = DataAccumulator::init()
            .update(btr_fee)
            .map_err(|e| format!("Unable to update DataAccumulator with btr_fee: {:?}", e))?
            .update(ft_min_amount)
            .map_err(|e| {
                format!(
                    "Unable to update DataAccumulator with ft_min_amount: {:?}",
                    e
                )
            })?
            .get_field_elements()
            .map_err(|e| format!("Unable to finalize DataAccumulator {:?}", e))?;
        assert_eq!(fes.len(), 1);
        fes[0]
    };

    // Compute custom_fields_hash if they are present
    let custom_fields_hash = if let Some(custom_fields) = custom_fields {
        let mut h = FieldHash::init_constant_length(custom_fields.len(), None);
        custom_fields.into_iter().for_each(|custom_field| {
            h.update(custom_field);
        });
        Some(
            h.finalize()
                .map_err(|e| format!("Unable to compute custom_fields_hash: {:?}", e))?,
        )
    } else {
        None
    };

    //Compute message to be verified
    let mut h =
        FieldHash::init_constant_length(5 + if custom_fields_hash.is_some() { 1 } else { 0 }, None);

    h.update(*sc_id)
        .update(epoch_number)
        .update(mr_bt)
        .update(*end_cumulative_sc_tx_comm_tree_root)
        .update(fees_field_element);

    if let Some(custom_fields_hash) = custom_fields_hash {
        h.update(custom_fields_hash);
    }

    let msg = h
        .finalize()
        .map_err(|e| format!("Unable to compute final hash: {:?}", e))?;

    Ok((mr_bt, msg))
}

fn get_naive_threshold_sig_circuit_prover_data(
    pks: &[SchnorrPk],
    mut sigs: Vec<Option<SchnorrSig>>,
    sc_id: &FieldElement,
    epoch_number: u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
    bt_list: Vec<BackwardTransfer>,
    threshold: u64,
    custom_fields: Option<Vec<FieldElement>>,
) -> Result<(NaiveTresholdSignature, u64), Error> {
    //Get max pks
    let max_pks = pks.len();
    assert_eq!(sigs.len(), max_pks);

    // Compute msg to sign
    let (mr_bt, msg) = compute_msg_to_sign(
        sc_id,
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        btr_fee,
        ft_min_amount,
        bt_list,
        custom_fields.clone(),
    )
    .map_err(|e| format!("Unable to compute msg_to_sign: {:?}", e))?;

    // Iterate over sigs, check and count number of valid signatures,
    // and replace with NULL_CONST.null_sig the None ones
    let mut valid_signatures = 0;
    for i in 0..max_pks {
        if sigs[i].is_some() {
            let is_verified = schnorr_verify_signature(&msg, &pks[i], &sigs[i].unwrap())
                .map_err(|e| format!("Unable to verify signature {}: {:?}", i, e))?;
            if is_verified {
                valid_signatures += 1;
            }
        } else {
            sigs[i] = Some(NULL_CONST.null_sig)
        }
    }

    //Compute b as v-t and convert it to field element
    let b = FieldElement::from(valid_signatures - threshold);

    //Convert affine pks to projective
    let pks = pks
        .iter()
        .map(|&pk| FieldBasedSchnorrPk(pk.into_projective()))
        .collect::<Vec<_>>();

    //Convert needed variables into field elements
    let threshold = FieldElement::from(threshold);

    let c = NaiveTresholdSignature::new(
        pks,
        sigs,
        threshold,
        b,
        *sc_id,
        FieldElement::from(epoch_number),
        *end_cumulative_sc_tx_comm_tree_root,
        mr_bt,
        ft_min_amount,
        btr_fee,
        max_pks,
        valid_signatures,
        custom_fields,
    );

    Ok((c, valid_signatures))
}

pub fn debug_naive_threshold_sig_circuit(
    pks: &[SchnorrPk],
    sigs: Vec<Option<SchnorrSig>>,
    sc_id: &FieldElement,
    epoch_number: u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
    bt_list: Vec<BackwardTransfer>,
    threshold: u64,
    custom_fields: Option<Vec<FieldElement>>,
) -> Result<Option<String>, Error> {
    let (c, _) = get_naive_threshold_sig_circuit_prover_data(
        pks,
        sigs,
        sc_id,
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        btr_fee,
        ft_min_amount,
        bt_list,
        threshold,
        custom_fields,
    )
    .map_err(|e| {
        format!(
            "Unable to create concrete instance of NaiveThresholdSignature circuit: {:?}",
            e
        )
    })?;

    let failing_constraint = debug_circuit(c)
        .map_err(|e| format!("Unable to debug received instance of CSW circuit: {:?}", e))?;

    Ok(failing_constraint)
}

pub fn create_naive_threshold_sig_proof(
    pks: &[SchnorrPk],
    sigs: Vec<Option<SchnorrSig>>,
    sc_id: &FieldElement,
    epoch_number: u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
    bt_list: Vec<BackwardTransfer>,
    threshold: u64,
    custom_fields: Option<Vec<FieldElement>>,
    supported_degree: Option<usize>, //TODO: We can probably read segment size from the ProverKey and save passing this additional parameter.
    proving_key_path: &Path,
    enforce_membership: bool,
    zk: bool,
    compressed_pk: bool,
    compress_proof: bool,
) -> Result<(Vec<u8>, u64), Error> {
    let (c, valid_signatures) = get_naive_threshold_sig_circuit_prover_data(
        pks,
        sigs,
        sc_id,
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        btr_fee,
        ft_min_amount,
        bt_list,
        threshold,
        custom_fields,
    )
    .map_err(|e| {
        format!(
            "Unable to create concrete instance of NaiveThresholdSignature circuit: {:?}",
            e
        )
    })?;

    let pk: ZendooProverKey = read_from_file(
        proving_key_path,
        Some(enforce_membership),
        Some(compressed_pk),
    )
    .map_err(|e| {
        format!(
            "Unable to read proving key from file {:?}: {:?}. Semantic checks: {}, Compressed: {}",
            proving_key_path, e, enforce_membership, compressed_pk
        )
    })?;

    let g1_ck = get_g1_committer_key(supported_degree).map_err(|e| {
        format!(
            "Unable to get DLOG key of degree {:?}: {:?}",
            supported_degree, e
        )
    })?;

    let proof = match pk {
        ZendooProverKey::Darlin(_) => unimplemented!(),
        ZendooProverKey::CoboundaryMarlin(pk) => {
            // Call prover
            let rng = &mut OsRng;
            let proof =
                CoboundaryMarlin::prove(&pk, &g1_ck, c, zk, if zk { Some(rng) } else { None })
                    .map_err(|e| format!("Error during proof creation: {:?}", e))?;
            serialize_to_buffer(
                &ZendooProof::CoboundaryMarlin(MarlinProof(proof)),
                Some(compress_proof),
            )
            .map_err(|e| {
                format!(
                    "Proof serialization (compressed: {}) failed: {:?}",
                    compress_proof, e
                )
            })?
        }
    };
    Ok((proof, valid_signatures))
}

pub fn verify_naive_threshold_sig_proof(
    constant: &FieldElement,
    sc_id: &FieldElement,
    epoch_number: u32,
    end_cumulative_sc_tx_commitment_tree_root: &FieldElement,
    btr_fee: u64,
    ft_min_amount: u64,
    bt_list: Vec<BackwardTransfer>,
    valid_sigs: u64,
    custom_fields: Vec<FieldElement>,
    proof: Vec<u8>,
    check_proof: bool,
    compressed_proof: bool,
    vk_path: &Path,
    check_vk: bool,
    compressed_vk: bool,
) -> Result<bool, Error> {
    let bt_list_opt = if !bt_list.is_empty() {
        Some(bt_list.as_slice())
    } else {
        None
    };

    let ins = CertificateProofUserInputs {
        constant: Some(constant),
        sc_id,
        epoch_number,
        quality: valid_sigs,
        bt_list: bt_list_opt,
        custom_fields: if custom_fields.is_empty() {
            None
        } else {
            Some(custom_fields.iter().collect())
        },
        end_cumulative_sc_tx_commitment_tree_root,
        btr_fee,
        ft_min_amount,
    };

    // Check that the proving system type of the vk and proof are the same, before
    // deserializing them all
    let vk_ps_type = read_from_file::<ProvingSystem>(vk_path, None, None).map_err(|e| {
        format!(
            "Unable to read proving system type from vk at {:?}: {:?}",
            vk_path, e
        )
    })?;

    let proof_ps_type = deserialize_from_buffer::<ProvingSystem>(&proof[..1], None, None)
        .map_err(|e| format!("Unable to read proving system type from proof: {:?}", e))?;

    if vk_ps_type != proof_ps_type {
        return Err(ProvingSystemError::ProvingSystemMismatch.into());
    }

    // Deserialize proof and vk
    let vk: ZendooVerifierKey = read_from_file(vk_path, Some(check_vk), Some(compressed_vk))
        .map_err(|e| {
            format!(
                "Unable to read vk at {:?}: {:?}. Semantic checks: {}, Compressed: {}",
                vk_path, e, check_vk, compressed_vk
            )
        })?;

    let proof: ZendooProof =
        deserialize_from_buffer(proof.as_slice(), Some(check_proof), Some(compressed_proof))
            .map_err(|e| {
                format!(
                    "Unable to read proof: {:?}. Semantic checks: {}, Compressed: {}",
                    e, check_proof, compressed_proof
                )
            })?;

    // Verify proof
    let rng = &mut OsRng;
    let is_verified = verify_zendoo_proof(ins, &proof, &vk, Some(rng))
        .map_err(|e| format!("Proof verification error: {:?}", e))?;

    Ok(is_verified)
}

// ******************************* CSW Proof ***************************
pub fn debug_csw_circuit(
    sidechain_id: FieldElement,
    constant: Option<FieldElement>,
    sys_data: CswSysData,
    last_wcert: Option<WithdrawalCertificateData>,
    utxo_data: Option<CswUtxoProverData>,
    ft_data: Option<CswFtProverData>,
    range_size: u32,
    num_custom_fields: u32,
) -> Result<Option<String>, Error> {
    let c = CeasedSidechainWithdrawalCircuit::new(
        sidechain_id,
        constant,
        sys_data,
        last_wcert,
        utxo_data,
        ft_data,
        range_size,
        num_custom_fields,
    )
    .map_err(|e| format!("Unable to create concrete instance of CSW circuit: {:?}", e))?;

    let failing_constraint = debug_circuit(c)
        .map_err(|e| format!("Unable to debug received instance of CSW circuit: {:?}", e))?;

    Ok(failing_constraint)
}

pub fn create_csw_proof(
    sidechain_id: FieldElement,
    constant: Option<FieldElement>,
    sys_data: CswSysData,
    last_wcert: Option<WithdrawalCertificateData>,
    utxo_data: Option<CswUtxoProverData>,
    ft_data: Option<CswFtProverData>,
    range_size: u32,
    num_custom_fields: u32,
    supported_degree: Option<usize>, //TODO: We can probably read segment size from the ProverKey and save passing this additional parameter.
    proving_key_path: &Path,
    enforce_membership: bool,
    zk: bool,
    compressed_pk: bool,
    compress_proof: bool,
) -> Result<Vec<u8>, Error> {
    let c = CeasedSidechainWithdrawalCircuit::new(
        sidechain_id,
        constant,
        sys_data,
        last_wcert,
        utxo_data,
        ft_data,
        range_size,
        num_custom_fields,
    )
    .map_err(|e| format!("Unable to create concrete instance of CSW circuit: {:?}", e))?;

    let pk: ZendooProverKey = read_from_file(
        proving_key_path,
        Some(enforce_membership),
        Some(compressed_pk),
    )
    .map_err(|e| {
        format!(
            "Unable to read proving key from file {:?}: {:?}. Semantic checks: {}, Compressed: {}",
            proving_key_path, e, enforce_membership, compressed_pk
        )
    })?;

    let g1_ck = get_g1_committer_key(supported_degree).map_err(|e| {
        format!(
            "Unable to get DLOG key of degree {:?}: {:?}",
            supported_degree, e
        )
    })?;

    let proof = match pk {
        ZendooProverKey::Darlin(_) => unimplemented!(),
        ZendooProverKey::CoboundaryMarlin(pk) => {
            // Call prover
            let rng = &mut OsRng;
            let proof =
                CoboundaryMarlin::prove(&pk, &g1_ck, c, zk, if zk { Some(rng) } else { None })
                    .map_err(|e| format!("Error during proof creation: {:?}", e))?;
            serialize_to_buffer(
                &ZendooProof::CoboundaryMarlin(MarlinProof(proof)),
                Some(compress_proof),
            )
            .map_err(|e| {
                format!(
                    "Proof serialization (compressed: {}) failed: {:?}",
                    compress_proof, e
                )
            })?
        }
    };

    Ok(proof)
}

pub fn verify_csw_proof(
    sc_id: &FieldElement,
    constant: Option<FieldElement>,
    sys_data: CswSysData,
    proof: Vec<u8>,
    check_proof: bool,
    compressed_proof: bool,
    vk_path: &Path,
    check_vk: bool,
    compressed_vk: bool,
) -> Result<bool, Error> {
    let ins = CSWProofUserInputs {
        amount: sys_data.amount,
        constant: constant.as_ref(),
        sc_id,
        nullifier: &sys_data.nullifier,
        pub_key_hash: &sys_data.receiver,
        cert_data_hash: &sys_data.sc_last_wcert_hash,
        end_cumulative_sc_tx_commitment_tree_root: &sys_data.mcb_sc_txs_com_end,
    };

    // Check that the proving system type of the vk and proof are the same, before
    // deserializing them all
    let vk_ps_type = read_from_file::<ProvingSystem>(vk_path, None, None).map_err(|e| {
        format!(
            "Unable to read proving system type from vk at {:?}: {:?}",
            vk_path, e
        )
    })?;

    let proof_ps_type = deserialize_from_buffer::<ProvingSystem>(&proof[..1], None, None)
        .map_err(|e| format!("Unable to read proving system type from proof: {:?}", e))?;

    if vk_ps_type != proof_ps_type {
        return Err(ProvingSystemError::ProvingSystemMismatch.into());
    }

    // Deserialize proof and vk
    let vk: ZendooVerifierKey = read_from_file(vk_path, Some(check_vk), Some(compressed_vk))
        .map_err(|e| {
            format!(
                "Unable to read vk at {:?}: {:?}. Semantic checks: {}, Compressed: {}",
                vk_path, e, check_vk, compressed_vk
            )
        })?;

    let proof: ZendooProof =
        deserialize_from_buffer(proof.as_slice(), Some(check_proof), Some(compressed_proof))
            .map_err(|e| {
                format!(
                    "Unable to read proof: {:?}. Semantic checks: {}, Compressed: {}",
                    e, check_proof, compressed_proof
                )
            })?;

    // Verify proof
    let rng = &mut OsRng;
    let is_verified = verify_zendoo_proof(ins, &proof, &vk, Some(rng))
        .map_err(|e| format!("Proof verification error: {:?}", e))?;

    Ok(is_verified)
}