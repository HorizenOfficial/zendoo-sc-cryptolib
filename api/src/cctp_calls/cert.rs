use super::*;

use cctp_primitives::{
    proving_system::verifier::certificate::CertificateProofUserInputs,
    utils::{
        data_structures::BackwardTransfer, get_bt_merkle_root,
    },
};


//*****************************Naive threshold sig circuit related functions************************

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(
    pks: &[SchnorrPk],
    threshold: u64,
) -> Result<FieldElement, Error> {
    let threshold_field = FieldElement::from(threshold);

    // pks must always be all present
    let mut h = get_poseidon_hash_constant_length(pks.len(), None);
    pks.iter().for_each(|pk| {
        update_poseidon_hash(&mut h, &pk.x)
    });
    let pks_hash = finalize_poseidon_hash(&mut h)
        .map_err(|e| format!("Unable to compute pks hash: {:?}", e))?;

    let mut h = get_poseidon_hash_constant_length(2, None);
    update_poseidon_hash(&mut h, &pks_hash);
    update_poseidon_hash(&mut h, &threshold_field);
    Ok(
        finalize_poseidon_hash(&mut h)
            .map_err(|e| format!("Unable to compute pks_treshold_hash: {:?}", e))?
    )
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
        let mut h = get_poseidon_hash_constant_length(custom_fields.len(), None);
        custom_fields.into_iter().for_each(|custom_field| {
            update_poseidon_hash(&mut h, &custom_field)
        });
        Some(
            finalize_poseidon_hash(&mut h)
                .map_err(|e| format!("Unable to compute custom_fields_hash: {:?}", e))?,
        )
    } else {
        None
    };

    //Compute message to be verified
    let mut h =
        get_poseidon_hash_constant_length(5 + if custom_fields_hash.is_some() { 1 } else { 0 }, None);

    update_poseidon_hash(&mut h, sc_id);
    update_poseidon_hash(&mut h, &epoch_number);
    update_poseidon_hash(&mut h, &mr_bt);
    update_poseidon_hash(&mut h, end_cumulative_sc_tx_comm_tree_root);
    update_poseidon_hash(&mut h, &fees_field_element);

    if let Some(custom_fields_hash) = custom_fields_hash {
        update_poseidon_hash(&mut h, &custom_fields_hash);
    }

    let msg = finalize_poseidon_hash(&mut h)
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
        .copied()
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
    proving_key_path: &str,
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
    vk_path: &str,
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