use algebra::{AffineCurve, ProjectiveCurve, UniformRand};
use blake2::digest::{FixedOutput, Input};
use demo_circuit::{
    blaze_csw::{
        constraints::CeasedSidechainWithdrawalCircuit, 
        data_structures::{CswFtProverData, CswSysData, CswUtxoProverData}
    },
    constants::VRFParams,
    create_msg_to_sign, naive_threshold_sig::*, naive_threshold_sig_w_key_rotation::{*, data_structures::ValidatorKeysUpdates},
    type_mapping::*, common::{NULL_CONST, WithdrawalCertificateData}, sc2sc::{Sc2Sc, ScCommitmentCertPath, Sc2ScUserInput}, 
};
use lazy_static::*;
use primitives::{
    crh::{bowe_hopwood::BoweHopwoodPedersenParameters, FieldBasedHash},
    signature::{schnorr::field_based_schnorr::FieldBasedSchnorrPk, FieldBasedSignatureScheme},
    vrf::{ecvrf::FieldBasedEcVrfPk, FieldBasedVrf},
};
use r1cs_core::{debug_circuit, ConstraintSynthesizer};
use rand::{rngs::OsRng, CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rand_xorshift::XorShiftRng;
use std::convert::{TryFrom, TryInto};

use cctp_primitives::{
    proving_system::{
        error::ProvingSystemError,
        init::get_g1_committer_key,
        verifier::{
            ceased_sidechain_withdrawal::CSWProofUserInputs,
            certificate::CertificateProofUserInputs, verify_zendoo_proof, UserInputs,
        },
        ProvingSystem, ZendooProof, ZendooProverKey, ZendooVerifierKey,
    },
    utils::{
        commitment_tree::hash_vec, data_structures::BackwardTransfer, get_bt_merkle_root,
        serialization::*,
    },
};

use cctp_primitives::proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH;
use cctp_primitives::utils::get_cert_data_hash_from_bt_root_and_custom_fields_hash;
use std::path::Path;

//*******************************Generic functions**********************************************

// NOTE: This function relies on a non-cryptographically safe RNG, therefore it
// must be used ONLY for testing purposes
pub fn get_random_field_element(seed: u64) -> FieldElement {
    let mut rng = XorShiftRng::seed_from_u64(seed);
    FieldElement::rand(&mut rng)
}

//***************************Schnorr types and functions********************************************

pub fn schnorr_generate_key() -> (SchnorrPk, SchnorrSk) {
    let mut rng = OsRng;
    schnorr_generate_key_from_rng(&mut rng)
}

pub fn schnorr_get_public_key(sk: &SchnorrSk) -> SchnorrPk {
    SchnorrSigScheme::get_public_key(sk).0.into_affine()
}

pub fn schnorr_verify_public_key(pk: &SchnorrPk) -> bool {
    SchnorrSigScheme::keyverify(&FieldBasedSchnorrPk(pk.into_projective()))
}

pub fn schnorr_sign(
    msg: &FieldElement,
    sk: &SchnorrSk,
    pk: &SchnorrPk,
) -> Result<SchnorrSig, Error> {
    let mut rng = OsRng;
    SchnorrSigScheme::sign(
        &mut rng,
        &FieldBasedSchnorrPk(pk.into_projective()),
        sk,
        *msg,
    )
}

pub fn schnorr_verify_signature(
    msg: &FieldElement,
    pk: &SchnorrPk,
    signature: &SchnorrSig,
) -> Result<bool, Error> {
    SchnorrSigScheme::verify(&FieldBasedSchnorrPk(pk.into_projective()), *msg, signature)
}

/// Derive key from seed. It's caller responsibility to pass a seed of proper length.
pub fn schnorr_derive_key_from_seed(seed: &[u8]) -> (SchnorrPk, SchnorrSk) {
    // zero just default to random,
    if seed.is_empty() {
        return schnorr_generate_key();
    }

    // Domain separation tag
    const DST: &[u8] = &[0xFFu8; 32];

    // Hash first to ensure size an eliminate any bias
    // that may exist in `seed`
    let mut hasher = blake2::Blake2b::default();
    hasher.input(DST);
    hasher.input(seed);
    let digest = hasher.fixed_result();
    let rng_seed = <[u8; 32]>::try_from(&digest[..32]).unwrap();
    let mut rng = ChaChaRng::from_seed(rng_seed);
    schnorr_generate_key_from_rng(&mut rng)
}

fn schnorr_generate_key_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> (SchnorrPk, SchnorrSk) {
    let (pk, sk) = SchnorrSigScheme::keygen(rng);
    (pk.0.into_affine(), sk)
}

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
    //Compute bt_list merkle_root
    let bt_list_opt = if !bt_list.is_empty() {
        Some(bt_list.as_slice())
    } else {
        None
    };
    let mr_bt = get_bt_merkle_root(bt_list_opt)
        .map_err(|e| format!("Backward transfer Merkle Root computation failed: {:?}", e))?;

    let msg = create_msg_to_sign(
        sc_id,
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        btr_fee,
        ft_min_amount,
        &mr_bt,
        custom_fields,
    )?;

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
) -> Result<(NaiveThresholdSignature, u64), Error> {
    //Get max pks
    let max_pks = pks.len();
    if max_pks != sigs.len() {
        Err("number of public keys different from number of signatures")?
    }

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
    let b = FieldElement::from(valid_signatures) - FieldElement::from(threshold);

    //Convert affine pks to projective
    let pks = pks
        .iter()
        .map(|&pk| FieldBasedSchnorrPk(pk.into_projective()))
        .collect::<Vec<_>>();

    //Convert needed variables into field elements
    let threshold = FieldElement::from(threshold);

    let c = NaiveThresholdSignature::new(
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

pub fn debug_naive_threshold_sig_w_key_rotation_circuit(
    validator_keys_updates: ValidatorKeysUpdates,
    sigs: Vec<Option<SchnorrSig>>,
    withdrawal_certificate: WithdrawalCertificateData,
    prev_withdrawal_certificate: Option<WithdrawalCertificateData>,
    threshold: u64,
    genesis_key_root_hash: &FieldElement,
) -> Result<Option<String>, Error> {
    let c = NaiveThresholdSignatureWKeyRotation::new(
        validator_keys_updates,
        sigs,
        withdrawal_certificate,
        prev_withdrawal_certificate,
        threshold,
        *genesis_key_root_hash,
    )
    .map_err(|e| {
        format!(
            "Unable to create concrete instance of NaiveThresholdSignatureWKeyRotation circuit: {:?}",
            e
        )
    })?;

    let failing_constraint = debug_circuit(c)
        .map_err(|e| format!("Unable to debug received instance of NaiveThresholdSignatureWKeyRotation circuit: {:?}", e))?;

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
    semantic_checks: bool,
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

    check_and_generate_proof_raw(c, 
        supported_degree,
        proving_key_path,
        semantic_checks,
        zk,
        compressed_pk,
        compress_proof,
    ).map(|proof| (proof, valid_signatures as u64))
}

pub fn create_naive_threshold_sig_w_key_rotation_proof(
    validator_keys_updates: ValidatorKeysUpdates,
    sigs: Vec<Option<SchnorrSig>>,
    withdrawal_certificate: WithdrawalCertificateData,
    prev_withdrawal_certificate: Option<WithdrawalCertificateData>,
    threshold: u64,
    genesis_key_root_hash: &FieldElement,
    supported_degree: Option<usize>, //TODO: We can probably read segment size from the ProverKey and save passing this additional parameter.
    proving_key_path: &Path,
    semantic_checks: bool,
    zk: bool,
    compressed_pk: bool,
    compress_proof: bool,
) -> Result<(Vec<u8>, u64), Error> {
    let c = NaiveThresholdSignatureWKeyRotation::new(
        validator_keys_updates,
        sigs,
        withdrawal_certificate,
        prev_withdrawal_certificate,
        threshold,
        *genesis_key_root_hash,
    )
    .map_err(|e| {
        format!(
            "Unable to create concrete instance of NaiveThresholdSignatureWKeyRotation circuit: {:?}",
            e
        )
    })?;
    let valid_signatures = c.get_valid_signatures();
    check_and_generate_proof_raw(c, 
        supported_degree,
        proving_key_path,
        semantic_checks,
        zk,
        compressed_pk,
        compress_proof,
    ).map(|proof| (proof, valid_signatures as u64))
}

fn check_and_generate_proof_raw<C: ConstraintSynthesizer<FieldElement>>(
    circuit: C,
    supported_degree: Option<usize>, //TODO: We can probably read segment size from the ProverKey and save passing this additional parameter.
    proving_key_path: &Path,
    semantic_checks: bool,
    zk: bool,
    compressed_pk: bool,
    compress_proof: bool,
) -> Result<Vec<u8>, Error> {
    let pk: ZendooProverKey = read_from_file(
        proving_key_path,
        Some(semantic_checks),
        Some(compressed_pk),
    )
    .map_err(|e| {
        format!(
            "Unable to read proving key from file {:?}: {:?}. Semantic checks: {}, Compressed: {}",
            proving_key_path, e, semantic_checks, compressed_pk
        )
    })?;

    let g1_ck = get_g1_committer_key(supported_degree).map_err(|e| {
        format!(
            "Unable to get DLOG key of degree {:?}: {:?}",
            supported_degree, e
        )
    })?;

    match pk {
        ZendooProverKey::Darlin(_) => unimplemented!(),
        ZendooProverKey::CoboundaryMarlin(pk) => {
            // Call prover
            let rng = &mut OsRng;
            let proof =
                CoboundaryMarlin::prove(&pk, &g1_ck, circuit, zk, if zk { Some(rng) } else { None })
                    .map_err(|e| format!("Error during proof creation: {:?}", e))?;
            serialize_to_buffer(
                &ZendooProof::CoboundaryMarlin(MarlinProof(proof)),
                Some(compress_proof),
            )
            .map_err(|e| {
                format!(
                    "Proof serialization (compressed: {}) failed: {:?}",
                    compress_proof, e
                ).into()
            })
        }
    }
}

pub fn create_native_sc2sc_proof(
    next_sc_tx_commitments_root: FieldElement,
    curr_sc_tx_commitments_root: FieldElement,
    msg_hash: FieldElement,
    next_withdrawal_certificate: WithdrawalCertificateData,
    curr_withdrawal_certificate: WithdrawalCertificateData,
    next_cert_commitment_path: ScCommitmentCertPath,
    curr_cert_commitment_path: ScCommitmentCertPath,
    msg_path: GingerMHTPath,
    supported_degree: Option<usize>, //TODO: We can probably read segment size from the ProverKey and save passing this additional parameter.
    proving_key_path: &Path,
    semantic_checks: bool,
    zk: bool,
    compressed_pk: bool,
    compress_proof: bool,
) -> Result<Vec<u8>, Error> {
    let c = Sc2Sc::new(
        next_sc_tx_commitments_root,
        curr_sc_tx_commitments_root,
        msg_hash,
        next_withdrawal_certificate,
        curr_withdrawal_certificate,
        next_cert_commitment_path,
        curr_cert_commitment_path,
        msg_path.try_into()?
    );

    check_and_generate_proof_raw(c, 
        supported_degree,
        proving_key_path,
        semantic_checks,
        zk,
        compressed_pk,
        compress_proof,
    )
}

fn verify_proof(ui: impl UserInputs, proof: Vec<u8>,
    check_proof: bool,
    compressed_proof: bool,
    vk_path: &Path,
    check_vk: bool,
    compressed_vk: bool) -> Result<bool, Error> {

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

    verify_zendoo_proof(ui, &proof, &vk, Some(rng))
        .map_err(|e| format!("Proof verification error: {:?}", e).into())
}

pub fn verify_sc2sc_proof(
    next_sc_tx_commitments_root: FieldElement,
    curr_sc_tx_commitments_root: FieldElement,
    msg_hash: FieldElement,
    proof: Vec<u8>,
    check_proof: bool,
    compressed_proof: bool,
    vk_path: &Path,
    check_vk: bool,
    compressed_vk: bool,
) -> Result<bool, Error> {
    verify_proof(
        Sc2ScUserInput::new(
            next_sc_tx_commitments_root, 
            curr_sc_tx_commitments_root, 
            msg_hash),
            proof,check_proof, compressed_proof, 
            vk_path, check_vk, compressed_vk)
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
        sc_prev_wcert_hash: None,
    };

    verify_proof(ins, proof,check_proof, compressed_proof, 
            vk_path, check_vk, compressed_vk)
}

pub fn verify_naive_threshold_sig_w_key_rotation_proof(
    withdrawal_certificate: WithdrawalCertificateData,
    prev_withdrawal_certificate: Option<WithdrawalCertificateData>,
    bt_list: Vec<BackwardTransfer>,
    constant: &FieldElement,
    proof: Vec<u8>,
    check_proof: bool,
    compressed_proof: bool,
    vk_path: &Path,
    check_vk: bool,
    compressed_vk: bool,
) -> Result<bool, Error> {
    let prev_cert_data_hash = if let Some(cert) = prev_withdrawal_certificate {
        let custom_fields_hash = if !cert.custom_fields.is_empty() {
            Some(hash_vec(cert.custom_fields)?)
        } else {
            None
        };
        get_cert_data_hash_from_bt_root_and_custom_fields_hash(
            &cert.ledger_id,
            cert.epoch_id,
            cert.quality,
            cert.bt_root,
            custom_fields_hash,
            &cert.mcb_sc_txs_com,
            cert.btr_min_fee,
            cert.ft_min_amount,
        )?
    } else {
        PHANTOM_CERT_DATA_HASH
    };

    let custom_fields: Option<Vec<&FieldElement>> =
        Some(withdrawal_certificate.custom_fields.iter().collect());

    let ins = CertificateProofUserInputs {
        constant: Some(constant),
        sc_id: &withdrawal_certificate.ledger_id,
        epoch_number: withdrawal_certificate.epoch_id,
        quality: withdrawal_certificate.quality,
        bt_list: Some(&bt_list),
        custom_fields,
        end_cumulative_sc_tx_commitment_tree_root: &withdrawal_certificate.mcb_sc_txs_com,
        btr_fee: withdrawal_certificate.btr_min_fee,
        ft_min_amount: withdrawal_certificate.ft_min_amount,
        sc_prev_wcert_hash: Some(&prev_cert_data_hash),
    };

    verify_proof(ins, proof,check_proof, compressed_proof, 
        vk_path, check_vk, compressed_vk)
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
    semantic_checks: bool,
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

    check_and_generate_proof_raw(c, 
        supported_degree,
        proving_key_path,
        semantic_checks,
        zk,
        compressed_pk,
        compress_proof,
    )
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

    verify_proof(ins, proof,check_proof, compressed_proof, 
        vk_path, check_vk, compressed_vk)
}

//VRF types and functions

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<G2Projective> = {
        let params = VRFParams::new();
        GroupHash::setup_from_generators(
            params.group_hash_generators,
        ).unwrap()
    };
}

pub fn vrf_generate_key() -> (VRFPk, VRFSk) {
    let mut rng = OsRng;
    vrf_generate_key_from_rng(&mut rng)
}

pub fn vrf_get_public_key(sk: &VRFSk) -> VRFPk {
    VRFScheme::get_public_key(sk).0.into_affine()
}

pub fn vrf_verify_public_key(pk: &VRFPk) -> bool {
    VRFScheme::keyverify(&FieldBasedEcVrfPk(pk.into_projective()))
}

pub fn vrf_prove(
    msg: &FieldElement,
    sk: &VRFSk,
    pk: &VRFPk,
) -> Result<(VRFProof, FieldElement), Error> {
    let mut rng = OsRng;

    //Compute proof
    let proof = VRFScheme::prove(
        &mut rng,
        &VRF_GH_PARAMS,
        &FieldBasedEcVrfPk(pk.into_projective()),
        sk,
        *msg,
    )?;
    //Compute VRF output
    let output = VRFScheme::proof_to_hash(*msg, &proof)?;

    Ok((proof, output))
}

pub fn vrf_verify(
    msg: &FieldElement,
    pk: &VRFPk,
    proof: &VRFProof,
) -> Result<FieldElement, Error> {
    VRFScheme::verify(
        &VRF_GH_PARAMS,
        &FieldBasedEcVrfPk(pk.into_projective()),
        *msg,
        proof,
    )
}

/// Derive key from seed. It's caller responsibility to pass a seed of proper length.
pub fn vrf_derive_key_from_seed(seed: &[u8]) -> (VRFPk, VRFSk) {
    // zero just default to random,
    if seed.is_empty() {
        return vrf_generate_key();
    }

    // Domain separation tag
    const DST: &[u8] = &[0xFEu8; 32];

    // Hash first to ensure size an eliminate any bias
    // that may exist in `seed`
    let mut hasher = blake2::Blake2b::default();
    hasher.input(DST);
    hasher.input(seed);
    let digest = hasher.fixed_result();
    let rng_seed = <[u8; 32]>::try_from(&digest[..32]).unwrap();
    let mut rng = ChaChaRng::from_seed(rng_seed);
    vrf_generate_key_from_rng(&mut rng)
}

fn vrf_generate_key_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> (VRFPk, VRFSk) {
    let (pk, sk) = VRFScheme::keygen(rng);
    (pk.0.into_affine(), sk)
}

// Test functions

pub(crate) fn into_i8(v: Vec<u8>) -> Vec<i8> {
    // first, make sure v's destructor doesn't free the data
    // it thinks it owns when it goes out of scope
    let mut v = std::mem::ManuallyDrop::new(v);

    // then, pick apart the existing Vec
    let p = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();

    // finally, adopt the data into a new Vec
    unsafe { Vec::from_raw_parts(p as *mut i8, len, cap) }
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::Field;
    use cctp_primitives::utils::{mht::*, poseidon_hash::*};
    use serial_test::*;

    #[serial]
    #[test]
    fn sample_calls_schnorr_sig_prove_verify() {
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);
        {
            let msg_bytes = serialize_to_buffer(&msg, None).unwrap();
            println!("msg bytes: {:?}", into_i8(msg_bytes));
        }

        let (pk, sk) = schnorr_generate_key(); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let pk_serialized = serialize_to_buffer(&pk, Some(true)).unwrap();
        assert_eq!(pk_serialized.len(), SCHNORR_PK_SIZE);
        let pk_deserialized: SchnorrPk =
            deserialize_from_buffer(&pk_serialized, Some(true), Some(true)).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let sk_serialized = serialize_to_buffer(&sk, None).unwrap();
        assert_eq!(sk_serialized.len(), SCHNORR_SK_SIZE);
        println!("sk bytes: {:?}", into_i8(sk_serialized.clone()));
        let sk_deserialized = deserialize_from_buffer(&sk_serialized, None, None).unwrap();
        assert_eq!(sk, sk_deserialized);

        let sig = schnorr_sign(&msg, &sk, &pk).unwrap(); //Sign msg
        assert!(is_valid(&sig));

        //Serialize/deserialize sig
        let sig_serialized = serialize_to_buffer(&sig, None).unwrap();
        println!("sig bytes: {:?}", into_i8(sig_serialized.clone()));
        assert_eq!(sig_serialized.len(), SCHNORR_SIG_SIZE);
        let sig_deserialized = deserialize_from_buffer(&sig_serialized, Some(true), None).unwrap();
        assert_eq!(sig, sig_deserialized);

        assert!(schnorr_verify_signature(&msg, &pk, &sig).unwrap()); //Verify sig

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(!schnorr_verify_signature(&wrong_msg, &pk, &sig).unwrap());
    }

    #[serial]
    #[test]
    fn sample_calls_schnorr_derive_from_seed() {
        let (pk, sk) = schnorr_derive_key_from_seed(&[1u8; 32]); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk

        let buffer = serialize_to_buffer(&pk, Some(true)).unwrap();
        assert_eq!(
            vec![
                94, 177, 202, 201, 84, 192, 33, 180, 36, 187, 196, 225, 147, 79, 190, 169, 94, 160,
                22, 160, 98, 217, 221, 51, 44, 229, 124, 204, 2, 227, 154, 5, 0
            ],
            buffer
        );
        let buffer = serialize_to_buffer(&sk, Some(true)).unwrap();
        assert_eq!(
            vec![
                176, 141, 47, 233, 14, 73, 90, 250, 133, 0, 245, 33, 57, 188, 1, 150, 172, 209,
                144, 240, 138, 181, 98, 64, 52, 77, 171, 39, 8, 30, 154, 45
            ],
            buffer
        );

        let (pk, sk) = schnorr_derive_key_from_seed(&[]); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk
    }

    #[serial]
    #[test]
    fn sample_calls_vrf_prove_verify() {
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);
        {
            let msg_bytes = serialize_to_buffer(&msg, None).unwrap();
            println!("msg bytes: {:?}", into_i8(msg_bytes));
        }

        let (pk, sk) = vrf_generate_key(); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let pk_serialized = serialize_to_buffer(&pk, Some(true)).unwrap();
        assert_eq!(pk_serialized.len(), VRF_PK_SIZE);
        let pk_deserialized: VRFPk =
            deserialize_from_buffer(&pk_serialized, Some(true), Some(true)).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let sk_serialized = serialize_to_buffer(&sk, None).unwrap();
        assert_eq!(sk_serialized.len(), VRF_SK_SIZE);
        println!("sk bytes: {:?}", into_i8(sk_serialized.clone()));
        let sk_deserialized = deserialize_from_buffer(&sk_serialized, None, None).unwrap();
        assert_eq!(sk, sk_deserialized);

        let (vrf_proof, vrf_out) = vrf_prove(&msg, &sk, &pk).unwrap(); //Create vrf proof for msg
        assert!(is_valid(&vrf_proof));

        //Serialize/deserialize vrf proof
        let proof_serialized = serialize_to_buffer(&vrf_proof, Some(true)).unwrap();
        assert_eq!(proof_serialized.len(), VRF_PROOF_SIZE);
        println!("proof bytes: {:?}", into_i8(proof_serialized.clone()));
        let proof_deserialized =
            deserialize_from_buffer(&proof_serialized, Some(true), Some(true)).unwrap();
        assert_eq!(vrf_proof, proof_deserialized);

        //Serialize/deserialize vrf out (i.e. a field element)
        let vrf_out_serialized = serialize_to_buffer(&vrf_out, None).unwrap();
        println!("vrf out bytes: {:?}", into_i8(vrf_out_serialized.clone()));
        let vrf_out_deserialized =
            deserialize_from_buffer(&vrf_out_serialized, None, None).unwrap();
        assert_eq!(vrf_out, vrf_out_deserialized);

        let vrf_out_dup = vrf_verify(&msg, &pk, &vrf_proof).unwrap(); //Verify vrf proof and get vrf out for msg
        assert_eq!(vrf_out, vrf_out_dup);

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(vrf_verify(&wrong_msg, &pk, &vrf_proof).is_err());
    }

    #[serial]
    #[test]
    fn sample_calls_vrf_derive_from_seed() {
        let (pk, sk) = vrf_derive_key_from_seed(&[1u8; 32]); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk

        let buffer = serialize_to_buffer(&pk, Some(true)).unwrap();
        assert_eq!(
            vec![
                128, 191, 74, 210, 117, 186, 140, 139, 78, 124, 85, 185, 120, 198, 208, 89, 243,
                56, 108, 213, 212, 1, 108, 240, 55, 216, 253, 186, 130, 88, 235, 25, 128
            ],
            buffer
        );
        let buffer = serialize_to_buffer(&sk, Some(true)).unwrap();
        assert_eq!(
            vec![
                205, 235, 16, 65, 216, 239, 34, 146, 88, 211, 151, 125, 255, 226, 16, 87, 91, 125,
                179, 203, 231, 249, 219, 236, 121, 48, 63, 117, 137, 14, 167, 37
            ],
            buffer
        );

        let (pk, sk) = vrf_derive_key_from_seed(&[]); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk
    }

    #[serial]
    #[test]
    fn sample_calls_schnorr_vrf_derive_different_keys_from_same_seed() {
        const SEED: [u8; 32] = [7u8; 32];
        let (spk, ssk) = schnorr_derive_key_from_seed(&SEED); //Keygen
        let (vpk, vsk) = vrf_derive_key_from_seed(&SEED); //Keygen

        assert_ne!(vpk, spk);
        assert_ne!(vsk, ssk);
    }

    #[serial]
    #[test]
    fn sample_calls_merkle_path() {
        let height = 6;
        let leaves_num = 2usize.pow(height as u32);

        // Get GingerMHT
        let mut mht = new_ginger_mht(height, leaves_num).unwrap();

        // Add leaves
        let mut mht_leaves = Vec::with_capacity(leaves_num);
        for i in 0..leaves_num / 2 {
            let leaf = get_random_field_element(i as u64);
            mht_leaves.push(leaf);
            append_leaf_to_ginger_mht(&mut mht, &leaf).unwrap();
        }
        for _ in leaves_num / 2..leaves_num {
            mht_leaves.push(FieldElement::zero());
        }

        // Compute the root
        finalize_ginger_mht_in_place(&mut mht).unwrap();
        let mht_root = get_ginger_mht_root(&mht).expect("Tree must've been finalized");

        for (i, leaf) in mht_leaves.iter().enumerate().take(leaves_num) {
            //Create and verify merkle paths for each leaf
            let path = get_ginger_mht_path(&mht, i as u64).unwrap();
            assert!(verify_ginger_merkle_path_without_length_check(
                &path, leaf, &mht_root
            ));

            // Check leaf index is the correct one
            assert_eq!(i as u64, get_leaf_index_from_path(&path));

            if i == 0 {
                // leftmost check
                assert!(is_path_leftmost(&path));
            } else if i == (leaves_num / 2) - 1 {
                // non-empty rightmost check
                assert!(are_right_leaves_empty(&path));
            } else if i == leaves_num - 1 {
                //rightmost check
                assert!(is_path_rightmost(&path));
            } else {
                // Other cases check
                assert!(!is_path_leftmost(&path));
                assert!(!is_path_rightmost(&path));

                if i < (leaves_num / 2) - 1 {
                    assert!(!are_right_leaves_empty(&path));
                }
            }

            // Serialization/deserialization test
            let path_serialized = serialize_to_buffer(&path, None).unwrap();
            let path_deserialized: GingerMHTPath =
                deserialize_from_buffer(&path_serialized, Some(true), None).unwrap();
            assert_eq!(path, path_deserialized);
        }
    }

    #[serial]
    #[test]
    fn sample_calls_poseidon_hash() {
        let mut rng = OsRng;
        let hash_input = vec![FieldElement::rand(&mut rng); 2];
        let mut h = get_poseidon_hash_variable_length(false, None);

        //Compute poseidon hash
        update_poseidon_hash(&mut h, &hash_input[0]);
        update_poseidon_hash(&mut h, &hash_input[1]);
        let h_output = finalize_poseidon_hash(&h).unwrap();

        //Call to finalize keeps the state
        reset_poseidon_hash(&mut h, None);
        update_poseidon_hash(&mut h, &hash_input[0]);
        finalize_poseidon_hash(&h).unwrap(); //Call to finalize() keeps the state
        update_poseidon_hash(&mut h, &hash_input[1]);
        assert_eq!(h_output, finalize_poseidon_hash(&h).unwrap());

        //finalize() is idempotent
        assert_eq!(h_output, finalize_poseidon_hash(&h).unwrap());
    }
}
