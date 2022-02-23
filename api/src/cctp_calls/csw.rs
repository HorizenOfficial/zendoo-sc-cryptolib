use super::*;
use demo_circuit::{
    constraints::CeasedSidechainWithdrawalCircuit,
    CswFtProverData, CswSysData, CswUtxoProverData, WithdrawalCertificateData,
};
use cctp_primitives::proving_system::verifier::ceased_sidechain_withdrawal::CSWProofUserInputs;

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
    proving_key_path: &str,
    enforce_membership: bool,
    zk: bool,
    compressed_pk: bool,
) -> Result<ZendooProof, Error> {
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

    match pk {
        ZendooProverKey::Darlin(_) => unimplemented!(),
        ZendooProverKey::CoboundaryMarlin(pk) => {
            // Call prover
            let rng = &mut OsRng;
            let proof =
                CoboundaryMarlin::prove(&pk, &g1_ck, c, zk, if zk { Some(rng) } else { None })
                    .map_err(|e| format!("Error during proof creation: {:?}", e))?;
            Ok(ZendooProof::CoboundaryMarlin(MarlinProof(proof)))
        }
    }
}

pub fn verify_csw_proof(
    sc_id: &FieldElement,
    constant: Option<FieldElement>,
    sys_data: CswSysData,
    proof: Vec<u8>,
    check_proof: bool,
    compressed_proof: bool,
    vk_path: &str,
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