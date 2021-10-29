use algebra::AffineCurve;
use primitives::{crh::FieldBasedHash, signature::schnorr::field_based_schnorr::FieldBasedSchnorrPk
};
use demo_circuit::naive_threshold_sig::*;
use rand::rngs::OsRng;
use cctp_primitives::{
    proving_system::{
        init::get_g1_committer_key,
        verifier::{
            certificate::CertificateProofUserInputs, verify_zendoo_proof
        },
        error::ProvingSystemError,
        ZendooProof, ZendooVerifierKey, ZendooProverKey, ProvingSystem
    },
    utils::{
        get_bt_merkle_root,
        commitment_tree::ByteAccumulator,
        data_structures::BackwardTransfer,
    },
};
use super::*;

//*****************************Naive threshold sig circuit related functions************************

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(pks: &[&SchnorrPk], threshold: u64) -> Result<FieldElement, Error>
{
    let threshold_field = FieldElement::from(threshold);

    // pks must always be all present
    let mut h = FieldHash::init_constant_length(pks.len(), None);
    pks.iter().for_each(|&pk| { h.update(pk.x); });
    let pks_hash = h.finalize()?;

    FieldHash::init_constant_length(2, None)
        .update(pks_hash)
        .update(threshold_field)
        .finalize()
}

/// Compute BackwardTransfer MerkleTree root
pub fn compute_bt_root(bt_list: Vec<BackwardTransfer>) -> Result<FieldElement, Error>
{
    //Compute bt_list merkle_root
    let bt_list_opt = if bt_list.len() > 0 {
        Some(bt_list.as_slice())
    } else {
        None
    };

    get_bt_merkle_root(bt_list_opt)
}

//Compute and return msg_to_sign: H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)
pub fn compute_msg_to_sign(
    sc_id:                               &FieldElement,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_amount:                       u64,
    mr_bt:                               FieldElement,
) -> Result<FieldElement, Error> {

    let epoch_number = FieldElement::from(epoch_number);

    let fees_field_element = {
        let fes = ByteAccumulator::init()
            .update(btr_fee)?
            .update(ft_min_amount)?
            .get_field_elements()?;
        assert_eq!(fes.len(), 1);
        fes[0]
    };

    //Compute message to be verified
    let msg = FieldHash::init_constant_length(5, None)
        .update(*sc_id)
        .update(epoch_number)
        .update(mr_bt)
        .update(*end_cumulative_sc_tx_comm_tree_root)
        .update(fees_field_element)
        .finalize()?;

    Ok(msg)
}

pub fn compute_msg_to_sign_from_bt_list(
    sc_id:                               &FieldElement,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_amount:                       u64,
    bt_list:                             Vec<BackwardTransfer>,
) -> Result<FieldElement, Error> {

    let mr_bt = compute_bt_root(bt_list)?;
    compute_msg_to_sign(sc_id, epoch_number, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount, mr_bt)
}

pub fn create_naive_threshold_sig_proof(
    pks:                                 &[&SchnorrPk],
    mut sigs:                            Vec<Option<SchnorrSig>>,
    sc_id:                               &FieldElement,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_amount:                       u64,
    bt_list:                             Vec<BackwardTransfer>,
    threshold:                           u64,
    proving_key_path:                    &str,
    enforce_membership:                  bool,
    zk:                                  bool,
    compressed_pk:                       bool,
    compress_proof:                      bool,
) -> Result<(Vec<u8>, u64), Error> {

    //Get max pks
    let max_pks = pks.len();
    assert_eq!(sigs.len(), max_pks);

    // Compute msg to sign
    let mr_bt = compute_bt_root(bt_list)?;
    let msg = compute_msg_to_sign(
        sc_id,
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        btr_fee,
        ft_min_amount,
        mr_bt,
    )?;

    // Iterate over sigs, check and count number of valid signatures,
    // and replace with PHANTOM_SIG the None ones
    let mut valid_signatures = 0;
    for i in 0..max_pks {
        if sigs[i].is_some(){
            let is_verified = schnorr_verify_signature(&msg, pks[i], &sigs[i].unwrap())?;
            if is_verified { valid_signatures += 1; }
        }
        else {
            sigs[i] = Some(*PHANTOM_SIG)
        }
    }

    //Compute b as v-t and convert it to field element
    let b = FieldElement::from(valid_signatures - threshold);

    //Convert affine pks to projective
    let pks = pks.iter().map(|&pk| FieldBasedSchnorrPk(pk.into_projective())).collect::<Vec<_>>();

    //Convert needed variables into field elements
    let threshold = FieldElement::from(threshold);

    let c = NaiveTresholdSignature::<FieldElement>::new(
        pks, sigs, threshold, b, *sc_id, FieldElement::from(epoch_number),
        *end_cumulative_sc_tx_comm_tree_root, mr_bt, ft_min_amount, btr_fee, max_pks,
    );

    let pk: ZendooProverKey = read_from_file(
        proving_key_path,
        Some(enforce_membership),
        Some(compressed_pk)
    )?;

    let g1_ck = get_g1_committer_key()?;

    let proof = match pk {
        ZendooProverKey::Darlin(_) => unimplemented!(),
        ZendooProverKey::CoboundaryMarlin(pk) => {
            // Call prover
            let rng = &mut OsRng;
            let proof = CoboundaryMarlin::prove(
                &pk,
                g1_ck.as_ref().unwrap(),
                c,
                zk,
                if zk { Some(rng) } else { None },
            )?;
            serialize_to_buffer(&ZendooProof::CoboundaryMarlin(MarlinProof(proof)), Some(compress_proof))?
        },
    };
    Ok((proof, valid_signatures))
}

pub fn verify_naive_threshold_sig_proof(
    constant:                                   &FieldElement,
    sc_id:                                      &FieldElement,
    epoch_number:                               u32,
    end_cumulative_sc_tx_commitment_tree_root:  &FieldElement,
    btr_fee:                                    u64,
    ft_min_amount:                              u64,
    bt_list:                                    Vec<BackwardTransfer>,
    valid_sigs:                                 u64,
    proof:                                      Vec<u8>,
    check_proof:                                bool,
    compressed_proof:                           bool,
    vk_path:                                    &str,
    check_vk:                                   bool,
    compressed_vk:                              bool,
) -> Result<bool, Error>
{
    let bt_list_opt = if bt_list.len() > 0 {
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
        custom_fields: None,
        end_cumulative_sc_tx_commitment_tree_root,
        btr_fee,
        ft_min_amount
    };

    // Check that the proving system type of the vk and proof are the same, before
    // deserializing them all
    let vk_ps_type = read_from_file::<ProvingSystem>(
        vk_path,
        None,
        None,
    )?;

    let proof_ps_type = deserialize_from_buffer::<ProvingSystem>(
        &proof[..1],
        None,
        None,
    )?;

    if vk_ps_type != proof_ps_type {
        Err(ProvingSystemError::ProvingSystemMismatch)?
    }

    // Deserialize proof and vk
    let vk: ZendooVerifierKey = read_from_file(vk_path, Some(check_vk), Some(compressed_vk))?;

    let proof: ZendooProof = deserialize_from_buffer(proof.as_slice(), Some(check_proof), Some(compressed_proof))?;

    // Verify proof
    let rng = &mut OsRng;
    let is_verified = verify_zendoo_proof(ins, &proof, &vk, Some(rng))?;

    Ok(is_verified)
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
    use rand::Rng;
    use algebra::UniformRand;
    use cctp_primitives::proving_system::init_dlog_keys;
    use demo_circuit::generate_circuit_keypair;

    fn create_sample_naive_threshold_sig_circuit(
        bt_num:     usize,
        pk_path:    &str,
        vk_path:    &str,
        proof_path: &str,
    ) {
        //assume to have 3 pks, threshold = 2
        let mut rng = OsRng;

        // Generate random data
        let mut bt_list = vec![];
        for _ in 0..bt_num {
            bt_list.push(BackwardTransfer::default());
        }

        let end_cumulative_sc_tx_comm_tree_root = FieldElement::rand(&mut rng);
        let sc_id = FieldElement::rand(&mut rng);
        let epoch_number: u32 = rng.gen();
        let btr_fee: u64 = rng.gen();
        let ft_min_amount: u64 = rng.gen();

        //Compute msg to sign
        let msg = compute_msg_to_sign_from_bt_list(
            &sc_id,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root,
            btr_fee,
            ft_min_amount,
            bt_list.clone()
        ).unwrap();
        println!("compute_msg_to_sign finished");

        //Generate params and write them to file
        let circ = get_instance_for_setup(3);
        generate_circuit_keypair(
            circ,
            ProvingSystem::CoboundaryMarlin,
            pk_path,
            vk_path,
            7000,
            4000,
            false,
            Some(true),
            Some(true)
        ).unwrap();
        println!("generate_parameters finished");

        //Generate sample pks and sigs vec
        let threshold: u64 = 2;
        let mut pks = vec![];
        let mut sks = vec![];
        for _ in 0..3 {
            let keypair = schnorr_generate_key();
            pks.push(keypair.0);
            sks.push(keypair.1);
            println!("sk: {:?}", into_i8(serialize_to_buffer(&keypair.1, None).unwrap()));
        }
        println!("pks / sks finished");

        let mut sigs = vec![];
        sigs.push(Some(schnorr_sign(&msg, &sks[0], &pks[0]).unwrap()));
        sigs.push(None);
        sigs.push(Some(schnorr_sign(&msg, &sks[2], &pks[2]).unwrap()));

        println!("sk: {:?}", into_i8(serialize_to_buffer(&sks[0], None).unwrap()));
        println!("sk: {:?}", into_i8(serialize_to_buffer(&sks[2], None).unwrap()));
        println!("sk: {:?}", into_i8(serialize_to_buffer(&sks[1], None).unwrap()));

        println!("sig: {:?}", into_i8(serialize_to_buffer(&sigs[0], None).unwrap()));
        println!("sig: {:?}", into_i8(serialize_to_buffer(&sigs[2], None).unwrap()));

        let pks_ref = pks.iter().map(|pk| pk).collect::<Vec<_>>();
        let constant = compute_pks_threshold_hash(pks_ref.as_slice(), threshold).unwrap();
        println!("Constant u8: {:?}", serialize_to_buffer(&constant, None).unwrap());

        //Create and serialize proof
        let (proof, quality) = create_naive_threshold_sig_proof(
            pks_ref.as_slice(),
            sigs,
            &sc_id,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root,
            btr_fee,
            ft_min_amount,
            bt_list.clone(),
            threshold,
            pk_path,
            false,
            false,
            true,
            true
        ).unwrap();
        write_to_file(&proof, proof_path, Some(true)).unwrap();

        //Verify proof
        assert!(verify_naive_threshold_sig_proof(
            &constant,
            &sc_id,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root,
            btr_fee,
            ft_min_amount,
            bt_list.clone(),
            quality,
            proof.clone(),
            true,
            true,
            vk_path,
            true,
            true,
        ).unwrap());


        //Generate wrong public inputs by changing quality and assert proof verification doesn't pass
        assert!(!verify_naive_threshold_sig_proof(
            &constant,
            &sc_id,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root,
            btr_fee,
            ft_min_amount,
            bt_list,
            quality - 1,
            proof,
            true,
            true,
            vk_path,
            true,
            true,
        ).unwrap());
    }

    #[test]
    fn sample_calls_naive_threshold_sig_circuit() {
        let tmp_dir = std::env::temp_dir();
        let ps_type = ProvingSystem::CoboundaryMarlin;

        init_dlog_keys(
            ps_type,
            1 << 17,
            1 << 14,
        ).unwrap();

        println!("****************With BWT**********************");

        let mut pk_path = tmp_dir.clone();
        pk_path.push("sample_pk");

        let mut vk_path = tmp_dir.clone();
        vk_path.push("sample_vk");

        let mut proof_path = tmp_dir.clone();
        proof_path.push("sample_proof");

        create_sample_naive_threshold_sig_circuit(10, pk_path.to_str().unwrap(), vk_path.to_str().unwrap(), proof_path.to_str().unwrap());

        println!("****************Without BWT*******************");

        let mut pk_path_no_bwt = tmp_dir.clone();
        pk_path_no_bwt.push("sample_pk_no_bwt");

        let mut vk_path_no_bwt = tmp_dir.clone();
        vk_path_no_bwt.push("sample_vk_no_bwt");

        let mut proof_path_no_bwt = tmp_dir.clone();
        proof_path_no_bwt.push("sample_proof_no_bwt");

        create_sample_naive_threshold_sig_circuit(0, pk_path_no_bwt.to_str().unwrap(), vk_path_no_bwt.to_str().unwrap(), proof_path_no_bwt.to_str().unwrap());

        println!("*************** Clean up **********************");
        std::fs::remove_file(pk_path).unwrap();
        std::fs::remove_file(vk_path).unwrap();
        std::fs::remove_file(proof_path).unwrap();
        std::fs::remove_file(pk_path_no_bwt).unwrap();
        std::fs::remove_file(vk_path_no_bwt).unwrap();
        std::fs::remove_file(proof_path_no_bwt).unwrap();
    }
}