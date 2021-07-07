use algebra::{
    ProjectiveCurve, AffineCurve,
    ToConstraintField, UniformRand,
};
use primitives::{crh::{
    FieldBasedHash,
    bowe_hopwood::{
        BoweHopwoodPedersenParameters
    },
}, signature::{
    FieldBasedSignatureScheme, schnorr::field_based_schnorr::FieldBasedSchnorrPk
}, vrf::{FieldBasedVrf, ecvrf::FieldBasedEcVrfPk}};

use demo_circuit::{
    constants::VRFParams,
    naive_threshold_sig::*,
    type_mapping::*,
};
use rand::{
    SeedableRng, rngs::OsRng,
};
use rand_xorshift::XorShiftRng;
use lazy_static::*;

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
        serialization::*,
        commitment_tree::ByteAccumulator,
        data_structures::BackwardTransfer
    },
};

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
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
    (pk.0.into_affine(), sk)
}

pub fn schnorr_get_public_key(sk: &SchnorrSk) -> SchnorrPk {
    SchnorrSigScheme::get_public_key(sk).0.into_affine()
}

pub fn schnorr_verify_public_key(pk: &SchnorrPk) -> bool {
    SchnorrSigScheme::keyverify(&FieldBasedSchnorrPk(pk.into_projective()))
}

pub fn schnorr_sign(msg: &FieldElement, sk: &SchnorrSk, pk: &SchnorrPk) -> Result<SchnorrSig, Error> {
    let mut rng = OsRng;
    SchnorrSigScheme::sign(&mut rng, &FieldBasedSchnorrPk(pk.into_projective()), sk, msg.clone())
}

pub fn schnorr_verify_signature(msg: &FieldElement, pk: &SchnorrPk, signature: &SchnorrSig) -> Result<bool, Error> {
    SchnorrSigScheme::verify(&FieldBasedSchnorrPk(pk.into_projective()), msg.clone(), signature)
}

//*****************************Naive threshold sig circuit related functions************************

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(pks: &[SchnorrPk], threshold: u64) -> Result<FieldElement, Error>
{
    let threshold_field = FieldElement::from(threshold);

    // pks must always be all present
    let mut h = FieldHash::init_constant_length(pks.len(), None);
    pks.iter().for_each(|pk| { h.update(pk.x); });
    let pks_hash = h.finalize()?;

    FieldHash::init_constant_length(2, None)
        .update(pks_hash)
        .update(threshold_field)
        .finalize()
}

//Compute and return (MR(bt_list), H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount))
pub fn compute_msg_to_sign(
    sc_id:                               &FieldElement,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_amount:                       u64,
    bt_list:                             Vec<BackwardTransfer>,
) -> Result<(FieldElement, FieldElement), Error> {

    let epoch_number = FieldElement::from(epoch_number);

    //Compute bt_list merkle_root
    let bt_list_opt = if bt_list.len() > 0 {
        Some(bt_list.as_slice())
    } else {
        None
    };
    let mr_bt = get_bt_merkle_root(bt_list_opt)?;

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

    Ok((mr_bt, msg))
}

pub fn create_naive_threshold_sig_proof(
    pks:                                 &[SchnorrPk],
    mut sigs:                            Vec<Option<SchnorrSig>>,
    sc_id:                               &FieldElement,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_amount:                       u64,
    bt_list:                             Vec<BackwardTransfer>,
    threshold:                           u64,
    proving_key_path:                    &Path,
    enforce_membership:                  bool,
    zk:                                  bool,
    compressed_pk:                       bool,
    compress_proof:                      bool,
) -> Result<(Vec<u8>, u64), Error> {

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
    )?;

    // Iterate over sigs, check and count number of valid signatures,
    // and replace with NULL_CONST.null_sig the None ones
    let mut valid_signatures = 0;
    for i in 0..max_pks {
        if sigs[i].is_some(){
            let is_verified = schnorr_verify_signature(&msg, &pks[i], &sigs[i].unwrap())?;
            if is_verified { valid_signatures += 1; }
        }
        else {
            sigs[i] = Some(NULL_CONST.null_sig)
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

    let proof = match pk {
        ZendooProverKey::Darlin(_) => unimplemented!(),
        ZendooProverKey::CoboundaryMarlin(pk) => {
            // Call prover
            let rng = &mut OsRng;
            let proof = CoboundaryMarlin::prove(
                &pk,
                get_g1_committer_key().unwrap().as_ref().unwrap(),
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
    vk_path:                                    &Path,
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

//VRF types and functions

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<G2Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<G2Projective>{generators: params.group_hash_generators}
    };
}

pub fn vrf_generate_key() -> (VRFPk, VRFSk) {
    let mut rng = OsRng;
    let (pk, sk) = VRFScheme::keygen(&mut rng);
    (pk.0.into_affine(), sk)
}

pub fn vrf_get_public_key(sk: &VRFSk) -> VRFPk {
    VRFScheme::get_public_key(sk).0.into_affine()
}

pub fn vrf_verify_public_key(pk: &VRFPk) -> bool {
    VRFScheme::keyverify(&FieldBasedEcVrfPk(pk.into_projective()))
}

pub fn vrf_prove(msg: &FieldElement, sk: &VRFSk, pk: &VRFPk) -> Result<(VRFProof, FieldElement), Error> {
    let mut rng = OsRng;

    //Compute proof
    let proof = VRFScheme::prove(
        &mut rng,
        &VRF_GH_PARAMS,
        &FieldBasedEcVrfPk(pk.into_projective()),
        sk,
        msg.clone()
    )?;

    //Convert gamma from proof to field elements
    let gamma_coords = proof.gamma.to_field_elements().unwrap();

    //Compute VRF output
    let output = {
        let mut h = FieldHash::init_constant_length(3, None);
        h.update(msg.clone());
        gamma_coords.into_iter().for_each(|c| { h.update(c); });
        h.finalize()
    }?;

    Ok((proof, output))
}

pub fn vrf_proof_to_hash(msg: &FieldElement, pk: &VRFPk, proof: &VRFProof) -> Result<FieldElement, Error> {
    VRFScheme::proof_to_hash(
        &VRF_GH_PARAMS,
        &FieldBasedEcVrfPk(pk.into_projective()),
        msg.clone(),
        proof
    )
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
    use algebra::Field;
    use cctp_primitives::utils::{
        poseidon_hash::*, mht::*
    };
    use cctp_primitives::proving_system::init_dlog_keys;
    use demo_circuit::generate_circuit_keypair;

    fn create_sample_naive_threshold_sig_circuit(
        bt_num:     usize,
        pk_path:    &Path,
        vk_path:    &Path,
        proof_path: &Path,
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
        let (_, msg) = compute_msg_to_sign(
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

        let constant = compute_pks_threshold_hash(pks.as_slice(), threshold).unwrap();
        println!("Constant u8: {:?}", serialize_to_buffer(&constant, None).unwrap());

        //Create and serialize proof
        let (proof, quality) = create_naive_threshold_sig_proof(
            pks.as_slice(),
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

        create_sample_naive_threshold_sig_circuit(10, &pk_path, &vk_path, &proof_path);

        println!("****************Without BWT*******************");

        let mut pk_path_no_bwt = tmp_dir.clone();
        pk_path_no_bwt.push("sample_pk_no_bwt");

        let mut vk_path_no_bwt = tmp_dir.clone();
        vk_path_no_bwt.push("sample_vk_no_bwt");

        let mut proof_path_no_bwt = tmp_dir.clone();
        proof_path_no_bwt.push("sample_proof_no_bwt");

        create_sample_naive_threshold_sig_circuit(0, &pk_path_no_bwt, &vk_path_no_bwt, &proof_path_no_bwt);

        println!("*************** Clean up **********************");
        std::fs::remove_file(pk_path).unwrap();
        std::fs::remove_file(vk_path).unwrap();
        std::fs::remove_file(proof_path).unwrap();
        std::fs::remove_file(pk_path_no_bwt).unwrap();
        std::fs::remove_file(vk_path_no_bwt).unwrap();
        std::fs::remove_file(proof_path_no_bwt).unwrap();
    }

    #[test]
    fn sample_calls_schnorr_sig_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);
        {
            let msg_bytes = serialize_to_buffer(&msg, None).unwrap();
            println!("msg bytes: {:?}", into_i8(msg_bytes.clone()));
        }

        let (pk, sk) = schnorr_generate_key(); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let pk_serialized = serialize_to_buffer(&pk, Some(true)).unwrap();
        assert_eq!(pk_serialized.len(), SCHNORR_PK_SIZE);
        let pk_deserialized: SchnorrPk = deserialize_from_buffer(&pk_serialized, Some(true), Some(true)).unwrap();
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

    #[test]
    fn sample_calls_vrf_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);
        {
            let msg_bytes = serialize_to_buffer(&msg, None).unwrap();
            println!("msg bytes: {:?}", into_i8(msg_bytes.clone()));
        }

        let (pk, sk) = vrf_generate_key(); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let pk_serialized = serialize_to_buffer(&pk, Some(true)).unwrap();
        assert_eq!(pk_serialized.len(), VRF_PK_SIZE);
        let pk_deserialized: VRFPk = deserialize_from_buffer(&pk_serialized, Some(true), Some(true)).unwrap();
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
        let proof_deserialized = deserialize_from_buffer(&proof_serialized, Some(true), Some(true)).unwrap();
        assert_eq!(vrf_proof, proof_deserialized);

        //Serialize/deserialize vrf out (i.e. a field element)
        let vrf_out_serialized = serialize_to_buffer(&vrf_out, None).unwrap();
        println!("vrf out bytes: {:?}", into_i8(vrf_out_serialized.clone()));
        let vrf_out_deserialized = deserialize_from_buffer(&vrf_out_serialized, None, None).unwrap();
        assert_eq!(vrf_out, vrf_out_deserialized);

        let vrf_out_dup = vrf_proof_to_hash(&msg, &pk, &vrf_proof).unwrap(); //Verify vrf proof and get vrf out for msg
        assert_eq!(vrf_out, vrf_out_dup);

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(vrf_proof_to_hash(&wrong_msg, &pk, &vrf_proof).is_err());
    }

    #[test]
    fn sample_calls_merkle_path() {
        let height = 6;
        let leaves_num = 2usize.pow(height as u32);

        // Get GingerMHT
        let mut mht = new_ginger_mht(height, leaves_num);

        // Add leaves
        let mut mht_leaves = Vec::with_capacity(leaves_num);
        for i in 0..leaves_num/2 {
            let leaf = get_random_field_element(i as u64);
            mht_leaves.push(leaf);
            append_leaf_to_ginger_mht(&mut mht, &leaf).unwrap();
        }
        for _ in leaves_num/2..leaves_num {
            mht_leaves.push(FieldElement::zero());
        }

        // Compute the root
        finalize_ginger_mht_in_place(&mut mht);
        let mht_root = get_ginger_mht_root(&mht).expect("Tree must've been finalized");

        for i in 0..leaves_num {

            //Create and verify merkle paths for each leaf
            let path = get_ginger_mht_path(&mht, i as u64).unwrap();
            assert!(verify_ginger_merkle_path_without_length_check(&path,&mht_leaves[i], &mht_root));

            // Check leaf index is the correct one
            assert_eq!(i as u64, get_leaf_index_from_path(&path));

            if i == 0 { // leftmost check
                assert!(is_path_leftmost(&path));
            }
            else if i == (leaves_num / 2) - 1 { // non-empty rightmost check
                assert!(are_right_leaves_empty(&path));
            }
            else if i == leaves_num - 1 { //rightmost check
                assert!(is_path_rightmost(&path));
            }
            else { // Other cases check
                assert!(!is_path_leftmost(&path));
                assert!(!is_path_rightmost(&path));

                if i < (leaves_num / 2) - 1 {
                    assert!(!are_right_leaves_empty(&path));
                }
            }

            // Serialization/deserialization test
            let path_serialized = serialize_to_buffer(&path, None).unwrap();
            let path_deserialized: GingerMHTPath = deserialize_from_buffer(&path_serialized, Some(true), None).unwrap();
            assert_eq!(path, path_deserialized);
        }
    }

    #[test]
    fn sample_calls_poseidon_hash(){
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