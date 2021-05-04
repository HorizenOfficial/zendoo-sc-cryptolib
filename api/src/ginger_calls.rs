use algebra::{
    ProjectiveCurve, AffineCurve, validity::SemanticallyValid,
    ToConstraintField, UniformRand, serialize::*,
};
use primitives::{crh::{
    FieldBasedHash,
    bowe_hopwood::{
        BoweHopwoodPedersenParameters
    },
}, merkle_tree::field_based_mht::{
    FieldBasedMerkleTree,
    FieldBasedMerkleTreePath,
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
use std::fs::File;
use lazy_static::*;

use cctp_primitives::{
    proving_system::{
        init::{load_g1_committer_key, load_g2_committer_key},
        verifier::{
            certificate::{CertificateProofUserInputs, ZendooCertProofVerifier},
            RawVerifierData, ZendooVerifier
        },
    },
    utils::{
        proof_system::ProvingSystemUtils, get_bt_merkle_root,
        serialization::SerializationUtils,
        commitment_tree::bytes_to_field_elements
    },
};

//*******************************Generic functions**********************************************
// Note: Should decide if panicking or handling IO errors

pub fn deserialize_from_buffer<T: CanonicalDeserialize>(buffer: &[u8]) ->  Result<T, SerializationError>
{
    T::deserialize(buffer)
}

pub fn deserialize_from_buffer_checked<T: CanonicalDeserialize + SemanticallyValid>(buffer: &[u8]) ->  Result<T, SerializationError>
{
    let elem = deserialize_from_buffer::<T>(buffer)?;
    if !elem.is_valid() {
        return Err(SerializationError::InvalidData)
    }
    Ok(elem)
}

pub fn serialize_to_buffer<T: CanonicalSerialize>(to_write: &T) -> Result<Vec<u8>, SerializationError> {
    let mut buffer = Vec::with_capacity(to_write.serialized_size());
    CanonicalSerialize::serialize(to_write, &mut buffer)?;
    Ok(buffer)
}

pub fn read_from_file<T: CanonicalDeserialize>(file_path: &str) -> Result<T, SerializationError> {
    let fs = File::open(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    T::deserialize(fs)
}

pub fn read_from_file_checked<T: CanonicalDeserialize + SemanticallyValid>(file_path: &str) -> Result<T, SerializationError>
{
    let elem = read_from_file::<T>(file_path)?;
    if !elem.is_valid() {
        return Err(SerializationError::InvalidData)
    }
    Ok(elem)
}

pub fn write_to_file<T: CanonicalSerialize>(to_write: &T, file_path: &str) -> Result<(), SerializationError>
{
    let mut fs = File::create(file_path)
        .map_err(|e| SerializationError::IoError(e))?;
    CanonicalSerialize::serialize(to_write, &mut fs)?;
    Ok(())
}

pub fn is_valid<T: SemanticallyValid>(to_check: &T) -> bool {
    T::is_valid(to_check)
}

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

//************************************Poseidon Hash functions****************************************

pub fn get_poseidon_hash_constant_length(input_size: usize, personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init_constant_length(input_size, personalization)
}

pub fn get_poseidon_hash_variable_length(mod_rate: bool, personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init_variable_length(mod_rate, personalization)
}

pub fn update_poseidon_hash(hash: &mut FieldHash, input: &FieldElement){
    hash.update(*input);
}

pub fn reset_poseidon_hash(hash: &mut FieldHash, personalization: Option<&[FieldElement]>){
    hash.reset(personalization);
}

pub fn finalize_poseidon_hash(hash: &FieldHash) -> Result<FieldElement, Error> {
    let result = hash.finalize()?;
    Ok(result)
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

//Compute and return (MR(bt_list), H(epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_fee))
pub fn compute_msg_to_sign(
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_fee:                          u64,
    bt_list:                             Vec<(u64, [u8; MC_PK_SIZE])>,
) -> Result<(FieldElement, FieldElement), Error> {

    let epoch_number = FieldElement::from(epoch_number);

    //Compute bt_list merkle_root
    let mr_bt = get_bt_merkle_root(bt_list.as_slice())?;

    let fees_field_element = {
        let fes = bytes_to_field_elements(vec![btr_fee, ft_min_fee])?;
        assert_eq!(fes.len(), 1);
        fes[0]
    };

    //Compute message to be verified
    let msg = FieldHash::init_constant_length(4, None)
        .update(epoch_number)
        .update(mr_bt)
        .update(*end_cumulative_sc_tx_comm_tree_root)
        .update(fees_field_element)
        .finalize()?;

    Ok((mr_bt, msg))
}

pub fn init_dlog_keys(
    proving_system: ProvingSystem,
    segment_size: usize,
    ck_g1_path: &str,
    ck_g2_path: &str,
) -> Result<(), Error> {
    load_g1_committer_key(segment_size - 1, ck_g1_path)?;

    if matches!(proving_system, ProvingSystem::Darlin) {
        load_g2_committer_key(segment_size - 1, ck_g2_path)?
    }

    Ok(())
}

pub fn generate_naive_threshold_sig_circuit_keypair(
    proving_system: ProvingSystem,
    max_pks: usize,
    pk_path: &str,
    vk_path: &str,
) -> Result<(), Error>
{
    let circ = get_instance_for_setup(max_pks);

    match proving_system {
        ProvingSystem::CoboundaryMarlin => {
            let (pk, vk) = CoboundaryMarlin::setup(circ)?;
            write_to_file(&pk, pk_path)?;
            write_to_file(&vk, vk_path)?;
        },
        ProvingSystem::Darlin => unreachable!()
    }

    Ok(())
}

pub fn create_naive_threshold_sig_proof(
    proving_system:                      ProvingSystem,
    pks:                                 &[SchnorrPk],
    mut sigs:                            Vec<Option<SchnorrSig>>,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_fee:                          u64,
    bt_list:                             Vec<(u64, [u8; MC_PK_SIZE])>,
    threshold:                           u64,
    proving_key_path:                    &str,
    enforce_membership:                  bool,
    zk:                                  bool,
) -> Result<(Vec<u8>, u64), Error> {

    //Get max pks
    let max_pks = pks.len();
    assert_eq!(sigs.len(), max_pks);

    // Compute msg to sign
    let (mr_bt, msg) = compute_msg_to_sign(
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        btr_fee,
        ft_min_fee,
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
        pks, sigs, threshold, b, FieldElement::from(epoch_number),
        *end_cumulative_sc_tx_comm_tree_root, mr_bt, ft_min_fee, btr_fee, max_pks,
    );

    let proof = match proving_system {
        ProvingSystem::CoboundaryMarlin => {

            // Read proving key
            let pk: CoboundaryMarlinProverKey = if enforce_membership {
                read_from_file_checked(proving_key_path)
            } else {
                read_from_file(proving_key_path)
            }?;

            // Call prover
            let rng = &mut OsRng;
            CoboundaryMarlin::create_proof(
                c,
                &pk,
                zk,
                if zk { Some(rng) } else { None },
            )?.as_bytes()?
        },
        ProvingSystem::Darlin => unreachable!()
    };
    Ok((proof, valid_signatures))
}


pub fn verify_naive_threshold_sig_proof(
    proving_system:                      ProvingSystem,
    constant:                            &FieldElement,
    epoch_number:                        u32,
    end_cumulative_sc_tx_comm_tree_root: &FieldElement,
    btr_fee:                             u64,
    ft_min_fee:                          u64,
    bt_list:                             Vec<(u64, [u8; MC_PK_SIZE])>,
    valid_sigs:                          u64,
    proof:                               Vec<u8>,
    check_proof:                         bool,
    vk_path:                             &str,
    check_vk:                            bool
) -> Result<bool, Error>
{
    // TODO: These copies here are wasted, since most of the CertificateProofUserInputs are
    //       already passed around in their deserialized form. Instead this representation is
    //       useful in zendoo-mc-cryptolib. We should consider adding a "non raw" representation
    //       in zendoo-cctp-lib to save some copies.
    let constant = &{
        let mut buffer = [0u8; FIELD_SIZE];
        CanonicalSerialize::serialize(constant, &mut buffer[..])?;
        buffer
    };

    let end_cumulative_sc_tx_commitment_tree_root = &{
        let mut buffer = [0u8; FIELD_SIZE];
        CanonicalSerialize::serialize(end_cumulative_sc_tx_comm_tree_root, &mut buffer[..])?;
        buffer
    };

    let ins = CertificateProofUserInputs {
        constant: Some(constant),
        epoch_number,
        quality: valid_sigs,
        bt_list: bt_list.as_slice(),
        custom_fields: None,
        end_cumulative_sc_tx_commitment_tree_root,
        btr_fee,
        ft_min_fee
    };

    // Read verifier key
    let vk: Vec<u8> = std::fs::read(vk_path)?;

    let raw_verifier_data = match proving_system {
        ProvingSystem::CoboundaryMarlin => {
            RawVerifierData::CoboundaryMarlin {proof, vk}
        },
        ProvingSystem::Darlin => unreachable!()
    };

    let rng = &mut OsRng;
    let is_verified = ZendooCertProofVerifier::verify_proof(
        &ins,
        raw_verifier_data,
        check_proof,
        check_vk,
        Some(rng)
    )?;

    Ok(is_verified)
}

//VRF types and functions

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<Projective>{generators: params.group_hash_generators}
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

//************Merkle Tree functions******************

////////////MERKLE_PATH

pub fn verify_ginger_merkle_path(
    path: &GingerMHTPath,
    height: usize,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify(height, leaf, root)
}

pub fn verify_ginger_merkle_path_without_length_check(
    path: &GingerMHTPath,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify_without_length_check(leaf, root)
}

pub fn is_path_leftmost(path: &GingerMHTPath) -> bool {
    path.is_leftmost()
}

pub fn is_path_rightmost(path: &GingerMHTPath) -> bool {
    path.is_rightmost()
}

pub fn are_right_leaves_empty(path: &GingerMHTPath) -> bool { path.are_right_leaves_empty() }

pub fn get_leaf_index_from_path(path: &GingerMHTPath) -> u64 {
    path.leaf_index() as u64
}

//TODO: Move to GingerLib
pub fn apply(path: &GingerMHTPath, leaf: &FieldElement) -> FieldElement
{
    let mut digest = FieldHash::init_constant_length(2, None);
    let mut prev_node = *leaf;
    for (sibling, direction) in path.get_raw_path().iter() {

        assert_eq!(sibling.len(), 2);
        assert!(*direction == 0 || *direction == 1);

        // Choose left and right hash according to direction
        let (left, right) = if *direction == 0{
            (prev_node, sibling[0].clone())
        } else {
            (sibling[0].clone(), prev_node)
        };

        // Compute the parent node
        prev_node = digest
            .update(left)
            .update(right)
            .finalize()
            .unwrap();

        digest.reset(None);
    }
    prev_node
}

////////////OPTIMIZED MERKLE TREE

pub fn new_ginger_mht(height: usize, processing_step: usize) -> GingerMHT {
    GingerMHT::init(height, processing_step)
}

pub fn append_leaf_to_ginger_mht(tree: &mut GingerMHT, leaf: &FieldElement){
    tree.append(*leaf);
}

pub fn finalize_ginger_mht(tree: &GingerMHT) -> GingerMHT {
    tree.finalize()
}

pub fn finalize_ginger_mht_in_place(tree: &mut GingerMHT) {
    tree.finalize_in_place();
}

pub fn get_ginger_mht_root(tree: &GingerMHT) -> Option<FieldElement> {
    tree.root()
}

pub fn get_ginger_mht_path(tree: &GingerMHT, leaf_index: u64) -> Option<GingerMHTPath> {
    match tree.get_merkle_path(leaf_index as usize) {
        Some(path) => Some(path.into()),
        None => None,
    }
}

pub fn reset_ginger_mht(tree: &mut GingerMHT){
    tree.reset();
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{RngCore, Rng};
    use algebra::Field;

    #[allow(dead_code)]
    fn into_i8(v: Vec<u8>) -> Vec<i8> {
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

    fn create_sample_naive_threshold_sig_circuit(bt_num: usize) {
        //assume to have 3 pks, threshold = 2
        let mut rng = OsRng;

        //Generate random mc block hashes and bt list
        let mut end_cumulative_sc_tx_comm_tree_root = [0u8; 32];
        rng.fill_bytes(&mut end_cumulative_sc_tx_comm_tree_root);
        end_cumulative_sc_tx_comm_tree_root[31] = 0u8; // Mask away last byte
        println!("end_cumulative_sc_tx_comm_tree_root u8: {:?}", end_cumulative_sc_tx_comm_tree_root);
        println!("end_cumulative_sc_tx_comm_tree_root i8: {:?}", into_i8(end_cumulative_sc_tx_comm_tree_root.to_vec()));

        let mut bt_list = vec![];
        for _ in 0..bt_num {
            bt_list.push((0u64, [0u8; MC_PK_SIZE]));
        }

        let end_cumulative_sc_tx_comm_tree_root_f = FieldElement::from_bytes(&end_cumulative_sc_tx_comm_tree_root).unwrap();

        let epoch_number: u32 = rng.gen();
        let btr_fee: u64 = rng.gen();
        let ft_min_fee: u64 = rng.gen();

        //Compute msg to sign
        let (_, msg) = compute_msg_to_sign(
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root_f,
            btr_fee,
            ft_min_fee,
            bt_list.clone()
        ).unwrap();
        println!("compute_msg_to_sign finished");

        //Generate params and write them to file
        let proving_key_path = if bt_num != 0 {"./sample_pk"} else {"./sample_pk_no_bwt"};
        let verifying_key_path = if bt_num != 0 {"./sample_vk"} else {"./sample_vk_no_bwt"};
        generate_naive_threshold_sig_circuit_keypair(
            ProvingSystem::CoboundaryMarlin,
            3,
            proving_key_path,
            verifying_key_path
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
            println!("sk: {:?}", into_i8(keypair.1.as_bytes().unwrap()));
        }
        println!("pks / sks finished");

        let mut sigs = vec![];
        sigs.push(Some(schnorr_sign(&msg, &sks[0], &pks[0]).unwrap()));
        sigs.push(None);
        sigs.push(Some(schnorr_sign(&msg, &sks[2], &pks[2]).unwrap()));

        println!("sk: {:?}", into_i8(serialize_to_buffer(&sks[0]).unwrap()));
        println!("sk: {:?}", into_i8(serialize_to_buffer(&sks[2]).unwrap()));
        println!("sk: {:?}", into_i8(serialize_to_buffer(&sks[1]).unwrap()));

        println!("sig: {:?}", into_i8(serialize_to_buffer(&sigs[0]).unwrap()));
        println!("sig: {:?}", into_i8(serialize_to_buffer(&sigs[2]).unwrap()));

        let constant = compute_pks_threshold_hash(pks.as_slice(), threshold).unwrap();
        println!("Constant u8: {:?}", constant.as_bytes().unwrap());

        //Create and serialize proof
        let (proof, quality) = create_naive_threshold_sig_proof(
            ProvingSystem::CoboundaryMarlin,
            pks.as_slice(),
            sigs,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root_f,
            btr_fee,
            ft_min_fee,
            bt_list.clone(),
            threshold,
            proving_key_path,
            false,
            false,
        ).unwrap();
        let proof_path = if bt_num != 0 {"./sample_proof"} else {"./sample_proof_no_bwt"};
        write_to_file(&proof, proof_path).unwrap();

        //Verify proof
        assert!(verify_naive_threshold_sig_proof(
            ProvingSystem::CoboundaryMarlin,
            &constant,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root_f,
            btr_fee,
            ft_min_fee,
            bt_list.clone(),
            quality,
            proof.clone(),
            true,
            verifying_key_path,
            true,
        ).unwrap());


        //Generate wrong public inputs by changing quality and assert proof verification doesn't pass
        assert!(!verify_naive_threshold_sig_proof(
            ProvingSystem::CoboundaryMarlin,
            &constant,
            epoch_number,
            &end_cumulative_sc_tx_comm_tree_root_f,
            btr_fee,
            ft_min_fee,
            bt_list,
            quality - 1,
            proof,
            true,
            verifying_key_path,
            true,
        ).unwrap());
    }

    #[test]
    fn sample_calls_naive_threshold_sig_circuit() {
        init_dlog_keys(
            ProvingSystem::CoboundaryMarlin,
            1 << 17,
            "./g1_ck",
            "./g2_ck"
        ).unwrap();

        println!("****************With BWT**********************");
        create_sample_naive_threshold_sig_circuit(10);
        println!("****************Without BWT*******************");
        create_sample_naive_threshold_sig_circuit(0);

        std::fs::remove_file("./sample_pk").unwrap();
        std::fs::remove_file("./sample_vk").unwrap();
        std::fs::remove_file("./sample_proof").unwrap();
        std::fs::remove_file("./sample_pk_no_bwt").unwrap();
        std::fs::remove_file("./sample_vk_no_bwt").unwrap();
        std::fs::remove_file("./sample_proof_no_bwt").unwrap();
        std::fs::remove_file("./g1_ck").unwrap();
    }

    #[test]
    fn sample_calls_schnorr_sig_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);

        let (pk, sk) = schnorr_generate_key(); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let pk_serialized = serialize_to_buffer(&pk).unwrap();
        assert_eq!(pk_serialized.len(), SCHNORR_PK_SIZE);
        let pk_deserialized: SchnorrPk = deserialize_from_buffer_checked(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let sk_serialized = serialize_to_buffer(&sk).unwrap();
        assert_eq!(sk_serialized.len(), SCHNORR_SK_SIZE);
        let sk_deserialized = deserialize_from_buffer(&sk_serialized).unwrap();
        assert_eq!(sk, sk_deserialized);

        let sig = schnorr_sign(&msg, &sk, &pk).unwrap(); //Sign msg
        assert!(is_valid(&sig));

        //Serialize/deserialize sig
        let sig_serialized = serialize_to_buffer(&sig).unwrap();
        assert_eq!(sig_serialized.len(), SCHNORR_SIG_SIZE);
        let sig_deserialized = deserialize_from_buffer(&sig_serialized).unwrap();
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

        let (pk, sk) = vrf_generate_key(); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let pk_serialized = serialize_to_buffer(&pk).unwrap();
        assert_eq!(pk_serialized.len(), VRF_PK_SIZE);
        let pk_deserialized: VRFPk = deserialize_from_buffer_checked(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let sk_serialized = serialize_to_buffer(&sk).unwrap();
        assert_eq!(sk_serialized.len(), VRF_SK_SIZE);
        let sk_deserialized = deserialize_from_buffer(&sk_serialized).unwrap();
        assert_eq!(sk, sk_deserialized);

        let (vrf_proof, vrf_out) = vrf_prove(&msg, &sk, &pk).unwrap(); //Create vrf proof for msg
        assert!(is_valid(&vrf_proof));

        //Serialize/deserialize vrf proof
        let proof_serialized = serialize_to_buffer(&vrf_proof).unwrap();
        assert_eq!(proof_serialized.len(), VRF_PROOF_SIZE);
        let proof_deserialized = deserialize_from_buffer_checked(&proof_serialized).unwrap();
        assert_eq!(vrf_proof, proof_deserialized);

        //Serialize/deserialize vrf out (i.e. a field element)
        let vrf_out_serialized = serialize_to_buffer(&vrf_out).unwrap();
        let vrf_out_deserialized = deserialize_from_buffer(&vrf_out_serialized).unwrap();
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
            append_leaf_to_ginger_mht(&mut mht, &leaf);
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
            assert!(verify_ginger_merkle_path_without_length_check(&path,&mht_leaves[i], &mht_root).unwrap());

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
            let path_serialized = serialize_to_buffer(&path).unwrap();
            let path_deserialized: GingerMHTPath = deserialize_from_buffer(&path_serialized).unwrap();
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