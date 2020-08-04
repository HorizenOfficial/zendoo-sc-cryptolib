use algebra::{fields::{
    mnt4753::{Fr as MNT4Fr, Fq as MNT4Fq}, PrimeField
}, curves::{
    mnt4753::MNT4,
    mnt6753::{
        G1Projective as MNT6G1Projective, G1Affine as MNT6G1Affine
    },
}, FromBytes, ToBytes, BigInteger768, ProjectiveCurve, AffineCurve, ToConstraintField, UniformRand, ToBits};
use primitives::{crh::{
    poseidon::{
        parameters::MNT4753PoseidonParameters,
        PoseidonHash, MNT4PoseidonHash
    },
    FieldBasedHash,
    bowe_hopwood::{
        BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters
    },
},  merkle_tree::field_based_mht::{
    smt::*,
    smt::big_lazy_merkle_tree::*,
}, signature::{
    FieldBasedSignatureScheme, schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrSignature
    },
}, vrf::{FieldBasedVrf, ecvrf::*}};
use proof_systems::groth16::{
    Proof, create_random_proof,
    prepare_verifying_key, verify_proof,
};
use demo_circuit::{
    constants::{
        VRFParams, VRFWindow,
    },
    naive_threshold_sig::*
};
use rand::rngs::OsRng;

use std::{
    fs::File, io::Result as IoResult
};
use lazy_static::*;
use primitives::merkle_tree::field_based_mht::MNT4753_PHANTOM_MERKLE_ROOT;
use primitives::merkle_tree::field_based_mht::ramht::poseidon::PoseidonRandomAccessMerkleTree;
use primitives::merkle_tree::field_based_mht::ramht::RandomAccessMerkleTree;

pub type FieldElement = MNT4Fr;
pub const FIELD_SIZE: usize = 96; //Field size in bytes
pub const SCALAR_FIELD_SIZE: usize = FIELD_SIZE;// 96
pub const G1_SIZE: usize = 193;
pub const G2_SIZE: usize = 385;

pub const SCHNORR_PK_SIZE: usize = G1_SIZE; // 193
pub const SCHNORR_SK_SIZE: usize = SCALAR_FIELD_SIZE; // 96
pub const SCHNORR_SIG_SIZE: usize = 2 * FIELD_SIZE; // 192

pub const VRF_PK_SIZE: usize = G1_SIZE; // 193
pub const VRF_SK_SIZE: usize = SCALAR_FIELD_SIZE; // 96
pub const VRF_PROOF_SIZE: usize = G1_SIZE + 2 * FIELD_SIZE; // 192

pub const ZK_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771
pub type Error = Box<dyn std::error::Error>;

//*******************************Generic I/O functions**********************************************
// Note: Should decide if panicking or handling IO errors

pub fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8]) ->  IoResult<T> {
    T::read(buffer)
}

pub fn serialize_to_buffer<T: ToBytes>(to_write: &T, buffer: &mut [u8]) -> IoResult<()> {
    to_write.write(buffer)
}

pub fn read_from_file<T: FromBytes>(file_path: &str) -> IoResult<T>{
    let mut fs = File::open(file_path)?;
    let t = T::read(&mut fs)?;
    Ok(t)
}

pub fn get_random_field_element() -> FieldElement {
    let mut rng = OsRng;
    FieldElement::rand(&mut rng)
}

//***************************Schnorr types and functions********************************************

pub type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash>;
pub type SchnorrSig = FieldBasedSchnorrSignature<MNT4Fr>;
pub type SchnorrPk = MNT6G1Affine;
pub type SchnorrSk = MNT4Fq;

pub fn schnorr_generate_key() -> (SchnorrPk, SchnorrSk) {
    let mut rng = OsRng;
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
    (pk.into_affine(), sk)
}

pub fn schnorr_get_public_key(sk: &SchnorrSk) -> SchnorrPk {
    SchnorrSigScheme::get_public_key(sk).into_affine()
}

pub fn schnorr_verify_public_key(pk: &SchnorrPk) -> bool {
    SchnorrSigScheme::keyverify(&pk.into_projective())
}

pub fn schnorr_sign(msg: &FieldElement, sk: &SchnorrSk, pk: &SchnorrPk) -> Result<SchnorrSig, Error> {
    let mut rng = OsRng;
    SchnorrSigScheme::sign(&mut rng, &pk.into_projective(), sk, &[*msg])
}

pub fn schnorr_verify_signature(msg: &FieldElement, pk: &SchnorrPk, signature: &SchnorrSig) -> Result<bool, Error> {
    SchnorrSigScheme::verify(&pk.into_projective(), &[*msg], signature)
}

//************************************Poseidon Hash functions****************************************

pub type FieldHash = PoseidonHash<FieldElement, MNT4753PoseidonParameters>;

pub fn get_poseidon_hash(personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init(personalization)
}

pub fn update_poseidon_hash(hash: &mut FieldHash, input: &FieldElement){
    hash.update(*input);
}

pub fn reset_poseidon_hash(hash: &mut FieldHash, personalization: Option<&[FieldElement]>){
    hash.reset(personalization);
}

pub fn finalize_poseidon_hash(hash: &FieldHash) -> FieldElement{
    hash.finalize()
}

//*****************************Naive threshold sig circuit related functions************************

pub type SCProof = Proof<MNT4>;

#[derive(Clone, Default)]
pub struct BackwardTransfer {
    pub pk_dest:    [u8; 20],
    pub amount:     u64,
}

impl BackwardTransfer {
    pub fn new(pk_dest: [u8; 20], amount: u64) -> Self
    {
        Self{ pk_dest, amount }
    }

    pub fn to_field_element(&self) -> IoResult<FieldElement>
    {
        let mut buffer = vec![];
        self.pk_dest.write(&mut buffer)?;
        self.amount.write(&mut buffer)?;
        read_field_element_from_buffer_with_padding(buffer.as_slice())
    }
}

//Will return error if buffer.len > FIELD_SIZE. If buffer.len < FIELD_SIZE, padding 0s will be added
pub fn read_field_element_from_buffer_with_padding(buffer: &[u8]) -> IoResult<FieldElement>
{
    let buff_len = buffer.len();

    //Pad to reach field element size
    let mut new_buffer = vec![];
    new_buffer.extend_from_slice(buffer);
    for _ in buff_len..FIELD_SIZE { new_buffer.push(0u8) } //Add padding zeros to reach field size

    FieldElement::read(&new_buffer[..])
}

pub fn read_field_element_from_u64(num: u64) -> FieldElement {
    FieldElement::from_repr(BigInteger768::from(num))
}

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(pks: &[SchnorrPk], threshold: u64) -> Result<FieldElement, Error> {
    let threshold_field = read_field_element_from_u64(threshold);
    let mut h = FieldHash::init(None);
    pks.iter().for_each(|pk| { h.update(pk.x); });
    let pks_hash = h.finalize();
    Ok(h
        .reset(None)
        .update(pks_hash)
        .update(threshold_field)
        .finalize())
}

//Compute and return (MR(bt_list), H(MR(bt_list), H(bi-1), H(bi))
pub fn compute_msg_to_sign(
    end_epoch_mc_b_hash:      &FieldElement,
    prev_end_epoch_mc_b_hash: &FieldElement,
    bt_list:                  &[BackwardTransfer],
) -> Result<(FieldElement, FieldElement), Error> {

    let mr_bt = if bt_list.is_empty() {
        MNT4753_PHANTOM_MERKLE_ROOT
    } else {
        let mut bt_field_list = vec![];
        for bt in bt_list.iter() {
            let bt_f = bt.to_field_element()?;
            bt_field_list.push(bt_f);
        }

        //Compute bt_list merkle_root
        compute_bt_root(bt_field_list.as_slice())?
    };

    //Compute message to be verified
    let msg = FieldHash::init(None)
        .update(mr_bt)
        .update(*prev_end_epoch_mc_b_hash)
        .update(*end_epoch_mc_b_hash)
        .finalize();

    Ok((mr_bt, msg))
}

pub fn compute_wcert_sysdata_hash(
    valid_sigs:               u64,
    mr_bt:                    &FieldElement,
    prev_end_epoch_mc_b_hash: &FieldElement,
    end_epoch_mc_b_hash:      &FieldElement,
) -> Result<FieldElement, Error> {

    //Compute quality and wcert_sysdata_hash
    let quality = read_field_element_from_u64(valid_sigs);
    let wcert_sysdata_hash = FieldHash::init(None)
        .update(quality)
        .update(*mr_bt)
        .update(*prev_end_epoch_mc_b_hash)
        .update(*end_epoch_mc_b_hash)
        .finalize();
    Ok(wcert_sysdata_hash)
}

pub fn create_naive_threshold_sig_proof(
    pks:                      &[SchnorrPk],
    mut sigs:                 Vec<Option<SchnorrSig>>,
    end_epoch_mc_b_hash:      &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list:                  &[BackwardTransfer],
    threshold:                u64,
    proving_key_path:         &str
) -> Result<(SCProof, u64), Error> {

    //Get max pks
    let max_pks = pks.len();
    assert_eq!(sigs.len(), max_pks);

    //Read end_epoch_mc_b_hash, prev_end_epoch_mc_b_hash and bt_list as field elements
    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..])?;
    let prev_end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..])?;
    let (mr_bt, msg) = compute_msg_to_sign(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
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
    let b = read_field_element_from_u64(valid_signatures - threshold);

    //Convert affine pks to projective
    let pks = pks.iter().map(|&pk| pk.into_projective()).collect::<Vec<_>>();

    //Convert needed variables into field elements
    let threshold = read_field_element_from_u64(threshold);

    let c = NaiveTresholdSignature::<FieldElement>::new(
        pks, sigs, threshold, b, end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash, mr_bt, max_pks,
    );

    //Read proving key
    let params = read_from_file(proving_key_path)?;

    //Create and return proof
    let mut rng = OsRng;
    let proof = create_random_proof(c, &params, &mut rng)?;
    Ok((proof, valid_signatures))
}

pub fn verify_naive_threshold_sig_proof(
    constant:                 &FieldElement,
    end_epoch_mc_b_hash:      &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list:                  &[BackwardTransfer],
    valid_sigs:               u64,
    proof:                    &SCProof,
    vk_path:                  &str,
) -> Result<bool, Error>
{
    //Compute wcert_sysdata_hash
    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..])?;
    let prev_end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..])?;
    let (mr_bt, _) = compute_msg_to_sign(&end_epoch_mc_b_hash, &prev_end_epoch_mc_b_hash, bt_list)?;
    let wcert_sysdata_hash = compute_wcert_sysdata_hash(valid_sigs, &mr_bt, &prev_end_epoch_mc_b_hash, &end_epoch_mc_b_hash)?;
    let aggregated_input = FieldHash::init(None)
        .update(*constant)
        .update(wcert_sysdata_hash)
        .finalize();

    //Verify proof
    let vk = read_from_file(vk_path)?;
    let pvk = prepare_verifying_key(&vk); //Get verifying key
    let is_verified = verify_proof(&pvk, &proof, &[aggregated_input])?;

    Ok(is_verified)
}

//VRF types and functions

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<MNT6G1Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<MNT6G1Projective>{generators: params.group_hash_generators}
    };
}

type GroupHash = BoweHopwoodPedersenCRH<MNT6G1Projective, VRFWindow>;

pub type VRFScheme = FieldBasedEcVrf<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash, GroupHash>;
pub type VRFProof = FieldBasedEcVrfProof<MNT4Fr, MNT6G1Projective>;
pub type VRFPk = MNT6G1Affine;
pub type VRFSk = MNT4Fq;

pub fn vrf_generate_key() -> (VRFPk, VRFSk) {
    let mut rng = OsRng;
    let (pk, sk) = VRFScheme::keygen(&mut rng);
    (pk.into_affine(), sk)
}

pub fn vrf_get_public_key(sk: &VRFSk) -> VRFPk {
    SchnorrSigScheme::get_public_key(sk).into_affine()
}

pub fn vrf_verify_public_key(pk: &VRFPk) -> bool {
    SchnorrSigScheme::keyverify(&pk.into_projective())
}

pub fn vrf_prove(msg: &FieldElement, sk: &VRFSk, pk: &VRFPk) -> Result<(VRFProof, FieldElement), Error> {
    let mut rng = OsRng;

    //Compute proof
    let proof = VRFScheme::prove(
        &mut rng,
        &VRF_GH_PARAMS,
        &pk.into_projective(),
        sk,
        &[*msg]
    )?;

    //Convert gamma from proof to field elements
    let gamma_coords = proof.gamma.to_field_elements().unwrap();

    //Compute VRF output
    let mut hash_input = Vec::new();
    hash_input.push(*msg);
    hash_input.extend_from_slice(gamma_coords.as_slice());
    let output = {
        let mut h = FieldHash::init(None);
        h.update(*msg);
        gamma_coords.into_iter().for_each(|c| { h.update(c); });
        h.finalize()
    };

    Ok((proof, output))
}

pub fn vrf_proof_to_hash(msg: &FieldElement, pk: &VRFPk, proof: &VRFProof) -> Result<FieldElement, Error> {
    VRFScheme::proof_to_hash(&VRF_GH_PARAMS,&pk.into_projective(), &[*msg], proof)
}

//************Merkle Tree functions******************

type BTMerkleTree = PoseidonRandomAccessMerkleTree<FieldElement, MNT4753PoseidonParameters>;
const BT_MERKLE_TREE_HEIGHT: usize = 13;

fn compute_bt_root(bts: &[FieldElement]) -> Result<FieldElement, Error> {
    let mut bt_mt = BTMerkleTree::init(2usize.pow((BT_MERKLE_TREE_HEIGHT - 1) as u32));
    for &bt in bts.iter(){
        bt_mt.append(bt);
    }
    bt_mt.finalize_in_place();
    bt_mt.root().ok_or(Error::from("Failed to compute BT Merkle Tree root"))
}

pub const SC_UTXO_MERKLE_TREE_HEIGHT: usize = 13;
pub const NON_EMPTY_POSITION: i32 = -1;

fn leaf_to_index(leaf: &FieldElement) -> usize {
    //let leaf_bits = &leaf.write_bits()[..SC_UTXO_MERKLE_TREE_HEIGHT - 1];
    let bits = leaf.write_bits();
    assert!(SC_UTXO_MERKLE_TREE_HEIGHT - 1 <= bits.len());
    let leaf_bits = &bits[..SC_UTXO_MERKLE_TREE_HEIGHT - 1];
    let position = leaf_bits.iter().rev().fold(0, |acc, &b| acc*2 + b as usize);
    position
}

pub type ScUtxoMerkleTree = MNT4PoseidonSmt;

pub fn new_ginger_merkle_tree(db_path: &str, cache_path: &str) -> Result<ScUtxoMerkleTree, Error> {
    match ScUtxoMerkleTree::new(
        2usize.pow((SC_UTXO_MERKLE_TREE_HEIGHT - 1) as u32),
        db_path.to_owned(),
        cache_path.to_owned()
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

pub fn add_leaf_to_ginger_merkle_tree(tree: &mut ScUtxoMerkleTree, leaf: &FieldElement, position: usize){
    tree.insert_leaf(Coord::new(0, position), *leaf)
}

pub fn get_position_in_ginger_merkle_tree(tree: &ScUtxoMerkleTree, leaf: &FieldElement) -> i32
{
    let position = leaf_to_index(leaf);
    match tree.is_leaf_empty(Coord::new(0, position)){
        true => position as i32,
        false => NON_EMPTY_POSITION
    }
}

pub fn get_ginger_merkle_root(tree: &ScUtxoMerkleTree) -> FieldElement {
    tree.get_root()
}

///////////LAZY VARIANT
pub type LazyScUtxoMerkleTree = MNT4PoseidonSmtLazy;
type GingerLeaf = OperationLeaf<FieldElement>;

pub fn new_lazy_ginger_merkle_tree(db_path: &str, cache_path: &str) -> Result<LazyScUtxoMerkleTree, Error> {
    match LazyScUtxoMerkleTree::new(
        2usize.pow((SC_UTXO_MERKLE_TREE_HEIGHT - 1) as u32),
        db_path.to_owned(),
        cache_path.to_owned()
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

pub fn add_leaves_to_ginger_merkle_tree(tree: &mut LazyScUtxoMerkleTree, leaves: &[FieldElement]) -> FieldElement{
    let leaves = leaves.iter().map(|leaf| {
        GingerLeaf::new(0, leaf_to_index(leaf), ActionLeaf::Insert, Some(*leaf))
    }).collect::<Vec<_>>();
    tree.process_leaves(leaves)
}

pub fn get_lazy_ginger_merkle_root(tree: &LazyScUtxoMerkleTree) -> FieldElement {
    tree.get_root()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;
    use algebra::{to_bytes, ToBytes};

    fn write_to_file<T: ToBytes>(to_write: &T, file_path: &str) -> IoResult<()>{
        let mut fs = File::create(file_path)?;
        to_write.write(&mut fs)?;
        Ok(())
    }

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
        let mut end_epoch_mc_b_hash = [0u8; 32];
        let mut prev_end_epoch_mc_b_hash = [0u8; 32];
        rng.fill_bytes(&mut end_epoch_mc_b_hash);
        rng.fill_bytes(&mut prev_end_epoch_mc_b_hash);
        println!("end epoch: {:?}", into_i8(end_epoch_mc_b_hash.to_vec()));
        println!("prev end epoch: {:?}", into_i8(prev_end_epoch_mc_b_hash.to_vec()));
        let end_epoch_mc_b_hash_f = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..]).unwrap();
        let prev_end_epoch_mc_b_hash_f = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..]).unwrap();

        let mut bt_list = vec![];
        for _ in 0..bt_num {
            bt_list.push(BackwardTransfer::default());
        }

        //Compute msg to sign
        let (_, msg) = compute_msg_to_sign(
            &end_epoch_mc_b_hash_f,
            &prev_end_epoch_mc_b_hash_f,
            bt_list.as_slice()
        ).unwrap();

        //Generate params and write them to file
        let params = generate_parameters(3).unwrap();
        let proving_key_path = "./sample_proving_key";
        write_to_file(&params, proving_key_path).unwrap();

        let verifying_key_path = "./sample_vk";
        write_to_file(&(params.vk), verifying_key_path).unwrap();

        //Generate sample pks and sigs vec
        let threshold: u64 = 2;
        let mut pks = vec![];
        let mut sks = vec![];
        for _ in 0..3 {
            let keypair = schnorr_generate_key();
            pks.push(keypair.0);
            sks.push(keypair.1);
        }

        let mut sigs = vec![];
        sigs.push(Some(schnorr_sign(&msg, &sks[0], &pks[0]).unwrap()));
        sigs.push(None);
        sigs.push(Some(schnorr_sign(&msg, &sks[2], &pks[2]).unwrap()));

        println!("sk: {:?}", into_i8(to_bytes!(sks[0]).unwrap()));
        println!("sk: {:?}", into_i8(to_bytes!(sks[2]).unwrap()));
        println!("sk: {:?}", into_i8(to_bytes!(sks[1]).unwrap()));

        println!("sig: {:?}", into_i8(to_bytes!(sigs[0].unwrap()).unwrap()));
        println!("sig: {:?}", into_i8(to_bytes!(sigs[2].unwrap()).unwrap()));

        let constant = compute_pks_threshold_hash(pks.as_slice(), threshold).unwrap();

        //Create and serialize proof
        let (proof, quality) = create_naive_threshold_sig_proof(
            pks.as_slice(),
            sigs,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            threshold,
            proving_key_path
        ).unwrap();
        let proof_path = "./sample_proof";
        write_to_file(&proof, proof_path).unwrap();

        //Verify proof
        assert!(verify_naive_threshold_sig_proof(
            &constant,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            quality,
            &proof,
            "./sample_vk",
        ).unwrap());


        //Generate wrong public inputs by changing quality and assert proof verification doesn't pass
        assert!(!verify_naive_threshold_sig_proof(
            &constant,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            quality - 1,
            &proof,
            "./sample_vk",
        ).unwrap());
    }

    #[test]
    fn naive_threshold_sig_circuit_test() {
        create_sample_naive_threshold_sig_circuit(10);
        create_sample_naive_threshold_sig_circuit(0);
    }

    #[test]
    fn sample_schnorr_sig_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);

        let (pk, sk) = schnorr_generate_key(); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let mut pk_serialized = vec![0u8; SCHNORR_PK_SIZE];
        serialize_to_buffer(&pk, &mut pk_serialized).unwrap();
        let pk_deserialized = deserialize_from_buffer(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let mut sk_serialized = vec![0u8; SCHNORR_SK_SIZE];
        serialize_to_buffer(&sk, &mut sk_serialized).unwrap();
        let sk_deserialized = deserialize_from_buffer(&sk_serialized).unwrap();
        assert_eq!(sk, sk_deserialized);

        let sig = schnorr_sign(&msg, &sk, &pk).unwrap(); //Sign msg

        //Serialize/deserialize sig
        let mut sig_serialized = vec![0u8; SCHNORR_SIG_SIZE];
        serialize_to_buffer(&sig, &mut sig_serialized).unwrap();
        let sig_deserialized = deserialize_from_buffer(&sig_serialized).unwrap();
        assert_eq!(sig, sig_deserialized);

        assert!(schnorr_verify_signature(&msg, &pk, &sig).unwrap()); //Verify sig

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(!schnorr_verify_signature(&wrong_msg, &pk, &sig).unwrap());
    }

    #[test]
    fn sample_vrf_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);

        let (pk, sk) = vrf_generate_key(); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let mut pk_serialized = vec![0u8; VRF_PK_SIZE];
        serialize_to_buffer(&pk, &mut pk_serialized).unwrap();
        let pk_deserialized = deserialize_from_buffer(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let mut sk_serialized = vec![0u8; VRF_SK_SIZE];
        serialize_to_buffer(&sk, &mut sk_serialized).unwrap();
        let sk_deserialized = deserialize_from_buffer(&sk_serialized).unwrap();
        assert_eq!(sk, sk_deserialized);

        let (vrf_proof, vrf_out) = vrf_prove(&msg, &sk, &pk).unwrap(); //Create vrf proof for msg

        //Serialize/deserialize vrf proof
        let mut proof_serialized = vec![0u8; VRF_PROOF_SIZE];
        serialize_to_buffer(&vrf_proof, &mut proof_serialized).unwrap();
        let proof_deserialized = deserialize_from_buffer(&proof_serialized).unwrap();
        assert_eq!(vrf_proof, proof_deserialized);

        //Serialize/deserialize vrf out (i.e. a field element)
        let mut vrf_out_serialized = vec![0u8; FIELD_SIZE];
        serialize_to_buffer(&vrf_out, &mut vrf_out_serialized).unwrap();
        let vrf_out_deserialized = deserialize_from_buffer(&vrf_out_serialized).unwrap();
        assert_eq!(vrf_out, vrf_out_deserialized);

        let vrf_out_dup = vrf_proof_to_hash(&msg, &pk, &vrf_proof).unwrap(); //Verify vrf proof and get vrf out for msg
        assert_eq!(vrf_out, vrf_out_dup);

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(vrf_proof_to_hash(&wrong_msg, &pk, &vrf_proof).is_err());
    }

    #[test]
    fn sample_merkle_tree(){
        let leaves_num = 16;
        let mut leaves = vec![];
        let mut rng = OsRng;

        // Non lazy
        let mut mt = new_ginger_merkle_tree(
            "./temp_db",
            "./temp_cache",
        ).unwrap();

        // Add leaves to mt in different positions
        for _ in 0..leaves_num {
            loop {
                let r = FieldElement::rand(&mut rng);
                let position = get_position_in_ginger_merkle_tree(&mt, &r);
                if position != NON_EMPTY_POSITION { //Ensure that each leaf ends up in a different position
                    leaves.push(r);
                    add_leaf_to_ginger_merkle_tree(&mut mt, &r, position as usize);
                    break;
                }
            }
        }

        //Get root of mt
        let mt_root = get_ginger_merkle_root(&mt);

        // Lazy
        let mut lazy_mt = new_lazy_ginger_merkle_tree(
            "./temp_db_lazy",
            "./temp_cache_lazy",
        ).unwrap();

        // No conflicts here because we ensured each leaf to fall in a different position
        let lazy_mt_root = add_leaves_to_ginger_merkle_tree(&mut lazy_mt, leaves.as_slice());

        assert_eq!(mt_root, lazy_mt_root);
    }

    #[test]
    fn sample_poseidon_hash(){
        let mut rng = OsRng;
        let hash_input = vec![FieldElement::rand(&mut rng); 2];
        let mut h = get_poseidon_hash(None);

        //Compute poseidon hash
        update_poseidon_hash(&mut h, &hash_input[0]);
        update_poseidon_hash(&mut h, &hash_input[1]);
        let h_output = finalize_poseidon_hash(&h);

        //Call to finalize keeps the state
        reset_poseidon_hash(&mut h, None);
        update_poseidon_hash(&mut h, &hash_input[0]);
        finalize_poseidon_hash(&h); //Call to finalize() keeps the state
        update_poseidon_hash(&mut h, &hash_input[1]);
        assert_eq!(h_output, finalize_poseidon_hash(&h));

        //finalize() is idempotent
        assert_eq!(h_output, finalize_poseidon_hash(&h));

    }
}