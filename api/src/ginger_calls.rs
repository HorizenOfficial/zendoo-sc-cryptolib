use algebra::{
    fields::{
        mnt4753::{Fr as MNT4Fr, Fq as MNT4Fq}, PrimeField
    },
    curves::{
        mnt4753::MNT4,
        mnt6753::{
            G1Projective as MNT6G1Projective, G1Affine as MNT6G1Affine
        },
    },
    FromBytes, ToBytes,
    BigInteger768,
    ProjectiveCurve, AffineCurve
};
use primitives::{
    crh::{
        poseidon::MNT4PoseidonHash,
        FieldBasedHash,
        bowe_hopwood::{
            BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters
        },
    },
    merkle_tree::field_based_mht::{FieldBasedMerkleHashTree, FieldBasedMerkleTreeConfig, FieldBasedMerkleTreePath},
    signature::{
        FieldBasedSignatureScheme, schnorr::field_based_schnorr::{
            FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrSignature
        },
    },
    vrf::{FieldBasedVrf, ecvrf::*},
};
use proof_systems::groth16::{
    Parameters,
    Proof, create_random_proof,
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

fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8]) ->  IoResult<T> {
    T::read(buffer)
}

fn serialize_to_buffer<T: ToBytes>(to_write: &T, buffer: &mut [u8]) -> IoResult<()> {
    to_write.write(buffer)
}

fn read_from_file<T: FromBytes>(file_path: &str) -> IoResult<T>{
    let mut fs = File::open(file_path)?;
    let t = T::read(&mut fs)?;
    Ok(t)
}

fn write_to_file<T: ToBytes>(to_write: &T, file_path: &str) -> IoResult<()>{
    let mut fs = File::create(file_path)?;
    to_write.write(&mut fs)?;
    Ok(())
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

//************************************Poseidon Hash function****************************************

pub fn compute_poseidon_hash(input: &[FieldElement]) -> Result<FieldElement, Error> {
    MNT4PoseidonHash::evaluate(input)
}

//*****************************Naive threshold sig circuit related functions************************

#[derive(Clone, Default)]
pub struct BackwardTransfer {
    pub pk_dest:    [u8; 32],
    pub amount:     u64,
}

impl BackwardTransfer {
    pub fn new(pk_dest: [u8; 32], amount: u64) -> Self
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
    let pks_x = pks.iter().map(|pk| pk.x).collect::<Vec<_>>();
    let pks_hash = compute_poseidon_hash(pks_x.as_slice())?;
   compute_poseidon_hash(&[pks_hash, threshold_field])
}

//Compute and return (MR(bt_list), H(MR(bt_list), H(bi-1), H(bi))
pub fn compute_msg_to_sign(
    end_epoch_mc_b_hash:      &FieldElement,
    prev_end_epoch_mc_b_hash: &FieldElement,
    bt_list:                  &[BackwardTransfer],
) -> Result<(FieldElement, FieldElement), Error> {

    let mut bt_field_list = vec![];
    for bt in bt_list.iter() {
        let bt_f = bt.to_field_element()?;
        bt_field_list.push(bt_f);
    }

    //Compute bt_list merkle_root
    let bt_mt = new_ginger_merkle_tree(bt_field_list.as_slice())?;

    drop(bt_field_list);

    let mr_bt = get_ginger_merkle_root(&bt_mt);

    drop(bt_mt);

    //Compute message to be verified
    let msg = compute_poseidon_hash(&[mr_bt, *prev_end_epoch_mc_b_hash, *end_epoch_mc_b_hash])?;

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
    let wcert_sysdata_hash = compute_poseidon_hash(&[quality, *mr_bt, *prev_end_epoch_mc_b_hash, *end_epoch_mc_b_hash])?;
    Ok(wcert_sysdata_hash)
}

//Return (wcert_sysdata_hash, pk_threshold_hash)
pub fn get_public_inputs_for_naive_threshold_sig_proof(
    pks:                      &[SchnorrPk],
    threshold:                u64,
    end_epoch_mc_b_hash:      &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list:                  &[BackwardTransfer],
    valid_sigs:               u64,
) -> Result<(FieldElement, FieldElement), Error> {

    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..])?;
    let prev_end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..])?;
    let (mr_bt, _) = compute_msg_to_sign(&end_epoch_mc_b_hash, &prev_end_epoch_mc_b_hash, bt_list)?;
    let wcert_sysdata_hash = compute_wcert_sysdata_hash(valid_sigs, &mr_bt, &prev_end_epoch_mc_b_hash, &end_epoch_mc_b_hash)?;
    let pks_threshold_hash = compute_pks_threshold_hash(pks, threshold)?;

    Ok((wcert_sysdata_hash, pks_threshold_hash))
}

pub fn create_naive_threshold_sig_proof(
    pks:                      &[SchnorrPk],
    mut sigs:                 Vec<Option<SchnorrSig>>,
    end_epoch_mc_b_hash:      &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list:                  &[BackwardTransfer],
    threshold:                u64,
    proving_key_path:         &str
) -> Result<Proof<MNT4>, Error> {

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

    //Compute wcert_sysdata_hash
    let wcert_sysdata_hash = compute_wcert_sysdata_hash(valid_signatures, &mr_bt, &prev_end_epoch_mc_b_hash, &end_epoch_mc_b_hash)?;

    //Compute pks_threshold_hash
    let pks_threshold_hash = compute_pks_threshold_hash(pks, threshold)?;

    //Convert affine pks to projective
    let pks = pks.iter().map(|&pk| pk.into_projective()).collect::<Vec<_>>();

    //Convert needed variables into field elements
    let threshold = read_field_element_from_u64(threshold);

    let c = NaiveTresholdSignature::<FieldElement>::new(
        pks, sigs, threshold, b, end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash, mr_bt, pks_threshold_hash,
        wcert_sysdata_hash, max_pks,
    );

    //Read proving key
    let mut file = File::open(proving_key_path)?;
    let params = Parameters::<MNT4>::read(&mut file)?;

    //Create and return proof
    let mut rng = OsRng;
    let proof = create_random_proof(c, &params, &mut rng)?;
    Ok(proof)
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

pub fn vrf_prove(msg: &FieldElement, sk: &VRFSk, pk: &VRFPk) -> Result<VRFProof, Error> {
    let mut rng = OsRng;
    VRFScheme::prove(&mut rng, &VRF_GH_PARAMS, &pk.into_projective(), sk, &[*msg])
}

pub fn vrf_proof_to_hash(msg: &FieldElement, pk: &VRFPk, proof: &VRFProof) -> Result<FieldElement, Error> {
    VRFScheme::proof_to_hash(&VRF_GH_PARAMS,&pk.into_projective(), &[*msg], proof)
}

//************Merkle Tree functions******************

pub struct FieldBasedMerkleTreeParams;

impl FieldBasedMerkleTreeConfig for FieldBasedMerkleTreeParams {
    const HEIGHT: usize = 9;
    type H = MNT4PoseidonHash;
}

type GingerMerkleTree = FieldBasedMerkleHashTree<FieldBasedMerkleTreeParams>;
type GingerMerkleTreePath = FieldBasedMerkleTreePath<FieldBasedMerkleTreeParams>;

pub fn new_ginger_merkle_tree(leaves: &[FieldElement]) -> Result<GingerMerkleTree, Error> {
    GingerMerkleTree::new(leaves)
}

pub fn get_ginger_merkle_root(tree: &GingerMerkleTree) -> FieldElement {
    tree.root()
}

pub fn get_ginger_merkle_path(leaf: &FieldElement, leaf_index: usize, tree: &GingerMerkleTree)
    -> Result<GingerMerkleTreePath, Error>
{
    tree.generate_proof(leaf_index, leaf)
}

pub fn verify_ginger_merkle_path(path: GingerMerkleTreePath, merkle_root: &FieldElement, leaf: &FieldElement)
    -> Result<bool, Error>
{
    path.verify(merkle_root, leaf)
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::UniformRand;
    use proof_systems::groth16::{
        prepare_verifying_key, verify_proof,
    };
    use rand::RngCore;

    #[test]
    fn create_sample_naive_threshold_sig_circuit() {
        //assume to have 3 pks, threshold = 2
        let mut rng = OsRng;

        //Generate random mc block hashes and bt list
        let mut end_epoch_mc_b_hash = [0u8; 32];
        let mut prev_end_epoch_mc_b_hash = [0u8; 32];
        rng.fill_bytes(&mut end_epoch_mc_b_hash);
        rng.fill_bytes(&mut prev_end_epoch_mc_b_hash);
        let end_epoch_mc_b_hash_f = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..]).unwrap();
        let prev_end_epoch_mc_b_hash_f = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..]).unwrap();

        let bt_num = 10;
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

        //Create and serialize proof
        let proof = create_naive_threshold_sig_proof(
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
        let (wcert_sysdata_hash, pks_threshold_hash) = get_public_inputs_for_naive_threshold_sig_proof(
            &pks,
            threshold,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            2
        ).unwrap();
        let pvk = prepare_verifying_key(&params.vk); //Get verifying key
        assert!(verify_proof(&pvk, &proof, &[pks_threshold_hash, wcert_sysdata_hash]).unwrap()); //Assert proof verification passes

        //Generate wrong public inputs by changing threshold and valid sigs and assert proof verification doesn't pass
        let (wrong_wcert_sysdata_hash, wrong_pks_threshold_hash) = get_public_inputs_for_naive_threshold_sig_proof(
            &pks,
            1,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            1
        ).unwrap();
        assert!(!verify_proof(&pvk, &proof, &[wrong_pks_threshold_hash, wrong_wcert_sysdata_hash]).unwrap()); //Assert proof verification passes
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

        let vrf_proof = vrf_prove(&msg, &sk, &pk).unwrap(); //Create vrf proof for msg

        //Serialize/deserialize vrf proof
        let mut proof_serialized = vec![0u8; VRF_PROOF_SIZE];
        serialize_to_buffer(&vrf_proof, &mut proof_serialized).unwrap();
        let proof_deserialized = deserialize_from_buffer(&proof_serialized).unwrap();
        assert_eq!(vrf_proof, proof_deserialized);

        let vrf_out = vrf_proof_to_hash(&msg, &pk, &vrf_proof).unwrap(); //Verify vrf proof and get vrf out for msg

        //Serialize/deserialize vrf out (i.e. a field element)
        let mut vrf_out_serialized = vec![0u8; FIELD_SIZE];
        serialize_to_buffer(&vrf_out, &mut vrf_out_serialized).unwrap();
        let vrf_out_deserialized = deserialize_from_buffer(&vrf_out_serialized).unwrap();
        assert_eq!(vrf_out, vrf_out_deserialized);

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(vrf_proof_to_hash(&wrong_msg, &pk, &vrf_proof).is_err());
    }

    #[test]
    fn sample_merkle_tree(){
        let leaves_num = 16;
        let mut leaves = vec![];
        let mut rng = OsRng;
        for _ in 0..leaves_num {
            leaves.push(FieldElement::rand(&mut rng));
        }

        let mt = GingerMerkleTree::new(leaves.as_slice()).unwrap();
        let root = get_ginger_merkle_root(&mt);
        let wrong_root = FieldElement::rand(&mut rng);

        for i in 0..leaves_num {
            let path = get_ginger_merkle_path(&leaves[i], i, &mt).unwrap();
            assert!(verify_ginger_merkle_path(path.clone(), &root, &leaves[i]).unwrap());
            assert!(!verify_ginger_merkle_path(path, &wrong_root, &leaves[i]).unwrap());
        }
    }
}