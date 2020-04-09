use algebra::{fields::{mnt4753::{Fr as MNT4Fr, Fq as MNT4Fq}, PrimeField}, curves::mnt4753::MNT4, curves::mnt6753::{G1Projective as MNT6G1Projective, G1Affine as MNT6G1Affine}, ToBits, FromBytes, ToBytes, BigInteger768, ProjectiveCurve, Field, AffineCurve};
use primitives::{
    crh::{
        poseidon::MNT4PoseidonHash,
        FieldBasedHash,
        bowe_hopwood::{
            BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters
        },
    },
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
    prepare_verifying_key, verify_proof,
};
use demo_circuit::{
    constants::{
        VRFParams, VRFWindow,
    },
    naive_threshold_sig::*
};
use rand::{
    Rng, rngs::OsRng
};
use std::fs::File;
use lazy_static::*;

pub type FieldElement = MNT4Fr;
pub type Error = Box<dyn std::error::Error>;

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

pub fn schnorr_sign(msg: &FieldElement, sk: &SchnorrSk, pk: &SchnorrPk) -> Result<SchnorrSig, Error> {
    let mut rng = OsRng;
    SchnorrSigScheme::sign(&mut rng, &pk.into_projective(), sk, &[*msg])
}

pub fn schnorr_verify_signature(msg: &FieldElement, pk: &SchnorrPk, signature: &SchnorrSig) -> Result<bool, Error> {
    SchnorrSigScheme::verify(&pk.into_projective(), &[*msg], signature)
}

//*****************************Naive threshold sig circuit related functions************************

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(pks: &[SchnorrPk], threshold: u64) -> Result<FieldElement, Error> {
    let threshold_field = MNT4Fr::from_repr(BigInteger768::from(threshold));
    let mut pks_x = pks.iter().map(|pk| pk.x).collect::<Vec<_>>();
    let pks_hash = MNT4PoseidonHash::evaluate(pks_x.as_slice())?;
    MNT4PoseidonHash::evaluate(&[pks_hash, threshold_field])
}

pub fn schnorr_create_threshold_signature_proof(
    pks:                      &[SchnorrPk],
    mut sigs:                 Vec<Option<SchnorrSig>>,
    msg:                      &FieldElement,
    threshold:                u64,
    proving_key_path:         &str
) -> Proof<MNT4> {

    //Get max pks
    let n = pks.len();
    assert_eq!(sigs.len(), n);

    // Iterate over sigs, check and count number of valid signatures,
    // and replace with NULL_CONST.null_sig the None ones
    let mut valid_signatures = 0;
    for i in 0..n {
        if sigs[i].is_some(){
            if schnorr_verify_signature(msg, &pks[i], &sigs[i].unwrap()).unwrap() {
                valid_signatures += 1;
            }
        }
        else {
            sigs[i] = Some(NULL_CONST.null_sig)
        }
    }

    //Compute b as v-t and convert it to field element
    let b_field = MNT4Fr::from_repr(BigInteger768::from(valid_signatures - threshold));
    let threshold_field = MNT4Fr::from_repr(BigInteger768::from(threshold));

    //Compute hash commitment
    let pks_hash_input = pks.iter().map(|pk| pk.x).collect::<Vec<_>>();
    let pks_hash = MNT4PoseidonHash::evaluate(pks_hash_input.as_slice()).unwrap();
    let hash_commitment = MNT4PoseidonHash::evaluate(&[pks_hash, threshold_field]).unwrap();

    //Convert affine pks to projective
    let pks = pks.iter().map(|&pk| pk.into_projective()).collect::<Vec<_>>();
    let c = NaiveTresholdSignature::<MNT4Fr>::new(
        pks, sigs, threshold_field, b_field, *msg, hash_commitment, n
    );

    //Read proving key
    let mut file = File::open(proving_key_path).unwrap();
    let params = Parameters::<MNT4>::read(&mut file).unwrap();

    //Create and return proof
    let mut rng = OsRng;
    create_random_proof(c, &params, &mut rng).unwrap()
}

#[test]
fn create_sample_naive_threshold_sig_circuit() {
    //assume to have 3 pks, threshold = 2
    let mut rng = OsRng;
    let msg = FieldElement::rand(&mut rng);
    let threshold: u64 = 2;

    //Generate params and write them to file
    let params = generate_parameters(3).unwrap();
    let proving_key_path = "./sample_proving_key";
    let mut file = File::create(proving_key_path).unwrap();
    params.write(&mut file).unwrap();

    //Generate sample pks and sigs vec
    let mut pks = vec![];
    let mut sks = vec![];
    for i in 0..3 {
        let keypair = schnorr_generate_key();
        pks.push(keypair.0);
        sks.push(keypair.1);
    }

    let mut sigs = vec![];
    sigs.push(Some(schnorr_sign(&msg, &sks[0], &pks[0]).unwrap()));
    sigs.push(None);
    sigs.push(Some(schnorr_sign(&msg, &sks[2], &pks[2]).unwrap()));

    //Create and serialize proof
    let proof = schnorr_create_threshold_signature_proof(pks.as_slice(), sigs, &msg, threshold, proving_key_path);
    let proof_path = "./sample_proof";
    let mut file = File::create(proof_path).unwrap();
    proof.write(&mut file).unwrap();

    //Verify proof
    let pks_threshold_hash = compute_pks_threshold_hash(&pks, threshold).unwrap(); //Compute one of the public input
    let pvk = prepare_verifying_key(&params.vk); //Get verifying key
    assert!(verify_proof(&pvk, &proof, &[msg, pks_threshold_hash])) //Assert proof verification passes
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

pub fn vrf_prove(msg: &FieldElement, sk: &VRFSk, pk: &VRFPk) -> Result<VRFProof, Error> {
    let mut rng = OsRng;
    VRFScheme::prove(&mut rng, &VRF_GH_PARAMS, &pk.into_projective(), sk, &[*msg])
}

pub fn vrf_proof_to_hash(msg: &FieldElement, pk: &VRFPk, proof: &VRFProof) -> Result<FieldElement, Error> {
    VRFScheme::proof_to_hash(&VRF_GH_PARAMS,&pk.into_projective(), &[*msg], proof)
}

#[test]
fn sample_vrf_prove_verify(){
    let mut rng = OsRng;
    let msg = FieldElement::rand(&mut rng);

    let (pk, sk) = vrf_generate_key(); //Keygen
    let vrf_proof = vrf_prove(&msg, &pk, &sk).unwrap(); //Create vrf proof for msg
    let vrf_output = vrf_proof_to_hash(&msg, &pk, &vrf_proof).unwrap(); //Verify vrf proof and get vrf out for msg
}

