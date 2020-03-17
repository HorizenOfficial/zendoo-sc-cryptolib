extern crate jni;

use algebra::{fields::{
    mnt4753::Fr,
    mnt4753::Fq as Fs,
}, curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{G1Projective, G1Affine},
}, bytes::{FromBytes, ToBytes},
              AffineCurve, ProjectiveCurve, UniformRand,
};

use crypto_primitives::{
    signature::{
        FieldBasedSignatureScheme,
        schnorr::field_impl::{
            FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme
        },
    },
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
        pedersen::PedersenWindow,
    },
};

use rand::rngs::OsRng;

use groth16::{Proof, verifier::verify_proof, prepare_verifying_key, VerifyingKey};

//use libc::c_uchar;
use std::path::Path;
use std::slice;
//use std::ffi::OsStr;
//use std::os::unix::ffi::OsStrExt;
use std::fs::File;

//Suitable to hash one Fr
#[derive(Clone)]
struct TestWindow {}
impl PedersenWindow for TestWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 2;
}

//Sig types
type SchnorrSig = FieldBasedSchnorrSignature<Fr>;
type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<Fr, G1Projective, FrHash>;

// ************CONSTANTS******************

const FR_SIZE: usize = 96;
const FS_SIZE: usize = FR_SIZE; // 96
const G1_SIZE: usize = 193;
const G2_SIZE: usize = 385;

const HASH_SIZE:        usize = FR_SIZE;                // 96
const SIG_SIZE:         usize = 2 * FR_SIZE;            // 192
const GROTH_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771

// ***********UTILITY FUNCTIONS*************

/// Reads a raw Fr from a [u8; FR_SIZE].
fn read_fr(from: &[u8; FR_SIZE]) -> Option<Fr> {
    match Fr::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads a raw Fs from a [u8; FS_SIZE].
fn read_fs(from: &[u8; FS_SIZE]) -> Option<Fs> {
    match Fs::read(&from[..]) {
        Ok(f) => Some(f),
        Err(_) => None,
    }
}

/// Reads as many FrReprs as FR_SIZE-byte chunks contained in `from`
/// NOTE: Probably there is a smarter way to pass a vector of field elements
fn read_frs_from_slice(from: &[u8]) -> Option<Vec<Fr>> {
    let mut fes = vec![];
    for chunk in from.chunks(FR_SIZE) {

        //Pad to reach expected field's number of bytes
        let mut chunk = chunk.to_vec();
        let len = chunk.len();
        for _ in len..FR_SIZE {
            chunk.push(0u8);
        }

        //Read Fr
        let mut const_chunk = [0u8; FR_SIZE];
        chunk.write(&mut const_chunk[..]).expect("Should be able to write fe bytes into a slice");
        match read_fr(&const_chunk) {
            Some(fe) => fes.push(fe),
            None => return None,
        };
    }
    Some(fes)
}

/// Reads as many G1 Affine points as G1_SIZE-byte chunks contained in `from`
/// NOTE: Probably there is a smarter way to pass a vector of curve points
fn read_points_from_slice(from: &[u8]) -> Option<Vec<G1Affine>>
{
    let mut points = vec![];
    for chunk in from.chunks(G1_SIZE) {

        //Pad to reach expected point's number of bytes
        let mut chunk = chunk.to_vec();
        let len = chunk.len();
        for _ in len..G1_SIZE {
            chunk.push(0u8);
        }

        //Read Fr
        match G1Affine::read(chunk.as_slice()) {
            Ok(p) => points.push(p),
            Err(_) => return None,
        };
    }
    Some(points)
}

fn read_vk(vk_path: &str) -> VerifyingKey<PairingCurve>
{
    // Load vk from file
    let mut vk_fs = File::open(vk_path).expect("couldn't load vk file");

    VerifyingKey::<PairingCurve>::read(&mut vk_fs)
        .expect("couldn't deserialize vk file")
}

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jboolean};
use jni::sys::{JNI_TRUE, JNI_FALSE};

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrf_VRFProof_nativeProofToVRFHash(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _proof: jbyteArray
) -> jbyteArray {

    let mut _input = _env.convert_byte_array(_proof).unwrap();
    _input.reverse();
    _env.byte_array_from_slice(&_input).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrf_VRFSecretKey_nativeVerify(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _key_path: JString,
    _message: jbyteArray,
    _proof: jbyteArray
) -> jboolean {

    let vkp = _env.get_string(_key_path)
        .expect("Verification key path is invalid.");
    let verification_key_path = vkp.to_str()
        .expect("Verification key path is invalid.");

    //Load Vk
    let vk = read_vk(verification_key_path);
    let pvk = prepare_verifying_key(&vk);

    //Read public inputs
    let public_inputs_raw = _env.convert_byte_array(_message)
        .expect("Message is invalid.");
    let public_inputs = match read_frs_from_slice(&public_inputs_raw) {
        Some(public_inputs) => public_inputs,
        None => return JNI_FALSE,
    };

    // Deserialize the proof
    let zkp_raw = _env.convert_byte_array(_proof)
        .expect("Proof is invalid.");
    let zkp = match Proof::<PairingCurve>::read(&(unsafe { &*zkp_raw })[..]) {
        Ok(zkp) => zkp,
        Err(_) => return JNI_FALSE,
    };

    // Verify the proof
    match verify_proof(&pvk, &zkp, &public_inputs) {
        // No error, and proof verification successful
        Ok(true) => JNI_TRUE,
        // Any other case
        _ => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrf_VRFSecretKey_nativeProve(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _key: jbyteArray,
    _message: jbyteArray
) -> jbyteArray {

    //let result_class = _env.find_class("com/horizen/vrf/VRFProof").unwrap();
    //let result = _env.new_object(result_class, "()V", &[]).unwrap();

    let mut _input = _env.convert_byte_array(_message).unwrap();
    _input.reverse();
    _env.byte_array_from_slice(&_input).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrf_VRFSecretKey_nativeVRFHash(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _key: jbyteArray,
    _message: jbyteArray
) -> jbyteArray {

    let mut _input = _env.convert_byte_array(_message).unwrap();
    _input.reverse();
    _env.byte_array_from_slice(&_input).unwrap()
}

