extern crate jni;

use algebra::{
    biginteger::BigInteger768 as BigInteger,
    fields::{
        mnt4753::{Fr, Fq as Fs},
        PrimeField,
    },
    curves::{
        mnt4753::MNT4 as PairingCurve,
        mnt6753::{G1Affine, G1Projective},
        ProjectiveCurve, AffineCurve,
    },
    bytes::{FromBytes, ToBytes},
    UniformRand
};

use primitives::{
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
        bowe_hopwood::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters},
    },
    merkle_tree::field_based_mht::{
        FieldBasedMerkleHashTree, FieldBasedMerkleTreeConfig, FieldBasedMerkleTreePath
    },
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme},
        FieldBasedSignatureScheme,
    },
    vrf::{
        FieldBasedVrf,
        ecvrf::{
            FieldBasedEcVrf, FieldBasedEcVrfProof,
        }
    },
};

use proof_systems::groth16::{
    Proof, prover::create_random_proof,
    verifier::verify_proof, prepare_verifying_key,
};

use demo_circuit::{
    naive_threshold_sig::{
        NaiveTresholdSignature, generate_parameters, NULL_CONST,
    },
    constants::{
        VRFParams, VRFWindow,
    },
};

use rand::rngs::OsRng;

use std::{
    path::Path, slice, fs::File, ptr::null_mut,
    io::{
        Error as IoError, ErrorKind,
    },
};

use lazy_static::*;
use std::panic;

pub mod error;
use error::*;

mod ginger_calls;

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
/// TODO: Probably there is a smarter way to pass a vector of field elements
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
/// TODO: Probably there is a smarter way to pass a vector of curve points
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

/*
fn read_vk(vk_path: &str) -> VerifyingKey<PairingCurve>
{
    // Load vk from file
    let mut vk_fs = File::open(vk_path)
        .expect("couldn't load vk file");

    VerifyingKey::<PairingCurve>::read(&mut vk_fs)
        .expect("couldn't deserialize vk file")
}
*/

fn read_raw_pointer<T>(input: *const T, elem_type: &str) -> Option<&T> {
    if input.is_null(){
        set_last_error(Box::new(NullPointerError(format!("Null {}", elem_type))), NULL_PTR_ERROR);
        return None
    }
    Some(unsafe{ &* input })
}

fn read_double_raw_pointer<T: Copy>(input: *const *const T, input_len: usize, elem_type: &str) -> Option<Vec<T>> {

    //Read *const T from *const *const T
    if input.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Ptr to {}s is null", elem_type))), NULL_PTR_ERROR);
        return None
    }
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for (i, &ptr) in input_raw.iter().enumerate() {
        if ptr.is_null() {
            set_last_error(Box::new(NullPointerError(format!("{} {} is null", elem_type, i))), NULL_PTR_ERROR);
            return None
        }
        input.push(unsafe{ *ptr });
    }

    Some(input)
}

fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8], buff_size: usize) -> *mut T {
    match T::read(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("should read {} bytes", buff_size));
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut()
        }
    }
}

fn serialize_to_buffer<T: ToBytes>(to_write: *const T, buffer: &mut [u8], buff_size: usize, elem_type: &str) -> bool {
    let to_write = match read_raw_pointer(to_write, elem_type) {
        Some(to_write) => to_write,
        None => return false,
    };

    match to_write.write(buffer){
        Ok(_) => true,
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("should write {} bytes", buff_size));
            set_last_error(Box::new(e), IO_ERROR);
            false
        }
    }
}

use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jbyteArray, jboolean, jint, jlong, jobject};
use jni::sys::{JNI_TRUE, JNI_FALSE};
use crate::ginger_calls::compute_poseidon_hash;

//Public key utility functions
#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_PublicKeyUtils_nativeGetPublicKeySize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { G1_SIZE as jint }

#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_PublicKeyUtils_nativeSerializePublicKey(
    _env: JNIEnv,
    _class: JClass,
    _pk: *const G1Affine,
) -> jbyteArray
{
    let pk: &mut [u8; G1_SIZE] = &mut [0; G1_SIZE];
    serialize_to_buffer(_pk, &mut (unsafe { &mut *pk })[..], G1_SIZE, "pk");

    match _env.byte_array_from_slice(pk.as_ref()) {
        Ok(result) => result,
        Err(_) => return _env.new_byte_array(0).unwrap(),
    }
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_PublicKeyUtils_nativeDeserializePublicKey(
    _env: JNIEnv,
    _class: JClass,
    _pkBytes: jbyteArray,
) -> *mut G1Affine
{
    let pk_bytes = match _env.convert_byte_array(_pkBytes) {
        Ok(pk_bytes) => pk_bytes,
        Err(_) => return null_mut(),

    };
    deserialize_from_buffer(&(unsafe { &*pk_bytes })[..], G1_SIZE)
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_PublicKeyUtils_nativeFreePublicKey(
    _env: JNIEnv,
    _class: JClass,
    _pk: *mut G1Affine,
)
{
    if _pk.is_null()  { return }
    drop(unsafe { Box::from_raw(_pk) });
}

//Secret key utility functions
#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_SecretKeyUtils_nativeGetSecretKeySize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { FS_SIZE as jint }

#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_SecretKeyUtils_nativeSerializeSecretKey(
    _env: JNIEnv,
    _class: JClass,
    _sk: *const Fs,
) -> jbyteArray
{
    let sk: &mut [u8; FS_SIZE] = &mut [0; FS_SIZE];
    serialize_to_buffer(_sk, &mut (unsafe { &mut *sk })[..], FS_SIZE, "sk");

    match _env.byte_array_from_slice(sk.as_ref()) {
        Ok(result) => result,
        Err(_) => return _env.new_byte_array(0).unwrap(),
    }
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_SecretKeyUtils_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _class: JClass,
    _skBytes: jbyteArray,
) -> *mut G1Affine
{
    let sk_bytes = match _env.convert_byte_array(_skBytes) {
        Ok(sk_bytes) => sk_bytes,
        Err(_) => return null_mut(),

    };
    deserialize_from_buffer(&(unsafe { &*sk_bytes })[..], FS_SIZE)
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_librustsidechains_SecretKeyUtils_nativeFreeSecretKey(
    _env: JNIEnv,
    _class: JClass,
    _sk: *mut G1Affine,
)
{
    if _sk.is_null()  { return }
    drop(unsafe { Box::from_raw(_sk) });
}

//Schnorr signature utility functions
#[no_mangle]
pub extern "C" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeGetSignatureSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { SIG_SIZE as jint }

#[no_mangle]
pub extern "C" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeSerializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig: *const SchnorrSig,
) -> jbyteArray
{
    let sig: &mut [u8; SIG_SIZE] = &mut [0; SIG_SIZE];
    serialize_to_buffer(_sig, &mut (unsafe { &mut *sig })[..], SIG_SIZE, "schnorr sig");

    match _env.byte_array_from_slice(sig.as_ref()) {
        Ok(result) => result,
        Err(_) => return _env.new_byte_array(0).unwrap(),
    }
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeDeserializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sigBytes: jbyteArray,
) -> *mut SchnorrSig
{
    let sig_bytes = match _env.convert_byte_array(_sigBytes) {
        Ok(sig_bytes) => sig_bytes,
        Err(_) => return null_mut(),

    };
    deserialize_from_buffer(&(unsafe { &*sig_bytes })[..], SIG_SIZE)
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativefreeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig: *mut SchnorrSig,
)
{
    if _sig.is_null()  { return }
    drop(unsafe { Box::from_raw(_sig) });
}

//Schnorr signature functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeGenerate(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
) -> jobject
{

    let mut rng = OsRng;
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);

    let skResult: jlong = jlong::from(Box::into_raw(Box::new(sk)) as i64);
    let pkResult: jlong = jlong::from(Box::into_raw(Box::new(pk.into_affine())) as i64);

    let class = match _env.find_class("com/horizen/schnorrnative/SchnorrKeyPair") {
        Ok(class) => class,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let result = match _env.new_object(class, "(JJ)V", &[
        JValue::Long(skResult),
        JValue::Long(pkResult)]) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeSignMessage(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _secretKey: JObject,
    _publicKey: JObject,
    _message: jbyteArray
) -> jobject {

    //Read sk
    let sk: *const Fs = match _env.call_method(_secretKey, "getSecretKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const Fs,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let secretKey = match read_raw_pointer(sk, "schnorr sk"){
        Some(s) => s,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Read pk
    let pk: *const G1Affine = match _env.call_method(_publicKey, "getPublicKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const G1Affine,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    // let publicKey = unsafe {&*pk};

    let publicKey= match read_raw_pointer(pk, "schnorr pk") {
        Some(pk) => pk,
        None => return std::ptr::null::<jobject>() as jobject
    };


    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Sign message and return opaque pointer to sig
    let mut rng = OsRng;
    let signature= match SchnorrSigScheme::sign(&mut rng, &publicKey.into_projective(), secretKey, fes.as_slice()) {
        Ok(sig) => Box::into_raw(Box::new(sig)),
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let signResult: jlong = jlong::from(signature as i64);

    let class = match _env.find_class("com/horizen/schnorrnative/SchnorrSignature") {
        Ok(class) => class,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let result = match _env.new_object(class, "(J)V", &[
        JValue::Long(signResult)]) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _obj: JObject,
) -> jboolean
{

    let pk: *const G1Affine = match _env.call_method(_obj, "getPublicKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const G1Affine,
        Err(_) => return JNI_FALSE
    };

    let publicKey = match read_raw_pointer(pk, "schnorr pk"){
        Some(pk) => pk,
        None => return JNI_FALSE
    };

    if SchnorrSigScheme::keyverify(&(publicKey.into_projective())) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeGetPublicKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _obj: JObject
) -> jobject {

    let sk: *const Fs = match _env.call_method(_obj, "getSecretKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const Fs,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let secretKey = match read_raw_pointer(sk, "schnorr sk"){
        Some(s) => s,
        None => return std::ptr::null::<jobject>() as jobject
    };

    let pk = SchnorrSigScheme::get_public_key(secretKey);
    let pkResult: jlong = jlong::from(Box::into_raw(Box::new(pk.into_affine())) as i64);

    let class = match _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey") {
        Ok(class) => class,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let result = match _env.new_object(class, "(J)V", &[
        JValue::Long(pkResult)]) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    *result
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifySignature(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _obj: JObject,
    _signature: JObject,
    _message: jbyteArray,
) -> jboolean {

    //Read pk
    let pk: *const G1Affine = match _env.call_method(_obj, "getPublicKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const G1Affine,
        Err(_) => return JNI_FALSE
    };

    // let publicKey = unsafe {&*pk};

    let publicKey= match read_raw_pointer(pk, "schnorr pk") {
        Some(pk) => pk,
        None => return JNI_FALSE
    };


    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => return JNI_FALSE
    };

    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => return JNI_FALSE
    };

    //Read sig
    let sig: *const SchnorrSig = match _env.call_method(_signature, "getSignaturePointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const SchnorrSig,
        Err(_) => return JNI_FALSE
    };

    let signature = match read_raw_pointer(sig, "schnorr sig") {
        Some(s) => s,
        None => return JNI_FALSE
    };

    //Verify sig
    match SchnorrSigScheme::verify(&publicKey.into_projective(), fes.as_slice(), signature) {
        Ok(_) => JNI_TRUE,
        Err(_) => JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeComputeHash(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _input: jbyteArray,
) -> jbyteArray
{
    //Read message as an array of Fr elements
    let input_raw = match _env.convert_byte_array(_input) {
        Ok(input_raw) => input_raw,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };
    let fes = match read_frs_from_slice(&input_raw) {
        Some(fes) => fes,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Compute hash
    let hash = match compute_poseidon_hash(fes.as_slice()) {
        Ok(hash) => hash,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    // Write out hash
    let result: &mut [u8; HASH_SIZE] = &mut [0; HASH_SIZE];
    if (hash.write(&mut (unsafe { &mut *result })[..])).is_err() {
        return std::ptr::null::<jobject>() as jobject
    }

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    }
}

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<G1Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<G1Projective>{generators: params.group_hash_generators}
    };
}

//Hash types
type GroupHash = BoweHopwoodPedersenCRH<G1Projective, VRFWindow>;


//Vrf types
type EcVrfProof = FieldBasedEcVrfProof<Fr, G1Projective>;
type EcVrfScheme = FieldBasedEcVrf<Fr, G1Projective, FrHash, GroupHash>;


const VRF_PROOF_SIZE:   usize = G1_SIZE + 2 * FR_SIZE;  // 385
const VRF_OUTPUT_SIZE:  usize = HASH_SIZE;              // 96

//VRF utility functions
#[no_mangle]
pub extern "C" fn Java_com_horizen_vrfnative_VRFProof_nativeGetProofSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { VRF_PROOF_SIZE as jint }

#[no_mangle]
pub extern "C" fn Java_com_horizen_vrfnative_VRFProof_nativeSerializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof: *const EcVrfProof,
) -> jbyteArray
{
    let proof: &mut [u8; VRF_PROOF_SIZE] = &mut [0; VRF_PROOF_SIZE];
    serialize_to_buffer(_proof, &mut (unsafe { &mut *proof })[..], VRF_PROOF_SIZE, "ecvrf proof");

    match _env.byte_array_from_slice(proof.as_ref()) {
        Ok(result) => result,
        Err(_) => return _env.new_byte_array(0).unwrap(),
    }
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_vrfnative_VRFProof_nativeDeserializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proofBytes: jbyteArray,
) -> *mut EcVrfProof
{
    let proof_bytes = match _env.convert_byte_array(_proofBytes) {
        Ok(bytes) => bytes,
        Err(_) => return null_mut(),

    };
    deserialize_from_buffer(&(unsafe { &*proof_bytes })[..], VRF_PROOF_SIZE)
}

#[no_mangle]
pub extern "C" fn Java_com_horizen_vrfnative_VRFProof_nativefreeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof: *mut EcVrfProof,
)
{
    if _proof.is_null()  { return }
    drop(unsafe { Box::from_raw(_proof) });
}


//VRF functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFKeyPair_nativeGenerate(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass
) -> jobject
{

    let mut rng = OsRng;
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);

    let skResult: jlong = jlong::from(Box::into_raw(Box::new(sk)) as i64);
    let pkResult: jlong = jlong::from(Box::into_raw(Box::new(pk.into_affine())) as i64);

    let class = match _env.find_class("com/horizen/vrfnative/VRFKeyPair") {
        Ok(class) => class,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let result = match _env.new_object(class, "(JJ)V", &[
        JValue::Long(skResult),
        JValue::Long(pkResult)]) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFKeyPair_nativeProve(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _secretKey: JObject,
    _publicKey: JObject,
    _message: jbyteArray
) -> jobject {

    //Read sk
    let sk: *const Fs = match _env.call_method(_secretKey, "getSecretKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const Fs,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let secretKey = match read_raw_pointer(sk, "ecvrf sk"){
        Some(s) => s,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Read pk
    let pk: *const G1Affine = match _env.call_method(_publicKey, "getPublicKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const G1Affine,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    // let publicKey = unsafe {&*pk};

    let publicKey= match read_raw_pointer(pk, "ecvrf pk") {
        Some(pk) => pk,
        None => return std::ptr::null::<jobject>() as jobject
    };


    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Sign message and return opaque pointer to sig
    let mut rng = OsRng;
    let proof = match EcVrfScheme::prove(&mut rng, &VRF_GH_PARAMS,
                                         &publicKey.into_projective(), secretKey, fes.as_slice()) {
        Ok(proof) => Box::into_raw(Box::new(proof)),
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let proofResult: jlong = jlong::from(proof as i64);

    let class = match _env.find_class("com/horizen/vrfnative/VRFProof") {
        Ok(class) => class,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let result = match _env.new_object(class, "(J)V", &[
        JValue::Long(proofResult)]) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetPublicKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _obj: JObject
) -> jobject {

    let sk: *const Fs = match _env.call_method(_obj, "getSecretKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const Fs,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let secretKey = match read_raw_pointer(sk, "ecvrf sk"){
        Some(s) => s,
        None => return std::ptr::null::<jobject>() as jobject
    };

    let pk = EcVrfScheme::get_public_key(secretKey);
    let pkResult: jlong = jlong::from(Box::into_raw(Box::new(pk.into_affine())) as i64);

    let class = match _env.find_class("com/horizen/vrfnative/VRFPublicKey") {
        Ok(class) => class,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let result = match _env.new_object(class, "(J)V", &[
        JValue::Long(pkResult)]) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _obj: JObject,
) -> jboolean
{

    let pk: *const G1Affine = match _env.call_method(_obj, "getPublicKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const G1Affine,
        Err(_) => return JNI_FALSE
    };

    let publicKey = match read_raw_pointer(pk, "ecvrf pk"){
        Some(pk) => pk,
        None => return JNI_FALSE
    };

    if SchnorrSigScheme::keyverify(&(publicKey.into_projective())) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeProofToHash(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _obj: JObject,
    _proof: JObject,
    _message: jbyteArray,
) -> jbyteArray
{
    //Read pk
    let pk: *const G1Affine = match _env.call_method(_obj, "getPublicKeyPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const G1Affine,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let public_key = match read_raw_pointer(pk, "ecvrf pk"){
        Some(pk) => pk,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Read message as an array of Fr elements
    let message = match _env.convert_byte_array(_message) {
        Ok(message) => message,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };
    let fes = match read_frs_from_slice(&message) {
        Some(fes) => fes,
        None => return std::ptr::null::<jobject>() as jobject
    };

    //Read proof
    let p: *const EcVrfProof = match _env.call_method(_obj, "getProofPointer", "()J", &[]) {
        Ok(k) => k.j().unwrap() as *const EcVrfProof,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    let proof = match read_raw_pointer(p, "ecvrf proof") {
        Some(proof) => proof,
        None => return std::ptr::null::<jobject>() as jobject
    };


    //Write out VRF output
    let result: &mut [u8; FS_SIZE] = &mut [0; FS_SIZE];
    let hash = match EcVrfScheme::proof_to_hash(&VRF_GH_PARAMS, &public_key.into_projective(), fes.as_slice(), proof) {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(_) => return std::ptr::null::<jobject>() as jobject
    };

    serialize_to_buffer(hash, &mut (unsafe { &mut *result })[..], FS_SIZE, "ecvrf hash");

    match _env.byte_array_from_slice(result.as_ref()) {
        Ok(r) => r,
        Err(_) => return std::ptr::null::<jobject>() as jobject
    }
}
