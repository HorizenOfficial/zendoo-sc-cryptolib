extern crate jni;

use algebra::bytes::{FromBytes, ToBytes};

use std::{ptr::null_mut, any::type_name};

use std::panic;

mod ginger_calls;
use ginger_calls::*;


fn read_raw_pointer<'a, T>(input: *const T) -> &'a T {
    assert!(!input.is_null());
    unsafe { &*input }
}

fn read_nullable_raw_pointer<'a, T>(input: *const T) -> Option<&'a T> {
    unsafe { input.as_ref() }
}

fn deserialize_to_raw_pointer<T: FromBytes>(buffer: &[u8]) -> *mut T {
    match deserialize_from_buffer(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => return null_mut(),
    }
}

fn serialize_from_raw_pointer<T: ToBytes>(
    to_write: *const T,
    buffer: &mut [u8],
) {
    serialize_to_buffer(read_raw_pointer(to_write), buffer)
        .expect(format!("unable to write {} to buffer", type_name::<T>()).as_str())
}

use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jbyteArray, jboolean, jint, jlong, jobject, jobjectArray};
use jni::sys::{JNI_TRUE, JNI_FALSE};

//Public Schnorr key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeGetPublicKeySize(
    _env: JNIEnv,
    _schnorr_public_key_class: JClass,
) -> jint { SCHNORR_PK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeSerializePublicKey(
    _env: JNIEnv,
    _schnorr_public_key: JObject,
) -> jbyteArray
{
    let public_key_pointer = _env.get_field(_schnorr_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = read_raw_pointer({public_key_pointer.j().unwrap() as *const SchnorrPk});

    let mut pk = [0u8; SCHNORR_PK_SIZE];
    serialize_from_raw_pointer(public_key, &mut pk[..]);

    _env.byte_array_from_slice(pk.as_ref())
        .expect("Cannot write public key.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeDeserializePublicKey(
    _env: JNIEnv,
    _schnorr_public_key_class: JClass,
    _public_key_bytes: jbyteArray,
) -> jobject
{
    let pk_bytes = _env.convert_byte_array(_public_key_bytes)
        .expect("Cannot read public key bytes.");

    let public_key_pointer: *const SchnorrPk = deserialize_to_raw_pointer(pk_bytes.as_slice());

    let public_key: jlong = jlong::from(public_key_pointer as i64);

    let public_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey")
        .expect("Cannot find SchnorrPublicKey class.");

    let public_key_object = _env.new_object(public_key_class, "(J)V",
                                            &[JValue::Long(public_key)])
        .expect("Cannot create public key object.");

    *public_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeFreePublicKey(
    _env: JNIEnv,
    _schnorr_public_key: JObject,
)
{
    let public_key_pointer = _env.get_field(_schnorr_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = public_key_pointer.j().unwrap() as *mut SchnorrPk;

    if public_key.is_null()  { return }
    drop(unsafe { Box::from_raw(public_key) });
}

//Secret Schnorr key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeGetSecretKeySize(
    _env: JNIEnv,
    _schnorr_secret_key_class: JClass,
) -> jint { SCHNORR_SK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeSerializeSecretKey(
    _env: JNIEnv,
    _schnorr_secret_key: JObject,
) -> jbyteArray
{
    let secret_key_pointer = _env.get_field(_schnorr_secret_key, "secretKeyPointer", "J")
        .expect("Cannot get secret key pointer.");

    let secret_key = read_raw_pointer({secret_key_pointer.j().unwrap() as *const SchnorrSk});

    let mut sk = [0u8; SCHNORR_SK_SIZE];
    serialize_from_raw_pointer(secret_key, &mut sk[..]);

    _env.byte_array_from_slice(sk.as_ref())
        .expect("Cannot write secret key.")
}

#[no_mangle]

pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _schnorr_public_key_class: JClass,
    _secret_key_bytes: jbyteArray,
) -> jobject
{
    let sk_bytes = _env.convert_byte_array(_secret_key_bytes)
        .expect("Cannot read public key bytes.");
    let secret_key_pointer: *const SchnorrSk = deserialize_to_raw_pointer(sk_bytes.as_slice());

    let secret_key: jlong = jlong::from(secret_key_pointer as i64);

    let secret_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrSecretKey")
        .expect("Cannot find SchnorrSecretKey class.");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V",
                                            &[JValue::Long(secret_key)])
        .expect("Cannot create secret key object.");

    *secret_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeFreeSecretKey(
    _env: JNIEnv,
    _schnorr_secret_key: JObject,
)
{
    let secret_key_pointer = _env.get_field(_schnorr_secret_key, "secretKeyPointer", "J")
        .expect("Cannot get secret key pointer.");

    let secret_key = secret_key_pointer.j().unwrap() as *mut SchnorrSk;

    if secret_key.is_null()  { return }
    drop(unsafe { Box::from_raw(secret_key) });
}

//Public VRF key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeGetPublicKeySize(
    _env: JNIEnv,
    _vrf_public_key_class: JClass,
) -> jint { VRF_PK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeSerializePublicKey(
    _env: JNIEnv,
    _vrf_public_key: JObject,
) -> jbyteArray
{
    let public_key_pointer = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = read_raw_pointer({public_key_pointer.j().unwrap() as *const VRFPk});

    let mut pk = [0u8; VRF_PK_SIZE];
    serialize_from_raw_pointer(public_key, &mut pk[..]);

    _env.byte_array_from_slice(pk.as_ref())
        .expect("Cannot write public key.")

}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeDeserializePublicKey(
    _env: JNIEnv,
    _vrf_public_key_class: JClass,
    _public_key_bytes: jbyteArray,
) -> jobject
{
    let pk_bytes = _env.convert_byte_array(_public_key_bytes)
        .expect("Cannot read public key bytes.");

    let public_key_pointer: *mut VRFPk = deserialize_to_raw_pointer(pk_bytes.as_slice());

    let public_key: jlong = jlong::from(public_key_pointer as i64);

    let public_key_class = _env.find_class("com/horizen/vrfnative/VRFPublicKey")
        .expect("Cannot find SchnorrPublicKey class.");

    let public_key_object = _env.new_object(public_key_class, "(J)V",
                                            &[JValue::Long(public_key)])
        .expect("Cannot create public key object.");

    *public_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeFreePublicKey(
    _env: JNIEnv,
    _vrf_public_key: JObject,
)
{
    let public_key_pointer = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = public_key_pointer.j().unwrap() as *mut SchnorrPk;

    if public_key.is_null()  { return }
    drop(unsafe { Box::from_raw(public_key) });
}

//Secret VRF key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetSecretKeySize(
    _env: JNIEnv,
    _schnorr_secret_key_class: JClass,
) -> jint { VRF_SK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeSerializeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject,
) -> jbyteArray
{
    let secret_key_pointer = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to read field secretKeyPointer");

    let secret_key = read_raw_pointer({secret_key_pointer.j().unwrap() as *const VRFSk});

    let mut sk = [0u8; VRF_SK_SIZE];
    serialize_from_raw_pointer(secret_key, &mut sk[..]);

    _env.byte_array_from_slice(sk.as_ref())
        .expect("Cannot write secret key.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _vrf_public_key_class: JClass,
    _secret_key_bytes: jbyteArray,
) -> jobject
{
    let sk_bytes = _env.convert_byte_array(_secret_key_bytes)
        .expect("Cannot read public key bytes.");

    let secret_key_pointer: *mut SchnorrSk = deserialize_to_raw_pointer(sk_bytes.as_slice());

    let secret_key: jlong = jlong::from(secret_key_pointer as i64);

    let secret_key_class = _env.find_class("com/horizen/vrfnative/VRFSecretKey")
        .expect("Cannot find SchnorrSecretKey class.");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V",
                                            &[JValue::Long(secret_key)])
        .expect("Cannot create secret key object.");

    *secret_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeFreeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject,
)
{
    let secret_key_pointer = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Cannot get secret key pointer.");

    let secret_key = secret_key_pointer.j().unwrap() as *mut SchnorrSk;

    if secret_key.is_null()  { return }
    drop(unsafe { Box::from_raw(secret_key) });
}

//Schnorr signature utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeGetSignatureSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { SCHNORR_SIG_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeSerializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig: *const SchnorrSig,
) -> jbyteArray
{
    let mut sig = [0u8; SCHNORR_SIG_SIZE];
    serialize_from_raw_pointer(_sig, &mut sig[..], );

    _env.byte_array_from_slice(sig.as_ref())
        .expect("Should be able to convert to jbyteArray")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeDeserializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig_bytes: jbyteArray,
) -> *mut SchnorrSig
{
    let sig_bytes = _env.convert_byte_array(_sig_bytes)
        .expect("Should be able to convert to Rust byte array");
    deserialize_to_raw_pointer(sig_bytes.as_slice())
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativefreeSignature(
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
    let (pk, sk) = schnorr_generate_key();

    let secret_key: jlong = jlong::from(Box::into_raw(Box::new(sk)) as i64);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let secret_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrSecretKey")
        .expect("Should be able to find SchnorrSecretKey class");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V", &[
        JValue::Long(secret_key)])
        .expect("Should be able to create new SchnorrSecretKey object");

    let public_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey")
        .expect("Should be able to find SchnorrPublicKey class");

    let public_key_object = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)])
        .expect("Should be able to create new SchnorrPublicKey object");

    let class = _env.find_class("com/horizen/schnorrnative/SchnorrKeyPair")
        .expect("Should be able to find SchnorrKeyPair class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/schnorrnative/SchnorrSecretKey;Lcom/horizen/schnorrnative/SchnorrPublicKey;)V",
        &[JValue::Object(secret_key_object), JValue::Object(public_key_object)]
    ).expect("Should be able to create new (SchnorrSecretKey, SchnorrPublicKey) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeSignMessage(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _schnorr_key_pair: JObject,
    _message: JObject,
) -> jobject {

    //Read sk
    let sk_object = _env.get_field(_schnorr_key_pair,
                                   "secretKey",
                                   "Lcom/horizen/schnorrnative/SchnorrSecretKey;"
    ).expect("Should be able to get field secretKey").l().unwrap();
    let secret_key = {

        let s =_env.get_field(sk_object, "secretKeyPointer", "J")
            .expect("Should be able to get field secretKeyPointer");

        read_raw_pointer(s.j().unwrap() as *const SchnorrSk)
    };

    //Read pk
    let pk_object = _env.get_field(_schnorr_key_pair,
                                   "publicKey",
                                   "Lcom/horizen/schnorrnative/SchnorrPublicKey;"
    ).expect("Should be able to get field publicKey").l().unwrap();

    let public_key = {

        let p = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const SchnorrPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Sign message and return opaque pointer to sig
    let signature = match schnorr_sign(message, secret_key, public_key) {
        Ok(sig) => Box::into_raw(Box::new(sig)),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    let sign_result: jlong = jlong::from(signature as i64);

    let class = _env.find_class("com/horizen/schnorrnative/SchnorrSignature")
        .expect("Should be able to find class SchnorrSignature");

    let result =  _env.new_object(class, "(J)V", &[
        JValue::Long(sign_result)])
        .expect("Should be able to create new long for Schnorr signature");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _public_key: JObject,
) -> jboolean
{
    let pk = _env.get_field(_public_key, "publicKeyPointer", "J")
        .expect("Should be able to get field publicKeyPointer").j().unwrap() as *const SchnorrPk;

    if schnorr_verify_public_key(read_raw_pointer(pk)) {
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
    _secret_key: JObject
) -> jobject {

    let sk = _env.get_field(_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to get field secretKeyPointer").j().unwrap() as *const SchnorrSk;

    let secret_key = read_raw_pointer(sk);

    let pk = schnorr_get_public_key(secret_key);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let public_key_class =  _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey")
        .expect("Should be able to find SchnorrPublicKey class");

    let result = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)]).expect("Should be able to create new long for SchnorrPk");

    *result
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifySignature(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _public_key: JObject,
    _signature: JObject,
    _message: JObject,
) -> jboolean {

    //Read pk
    let pk_object = _env.get_field(_public_key,
                                   "publicKey",
                                   "Lcom/horizen/schnorrnative/SchnorrPublicKey;"
    ).expect("Should be able to get field publicKey").l().unwrap();

    let public_key = {

        let p = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const SchnorrPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Read sig
    let signature = {
        let sig = _env.get_field(_signature, "signaturePointer", "J")
            .expect("Should be able to get field signaturePointer");

        read_raw_pointer(sig.j().unwrap() as *const SchnorrSig)
    };

    //Verify sig
    match schnorr_verify_signature(message, public_key, signature) {
        Ok(result) => if result {
            JNI_TRUE
        } else {
            JNI_FALSE
        },
        Err(_) => JNI_FALSE //CRYPTO_ERROR
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
    _input: jobjectArray,
) -> jobject
{
    //Read _input as array of FieldElement
    let input_len = _env.get_array_length(_input)
        .expect("Should be able to read input array size");
    let mut input = vec![];

    for i in 0..input_len {
        let field_obj = _env.get_object_array_element(_input, i)
            .expect(format!("Should be able to read elem {} of the input array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        input.push(*field);
    }

    //Compute hash
    let hash = match compute_poseidon_hash(input.as_slice()) {
        Ok(hash) => hash,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Return hash
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(hash)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

//VRF utility functions

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeGetProofSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { VRF_PROOF_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeSerializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof: *const VRFProof,
) -> jbyteArray
{
    let mut proof = [0u8; VRF_PROOF_SIZE];
    serialize_from_raw_pointer(_proof, &mut proof[..]);

    _env.byte_array_from_slice(proof.as_ref())
        .expect("Should be able to convert to jbyteArray")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeDeserializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof_bytes: jbyteArray,
) -> *mut VRFProof
{
    let proof_bytes = _env.convert_byte_array(_proof_bytes)
        .expect("Should be able to convert to Rust byte array");
    deserialize_to_raw_pointer(proof_bytes.as_slice())
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativefreeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof: *mut VRFProof,
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

    let (pk, sk) = vrf_generate_key();

    let secret_key: jlong = jlong::from(Box::into_raw(Box::new(sk)) as i64);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let secret_key_class = _env.find_class("com/horizen/vrfnative/VRFSecretKey")
        .expect("Should be able to find VRFSecretKey class");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V", &[
        JValue::Long(secret_key)])
        .expect("Should be able to create new VRFSecretKey object");

    let public_key_class = _env.find_class("com/horizen/vrfnative/VRFPublicKey")
        .expect("Should be able to find VRFPublicKey class");

    let public_key_object = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)])
        .expect("Should be able to create new VRFPublicKey object");

    let class = _env.find_class("com/horizen/vrfnative/VRFKeyPair")
        .expect("Should be able to find VRFKeyPair class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/vrfnative/VRFSecretKey;Lcom/horizen/vrfnative/VRFPublicKey;)V",
        &[JValue::Object(secret_key_object), JValue::Object(public_key_object)]
    ).expect("Should be able to create new (VRFSecretKey, VRFPublicKey) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFKeyPair_nativeProve(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _vrf_key_pair: JObject,
    _message: JObject
) -> jobject {

    //Read sk
    let sk_object = _env.get_field(_vrf_key_pair,
                                   "secretKey",
                                   "Lcom/horizen/vrfnative/VRFSecretKey;"
    ).expect("Should be able to get field vrfKey").l().unwrap();

    let secret_key = {

        let s =_env.get_field(sk_object, "secretKeyPointer", "J")
            .expect("Should be able to get field secretKeyPointer");

        read_raw_pointer(s.j().unwrap() as *const VRFSk)
    };

    //Read pk
    let pk_object = _env.get_field(_vrf_key_pair,
                                   "publicKey",
                                   "Lcom/horizen/vrfnative/VRFPublicKey;"
    ).expect("Should be able to get field publicKey").l().unwrap();

    let public_key = {

        let p = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Sign message and return opaque pointer to sig
    let proof = match vrf_prove(message, secret_key, public_key) {
        Ok(p) => Box::into_raw(Box::new(p)),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    let proof_result: jlong = jlong::from(proof as i64);

    let class = _env.find_class("com/horizen/vrfnative/VRFProof")
        .expect("Should be able to find class VRFProof");

    let result =  _env.new_object(class, "(J)V", &[
        JValue::Long(proof_result)])
        .expect("Should be able to create new long for VRF proof");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetPublicKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _vrf_secret_key: JObject
) -> jobject {

    let sk = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to get field secretKeyPointer").j().unwrap() as *const VRFSk;

    let secret_key = read_raw_pointer(sk);

    let pk = vrf_get_public_key(secret_key);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let public_key_class =  _env.find_class("com/horizen/vrfnative/VRFPublicKey")
        .expect("Should be able to find VRFPublicKey class");

    let result = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)]).expect("Should be able to create new long for VRFPk");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _vrf_public_key: JObject,
) -> jboolean
{

    let pk = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
        .expect("Should be able to get field publicKeyPointer").j().unwrap() as *const VRFPk;

    if vrf_verify_public_key(read_raw_pointer(pk)) {
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
    _vrf_public_key: JObject,
    _proof: JObject,
    _message: JObject,
) -> jobject
{
    //Read pk
    let pk_object = _env.get_field(_vrf_public_key,
                                   "publicKey",
                                   "Lcom/horizen/vrfnative/VRFPublicKey;"
    ).expect("Should be able to get field publicKey").l().unwrap();

    let public_key = {

        let p = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Read sig
    let proof = {
        let p = _env.get_field(_proof, "proofPointer", "J")
            .expect("Should be able to get field proofPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFProof)
    };

    //Verify vrf proof and get vrf output
    let vrf_out = match vrf_proof_to_hash(message, public_key, proof) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Return vrf output
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(vrf_out)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

//Naive threshold signature proof functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateProof(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _end_epoch_block_hash: jbyteArray,
    _prev_end_epoch_block_hash: jbyteArray,
    _schnorr_sigs_list: jobjectArray,
    _schnorr_pks_list:  jobjectArray,
    _threshold: jlong,
    _proving_key_path: JString
) -> jbyteArray
{
    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    for i in 0..bt_list_size {
        let o = _env.get_object_array_element(_bt_list, i)
            .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());


        let pk: [u8; 32] = {
            let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

            let mut pk_bytes = [0u8; 32];

            _env.convert_byte_array(p)
                .expect("Should be able to convert to Rust byte array")
                .write(&mut pk_bytes[..])
                .expect("Should be able to write into byte array of fixed size");

            pk_bytes
        };

        let a = _env.call_method(o, "getAmount", "()J", &[])
            .expect("Should be able to call getAmount method").j().unwrap() as u64;

        bt_list.push(BackwardTransfer::new(pk, a));
    }

    //Extract Schnorr signatures and the corresponding Schnorr pks
    let mut sigs = vec![];
    let mut pks = vec![];

    let sigs_list_size = _env.get_array_length(_schnorr_sigs_list)
        .expect("Should be able to get schnorr_sigs_list size");

    let pks_list_size = _env.get_array_length(_schnorr_pks_list)
        .expect("Should be able to get schnorr_pks_list size");

    assert_eq!(sigs_list_size, pks_list_size);

    for i in 0..sigs_list_size {
        //Get i-th sig
        let sig_object = _env.get_object_array_element(_schnorr_sigs_list, i)
            .expect(format!("Should be able to get elem {} of schnorr_sigs_list", i).as_str());

        let pk_object = _env.get_object_array_element(_schnorr_pks_list, i)
            .expect(format!("Should be able to get elem {} of schnorr_pks_list", i).as_str());

        let signature = {
            let sig = _env.get_field(sig_object, "signaturePointer", "J")
                .expect("Should be able to get field signaturePointer");

            match read_nullable_raw_pointer(sig.j().unwrap() as *const SchnorrSig) {
                Some(sig) => Some(*sig),
                None => None,
            }
        };

        let public_key = {
            let pk = _env.get_field(pk_object, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(pk.j().unwrap() as *const SchnorrPk)
        };

        sigs.push(signature);
        pks.push(*public_key);
    }

    //Extract block hashes
    let end_epoch_block_hash = {
        let t = _env.convert_byte_array(_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        end_epoch_block_hash_bytes
    };

    let prev_end_epoch_block_hash = {
        let t = _env.convert_byte_array(_prev_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut prev_end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut prev_end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        prev_end_epoch_block_hash_bytes
    };

    //Extract threshold
    let threshold = _threshold as u64;

    //Extract params_path str
    let proving_key_path = _env.get_string(_proving_key_path)
        .expect("Should be able to read jstring as Rust String");


    //create proof
    let proof = match create_naive_threshold_sig_proof(
        pks.as_slice(),
        sigs,
        &end_epoch_block_hash,
        &prev_end_epoch_block_hash,
        bt_list.as_slice(),
        threshold,
        proving_key_path.to_str().unwrap()
    ) {
        Ok(proof) => proof,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Serialize proof
    let mut proof_bytes = [0u8; ZK_PROOF_SIZE];
    proof.write(&mut proof_bytes[..])
        .expect("Should be able to write proof into proof_bytes");

    //Return proof serialized
    _env.byte_array_from_slice(proof_bytes.as_ref())
        .expect("Should be able to convert Rust slice into jbytearray")
}

//Test functions

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_createFromLong(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _long: jlong
) -> jobject
{
    //Create field element from _long
    let fe = read_field_element_from_u64(_long as u64);

    //Return vrf output
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(fe)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}
