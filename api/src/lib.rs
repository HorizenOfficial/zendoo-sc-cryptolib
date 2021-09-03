extern crate jni;

use algebra::{SemanticallyValid, serialize::*};
use demo_circuit::{type_mapping::*, get_instance_for_setup, generate_circuit_keypair};
use cctp_primitives::{
    proving_system::{ProvingSystem, init_dlog_keys},
    utils::{
        serialization::*,
        poseidon_hash::*,
        mht::*,
        data_structures::*,
    }
};
use std::{
    any::type_name, path::Path,
};

mod cctp_calls;
use cctp_calls::*;

use cctp_primitives::commitment_tree::CommitmentTree;
use cctp_primitives::commitment_tree::proofs::{ScExistenceProof, ScAbsenceProof};


fn read_raw_pointer<'a, T>(input: *const T) -> &'a T {
    assert!(!input.is_null());
    unsafe { &*input }
}

fn read_mut_raw_pointer<'a, T>(input: *mut T) -> &'a mut T {
    assert!(!input.is_null());
    unsafe { &mut *input }
}

fn read_nullable_raw_pointer<'a, T>(input: *const T) -> Option<&'a T> {
    unsafe { input.as_ref() }
}

fn serialize_from_raw_pointer<T: CanonicalSerialize>(
    to_write: *const T,
    compressed: Option<bool>,
) -> Vec<u8> {
    // TODO: should be redone to Java exception
    serialize_to_buffer(read_raw_pointer(to_write), compressed)
        .expect(format!("unable to write {} to buffer", type_name::<T>()).as_str())
}

fn return_jobject<'a, T: Sized>(_env: &'a JNIEnv, obj: T, class_path: &str) -> JObject<'a>
{
    //Return field element
    let obj_ptr: jlong = jlong::from(Box::into_raw(Box::new(obj)) as i64);

    let obj_class = _env.find_class(class_path).expect("Should be able to find class");

    _env.new_object(obj_class, "(J)V", &[JValue::Long(obj_ptr)])
        .expect("Should be able to create new jobject")
}

fn deserialize_to_jobject<T: CanonicalDeserialize + SemanticallyValid>(
    _env: &JNIEnv,
    obj_bytes: jbyteArray,
    checked: Option<jboolean>, // Can be none for types with trivial checks or without themn
    compressed: Option<jboolean>, // Can be none for uncompressable types
    class_path: &str,
) -> jobject
{
    let obj_bytes = _env.convert_byte_array(obj_bytes)
        .expect("Cannot read bytes.");

    let obj = deserialize_from_buffer::<T>(
        obj_bytes.as_slice(),
        checked.map(|jni_bool| jni_bool == JNI_TRUE),
        compressed.map(|jni_bool| jni_bool == JNI_TRUE)
    );

    match obj {
        Ok(obj) => *return_jobject(&_env, obj, class_path),
        Err(_) => std::ptr::null::<jobject>() as jobject,
    }
}

fn serialize_from_jobject<T: CanonicalSerialize>(
    _env: &JNIEnv,
    obj: JObject,
    ptr_name: &str,
    compressed: Option<jboolean>, // Can be none for uncompressable types
) -> jbyteArray
{
    let pointer = _env.get_field(obj, ptr_name, "J")
        .expect("Cannot get object raw pointer.");

    let obj = read_raw_pointer(pointer.j().unwrap() as *const T);

    let obj_bytes = serialize_from_raw_pointer(obj, compressed.map(|jni_bool| jni_bool == JNI_TRUE));

    _env.byte_array_from_slice(obj_bytes.as_slice())
        .expect("Cannot write object.")
}

fn parse_jbyte_array_to_vec(_env: &JNIEnv, java_byte_array: &jbyteArray, length: usize) -> Vec<u8> {
    let vec = _env.convert_byte_array(*java_byte_array)
        .expect("Should be able to convert to Rust array");

    if vec.len() != length {
        panic!("Retrieved array size {} expected to be {}.", vec.len(), length);
    }

    vec
}

fn get_byte_array(_env: &JNIEnv, java_byte_array: &jbyteArray, buffer: &mut [u8]) {
    let vec = _env.convert_byte_array(*java_byte_array)
        .expect("Should be able to convert to Rust array");

    for (pos, e) in vec.iter().enumerate() {
        buffer[pos] = *e;
    }
}


use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jbyteArray, jboolean, jint, jlong, jobject, jobjectArray, jbyte};
use jni::sys::{JNI_TRUE, JNI_FALSE};
use cctp_primitives::utils::compute_sc_id;
use std::convert::TryInto;
use cctp_primitives::bit_vector::merkle_tree::{merkle_root_from_compressed_bytes_without_checks, merkle_root_from_compressed_bytes};
use cctp_primitives::proving_system::{ZendooVerifierKey, check_proof_vk_size};

//Field element related functions

fn return_field_element(_env: &JNIEnv, fe: FieldElement) -> jobject
{
    return_jobject(_env, fe, "com/horizen/librustsidechains/FieldElement")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeGetFieldElementSize(
    _env: JNIEnv,
    _field_element_class: JClass,
) -> jint { FIELD_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeSerializeFieldElement(
    _env: JNIEnv,
    _field_element: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<FieldElement>(
        &_env,
        _field_element,
        "fieldElementPointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeDeserializeFieldElement(
    _env: JNIEnv,
    _class: JClass,
    _field_element_bytes: jbyteArray,
) -> jobject
{
    deserialize_to_jobject::<FieldElement>(
        &_env,
        _field_element_bytes,
        None,
        None,
        "com/horizen/librustsidechains/FieldElement",
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeCreateRandom(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _seed: jlong,
) -> jobject
{
    //Create random field element
    let fe = get_random_field_element(_seed as u64);

    return_field_element(&_env, fe)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeCreateFromLong(
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
    let fe = FieldElement::from(_long as u64);

    return_field_element(&_env, fe)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativePrintFieldElementBytes(
    _env: JNIEnv,
    _field_element: JObject,
)
{
    let pointer = _env.get_field(_field_element, "fieldElementPointer", "J")
        .expect("Cannot get object raw pointer.");

    let obj = read_raw_pointer(pointer.j().unwrap() as *const FieldElement);

    let obj_bytes = serialize_from_raw_pointer(
        obj,
        None,
    );

    println!("{:?}", into_i8(obj_bytes));
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeFreeFieldElement(
    _env: JNIEnv,
    _class: JClass,
    _fe: *mut FieldElement,
)
{
    if _fe.is_null()  { return }
    drop(unsafe { Box::from_raw(_fe) });
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeEquals(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _field_element_1: JObject,
    _field_element_2: JObject,
) -> jboolean
{
    //Read field_1
    let field_1 = {

        let f =_env.get_field(_field_element_1, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer_1");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    //Read field_2
    let field_2 = {

        let f =_env.get_field(_field_element_2, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer_2");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    match field_1 == field_2 {
        true => JNI_TRUE,
        false => JNI_FALSE,
    }
}

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
    _compressed: jboolean,
) -> jbyteArray
{
    serialize_from_jobject::<SchnorrPk>(&_env, _schnorr_public_key, "publicKeyPointer", Some(_compressed))
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeDeserializePublicKey(
    _env: JNIEnv,
    _schnorr_public_key_class: JClass,
    _public_key_bytes: jbyteArray,
    _check_public_key: jboolean,
    _compressed: jboolean,
) -> jobject
{
    deserialize_to_jobject::<SchnorrPk>(
        &_env,
        _public_key_bytes,
        Some(_check_public_key),
        Some(_compressed),
        "com/horizen/schnorrnative/SchnorrPublicKey"
    )
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
    serialize_from_jobject::<SchnorrSk>(
        &_env,
        _schnorr_secret_key,
        "secretKeyPointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _schnorr_secret_key_class: JClass,
    _secret_key_bytes: jbyteArray,
) -> jobject
{
    deserialize_to_jobject::<SchnorrSk>(
        &_env,
        _secret_key_bytes,
        None,
        None,
        "com/horizen/schnorrnative/SchnorrSecretKey",
    )
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
    _compressed: jboolean,
) -> jbyteArray
{
    serialize_from_jobject::<VRFPk>(&_env, _vrf_public_key, "publicKeyPointer", Some(_compressed))
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeDeserializePublicKey(
    _env: JNIEnv,
    _vrf_public_key_class: JClass,
    _public_key_bytes: jbyteArray,
    _check_public_key: jboolean,
    _compressed: jboolean,
) -> jobject
{
    deserialize_to_jobject::<VRFPk>(
        &_env,
        _public_key_bytes,
        Some(_check_public_key),
        Some(_compressed),
        "com/horizen/vrfnative/VRFPublicKey"
    )
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
    _vrf_secret_key_class: JClass,
) -> jint { VRF_SK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeSerializeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<VRFSk>(
        &_env,
        _vrf_secret_key,
        "secretKeyPointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key_class: JClass,
    _secret_key_bytes: jbyteArray,
) -> jobject
{
    deserialize_to_jobject::<VRFSk>(
        &_env,
        _secret_key_bytes,
        None,
        None,
        "com/horizen/vrfnative/VRFSecretKey"
    )
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
    _schnorr_sig: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<SchnorrSig>(
        &_env,
        _schnorr_sig,
        "signaturePointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeDeserializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig_bytes: jbyteArray,
    _check_sig: jboolean,
) -> jobject
{
    deserialize_to_jobject::<SchnorrSig>(
        &_env,
        _sig_bytes,
        Some(_check_sig),
        None,
        "com/horizen/schnorrnative/SchnorrSignature"
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeIsValidSignature(
    _env: JNIEnv,
    _sig: JObject,
) -> jboolean
{
    let sig = _env.get_field(_sig, "signaturePointer", "J")
        .expect("Should be able to get field signaturePointer").j().unwrap() as *const SchnorrSig;

    if is_valid(read_raw_pointer(sig)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
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

    let secret_key_object = return_jobject(&_env, sk, "com/horizen/schnorrnative/SchnorrSecretKey");
    let public_key_object = return_jobject(&_env, pk, "com/horizen/schnorrnative/SchnorrPublicKey");

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
        Ok(sig) => sig,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    return_jobject(&_env, signature, "com/horizen/schnorrnative/SchnorrSignature")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifyKey(
    _env: JNIEnv,
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
    _secret_key: JObject
) -> jobject {

    let sk = _env.get_field(_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to get field secretKeyPointer").j().unwrap() as *const SchnorrSk;

    let secret_key = read_raw_pointer(sk);

    let pk = schnorr_get_public_key(secret_key);

    return_jobject(&_env, pk, "com/horizen/schnorrnative/SchnorrPublicKey")
        .into_inner()
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifySignature(
    _env: JNIEnv,
    _public_key: JObject,
    _signature: JObject,
    _message: JObject,
) -> jboolean {

    //Read pk
    let public_key = {

        let p = _env.get_field(_public_key, "publicKeyPointer", "J")
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
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeGetHashSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { FIELD_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeGetConstantLengthPoseidonHash(
    _env: JNIEnv,
    _class: JClass,
    _input_size: jint,
    _personalization: jobjectArray,
) -> jobject
{
    //Read _personalization as array of FieldElement
    let personalization_len = _env.get_array_length(_personalization)
        .expect("Should be able to read personalization array size");
    let mut personalization = vec![];

    // Array can be empty
    for i in 0..personalization_len {
        let field_obj = _env.get_object_array_element(_personalization, i)
            .expect(format!("Should be able to read elem {} of the personalization array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        personalization.push(field);
    }

    //Instantiate PoseidonHash
    let h = get_poseidon_hash_constant_length(
        _input_size as usize,
        if personalization.is_empty() { None } else { Some(personalization) }
    );

    //Return PoseidonHash instance
    return_jobject(&_env, h, "com/horizen/poseidonnative/PoseidonHash")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeGetVariableLengthPoseidonHash(
    _env: JNIEnv,
    _class: JClass,
    _mod_rate: jboolean,
    _personalization: jobjectArray,
) -> jobject
{
    //Read _personalization as array of FieldElement
    let personalization_len = _env.get_array_length(_personalization)
        .expect("Should be able to read personalization array size");
    let mut personalization = vec![];

    // Array can be empty
    for i in 0..personalization_len {
        let field_obj = _env.get_object_array_element(_personalization, i)
            .expect(format!("Should be able to read elem {} of the personalization array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        personalization.push(field);
    }

    //Instantiate PoseidonHash
    let h = get_poseidon_hash_variable_length(
        _mod_rate == JNI_TRUE,
        if personalization.is_empty() { None } else { Some(personalization) }
    );

    //Return PoseidonHash instance
    return_jobject(&_env, h, "com/horizen/poseidonnative/PoseidonHash")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeUpdate(
    _env: JNIEnv,
    _h: JObject,
    _input: JObject,
){
    //Read PoseidonHash instance
    let digest = {

        let h = _env.get_field(_h, "poseidonHashPointer", "J")
            .expect("Should be able to get field poseidonHashPointer");

        read_mut_raw_pointer(h.j().unwrap() as *mut FieldHash)
    };

    //Read input
    let input = {

        let i =_env.get_field(_input, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(i.j().unwrap() as *const FieldElement)
    };

    update_poseidon_hash(digest, input);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeFinalize(
    _env: JNIEnv,
    _h: JObject,
) -> jobject
{
    //Read PoseidonHash instance
    let digest = {

        let h = _env.get_field(_h, "poseidonHashPointer", "J")
            .expect("Should be able to get field poseidonHashPointer");

        read_raw_pointer(h.j().unwrap() as *const FieldHash)
    };

    //Get digest
    let fe = match finalize_poseidon_hash(digest) {
        Ok(fe) => fe,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    return_field_element(&_env, fe)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeReset(
    _env: JNIEnv,
    _h: JObject,
    _personalization: jobjectArray,
){
    //Read PoseidonHash instance
    let digest = {

        let h = _env.get_field(_h, "poseidonHashPointer", "J")
            .expect("Should be able to get field poseidonHashPointer");

        read_mut_raw_pointer(h.j().unwrap() as *mut FieldHash)
    };

    //Read _personalization as array of FieldElement
    let personalization_len = _env.get_array_length(_personalization)
        .expect("Should be able to read personalization array size");
    let mut personalization = vec![];

    // Array can be empty
    for i in 0..personalization_len {
        let field_obj = _env.get_object_array_element(_personalization, i)
            .expect(format!("Should be able to read elem {} of the personalization array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        personalization.push(field);
    }

    let personalization = if personalization.is_empty() { None } else { Some(personalization) };

    reset_poseidon_hash(digest, personalization)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeFreePoseidonHash(
    _env: JNIEnv,
    _h: JObject,
)
{
    let h_pointer = _env.get_field(_h, "poseidonHashPointer", "J")
        .expect("Cannot get poseidonHashPointer");

    let h = h_pointer.j().unwrap() as *mut FieldHash;

    if h.is_null()  { return }
    drop(unsafe { Box::from_raw(h) });
}

//Merkle tree functions

//////////// MERKLE PATH

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeVerify(
    _env: JNIEnv,
    _path: JObject,
    _height: jint,
    _leaf: JObject,
    _root: JObject,
) -> jboolean
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let root = {

        let fe =_env.get_field(_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    if !path.is_valid() {
        return JNI_FALSE;
    }

    match verify_ginger_merkle_path(path, _height as usize, leaf, root) {
        Ok(result) => if result { JNI_TRUE } else { JNI_FALSE },
        Err(_) => JNI_FALSE // CRYPTO_ERROR
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeVerifyWithoutLengthCheck(
    _env: JNIEnv,
    _path: JObject,
    _leaf: JObject,
    _root: JObject,
) -> jboolean
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let root = {

        let fe =_env.get_field(_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    if !path.is_valid() {
        return JNI_FALSE;
    }

    if verify_ginger_merkle_path_without_length_check(path, leaf, root) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeApply(
    _env: JNIEnv,
    _path: JObject,
    _leaf: JObject,
) -> jobject
{
    let path = {
        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let root = get_root_from_path(path, leaf);

    return_field_element(&_env, root)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeIsLeftmost(
    _env: JNIEnv,
    _path: JObject,
) -> jboolean
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    is_path_leftmost(path) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeIsRightmost(
    _env: JNIEnv,
    _path: JObject,
) -> jboolean
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    is_path_rightmost(path) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeAreRightLeavesEmpty(
    _env: JNIEnv,
    _path: JObject,
) -> jboolean
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    are_right_leaves_empty(path) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeLeafIndex(
    _env: JNIEnv,
    _path: JObject,
) -> jlong
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    get_leaf_index_from_path(path) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeSerialize(
    _env: JNIEnv,
    _path: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<GingerMHTPath>(
        &_env,
        _path,
        "merklePathPointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeDeserialize(
    _env: JNIEnv,
    _class: JClass,
    _path_bytes: jbyteArray,
    _checked: jboolean,
) -> jobject
{
    deserialize_to_jobject::<GingerMHTPath>(
        &_env,
        _path_bytes,
        Some(_checked),
        None,
        "com/horizen/merkletreenative/MerklePath"
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeFreeMerklePath(
    _env: JNIEnv,
    _class: JClass,
    _path: *mut GingerMHTPath,
)
{
    if _path.is_null()  { return }
    drop(unsafe { Box::from_raw(_path) });
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeInit(
    _env: JNIEnv,
    _class: JClass,
    _height: jint,
    _processing_step: jlong,
) -> jobject
{
    // Create new InMemoryOptimizedMerkleTree Rust side
    let mt = new_ginger_mht(
        _height as usize,
        _processing_step as usize
    );

    // Create and return new InMemoryOptimizedMerkleTree Java side
    match mt {
        Ok(mt) => return_jobject(&_env, mt, "com/horizen/merkletreenative/InMemoryOptimizedMerkleTree").into_inner(),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeAppend(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
) -> jboolean
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerMHT)
    };

    match append_leaf_to_ginger_mht(tree, leaf) {
        Ok(_) => JNI_TRUE,
        Err(_) => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeFinalize(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHT)
    };

    match finalize_ginger_mht(tree) {
        Ok(tree_copy) => return_jobject(&_env, tree_copy, "com/horizen/merkletreenative/InMemoryOptimizedMerkleTree").into_inner(),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeFinalizeInPlace(
    _env: JNIEnv,
    _tree: JObject,
) -> jboolean
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerMHT)
    };

    match finalize_ginger_mht_in_place(tree) {
        Ok(_) => JNI_TRUE,
        Err(_) => JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeRoot(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHT)
    };

    match get_ginger_mht_root(tree) {
        Some(root) => return_field_element(&_env, root),
        None => std::ptr::null::<jobject>() as jobject
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeGetMerklePath(
    _env: JNIEnv,
    _tree: JObject,
    _leaf_index: jlong,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHT)
    };

    match get_ginger_mht_path(tree, _leaf_index as u64) {
        Some(path) => return_jobject(&_env, path, "com/horizen/merkletreenative/MerklePath")
            .into_inner(),
        None => std::ptr::null::<jobject>() as jobject
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeReset(
    _env: JNIEnv,
    _tree: JObject,
)
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerMHT)
    };

    reset_ginger_mht(tree);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeFreeInMemoryOptimizedMerkleTree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut GingerMHT,
)
{
    if _tree.is_null()  { return }
    drop(unsafe { Box::from_raw(_tree) });
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
    _proof: JObject,
    _compressed: jboolean,
) -> jbyteArray
{
    serialize_from_jobject::<VRFProof>(&_env, _proof, "proofPointer", Some(_compressed))
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeDeserializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof_bytes: jbyteArray,
    _check_proof: jboolean,
    _compressed: jboolean,
) -> jobject
{
    deserialize_to_jobject::<VRFProof>(
        &_env,
        _proof_bytes,
        Some(_check_proof),
        Some(_compressed),
        "com/horizen/vrfnative/VRFProof"
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeIsValidVRFProof(
    _env: JNIEnv,
    _vrf_proof: JObject,
) -> jboolean
{
    let proof = _env.get_field(_vrf_proof, "proofPointer", "J")
        .expect("Should be able to get field proofPointer").j().unwrap() as *const VRFProof;

    if is_valid(read_raw_pointer(proof)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeFreeProof(
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

    let secret_key_object = return_jobject(&_env, sk, "com/horizen/vrfnative/VRFSecretKey");
    let public_key_object = return_jobject(&_env, pk, "com/horizen/vrfnative/VRFPublicKey");

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

    //Compute vrf proof
    let (proof, vrf_out) = match vrf_prove(message, secret_key, public_key) {
        Ok((proof, vrf_out)) => (
            return_jobject(&_env, proof, "com/horizen/vrfnative/VRFProof"),
            return_jobject(&_env, vrf_out, "com/horizen/librustsidechains/FieldElement")
        ),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Create and return VRFProveResult instance
    let class = _env.find_class("com/horizen/vrfnative/VRFProveResult")
        .expect("Should be able to find VRFProveResult class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/vrfnative/VRFProof;Lcom/horizen/librustsidechains/FieldElement;)V",
        &[JValue::Object(proof), JValue::Object(vrf_out)]
    ).expect("Should be able to create new VRFProveResult:(VRFProof, FieldElement) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetPublicKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject
) -> jobject {

    let sk = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to get field secretKeyPointer").j().unwrap() as *const VRFSk;

    let secret_key = read_raw_pointer(sk);

    let pk = vrf_get_public_key(secret_key);
    return_jobject(&_env, pk, "com/horizen/vrfnative/VRFPublicKey").into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerifyKey(
    _env: JNIEnv,
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
    _vrf_public_key: JObject,
    _proof: JObject,
    _message: JObject,
) -> jobject
{
    let public_key = {

        let p = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Read proof
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
    return_field_element(&_env, vrf_out)
}

//Naive threshold signature proof functions

#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_BackwardTransfer_nativeGetMcPkHashSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint
{
    MC_PK_SIZE as jint
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeGetConstant(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _schnorr_pks_list: jobjectArray,
    _threshold: jlong,
) -> jobject
{
    //Extract Schnorr pks
    let mut pks = vec![];

    let pks_list_size = _env.get_array_length(_schnorr_pks_list)
        .expect("Should be able to get schnorr_pks_list size");

    for i in 0..pks_list_size {

        let pk_object = _env.get_object_array_element(_schnorr_pks_list, i)
            .expect(format!("Should be able to get elem {} of schnorr_pks_list", i).as_str());

        let pk = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        pks.push(*read_raw_pointer(pk.j().unwrap() as *const SchnorrPk));
    }

    //Extract threshold
    let threshold = _threshold as u64;

    //Compute constant
    match compute_pks_threshold_hash(pks.as_slice(), threshold) {
        Ok(constant) => return_field_element(&_env, constant),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    }
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateMsgToSign(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _sc_id: JObject,
    _epoch_number: jint,
    _end_cumulative_sc_tx_comm_tree_root: JObject,
    _btr_fee: jlong,
    _ft_min_amount: jlong,
) -> jobject
{
    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0
    {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());

            let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

            let pk: [u8; 20] = _env.convert_byte_array(p)
                .expect("Should be able to convert to Rust byte array")
                .try_into()
                .expect("Should be able to write into fixed buffer of size 20");


            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push((a, pk));
        }
    }

    let bt_list = bt_list.into_iter().map(|bt_raw| BackwardTransfer {
        pk_dest: bt_raw.1,
        amount: bt_raw.0
    }).collect::<Vec<_>>();

    let sc_id = {
        let f =_env.get_field(_sc_id, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    let end_cumulative_sc_tx_comm_tree_root = {
        let f =_env.get_field(_end_cumulative_sc_tx_comm_tree_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    //Compute message to sign:
    let msg = match compute_msg_to_sign(
        sc_id,
        _epoch_number as u32,
        end_cumulative_sc_tx_comm_tree_root,
        _btr_fee as u64,
        _ft_min_amount as u64,
        bt_list
    ){
        Ok((_, msg)) => msg,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Return msg
    return_field_element(&_env, msg)
}

fn get_proving_system_type(_env: &JNIEnv, _proving_system: JObject) -> ProvingSystem {

    // Extract proving system type
    let proving_system = _env
        .call_method(_proving_system, "ordinal", "()I", &[])
        .expect("Should be able to call ordinal() on ProvingSystem enum")
        .i()
        .unwrap() as usize;

    // Convert to Rust enum
    match proving_system {
        0 => ProvingSystem::Undefined,
        1 => ProvingSystem::Darlin,
        2 => ProvingSystem::CoboundaryMarlin,
        _ => unreachable!()
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGenerateDLogKeys(
    _env: JNIEnv,
    _class: JClass,
    _proving_system: JObject,
    _max_segment_size: jint,
    _supported_segment_size: jint,
) -> jboolean
{
    // Get proving system type
    let proving_system = get_proving_system_type(&_env, _proving_system);

    // Generate DLOG keypair
    match init_dlog_keys(
        proving_system,
        _max_segment_size as usize,
        _supported_segment_size as usize,
    ) {
        Ok(_) => JNI_TRUE,
        Err(_) => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeCheckProofVkSize(
    _env: JNIEnv,
    _class: JClass,
    _zk: jboolean,
    _supported_segment_size: jint,
    _max_proof_size: jint,
    _max_vk_size: jint,
    _verification_key_path: JString
) -> jboolean
{
    // Read vk from file

    //Extract vk path
    let vk_path = _env.get_string(_verification_key_path)
        .expect("Should be able to read jstring as Rust String");

    // Deserialize vk
    let vk: ZendooVerifierKey = match read_from_file(Path::new(vk_path.to_str().unwrap()), Some(false), Some(true)) {
        Ok(vk) => vk,
        Err(e) => {
            println!("{:?}", e);
            return JNI_FALSE
        },
    };

    // Read zk value
    let zk = _zk == JNI_TRUE;

    // Get ps type from vk
    let ps_type = vk.get_proving_system_type();

    // Get index info from vk
    let index_info = match vk {
        ZendooVerifierKey::CoboundaryMarlin(cob_marlin_vk) => cob_marlin_vk.index_info,
        ZendooVerifierKey::Darlin(darlin_vk) => darlin_vk.index_info
    };

    // Perform check
    let result = check_proof_vk_size(
        _supported_segment_size as usize,
        index_info,
        zk,
        ps_type,
        _max_proof_size as usize,
        _max_vk_size as usize
    );

    if result { JNI_TRUE } else { JNI_FALSE }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeSetup(
    _env: JNIEnv,
    _class: JClass,
    _proving_system: JObject,
    _max_pks: jlong,
    _proving_key_path: JString,
    _verification_key_path: JString,
    _zk: jboolean,
    _max_proof_size: jint,
    _max_vk_size: jint,
    _compress_pk: jboolean,
    _compress_vk: jboolean,
) -> jboolean
{
    // Get proving system type
    let proving_system = get_proving_system_type(&_env, _proving_system);

    // Read paths
    let proving_key_path = _env.get_string(_proving_key_path)
        .expect("Should be able to read jstring as Rust String");

    let verification_key_path = _env.get_string(_verification_key_path)
        .expect("Should be able to read jstring as Rust String");

    let max_pks = _max_pks as usize;

    let circ = get_instance_for_setup(max_pks);

    // Read zk value
    let zk = _zk == JNI_TRUE;

    // Generate snark keypair
    match generate_circuit_keypair(
        circ,
        proving_system,
        Path::new(proving_key_path.to_str().unwrap()),
        Path::new(verification_key_path.to_str().unwrap()),
        _max_proof_size as usize,
        _max_vk_size as usize,
        zk,
        Some(_compress_pk == JNI_TRUE),
        Some(_compress_vk == JNI_TRUE),
    ) {
        Ok(_) => JNI_TRUE,
        Err(e) => {
            println!("{:?}", e);
            JNI_FALSE
        },
    }
}

fn get_proving_system_type_as_jint(_env: &JNIEnv, ps: ProvingSystem) -> jint {
    match ps {
        ProvingSystem::Undefined => 0i32 as jint,
        ProvingSystem::Darlin => 1i32 as jint,
        ProvingSystem::CoboundaryMarlin => 2i32 as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetProverKeyProvingSystemType(
    _env: JNIEnv,
    _class: JClass,
    _proving_key_path: JString,
) -> jint
{
    // Read paths
    let proving_key_path = _env.get_string(_proving_key_path)
        .expect("Should be able to read jstring as Rust String");

    match read_from_file::<ProvingSystem>(
        Path::new(proving_key_path.to_str().unwrap()),
        None,
        None,
    ) {
        Ok(ps) => get_proving_system_type_as_jint(&_env, ps),
        Err(_) => -1i32 as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetVerifierKeyProvingSystemType(
    _env: JNIEnv,
    _class: JClass,
    _verifier_key_path: JString,
) -> jint
{
    // Read paths
    let verifier_key_path = _env.get_string(_verifier_key_path)
        .expect("Should be able to read jstring as Rust String");

    match read_from_file::<ProvingSystem>(
        Path::new(verifier_key_path.to_str().unwrap()),
        None,
        None,
    ) {
        Ok(ps) => get_proving_system_type_as_jint(&_env, ps),
        Err(_) => -1i32 as jint,
    }
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateProof(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _sc_id: JObject,
    _epoch_number: jint,
    _end_cumulative_sc_tx_comm_tree_root: JObject,
    _btr_fee: jlong,
    _ft_min_amount: jlong,
    _schnorr_sigs_list: jobjectArray,
    _schnorr_pks_list:  jobjectArray,
    _threshold: jlong,
    _proving_key_path: JString,
    _check_proving_key: jboolean,
    _zk: jboolean,
    _compressed_pk: jboolean,
    _compress_proof: jboolean,
) -> jobject
{
    // Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());


            let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

            let pk: [u8; 20] = _env.convert_byte_array(p)
                .expect("Should be able to convert to Rust byte array")
                .try_into()
                .expect("Should be able to write into fixed buffer of size 20");


            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push((a, pk));
        }
    }

    let bt_list = bt_list.into_iter().map(|bt_raw| BackwardTransfer {
        pk_dest: bt_raw.1,
        amount: bt_raw.0
    }).collect::<Vec<_>>();

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

    let sc_id = {
        let f =_env.get_field(_sc_id, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    let end_cumulative_sc_tx_comm_tree_root = {
        let f =_env.get_field(_end_cumulative_sc_tx_comm_tree_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    //Extract params_path str
    let proving_key_path = _env.get_string(_proving_key_path)
        .expect("Should be able to read jstring as Rust String");

    //create proof
    let (proof, quality) = match create_naive_threshold_sig_proof(
        pks.as_slice(),
        sigs,
        sc_id,
        _epoch_number as u32,
        end_cumulative_sc_tx_comm_tree_root,
        _btr_fee as u64,
        _ft_min_amount as u64,
        bt_list,
        _threshold as u64,
        Path::new(proving_key_path.to_str().unwrap()),
        _check_proving_key == JNI_TRUE,
        _zk == JNI_TRUE,
        _compressed_pk == JNI_TRUE,
        _compress_proof == JNI_TRUE,
    ) {
        Ok(proof) => proof,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR or IO_ERROR
    };

    //Return proof serialized
    let proof_serialized = _env.byte_array_from_slice(proof.as_slice())
        .expect("Should be able to convert Rust slice into jbytearray");

    //Create new CreateProofResult object
    let proof_result_class = _env.find_class("com/horizen/sigproofnative/CreateProofResult")
        .expect("Should be able to find CreateProofResult class");

    let result = _env.new_object(
        proof_result_class,
        "([BJ)V",
        &[JValue::Object(JObject::from(proof_serialized)), JValue::Long(jlong::from(quality as i64))]
    ).expect("Should be able to create new CreateProofResult:(byte[], long) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetProofProvingSystemType(
    _env: JNIEnv,
    _class: JClass,
    _proof: jbyteArray,
) -> jint
{
    //Extract proof
    let proof_bytes = _env.convert_byte_array(_proof)
        .expect("Should be able to convert to Rust byte array");

    match deserialize_from_buffer::<ProvingSystem>(
        &proof_bytes[..1],
        None,
        None
    ) {
        Ok(ps) => get_proving_system_type_as_jint(&_env, ps),
        Err(_) => -1i32 as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeVerifyProof(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _sc_id: JObject,
    _epoch_number: jint,
    _end_cumulative_sc_tx_comm_tree_root: JObject,
    _btr_fee: jlong,
    _ft_min_amount: jlong,
    _constant: JObject,
    _quality: jlong,
    _sc_proof_bytes: jbyteArray,
    _check_proof: jboolean,
    _compressed_proof: jboolean,
    _verification_key_path: JString,
    _check_vk: jboolean,
    _compressed_vk: jboolean,
) -> jboolean
{
    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());

            let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

            let pk: [u8; 20] = _env.convert_byte_array(p)
                .expect("Should be able to convert to Rust byte array")
                .try_into()
                .expect("Should be able to write into fixed buffer of size 20");


            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push((a, pk));
        }
    }

    let bt_list = bt_list.into_iter().map(|bt_raw| BackwardTransfer {
        pk_dest: bt_raw.1,
        amount: bt_raw.0
    }).collect::<Vec<_>>();

    let sc_id = {
        let f =_env.get_field(_sc_id, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    let end_cumulative_sc_tx_comm_tree_root = {
        let f =_env.get_field(_end_cumulative_sc_tx_comm_tree_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    //Extract constant
    let constant = {

        let c =_env.get_field(_constant, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(c.j().unwrap() as *const FieldElement)
    };

    //Extract proof
    let proof_bytes = _env.convert_byte_array(_sc_proof_bytes)
        .expect("Should be able to convert to Rust byte array");

    //Extract vk path
    let vk_path = _env.get_string(_verification_key_path)
        .expect("Should be able to read jstring as Rust String");

    //Verify proof
    match verify_naive_threshold_sig_proof(
        constant,
        sc_id,
        _epoch_number as u32,
        end_cumulative_sc_tx_comm_tree_root,
        _btr_fee as u64,
        _ft_min_amount as u64,
        bt_list,
        _quality as u64,
        proof_bytes,
        _check_proof == JNI_TRUE,
        _compressed_proof == JNI_TRUE,
        Path::new(vk_path.to_str().unwrap()),
        _check_vk == JNI_TRUE,
        _compressed_vk == JNI_TRUE,

    ) {
        Ok(result) => if result { JNI_TRUE } else { JNI_FALSE },
        Err(_) => JNI_FALSE // CRYPTO_ERROR or IO_ERROR
    }
}

///////// COMMITMENT TREE
#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeInit(
    _env: JNIEnv,
    _class: JClass
) -> jobject
{

    // Create new CommitmentTree Rust side
    let commitment_tree = CommitmentTree::create();

    // Create and return new CommitmentTree Java side
    let commitment_tree_ptr: jlong = jlong::from(Box::into_raw(Box::new(commitment_tree)) as i64);

    _env.new_object(_class, "(J)V", &[JValue::Long(commitment_tree_ptr)])
        .expect("Should be able to create new CommitmentTree object")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeFreeCommitmentTree(
    _env: JNIEnv,
    _class: JClass,
    _commitment_tree: *mut CommitmentTree
)
{
    if _commitment_tree.is_null()  { return }
    drop(unsafe { Box::from_raw(_commitment_tree) });
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddScCr(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _amount: jlong,
    _pub_key: jbyteArray,
    _tx_hash: jbyteArray,
    _out_idx: jint,
    _withdrawal_epoch_length: jint,
    _mc_btr_request_data_length: jbyte,
    _custom_field_elements_configs: jobjectArray,
    _custom_bitvector_elements_configs: jobjectArray,
    _btr_fee: jlong,
    _ft_min_amount: jlong,
    _custom_creation_data: jbyteArray,
    _constant_nullable: jbyteArray,                 // can be null if there is no constant
    _cert_verification_key: jbyteArray,
    _csw_verification_key_nullable: jbyteArray // can be null if there is no key for CSWs
) -> jboolean
{

    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        match FieldElement::deserialize(sc_id_bytes.as_slice()) {
            Ok(fe) => fe,
            Err(_) => return JNI_FALSE
        }
    };

    let amount = _amount as u64;

    let mut pub_key = [0u8; FIELD_SIZE];
    get_byte_array(&_env, &_pub_key, &mut pub_key[..]);

    let mut tx_hash = [0u8; FIELD_SIZE];
    get_byte_array(&_env, &_tx_hash, &mut tx_hash[..]);

    let out_idx = _out_idx as u32;

    let withdrawal_epoch_length = _withdrawal_epoch_length as u32;

    let mc_btr_request_data_length = _mc_btr_request_data_length as u8;

    let mut custom_field_elements_configs = vec![];
    let custom_field_size = _env.get_array_length(_custom_field_elements_configs)
        .expect("Should be able to get _custom_field_elements_configs size");
    if custom_field_size > 0 {
        for i in 0..custom_field_size {
            let custom_field_config = _env.get_object_array_element(_custom_field_elements_configs, i)
                .expect(format!("Should be able to get elem {} of custom_field_elements_configs array", i).as_str());

            let bits = _env.call_method(custom_field_config, "getBits", "()B", &[])
                .expect("Should be able to call getBitVectorSizeBits method").b().unwrap() as u8;

            custom_field_elements_configs.push(bits);
        }
    }
    let custom_field_elements_configs_opt = if custom_field_elements_configs.len() > 0 {
        Some(custom_field_elements_configs.as_slice())
    } else {
        None
    };

    let mut custom_bitvector_elements_configs = vec![];
    let custom_bitvector_elements_size = _env.get_array_length(_custom_bitvector_elements_configs)
        .expect("Should be able to get _custom_field_elements_configs size");
    if custom_bitvector_elements_size > 0 {
        for i in 0..custom_bitvector_elements_size {
            let custom_bitvector_element_config = _env.get_object_array_element(_custom_bitvector_elements_configs, i)
                .expect(format!("Should be able to get elem {} of custom_bitvector_elements_configs array", i).as_str());

            let bit_vector_size_bits = _env.call_method(custom_bitvector_element_config, "getBitVectorSizeBits", "()I", &[])
                .expect("Should be able to call getBitVectorSizeBits method").i().unwrap() as u32;

            let max_compressed_byte_size = _env.call_method(custom_bitvector_element_config, "getMaxCompressedByteSize", "()I", &[])
                .expect("Should be able to call getMaxCompressedByteSize method").i().unwrap() as u32;

            custom_bitvector_elements_configs.push(BitVectorElementsConfig {bit_vector_size_bits, max_compressed_byte_size});
        }
    }

    let custom_bitvector_elements_configs_opt = if custom_bitvector_elements_configs.len() > 0 {
        Some(custom_bitvector_elements_configs.as_slice())
    } else {
        None
    };

    let btr_fee = _btr_fee as u64;

    let ft_min_amount = _ft_min_amount as u64;

    let custom_creation_data = _env.convert_byte_array(_custom_creation_data)
        .expect("Should be able to convert to Rust array");

    let custom_creation_data_opt = if custom_creation_data.len() > 0 {
        Some(custom_creation_data.as_slice())
    } else {
        None
    };

    // let constant_fe;
    let constant = if _constant_nullable.is_null() {
        Option::None
    } else {
        let constant_bytes = parse_jbyte_array_to_vec(&_env, &_constant_nullable, FIELD_SIZE);
        match FieldElement::deserialize(constant_bytes.as_slice()) {
            Ok(constant_fe) => Option::Some(constant_fe),
            Err(_) => return JNI_FALSE
        }
    };

    let cert_verification_key = _env.convert_byte_array(_cert_verification_key)
        .expect("Should be able to convert to Rust byte array");

    let mut _csw_verification_key_nullable_vec;
    let csw_verification_key_opt = if _csw_verification_key_nullable.is_null() {
        Option::None
    } else {
        _csw_verification_key_nullable_vec = _env.convert_byte_array(_csw_verification_key_nullable)
            .expect("Should be able to convert to Rust byte array");
        Some(_csw_verification_key_nullable_vec.as_slice())
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_scc(&sc_id,
                               amount,
                               &pub_key,
                               &tx_hash,
                               out_idx,
                               withdrawal_epoch_length,
                               mc_btr_request_data_length,
                               custom_field_elements_configs_opt,
                               custom_bitvector_elements_configs_opt,
                               btr_fee,
                               ft_min_amount,
                               custom_creation_data_opt,
                               constant.as_ref(),
                               cert_verification_key.as_slice(),
                               csw_verification_key_opt
                               ) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddFwt(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _amount: jlong,
    _pub_key: jbyteArray,
    _mc_return_address: jbyteArray,
    _tx_hash: jbyteArray,
    _out_idx: jint
) -> jboolean
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let amount = _amount as u64;

    let mut pub_key = [0u8; FIELD_SIZE];
    get_byte_array(&_env, &_pub_key, &mut pub_key[..]);

    let mut mc_return_address = [0u8; MC_PK_SIZE];
    get_byte_array(&_env, &_mc_return_address, &mut mc_return_address[..]);

    let mut tx_hash = [0u8; FIELD_SIZE];
    get_byte_array(&_env, &_tx_hash, &mut tx_hash[..]);

    let out_idx = _out_idx as u32;

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };


    if commitment_tree.add_fwt(&sc_id,
                               amount,
                               &pub_key,
                               &mc_return_address,
                               &tx_hash,
                               out_idx) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddBtr(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _sc_fee: jlong,
    _mc_destination_address: jbyteArray,
    _sc_request_data: jobjectArray,
    _tx_hash: jbyteArray,
    _out_idx: jint
) -> jboolean
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let sc_fee = _sc_fee as u64;

    let mut mc_destination_address = [0u8; 20];
    get_byte_array(&_env, &_mc_destination_address, &mut mc_destination_address[..]);

    let mut sc_request_data = vec![];
    let sc_request_data_size = _env.get_array_length(_sc_request_data)
        .expect("Should be able to get _custom_field_elements_configs size");
    if sc_request_data_size > 0 {
        for i in 0..sc_request_data_size {
            let o = _env.get_object_array_element(_sc_request_data, i)
                .expect(format!("Should be able to get elem {} of custom_field_elements_configs array", i).as_str());

            let data = _env.convert_byte_array(o.cast())
                .expect("Should be able to convert to Rust byte array");

            sc_request_data.push(FieldElement::deserialize(data.as_slice()).expect("Can't parse the input sc_request_data into FieldElement"));
        }
    }

    let mut tx_hash = [0u8; FIELD_SIZE];
    get_byte_array(&_env, &_tx_hash, &mut tx_hash[..]);

    let out_idx = _out_idx as u32;

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_bwtr(&sc_id,
                                sc_fee,
                                sc_request_data.iter().collect(),
                                &mc_destination_address,
                                &tx_hash,
                                out_idx) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddCert(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _epoch_number: jint,
    _quality: jlong,
    _bt_list: jobjectArray,
    _custom_fields_nullable: jobjectArray, // can be null if there is no constant
    _end_cumulative_sc_tx_commitment_tree_root: jbyteArray,
    _btr_fee: jlong,
    _ft_min_amount: jlong
) -> jboolean
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let epoch_number = _epoch_number as u32;

    let quality = _quality as u64;

    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());

            let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

            let pk: [u8; 20] = _env.convert_byte_array(p)
                .expect("Should be able to convert to Rust byte array")
                .try_into()
                .expect("Should be able to write into fixed buffer of size 20");

            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push(BackwardTransfer{pk_dest: pk, amount: a});
        }
    }

    let bt_list_opt = if bt_list.len() > 0 {
        Some(bt_list.as_slice())
    } else {
        None
    };


    let mut custom_fields = vec![];
    let custom_fields_opt = if _custom_fields_nullable.is_null() {
        Option::None
    } else {
        let custom_fields_size = _env.get_array_length(_custom_fields_nullable)
            .expect("Should be able to get custom_fields size");

        if custom_fields_size > 0 {
            for i in 0..custom_fields_size {
                let o = _env.get_object_array_element(_custom_fields_nullable, i)
                    .expect(format!("Should be able to get elem {} of custom_fields array", i).as_str());

                let cf = _env.convert_byte_array(o.cast())
                    .expect("Should be able to convert to Rust byte array");

                custom_fields.push(FieldElement::deserialize(cf.as_slice()).expect("Can't parse the input custom_field into FieldElement"));
            }
        }
        Some(custom_fields.iter().collect())
    };

    let end_cumulative_sc_tx_commitment_tree_root = {
        let tree_root_bytes = parse_jbyte_array_to_vec(&_env, &_end_cumulative_sc_tx_commitment_tree_root, FIELD_SIZE);
        FieldElement::deserialize(tree_root_bytes.as_slice()).expect("Can't parse the input end_cumulative_sc_tx_commitment_tree_root into FieldElement")
    };

    let btr_fee = _btr_fee as u64;

    let ft_min_amount = _ft_min_amount as u64;

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_cert(&sc_id,
                                epoch_number,
                                quality,
                                bt_list_opt,
                                custom_fields_opt,
                                &end_cumulative_sc_tx_commitment_tree_root,
                                btr_fee,
                                ft_min_amount) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddCertLeaf(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _leaf: jbyteArray
) -> jboolean
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let leaf_fe = {
        let leaf_bytes = parse_jbyte_array_to_vec(&_env, &_leaf, FIELD_SIZE);
        FieldElement::deserialize(leaf_bytes.as_slice()).expect("Can't parse the input leaf_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_cert_leaf(&sc_id, &leaf_fe) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCrtLeaves(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    match commitment_tree.get_cert_leaves(&sc_id) {
        Some(leaves) => {
            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let initial_element = _env.new_object(field_class, "(J)V", &[
                JValue::Long(0)]).expect("Should be able to create new long for FieldElement");

            let leaf_fe_array = _env.new_object_array(leaves.len() as i32, field_class, initial_element)
                .expect("Should be able to create array of FieldElements");

            for (idx, leaf) in leaves.iter().enumerate() {
                let leaf_field_ptr: jlong = jlong::from(Box::into_raw(Box::new(leaf.clone())) as i64);

                let leaf_element = _env.new_object(field_class, "(J)V", &[
                    JValue::Long(leaf_field_ptr)]).expect("Should be able to create new long for FieldElement");

                _env.set_object_array_element(leaf_fe_array, idx as i32, leaf_element)
                    .expect("Should be able to add FieldElement leaf to an array");
            }


            let cls_optional = _env.find_class("java/util/Optional").unwrap();

            let empty_res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;", &[JValue::from(JObject::from(leaf_fe_array))])
                .expect("Should be able to create new value for Optional");

            *empty_res.l().unwrap()
        }
        _ => {
            let cls_optional = _env.find_class("java/util/Optional").unwrap();

            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");

            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddCsw(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _amount: jlong,
    _nullifier: jbyteArray,
    _mc_pk_hash: jbyteArray
) -> jboolean
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let amount = _amount as u64;

    let nullifier = {
        let nullifier_bytes = parse_jbyte_array_to_vec(&_env, &_nullifier, FIELD_SIZE);
        FieldElement::deserialize(nullifier_bytes.as_slice()).expect("Can't parse the input nullifier_bytes into FieldElement")
    };

    let mut mc_pk_hash = [0u8; MC_PK_SIZE];
    get_byte_array(&_env, &_mc_pk_hash, &mut mc_pk_hash[..]);

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_csw(&sc_id,
                               amount,
                               &nullifier,
                               &mc_pk_hash) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScCrCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_scc(&sc_id) {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetFwtCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_fwt_commitment(&sc_id) {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeBtrCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_bwtr_commitment(&sc_id) {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCertCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_cert_commitment(&sc_id) {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCswCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_csw_commitment(&sc_id) {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_sc_commitment(&sc_id) {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject
) -> jobject
{
    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_commitment() {
        Some(sc_cr_commitment_fe) => {
            let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64);

            let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
                .expect("Should be able to find FieldElement class");

            let jfe = _env.new_object(field_class, "(J)V", &[
                JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jfe)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

// Sc Existance proof functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScExistenceProof(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_sc_existence_proof(&sc_id) {
        Some(sc_existence_proof) => {
            let proof_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_existence_proof)) as i64);

            let existence_proof_class = _env.find_class("com/horizen/commitmenttree/ScExistenceProof")
                .expect("Should be able to find ScExistenceProof class");

            let jep = _env.new_object(existence_proof_class, "(J)V", &[
                JValue::Long(proof_ptr)]).expect("Should be able to create new long for ScExistenceProof");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jep)]).unwrap();
            *res.l().unwrap()
        },
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_ScExistenceProof_nativeSerialize(
    _env: JNIEnv,
    _proof: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<ScExistenceProof>(
        &_env,
        _proof,
        "existenceProofPointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_ScExistenceProof_nativeDeserialize(
    _env: JNIEnv,
    _class: JClass,
    _proof_bytes: jbyteArray,
) -> jobject
{
    let proof_bytes = _env.convert_byte_array(_proof_bytes)
        .expect("Should be able to convert to Rust byte array");

    match ScExistenceProof::deserialize(proof_bytes.as_slice()) {
        Ok(sc_existence_proof) => {
            let proof_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_existence_proof)) as i64);

            let existence_proof_class = _env.find_class("com/horizen/commitmenttree/ScExistenceProof")
                .expect("Should be able to find ScExistenceProof class");

            let jep = _env.new_object(existence_proof_class, "(J)V", &[JValue::Long(proof_ptr)])
                .expect("Should be able to create new long for ScExistenceProof");

            *jep
        },
        Err(_) => {std::ptr::null::<jobject>() as jobject}
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_ScExistenceProof_nativeFreeScExistenceProof(
    _env: JNIEnv,
    _class: JClass,
    _sc_existence_proof: *mut ScExistenceProof
)
{
    if _sc_existence_proof.is_null()  { return }
    drop(unsafe { Box::from_raw(_sc_existence_proof) });
}


// Sc Absence proof functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScAbsenceProof(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut CommitmentTree)
    };

    let cls_optional = _env.find_class("java/util/Optional").unwrap();

    match commitment_tree.get_sc_absence_proof(&sc_id) {
        Some(sc_absence_proof) => {
            let proof_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_absence_proof)) as i64);

            let absence_proof_class = _env.find_class("com/horizen/commitmenttree/ScAbsenceProof")
                .expect("Should be able to find ScAbsenceProof class");

            let jep = _env.new_object(absence_proof_class, "(J)V", &[
                JValue::Long(proof_ptr)]).expect("Should be able to create new long for ScAbsenceProof");

            let res = _env.call_static_method(cls_optional, "of", "(Ljava/lang/Object;)Ljava/util/Optional;",
                                              &[JValue::Object(jep)]).unwrap();
            *res.l().unwrap()
        }
        _ => {
            let empty_res = _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                .expect("Should be able to create new value for Optional.empty()");
            *empty_res.l().unwrap()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_ScAbsenceProof_nativeSerialize(
    _env: JNIEnv,
    _proof: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<ScAbsenceProof>(
        &_env,
        _proof,
        "absenceProofPointer",
        None
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_ScAbsenceProof_nativeDeserialize(
    _env: JNIEnv,
    _class: JClass,
    _proof_bytes: jbyteArray,
) -> jobject
{
    let proof_bytes = _env.convert_byte_array(_proof_bytes)
        .expect("Should be able to convert to Rust byte array");

    match ScAbsenceProof::deserialize(proof_bytes.as_slice()) {
        Ok(sc_absence_proof) => {
            let proof_ptr: jlong = jlong::from(Box::into_raw(Box::new(sc_absence_proof)) as i64);

            let absence_proof_class = _env.find_class("com/horizen/commitmenttree/ScAbsenceProof")
                .expect("Should be able to find ScAbsenceProof class");

            let jep = _env.new_object(absence_proof_class, "(J)V", &[JValue::Long(proof_ptr)])
                .expect("Should be able to create new long for ScAbsenceProof");

            *jep
        },
        Err(_) => { std::ptr::null::<jobject>() as jobject }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_ScAbsenceProof_nativeFreeScAbsenceProof(
    _env: JNIEnv,
    _class: JClass,
    _sc_absence_proof: *mut ScAbsenceProof
)
{
    if _sc_absence_proof.is_null()  { return }
    drop(unsafe { Box::from_raw(_sc_absence_proof) });
}


// Verify existance/absence functions.

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeVerifyScCommitment(
    _env: JNIEnv,
    _commitment_tree_class: JObject,
    _sc_commitment: JObject,
    _sc_commitment_proof: JObject,
    _commitment: JObject
) -> bool
{

    //Read sidechain commitment
    let sc_commitment_fe = {
        let i =_env.get_field(_sc_commitment, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer from scCommitment");

        read_raw_pointer(i.j().unwrap() as *const FieldElement)
    };

    //Read commitment proof
    let sc_commitment_proof = {
        let i =_env.get_field(_sc_commitment_proof, "existenceProofPointer", "J")
            .expect("Should be able to get field existenceProofPointer from scCommitmentProof");

        read_raw_pointer(i.j().unwrap() as *const ScExistenceProof)
    };

    //Read commitment
    let commitment_fe = {
        let i =_env.get_field(_commitment, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer from commitment");

        read_raw_pointer(i.j().unwrap() as *const FieldElement)
    };

    CommitmentTree::verify_sc_commitment(sc_commitment_fe, sc_commitment_proof, commitment_fe)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_commitmenttree_CommitmentTree_nativeVerifyScAbsence(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _sc_absence_proof: JObject,
    _commitment: JObject
) -> bool
{
    // Read sidechain id
    let sc_id = {
        let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
        FieldElement::deserialize(sc_id_bytes.as_slice()).expect("Can't parse the input sc_id_bytes into FieldElement")
    };

    //Read commitment proof
    let sc_absence_proof = {
        let i =_env.get_field(_sc_absence_proof, "absenceProofPointer", "J")
            .expect("Should be able to get field absenceProofPointer from scAbsenceProof");

        read_raw_pointer(i.j().unwrap() as *const ScAbsenceProof)
    };

    //Read commitment
    let commitment_fe = {
        let i =_env.get_field(_commitment, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer from commitment");

        read_raw_pointer(i.j().unwrap() as *const FieldElement)
    };

    CommitmentTree::verify_sc_absence(&sc_id, sc_absence_proof, commitment_fe)
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_Utils_nativeCalculateSidechainId(
    _env: JNIEnv,
    _utils: JClass,
    _tx_hash: jbyteArray,
    _idx: jint
) -> jbyteArray
{
    // Parse tx_hash into a [u8; 32]
    let tx_hash: [u8; 32] = _env.convert_byte_array(_tx_hash)
        .expect("Should be able to convert to Rust byte array")
        .try_into()
        .expect("Should be able to write into fixed buffer of size 32");

    let idx = _idx as u32;

    // Compute sc_id
    let sc_id = compute_sc_id(&tx_hash, idx).expect("Cannot compute sc id.");

    // Return sc_id bytes
    let sc_id_bytes = serialize_to_buffer(
        &sc_id,
        None,
    ).expect("Should be able to serialize sc_id");
    _env.byte_array_from_slice(sc_id_bytes.as_slice()).expect("Cannot write jobject.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_Utils_nativeCompressedBitvectorMerkleRoot(
    _env: JNIEnv,
    _utils: JClass,
    _compressed_bit_vector: jbyteArray,
) -> jbyteArray
{
    // Parse compressed_bit_vector into a vector
    let compressed_bit_vector = _env.convert_byte_array(_compressed_bit_vector)
        .expect("Should be able to convert to Rust byte array");

    // Compute merkle_root
    let merkle_root = merkle_root_from_compressed_bytes_without_checks(compressed_bit_vector.as_slice())
        .expect("Cannot compute merkle root.");

    // Return merkle_root bytes
    let merkle_root_bytes = serialize_to_buffer(
        &merkle_root,
        None,
    ).expect("Should be able to serialize merkle_root");
    _env.byte_array_from_slice(merkle_root_bytes.as_slice()).expect("Cannot write jobject.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_Utils_nativeCompressedBitvectorMerkleRootWithSizeCheck(
    _env: JNIEnv,
    _utils: JClass,
    _compressed_bit_vector: jbyteArray,
    _expected_uncompressed_size: jint
) -> jbyteArray
{
    // Parse compressed_bit_vector into a vector
    let compressed_bit_vector = _env.convert_byte_array(_compressed_bit_vector)
        .expect("Should be able to convert to Rust byte array");

    let expected_uncompressed_size = _expected_uncompressed_size as usize;

    // Compute merkle_root
    match merkle_root_from_compressed_bytes(compressed_bit_vector.as_slice(), expected_uncompressed_size) {
        Ok(merkle_root) => {
            // Return merkle_root bytes
            let merkle_root_bytes = serialize_to_buffer(
                &merkle_root,
                None,
            ).expect("Should be able to serialize merkle_root");
            _env.byte_array_from_slice(merkle_root_bytes.as_slice()).expect("Cannot write jobject.")
        }
        Err(_) => {
            _env.throw_new("java/lang/Exception", "Cannot compute merkle root with size check.").expect("Exception expected.");
            JObject::null().into_inner()
        }
    }


}