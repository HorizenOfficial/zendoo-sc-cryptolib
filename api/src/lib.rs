#![allow(
    clippy::upper_case_acronyms,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::try_err,
    clippy::map_collect_result_unit,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::suspicious_op_assign_impl,
    clippy::suspicious_arithmetic_impl,
    clippy::assertions_on_constants
)]

extern crate jni;

use algebra::{serialize::*, AffineCurve, SemanticallyValid, ToBits, ToConstraintField};
use cctp_primitives::{
    bit_vector::merkle_tree::{
        merkle_root_from_compressed_bytes, merkle_root_from_compressed_bytes_without_checks,
    },
    commitment_tree::{
        hashers::hash_fwt,
        proofs::{ScAbsenceProof, ScExistenceProof},
        sidechain_tree_alive::FWT_MT_HEIGHT,
        CommitmentTree, CMT_MT_HEIGHT,
    },
    proving_system::{compute_proof_vk_size, init_dlog_keys, ProvingSystem, ZendooVerifierKey},
    utils::{data_structures::*, mht::*, poseidon_hash::*, serialization::*},
};
use demo_circuit::{
    blaze_csw::{
        constraints::CeasedSidechainWithdrawalCircuit,
        data_structures::{
            CswFtOutputData, CswFtProverData, CswSysData, CswUtxoInputData, CswUtxoOutputData,
            CswUtxoProverData,
        },
        deserialize_fe_unchecked,
    },
    common::{
        data_structures::WithdrawalCertificateData, MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS,
        MIN_CUSTOM_FIELDS, MSG_ROOT_HASH_CUSTOM_FIELDS_POS, NULL_CONST,
    },
    constants::{personalizations::BoxType, *},
    generate_circuit_keypair,
    naive_threshold_sig::NaiveThresholdSignature,
    naive_threshold_sig_w_key_rotation::{
        data_structures::ValidatorKeysUpdates, NaiveThresholdSignatureWKeyRotation,
    },
    read_field_element_from_buffer_with_padding,
    sc2sc::{Sc2Sc, ScCommitmentCertPath, MSG_MT_HEIGHT},
    type_mapping::*,
};

use jni_wrapper::{AsNativeRefMut, AsNativeRef, JNINativeWrapper};
use primitives::{
    bytes_to_bits, signature::schnorr::field_based_schnorr::FieldBasedSchnorrPk, FieldBasedHash,
    FieldBasedMerkleTree, FieldBasedMerkleTreePath, FieldBasedSparseMerkleTree, FieldHasher,
};
use std::{
    any::type_name,
    collections::{HashMap, HashSet},
    iter::Iterator,
    path::Path,
};

mod cctp_calls;
use cctp_calls::*;

#[macro_use]
mod exception;
use exception::*;

#[macro_use]
mod utils;
use utils::*;

use cctp_primitives::utils::compute_sc_id;
use jni::objects::{JClass, JMap, JObject, JString, JValue};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong, jobject, jobjectArray, jsize};
use jni::sys::{JNI_FALSE, JNI_TRUE};
use jni::{sys::jlongArray, JNIEnv};
use std::convert::TryInto;

//Field element related functions

mod jni_wrapper;

//TODO: We should use JNINativeWrapper and JNIMutNativeWrapper traits for every struct
// that is wrapped by a raw pointer in Java and replace all old approaches.
// See Java_com_horizen_sc2scnative_Sc2Sc_nativeCreateProof as example.

impl JNINativeWrapper for FieldElement {
    const INNER_FIELD: &'static str = "fieldElementPointer";

    const JAVA_PACKAGE: &'static str = "com/horizen/librustsidechains";

    const JAVA_CLASS: &'static str = "FieldElement";
}

impl JNINativeWrapper for ScCommitmentCertPath {
    const INNER_FIELD: &'static str = "scCommitmentCertPathPointer";

    const JAVA_PACKAGE: &'static str = "com/horizen/commitmenttreenative";

    const JAVA_CLASS: &'static str = "ScCommitmentCertPath";
}

impl JNINativeWrapper for CommitmentTree {
    const INNER_FIELD: &'static str = "commitmentTreePointer";

    const JAVA_PACKAGE: &'static str = "com/horizen/commitmenttreenative";

    const JAVA_CLASS: &'static str = "CommitmentTree";
}

impl JNINativeWrapper for GingerMHTPath {
    const INNER_FIELD: &'static str = "merklePathPointer";

    const JAVA_PACKAGE: &'static str = "com/horizen/merkletreenative";

    const JAVA_CLASS: &'static str = "MerklePath";
}

ffi_export!(
    fn Java_com_horizen_librustsidechains_Library_nativePanickingFunction(
        _env: JNIEnv,
        _class: JClass,
    ) {
        panic!("Oh no ! A panic occured !")
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_Constants_nativeInitializeAllConstants(
        _env: JNIEnv,
        _class: JClass,
    ) {
        let class = _env
            .find_class("com/horizen/librustsidechains/Constants")
            .expect("Should be able to find Constants class");

        macro_rules! set_constant {
            ($name: expr, $value: expr) => {
                _env.set_static_field(
                    class,
                    _env.get_static_field_id(class, $name, "I")
                        .expect(format!("Should be able to get ID of {} field", $name).as_str()),
                    JValue::Int($value as jint),
                )
                .expect(format!("Should be able to set {} field", $name).as_str());
            };
        }

        // Supply the value for all constants
        set_constant!("MC_PK_HASH_SIZE", MC_PK_SIZE);
        set_constant!("SC_PK_HASH_SIZE", SC_PUBLIC_KEY_LENGTH);
        set_constant!("SC_SK_SIZE", SC_SECRET_KEY_LENGTH);
        set_constant!("SC_TX_HASH_SIZE", SC_TX_HASH_LENGTH);
        set_constant!("SC_CUSTOM_HASH_SIZE", SC_CUSTOM_HASH_LENGTH);
        set_constant!("SC_MST_HEIGHT", MST_MERKLE_TREE_HEIGHT);
        set_constant!("SC_COMM_TREE_FT_SUBTREE_HEIGHT", FWT_MT_HEIGHT);
        set_constant!("SC_COMM_TREE_HEIGHT", CMT_MT_HEIGHT);
        set_constant!("FIELD_ELEMENT_LENGTH", FIELD_SIZE);
        set_constant!("SCHNORR_PK_LENGTH", SCHNORR_PK_SIZE);
        set_constant!("SCHNORR_SK_LENGTH", SCHNORR_SK_SIZE);
        set_constant!("SCHNORR_SIGNATURE_LENGTH", SCHNORR_SIG_SIZE);
        set_constant!("VRF_PK_LENGTH", VRF_PK_SIZE);
        set_constant!("VRF_SK_LENGTH", VRF_SK_SIZE);
        set_constant!("VRF_PROOF_LENGTH", VRF_PROOF_SIZE);
        set_constant!(
            "MSG_ROOT_HASH_CUSTOM_FIELDS_POS",
            MSG_ROOT_HASH_CUSTOM_FIELDS_POS
        );
        set_constant!(
            "MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS",
            MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS
        );
        set_constant!("MIN_CUSTOM_FIELDS", MIN_CUSTOM_FIELDS);
        set_constant!("MSG_MT_HEIGHT", MSG_MT_HEIGHT);
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativeSerializeFieldElement(
        _env: JNIEnv,
        _field_element: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<FieldElement>(&_env, _field_element, "fieldElementPointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativeDeserializeFieldElement(
        _env: JNIEnv,
        _class: JClass,
        _field_element_bytes: jbyteArray,
    ) -> jobject {
        let fe_bytes = _env
            .convert_byte_array(_field_element_bytes)
            .expect("Cannot read bytes.");

        match read_field_element_from_buffer_with_padding(fe_bytes.as_slice()) {
            Ok(fe) => return_field_element(&_env, fe),
            Err(e) => {
                log!(format!("Unable to deserialize FieldElement: {:?}", e));
                std::ptr::null::<jobject>() as jobject
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativeCreateRandom(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _class: JClass,
        _seed: jlong,
    ) -> jobject {
        //Create random field element
        let fe = get_random_field_element(_seed as u64);

        return_field_element(&_env, fe)
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativeCreateFromLong(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _class: JClass,
        _long: jlong,
    ) -> jobject {
        //Create field element from _long
        let fe = FieldElement::from(_long as u64);

        return_field_element(&_env, fe)
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativePrintFieldElementBytes(
        _env: JNIEnv,
        _field_element: JObject,
    ) {
        let pointer = _env
            .get_field(_field_element, "fieldElementPointer", "J")
            .expect("Cannot get object raw pointer.");

        let obj_bytes =
            serialize_from_raw_pointer(&_env, pointer.j().unwrap() as *const FieldElement, None);

        println!("{:?}", into_i8(obj_bytes));
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativeFreeFieldElement(
        _env: JNIEnv,
        _class: JClass,
        _fe: *mut FieldElement,
    ) {
        if _fe.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_fe) });
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_FieldElement_nativeEquals(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _field_element_1: JObject,
        _field_element_2: JObject,
    ) -> jboolean {
        //Read field_1
        let field_1 = {
            let f = _env
                .get_field(_field_element_1, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer_1");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        //Read field_2
        let field_2 = {
            let f = _env
                .get_field(_field_element_2, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer_2");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        match field_1 == field_2 {
            true => JNI_TRUE,
            false => JNI_FALSE,
        }
    }
);

//Public Schnorr key utility functions

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeSerializePublicKey(
        _env: JNIEnv,
        _schnorr_public_key: JObject,
        _compressed: jboolean,
    ) -> jbyteArray {
        serialize_from_jobject::<SchnorrPk>(
            &_env,
            _schnorr_public_key,
            "publicKeyPointer",
            Some(_compressed),
        )
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeDeserializePublicKey(
        _env: JNIEnv,
        _schnorr_public_key_class: JClass,
        _public_key_bytes: jbyteArray,
        _check_public_key: jboolean,
        _compressed: jboolean,
    ) -> jobject {
        deserialize_to_jobject::<SchnorrPk>(
            &_env,
            _public_key_bytes,
            Some(_check_public_key),
            Some(_compressed),
            "com/horizen/schnorrnative/SchnorrPublicKey",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeFreePublicKey(
        _env: JNIEnv,
        _schnorr_public_key: JObject,
    ) {
        let public_key_pointer = _env
            .get_field(_schnorr_public_key, "publicKeyPointer", "J")
            .expect("Cannot get public key pointer.");

        let public_key = public_key_pointer.j().unwrap() as *mut SchnorrPk;

        if public_key.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(public_key) });
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeSerializeSecretKey(
        _env: JNIEnv,
        _schnorr_secret_key: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<SchnorrSk>(&_env, _schnorr_secret_key, "secretKeyPointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeDeserializeSecretKey(
        _env: JNIEnv,
        _schnorr_secret_key_class: JClass,
        _secret_key_bytes: jbyteArray,
    ) -> jobject {
        deserialize_to_jobject::<SchnorrSk>(
            &_env,
            _secret_key_bytes,
            None,
            None,
            "com/horizen/schnorrnative/SchnorrSecretKey",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeFreeSecretKey(
        _env: JNIEnv,
        _schnorr_secret_key: JObject,
    ) {
        let secret_key_pointer = _env
            .get_field(_schnorr_secret_key, "secretKeyPointer", "J")
            .expect("Cannot get secret key pointer.");

        let secret_key = secret_key_pointer.j().unwrap() as *mut SchnorrSk;

        if secret_key.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(secret_key) });
    }
);

//Public VRF key utility functions

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFPublicKey_nativeSerializePublicKey(
        _env: JNIEnv,
        _vrf_public_key: JObject,
        _compressed: jboolean,
    ) -> jbyteArray {
        serialize_from_jobject::<VRFPk>(
            &_env,
            _vrf_public_key,
            "publicKeyPointer",
            Some(_compressed),
        )
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFPublicKey_nativeDeserializePublicKey(
        _env: JNIEnv,
        _vrf_public_key_class: JClass,
        _public_key_bytes: jbyteArray,
        _check_public_key: jboolean,
        _compressed: jboolean,
    ) -> jobject {
        deserialize_to_jobject::<VRFPk>(
            &_env,
            _public_key_bytes,
            Some(_check_public_key),
            Some(_compressed),
            "com/horizen/vrfnative/VRFPublicKey",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFPublicKey_nativeFreePublicKey(
        _env: JNIEnv,
        _vrf_public_key: JObject,
    ) {
        let public_key_pointer = _env
            .get_field(_vrf_public_key, "publicKeyPointer", "J")
            .expect("Cannot get public key pointer.");

        let public_key = public_key_pointer.j().unwrap() as *mut SchnorrPk;

        if public_key.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(public_key) });
    }
);

//Secret VRF key utility functions

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFSecretKey_nativeSerializeSecretKey(
        _env: JNIEnv,
        _vrf_secret_key: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<VRFSk>(&_env, _vrf_secret_key, "secretKeyPointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFSecretKey_nativeDeserializeSecretKey(
        _env: JNIEnv,
        _vrf_secret_key_class: JClass,
        _secret_key_bytes: jbyteArray,
    ) -> jobject {
        deserialize_to_jobject::<VRFSk>(
            &_env,
            _secret_key_bytes,
            None,
            None,
            "com/horizen/vrfnative/VRFSecretKey",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFSecretKey_nativeFreeSecretKey(
        _env: JNIEnv,
        _vrf_secret_key: JObject,
    ) {
        let secret_key_pointer = _env
            .get_field(_vrf_secret_key, "secretKeyPointer", "J")
            .expect("Cannot get secret key pointer.");

        let secret_key = secret_key_pointer.j().unwrap() as *mut SchnorrSk;

        if secret_key.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(secret_key) });
    }
);

//Schnorr signature utility functions

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeSerializeSignature(
        _env: JNIEnv,
        _schnorr_sig: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<SchnorrSig>(&_env, _schnorr_sig, "signaturePointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeDeserializeSignature(
        _env: JNIEnv,
        _class: JClass,
        _sig_bytes: jbyteArray,
        _check_sig: jboolean,
    ) -> jobject {
        deserialize_to_jobject::<SchnorrSig>(
            &_env,
            _sig_bytes,
            Some(_check_sig),
            None,
            "com/horizen/schnorrnative/SchnorrSignature",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeIsValidSignature(
        _env: JNIEnv,
        _sig: JObject,
    ) -> jboolean {
        let sig = _env
            .get_field(_sig, "signaturePointer", "J")
            .expect("Should be able to get field signaturePointer")
            .j()
            .unwrap() as *const SchnorrSig;

        if is_valid(read_raw_pointer(&_env, sig)) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSignature_nativefreeSignature(
        _env: JNIEnv,
        _class: JClass,
        _sig: *mut SchnorrSig,
    ) {
        if _sig.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_sig) });
    }
);

//Schnorr signature functions
ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeGenerate(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _class: JClass,
    ) -> jobject {
        let (pk, sk) = schnorr_generate_key();
        convert_schnorrnative_schnorr_key_pair(_env, pk, sk)
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeDeriveFromSeed(
        _env: JNIEnv,
        _class: JClass,
        _seed: jbyteArray,
    ) -> jobject {
        let ikm = _env.convert_byte_array(_seed).expect("Cannot read bytes");
        let (pk, sk) = schnorr_derive_key_from_seed(ikm.as_slice());
        convert_schnorrnative_schnorr_key_pair(_env, pk, sk)
    }
);

fn convert_schnorrnative_schnorr_key_pair(_env: JNIEnv, pk: SchnorrPk, sk: SchnorrSk) -> jobject {
    let secret_key_object = return_jobject(&_env, sk, "com/horizen/schnorrnative/SchnorrSecretKey");
    let public_key_object = return_jobject(&_env, pk, "com/horizen/schnorrnative/SchnorrPublicKey");

    let class = _env
        .find_class("com/horizen/schnorrnative/SchnorrKeyPair")
        .expect("Should be able to find SchnorrKeyPair class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/schnorrnative/SchnorrSecretKey;Lcom/horizen/schnorrnative/SchnorrPublicKey;)V",
        &[JValue::Object(secret_key_object), JValue::Object(public_key_object)]
    ).expect("Should be able to create new (SchnorrSecretKey, SchnorrPublicKey) object");

    *result
}

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeSignMessage(
        _env: JNIEnv,
        _schnorr_key_pair: JObject,
        _message: JObject,
    ) -> jobject {
        //Read sk
        let sk_object = _env
            .get_field(
                _schnorr_key_pair,
                "secretKey",
                "Lcom/horizen/schnorrnative/SchnorrSecretKey;",
            )
            .expect("Should be able to get field secretKey")
            .l()
            .unwrap();
        let secret_key = {
            let s = _env
                .get_field(sk_object, "secretKeyPointer", "J")
                .expect("Should be able to get field secretKeyPointer");

            read_raw_pointer(&_env, s.j().unwrap() as *const SchnorrSk)
        };

        //Read pk
        let pk_object = _env
            .get_field(
                _schnorr_key_pair,
                "publicKey",
                "Lcom/horizen/schnorrnative/SchnorrPublicKey;",
            )
            .expect("Should be able to get field publicKey")
            .l()
            .unwrap();

        let public_key = {
            let p = _env
                .get_field(pk_object, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(&_env, p.j().unwrap() as *const SchnorrPk)
        };

        //Read message
        let message = {
            let m = _env
                .get_field(_message, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, m.j().unwrap() as *const FieldElement)
        };

        //Sign message and return opaque pointer to sig
        let signature = match schnorr_sign(message, secret_key, public_key) {
            Ok(sig) => sig,
            Err(e) => {
                log!(format!("Unable to sign message: {:?}", e));
                return std::ptr::null::<jobject>() as jobject;
            } //CRYPTO_ERROR
        };

        return_jobject(
            &_env,
            signature,
            "com/horizen/schnorrnative/SchnorrSignature",
        )
        .into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeGetHash(
        _env: JNIEnv,
        _public_key: JObject,
    ) -> jobject {
        let pk = convert_public_key(&_env, _public_key);
        let pubkey = FieldBasedSchnorrPk(pk.into_projective());
        let pk_fe = pubkey.0.to_field_elements().unwrap();
        let mut h = FieldHash::init_constant_length(pk_fe.len(), None);
        pk_fe.into_iter().for_each(|fe| {
            h.update(fe);
        });
        let hash = h.finalize().unwrap();
        return_field_element(&_env, hash)
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifyKey(
        _env: JNIEnv,
        _public_key: JObject,
    ) -> jboolean {
        let pk = _env
            .get_field(_public_key, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer")
            .j()
            .unwrap() as *const SchnorrPk;

        if schnorr_verify_public_key(read_raw_pointer(&_env, pk)) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeGetPublicKey(
        _env: JNIEnv,
        _secret_key: JObject,
    ) -> jobject {
        let sk = _env
            .get_field(_secret_key, "secretKeyPointer", "J")
            .expect("Should be able to get field secretKeyPointer")
            .j()
            .unwrap() as *const SchnorrSk;

        let secret_key = read_raw_pointer(&_env, sk);

        let pk = schnorr_get_public_key(secret_key);

        return_jobject(&_env, pk, "com/horizen/schnorrnative/SchnorrPublicKey").into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifySignature(
        _env: JNIEnv,
        _public_key: JObject,
        _signature: JObject,
        _message: JObject,
    ) -> jboolean {
        //Read pk
        let public_key = {
            let p = _env
                .get_field(_public_key, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(&_env, p.j().unwrap() as *const SchnorrPk)
        };

        //Read message
        let message = {
            let m = _env
                .get_field(_message, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, m.j().unwrap() as *const FieldElement)
        };

        //Read sig
        let signature = {
            let sig = _env
                .get_field(_signature, "signaturePointer", "J")
                .expect("Should be able to get field signaturePointer");

            read_raw_pointer(&_env, sig.j().unwrap() as *const SchnorrSig)
        };

        //Verify sig
        match schnorr_verify_signature(message, public_key, signature) {
            Ok(result) => {
                if result {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
            Err(e) => {
                log!(format!("Signature verification error: {:?}", e));
                JNI_FALSE
            } //CRYPTO_ERROR
        }
    }
);

ffi_export!(
    fn Java_com_horizen_poseidonnative_PoseidonHash_nativeGetConstantLengthPoseidonHash(
        _env: JNIEnv,
        _class: JClass,
        _input_size: jint,
        _personalization: jobjectArray,
    ) -> jobject {
        //Read _personalization as array of FieldElement
        let personalization_len = _env
            .get_array_length(_personalization)
            .expect("Should be able to read personalization array size");
        let mut personalization = vec![];

        // Array can be empty
        for i in 0..personalization_len {
            let field_obj = _env
                .get_object_array_element(_personalization, i)
                .unwrap_or_else(|_| {
                    panic!(
                        "Should be able to read elem {} of the personalization array",
                        i
                    )
                });

            let field = {
                let f = _env
                    .get_field(field_obj, "fieldElementPointer", "J")
                    .expect("Should be able to get field fieldElementPointer");

                read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
            };

            personalization.push(field);
        }

        //Instantiate PoseidonHash
        let h = get_poseidon_hash_constant_length(
            _input_size as usize,
            if personalization.is_empty() {
                None
            } else {
                Some(personalization)
            },
        );

        //Return PoseidonHash instance
        return_jobject(&_env, h, "com/horizen/poseidonnative/PoseidonHash").into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_poseidonnative_PoseidonHash_nativeGetVariableLengthPoseidonHash(
        _env: JNIEnv,
        _class: JClass,
        _mod_rate: jboolean,
        _personalization: jobjectArray,
    ) -> jobject {
        //Read _personalization as array of FieldElement
        let personalization_len = _env
            .get_array_length(_personalization)
            .expect("Should be able to read personalization array size");
        let mut personalization = vec![];

        // Array can be empty
        for i in 0..personalization_len {
            let field_obj = _env
                .get_object_array_element(_personalization, i)
                .unwrap_or_else(|_| {
                    panic!(
                        "Should be able to read elem {} of the personalization array",
                        i
                    )
                });

            let field = {
                let f = _env
                    .get_field(field_obj, "fieldElementPointer", "J")
                    .expect("Should be able to get field fieldElementPointer");

                read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
            };

            personalization.push(field);
        }

        //Instantiate PoseidonHash
        let h = get_poseidon_hash_variable_length(
            _mod_rate == JNI_TRUE,
            if personalization.is_empty() {
                None
            } else {
                Some(personalization)
            },
        );

        //Return PoseidonHash instance
        return_jobject(&_env, h, "com/horizen/poseidonnative/PoseidonHash").into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_poseidonnative_PoseidonHash_nativeUpdate(
        _env: JNIEnv,
        _h: JObject,
        _input: JObject,
    ) {
        //Read PoseidonHash instance
        let digest = {
            let h = _env
                .get_field(_h, "poseidonHashPointer", "J")
                .expect("Should be able to get field poseidonHashPointer");

            read_mut_raw_pointer(&_env, h.j().unwrap() as *mut FieldHash)
        };

        //Read input
        let input = {
            let i = _env
                .get_field(_input, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
        };

        update_poseidon_hash(digest, input);
    }
);

ffi_export!(
    fn Java_com_horizen_poseidonnative_PoseidonHash_nativeFinalize(
        _env: JNIEnv,
        _h: JObject,
    ) -> jobject {
        //Read PoseidonHash instance
        let digest = {
            let h = _env
                .get_field(_h, "poseidonHashPointer", "J")
                .expect("Should be able to get field poseidonHashPointer");

            read_raw_pointer(&_env, h.j().unwrap() as *const FieldHash)
        };

        //Get digest
        let fe = match finalize_poseidon_hash(digest) {
            Ok(fe) => fe,
            Err(e) => {
                log!(format!("Unable to compute hash: {:?}", e));
                return std::ptr::null::<jobject>() as jobject;
            } //CRYPTO_ERROR
        };

        return_field_element(&_env, fe)
    }
);

ffi_export!(
    fn Java_com_horizen_poseidonnative_PoseidonHash_nativeReset(
        _env: JNIEnv,
        _h: JObject,
        _personalization: jobjectArray,
    ) {
        //Read PoseidonHash instance
        let digest = {
            let h = _env
                .get_field(_h, "poseidonHashPointer", "J")
                .expect("Should be able to get field poseidonHashPointer");

            read_mut_raw_pointer(&_env, h.j().unwrap() as *mut FieldHash)
        };

        //Read _personalization as array of FieldElement
        let personalization_len = _env
            .get_array_length(_personalization)
            .expect("Should be able to read personalization array size");
        let mut personalization = vec![];

        // Array can be empty
        for i in 0..personalization_len {
            let field_obj = _env
                .get_object_array_element(_personalization, i)
                .unwrap_or_else(|_| {
                    panic!(
                        "Should be able to read elem {} of the personalization array",
                        i
                    )
                });

            let field = {
                let f = _env
                    .get_field(field_obj, "fieldElementPointer", "J")
                    .expect("Should be able to get field fieldElementPointer");

                read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
            };

            personalization.push(field);
        }

        let personalization = if personalization.is_empty() {
            None
        } else {
            Some(personalization)
        };

        reset_poseidon_hash(digest, personalization)
    }
);

ffi_export!(
    fn Java_com_horizen_poseidonnative_PoseidonHash_nativeFreePoseidonHash(
        _env: JNIEnv,
        _h: JObject,
    ) {
        let h_pointer = _env
            .get_field(_h, "poseidonHashPointer", "J")
            .expect("Cannot get poseidonHashPointer");

        let h = h_pointer.j().unwrap() as *mut FieldHash;

        if h.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(h) });
    }
);

//Merkle tree functions

//////////// MERKLE PATH
ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeGetLength(
        _env: JNIEnv,
        _path: JObject,
    ) -> jint {
        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        path.get_length() as jint
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeVerify(
        _env: JNIEnv,
        _path: JObject,
        _leaf: JObject,
        _root: JObject,
    ) -> jboolean {
        let leaf = {
            let fe = _env
                .get_field(_leaf, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, fe.j().unwrap() as *const FieldElement)
        };

        let root = {
            let fe = _env
                .get_field(_root, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, fe.j().unwrap() as *const FieldElement)
        };

        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
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
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeApply(
        _env: JNIEnv,
        _path: JObject,
        _leaf: JObject,
    ) -> jobject {
        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        let leaf = {
            let fe = _env
                .get_field(_leaf, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, fe.j().unwrap() as *const FieldElement)
        };

        let root = get_root_from_path(path, leaf);

        return_field_element(&_env, root)
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeIsLeftmost(
        _env: JNIEnv,
        _path: JObject,
    ) -> jboolean {
        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        is_path_leftmost(path) as jboolean
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeIsRightmost(
        _env: JNIEnv,
        _path: JObject,
    ) -> jboolean {
        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        is_path_rightmost(path) as jboolean
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeAreRightLeavesEmpty(
        _env: JNIEnv,
        _path: JObject,
    ) -> jboolean {
        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        are_right_leaves_empty(path) as jboolean
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeLeafIndex(
        _env: JNIEnv,
        _path: JObject,
    ) -> jlong {
        let path = {
            let t = _env
                .get_field(_path, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        get_leaf_index_from_path(path) as jlong
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeSerialize(
        _env: JNIEnv,
        _path: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<GingerMHTPath>(&_env, _path, "merklePathPointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeDeserialize(
        _env: JNIEnv,
        _class: JClass,
        _path_bytes: jbyteArray,
        _checked: jboolean,
    ) -> jobject {
        deserialize_to_jobject::<GingerMHTPath>(
            &_env,
            _path_bytes,
            Some(_checked),
            None,
            "com/horizen/merkletreenative/MerklePath",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeEquals(
        _env: JNIEnv,
        _path_1: JObject,
        _path_2: JObject,
    ) -> jboolean {
        //Read path_1
        let path_1 = {
            let t = _env
                .get_field(_path_1, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        //Read path_1
        let path_2 = {
            let t = _env
                .get_field(_path_2, "merklePathPointer", "J")
                .expect("Should be able to get field merklePathPointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
        };

        match path_1 == path_2 {
            true => JNI_TRUE,
            false => JNI_FALSE,
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_MerklePath_nativeFreeMerklePath(
        _env: JNIEnv,
        _class: JClass,
        _path: *mut GingerMHTPath,
    ) {
        if _path.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_path) });
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeInit(
        _env: JNIEnv,
        _class: JClass,
        _height: jint,
        _processing_step: jlong,
    ) -> jobject {
        // Create new InMemoryAppendOnlyMerkleTree Rust side
        let mt = new_ginger_mht(_height as usize, _processing_step as usize);

        // Create and return new InMemoryAppendOnlyMerkleTree Java side
        match mt {
            Ok(mt) => return_jobject(
                &_env,
                mt,
                "com/horizen/merkletreenative/InMemoryAppendOnlyMerkleTree",
            )
            .into_inner(),
            Err(e) => {
                log!(format!(
                    "Unable to initialize InMemoryAppendOnlyMerkleTree: {:?}",
                    e
                ));
                std::ptr::null::<jobject>() as jobject
            } //CRYPTO_ERROR
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeAppend(
        _env: JNIEnv,
        _tree: JObject,
        _leaf: JObject,
    ) -> jboolean {
        let leaf = {
            let fe = _env
                .get_field(_leaf, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, fe.j().unwrap() as *const FieldElement)
        };

        let tree = {
            let t = _env
                .get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
                .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut GingerMHT)
        };

        match append_leaf_to_ginger_mht(tree, leaf) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                log!(format!(
                    "Unable to append leaf to InMemoryAppendOnlyMerkleTree: {:?}",
                    e
                ));
                JNI_FALSE
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeFinalize(
        _env: JNIEnv,
        _tree: JObject,
    ) -> jobject {
        let tree = {
            let t = _env
                .get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
                .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHT)
        };

        match finalize_ginger_mht(tree) {
            Ok(tree_copy) => return_jobject(
                &_env,
                tree_copy,
                "com/horizen/merkletreenative/InMemoryAppendOnlyMerkleTree",
            )
            .into_inner(),
            Err(e) => {
                log!(format!(
                    "Unable to finalize InMemoryAppendOnlyMerkleTree: {:?}",
                    e
                ));
                std::ptr::null::<jobject>() as jobject
            } //CRYPTO_ERROR
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeFinalizeInPlace(
        _env: JNIEnv,
        _tree: JObject,
    ) -> jboolean {
        let tree = {
            let t = _env
                .get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
                .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut GingerMHT)
        };

        match finalize_ginger_mht_in_place(tree) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                log!(format!(
                    "Unable to initialize InMemoryAppendOnlyMerkleTree in place: {:?}",
                    e
                ));
                JNI_FALSE
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeRoot(
        _env: JNIEnv,
        _tree: JObject,
    ) -> jobject {
        let tree = {
            let t = _env
                .get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
                .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHT)
        };

        match get_ginger_mht_root(tree) {
            Some(root) => return_field_element(&_env, root),
            None => {
                log!("Cannot return root. Have you finalized the tree ?");
                std::ptr::null::<jobject>() as jobject
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeGetMerklePath(
        _env: JNIEnv,
        _tree: JObject,
        _leaf_index: jlong,
    ) -> jobject {
        let tree = {
            let t = _env
                .get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
                .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHT)
        };

        match get_ginger_mht_path(tree, _leaf_index as u64) {
            Some(path) => {
                return_jobject(&_env, path, "com/horizen/merkletreenative/MerklePath").into_inner()
            }
            None => {
                log!("Cannot get path. Have you finalized the tree ?");
                std::ptr::null::<jobject>() as jobject
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeReset(
        _env: JNIEnv,
        _tree: JObject,
    ) {
        let tree = {
            let t = _env
                .get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
                .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut GingerMHT)
        };

        reset_ginger_mht(tree);
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemoryAppendOnlyMerkleTree_nativeFreeInMemoryAppendOnlyMerkleTree(
        _env: JNIEnv,
        _class: JClass,
        _tree: *mut GingerMHT,
    ) {
        if _tree.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_tree) });
    }
);

//VRF utility functions

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFProof_nativeSerializeProof(
        _env: JNIEnv,
        _proof: JObject,
        _compressed: jboolean,
    ) -> jbyteArray {
        serialize_from_jobject::<VRFProof>(&_env, _proof, "proofPointer", Some(_compressed))
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFProof_nativeDeserializeProof(
        _env: JNIEnv,
        _class: JClass,
        _proof_bytes: jbyteArray,
        _check_proof: jboolean,
        _compressed: jboolean,
    ) -> jobject {
        deserialize_to_jobject::<VRFProof>(
            &_env,
            _proof_bytes,
            Some(_check_proof),
            Some(_compressed),
            "com/horizen/vrfnative/VRFProof",
        )
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFProof_nativeIsValidVRFProof(
        _env: JNIEnv,
        _vrf_proof: JObject,
    ) -> jboolean {
        let proof = _env
            .get_field(_vrf_proof, "proofPointer", "J")
            .expect("Should be able to get field proofPointer")
            .j()
            .unwrap() as *const VRFProof;

        if is_valid(read_raw_pointer(&_env, proof)) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFProof_nativeFreeProof(
        _env: JNIEnv,
        _class: JClass,
        _proof: *mut VRFProof,
    ) {
        if _proof.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_proof) });
    }
);

//VRF functions
ffi_export!(
    fn Java_com_horizen_vrfnative_VRFKeyPair_nativeGenerate(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _class: JClass,
    ) -> jobject {
        let (pk, sk) = vrf_generate_key();
        convert_vrfnative_vrf_key_pair(_env, pk, sk)
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFKeyPair_nativeDeriveFromSeed(
        _env: JNIEnv,
        _class: JClass,
        _seed: jbyteArray,
    ) -> jobject {
        let ikm = _env.convert_byte_array(_seed).expect("Cannot read bytes");
        let (pk, sk) = vrf_derive_key_from_seed(ikm.as_slice());
        convert_vrfnative_vrf_key_pair(_env, pk, sk)
    }
);

fn convert_vrfnative_vrf_key_pair(_env: JNIEnv, pk: VRFPk, sk: VRFSk) -> jobject {
    let secret_key_object = return_jobject(&_env, sk, "com/horizen/vrfnative/VRFSecretKey");
    let public_key_object = return_jobject(&_env, pk, "com/horizen/vrfnative/VRFPublicKey");

    let class = _env
        .find_class("com/horizen/vrfnative/VRFKeyPair")
        .expect("Should be able to find VRFKeyPair class");

    let result = _env
        .new_object(
            class,
            "(Lcom/horizen/vrfnative/VRFSecretKey;Lcom/horizen/vrfnative/VRFPublicKey;)V",
            &[
                JValue::Object(secret_key_object),
                JValue::Object(public_key_object),
            ],
        )
        .expect("Should be able to create new (VRFSecretKey, VRFPublicKey) object");

    *result
}

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFKeyPair_nativeProve(
        _env: JNIEnv,
        _vrf_key_pair: JObject,
        _message: JObject,
    ) -> jobject {
        //Read sk
        let sk_object = _env
            .get_field(
                _vrf_key_pair,
                "secretKey",
                "Lcom/horizen/vrfnative/VRFSecretKey;",
            )
            .expect("Should be able to get field vrfKey")
            .l()
            .unwrap();

        let secret_key = {
            let s = _env
                .get_field(sk_object, "secretKeyPointer", "J")
                .expect("Should be able to get field secretKeyPointer");

            read_raw_pointer(&_env, s.j().unwrap() as *const VRFSk)
        };

        //Read pk
        let pk_object = _env
            .get_field(
                _vrf_key_pair,
                "publicKey",
                "Lcom/horizen/vrfnative/VRFPublicKey;",
            )
            .expect("Should be able to get field publicKey")
            .l()
            .unwrap();

        let public_key = {
            let p = _env
                .get_field(pk_object, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(&_env, p.j().unwrap() as *const VRFPk)
        };

        //Read message
        let message = {
            let m = _env
                .get_field(_message, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, m.j().unwrap() as *const FieldElement)
        };

        //Compute vrf proof
        let (proof, vrf_out) = match vrf_prove(message, secret_key, public_key) {
            Ok((proof, vrf_out)) => (
                return_jobject(&_env, proof, "com/horizen/vrfnative/VRFProof"),
                return_jobject(&_env, vrf_out, "com/horizen/librustsidechains/FieldElement"),
            ),
            Err(e) => {
                log!(format!("Unable to create VRF Proof: {:?}", e));
                return std::ptr::null::<jobject>() as jobject;
            } //CRYPTO_ERROR
        };

        //Create and return VRFProveResult instance
        let class = _env
            .find_class("com/horizen/vrfnative/VRFProveResult")
            .expect("Should be able to find VRFProveResult class");

        let result = _env
            .new_object(
                class,
                "(Lcom/horizen/vrfnative/VRFProof;Lcom/horizen/librustsidechains/FieldElement;)V",
                &[JValue::Object(proof), JValue::Object(vrf_out)],
            )
            .expect("Should be able to create new VRFProveResult:(VRFProof, FieldElement) object");

        *result
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetPublicKey(
        _env: JNIEnv,
        _vrf_secret_key: JObject,
    ) -> jobject {
        let sk = _env
            .get_field(_vrf_secret_key, "secretKeyPointer", "J")
            .expect("Should be able to get field secretKeyPointer")
            .j()
            .unwrap() as *const VRFSk;

        let secret_key = read_raw_pointer(&_env, sk);

        let pk = vrf_get_public_key(secret_key);
        return_jobject(&_env, pk, "com/horizen/vrfnative/VRFPublicKey").into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerifyKey(
        _env: JNIEnv,
        _vrf_public_key: JObject,
    ) -> jboolean {
        let pk = _env
            .get_field(_vrf_public_key, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer")
            .j()
            .unwrap() as *const VRFPk;

        if vrf_verify_public_key(read_raw_pointer(&_env, pk)) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_vrfnative_VRFPublicKey_nativeProofToHash(
        _env: JNIEnv,
        _vrf_public_key: JObject,
        _proof: JObject,
        _message: JObject,
    ) -> jobject {
        let public_key = {
            let p = _env
                .get_field(_vrf_public_key, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(&_env, p.j().unwrap() as *const VRFPk)
        };

        //Read message
        let message = {
            let m = _env
                .get_field(_message, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, m.j().unwrap() as *const FieldElement)
        };

        //Read proof
        let proof = {
            let p = _env
                .get_field(_proof, "proofPointer", "J")
                .expect("Should be able to get field proofPointer");

            read_raw_pointer(&_env, p.j().unwrap() as *const VRFProof)
        };

        //Verify vrf proof and get vrf output
        let vrf_out = match vrf_proof_to_hash(message, public_key, proof) {
            Ok(result) => result,
            Err(e) => {
                log!(format!("Unable to get VRF output from VRF proof: {:?}", e));
                return std::ptr::null::<jobject>() as jobject;
            } //CRYPTO_ERROR
        };

        //Return vrf output
        return_field_element(&_env, vrf_out)
    }
);

//Naive threshold signature proof functions

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSigProof_nativeGetConstant(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _class: JClass,
        _schnorr_pks_list: jobjectArray,
        _threshold: jlong,
    ) -> jobject {
        //Extract Schnorr pks
        let mut pks = vec![];

        let pks_list_size = _env
            .get_array_length(_schnorr_pks_list)
            .expect("Should be able to get schnorr_pks_list size");

        for i in 0..pks_list_size {
            let pk_object = _env
                .get_object_array_element(_schnorr_pks_list, i)
                .unwrap_or_else(|_| panic!("Should be able to get elem {} of schnorr_pks_list", i));

            let pk = _env
                .get_field(pk_object, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            pks.push(*read_raw_pointer(
                &_env,
                pk.j().unwrap() as *const SchnorrPk,
            ));
        }

        //Extract threshold
        let threshold = _threshold as u64;

        //Compute constant
        match compute_pks_threshold_hash(pks.as_slice(), threshold) {
            Ok(constant) => return_field_element(&_env, constant),
            Err(e) => {
                log!(e);
                std::ptr::null::<jobject>() as jobject
            } //CRYPTO_ERROR
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSigProof_nativeCreateMsgToSign(
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
        _custom_fields_list: jobjectArray,
    ) -> jobject {
        //Extract backward transfers
        let mut bt_list = vec![];

        let bt_list_size = _env
            .get_array_length(_bt_list)
            .expect("Should be able to get bt_list size");

        if bt_list_size > 0 {
            for i in 0..bt_list_size {
                let o = _env
                    .get_object_array_element(_bt_list, i)
                    .unwrap_or_else(|_| {
                        panic!("Should be able to get elem {} of bt_list array", i)
                    });

                let p = _env
                    .call_method(o, "getPublicKeyHash", "()[B", &[])
                    .expect("Should be able to call getPublicKeyHash method")
                    .l()
                    .unwrap()
                    .cast();

                let pk: [u8; 20] = _env
                    .convert_byte_array(p)
                    .expect("Should be able to convert to Rust byte array")
                    .try_into()
                    .expect("Should be able to write into fixed buffer of size 20");

                let a = _env
                    .call_method(o, "getAmount", "()J", &[])
                    .expect("Should be able to call getAmount method")
                    .j()
                    .unwrap() as u64;

                bt_list.push((a, pk));
            }
        }

        let bt_list = bt_list
            .into_iter()
            .map(|bt_raw| BackwardTransfer {
                pk_dest: bt_raw.1,
                amount: bt_raw.0,
            })
            .collect::<Vec<_>>();

        let sc_id = {
            let f = _env
                .get_field(_sc_id, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        let end_cumulative_sc_tx_comm_tree_root = {
            let f = _env
                .get_field(
                    _end_cumulative_sc_tx_comm_tree_root,
                    "fieldElementPointer",
                    "J",
                )
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        // Read custom fields if they are present
        let mut custom_fields_list = None;

        let custom_fields_list_size = _env
            .get_array_length(_custom_fields_list)
            .expect("Should be able to get custom_fields_list size");

        if custom_fields_list_size > 0 {
            let mut custom_fields = Vec::with_capacity(custom_fields_list_size as usize);

            for i in 0..custom_fields_list_size {
                let field_obj = _env
                    .get_object_array_element(_custom_fields_list, i)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Should be able to read elem {} of the personalization array",
                            i
                        )
                    });

                let field = {
                    let f = _env
                        .get_field(field_obj, "fieldElementPointer", "J")
                        .expect("Should be able to get field fieldElementPointer");

                    read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
                };

                custom_fields.push(*field);
            }
            custom_fields_list = Some(custom_fields);
        }

        //Compute message to sign:
        let msg = match compute_msg_to_sign(
            sc_id,
            _epoch_number as u32,
            end_cumulative_sc_tx_comm_tree_root,
            _btr_fee as u64,
            _ft_min_amount as u64,
            bt_list,
            custom_fields_list,
        ) {
            Ok((_, msg)) => msg,
            Err(e) => {
                log!(e);
                return std::ptr::null::<jobject>() as jobject;
            } //CRYPTO_ERROR
        };

        //Return msg
        return_field_element(&_env, msg)
    }
);

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
        _ => unreachable!(),
    }
}

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGenerateDLogKeys(
        _env: JNIEnv,
        _class: JClass,
        _proving_system: JObject,
        _segment_size: jint,
    ) -> jboolean {
        // Get proving system type
        let proving_system = get_proving_system_type(&_env, _proving_system);

        // Generate DLOG keypair
        match init_dlog_keys(proving_system, _segment_size as usize) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                log!(format!("DLOG keys initialization failed: {:?}", e));
                JNI_FALSE
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeCheckProofVkSize(
        _env: JNIEnv,
        _class: JClass,
        _zk: jboolean,
        _supported_segment_size: jint,
        _max_proof_plus_vk_size: jint,
        _verification_key_path: JString,
    ) -> jboolean {
        // Read vk from file

        //Extract vk path
        let vk_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        // Deserialize vk
        let vk_path = vk_path.to_str().unwrap();
        let vk: ZendooVerifierKey =
            match read_from_file(Path::new(vk_path), Some(false), Some(true)) {
                Ok(vk) => vk,
                Err(e) => {
                    log!(format!(
                        "Unable to read vk at {:?}: {:?}. Semantic checks: {}, Compressed: {}",
                        vk_path, e, false, true
                    ));
                    return JNI_FALSE;
                }
            };

        // Read zk value
        let zk = _zk == JNI_TRUE;

        // Get ps type from vk
        let ps_type = vk.get_proving_system_type();

        // Get index info from vk
        let index_info = match vk {
            ZendooVerifierKey::CoboundaryMarlin(cob_marlin_vk) => cob_marlin_vk.index_info,
            ZendooVerifierKey::Darlin(darlin_vk) => darlin_vk.index_info,
        };

        // Perform check
        let (proof_size, vk_size) =
            compute_proof_vk_size(_supported_segment_size as usize, index_info, zk, ps_type);

        if proof_size + vk_size <= _max_proof_plus_vk_size as usize {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSigProof_nativeSetup(
        _env: JNIEnv,
        _class: JClass,
        _proving_system: JObject,
        _max_pks: jlong,
        _num_custom_fields: jint,
        _segment_size: JObject,
        _proving_key_path: JString,
        _verification_key_path: JString,
        _zk: jboolean,
        _max_proof_plus_vk_size: jint,
        _compress_pk: jboolean,
        _compress_vk: jboolean,
    ) -> jboolean {
        // Get proving system type
        let proving_system = get_proving_system_type(&_env, _proving_system);

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&_env, _segment_size).map(|integer_object| {
                _env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        // Read paths
        let proving_key_path = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        let verification_key_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        let max_pks = _max_pks as usize;

        let circ =
            NaiveThresholdSignature::get_instance_for_setup(max_pks, _num_custom_fields as usize);

        // Read zk value
        let zk = _zk == JNI_TRUE;

        // Generate snark keypair
        match generate_circuit_keypair(
            circ,
            proving_system,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            Path::new(verification_key_path.to_str().unwrap()),
            _max_proof_plus_vk_size as usize,
            zk,
            Some(_compress_pk == JNI_TRUE),
            Some(_compress_vk == JNI_TRUE),
        ) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                log!(format!("(Pk, Vk) generation failed: {:?}", e));
                JNI_FALSE
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSignatureWKeyRotation_nativeGetConstant(
        _env: JNIEnv,
        _class: JClass,
        _keys_root_hash: JObject,
        _threshold: jlong,
    ) -> jobject {
        let keys_root_hash = convert_field_element(&_env, _keys_root_hash);
        let threshold_field = FieldElement::from(_threshold as u64);

        match FieldHash::init_constant_length(2, None)
            .update(*keys_root_hash)
            .update(threshold_field)
            .finalize()
        {
            Err(e) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    format!("unable to compute constant: {:?}", e).as_str(),
                    JObject::null().into_inner()
                );
            }
            Ok(hash) => return_field_element(&_env, hash),
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSignatureWKeyRotation_nativeSetup(
        _env: JNIEnv,
        _class: JClass,
        _proving_system: JObject,
        _max_pks: jlong,
        _num_custom_fields: jint,
        _segment_size: JObject,
        _proving_key_path: JString,
        _verification_key_path: JString,
        _zk: jboolean,
        _max_proof_plus_vk_size: jint,
        _compress_pk: jboolean,
        _compress_vk: jboolean,
    ) -> jboolean {
        // Get proving system type
        let proving_system = get_proving_system_type(&_env, _proving_system);

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&_env, _segment_size).map(|integer_object| {
                _env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        // Read paths
        let proving_key_path = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        let verification_key_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        let max_pks = _max_pks as usize;

        let circ = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(
            max_pks,
            _num_custom_fields as u32,
        );

        // Read zk value
        let zk = _zk == JNI_TRUE;

        // Generate snark keypair
        match generate_circuit_keypair(
            circ,
            proving_system,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            Path::new(verification_key_path.to_str().unwrap()),
            _max_proof_plus_vk_size as usize,
            zk,
            Some(_compress_pk == JNI_TRUE),
            Some(_compress_vk == JNI_TRUE),
        ) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    format!("(Pk, Vk) generation failed: {:?}", e).as_str(),
                    JNI_FALSE
                );
            }
        }
    }
);

fn get_proving_system_type_as_jint(_env: &JNIEnv, ps: ProvingSystem) -> jint {
    match ps {
        ProvingSystem::Undefined => 0_i32,
        ProvingSystem::Darlin => 1_i32,
        ProvingSystem::CoboundaryMarlin => 2_i32,
    }
}

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetProverKeyProvingSystemType(
        _env: JNIEnv,
        _class: JClass,
        _proving_key_path: JString,
    ) -> jint {
        // Read paths
        let proving_key_path_j = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        let proving_key_path = proving_key_path_j.to_str().unwrap();
        match read_from_file::<ProvingSystem>(Path::new(proving_key_path), None, None) {
            Ok(ps) => get_proving_system_type_as_jint(&_env, ps),
            Err(e) => {
                log!(format!(
                    "Unable to read proving system type from pk at {:?}: {:?}",
                    proving_key_path, e
                ));
                1_i32
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetVerifierKeyProvingSystemType(
        _env: JNIEnv,
        _class: JClass,
        _verifier_key_path: JString,
    ) -> jint {
        // Read paths
        let verifier_key_path_j = _env
            .get_string(_verifier_key_path)
            .expect("Should be able to read jstring as Rust String");

        let verifier_key_path = verifier_key_path_j.to_str().unwrap();
        match read_from_file::<ProvingSystem>(Path::new(verifier_key_path), None, None) {
            Ok(ps) => get_proving_system_type_as_jint(&_env, ps),
            Err(e) => {
                log!(format!(
                    "Unable to read proving system type from vk at {:?}: {:?}",
                    verifier_key_path, e
                ));
                1_i32
            }
        }
    }
);

fn parse_naive_threshold_sig_circuit_data<'a>(
    _env: &'a JNIEnv,
    _bt_list: jobjectArray,
    _sc_id: JObject,
    _end_cumulative_sc_tx_comm_tree_root: JObject,
    _schnorr_sigs_list: jobjectArray,
    _schnorr_pks_list: jobjectArray,
    _custom_fields_list: jobjectArray,
) -> (
    Vec<SchnorrPk>,
    Vec<Option<SchnorrSig>>,
    &'a FieldElement,
    &'a FieldElement,
    Vec<BackwardTransfer>,
    Option<Vec<FieldElement>>,
) {
    // Extract backward transfers
    let bt_list = extract_backward_transfers(_env, _bt_list);

    //Extract Schnorr signatures and the corresponding Schnorr pks
    let sigs: Vec<_> = JObjectArrayIter::new(_env, _schnorr_sigs_list)
        .map(|s| convert_option_signature(_env, s))
        .collect();
    let pks: Vec<_> = JObjectArrayIter::new(_env, _schnorr_pks_list)
        .map(|p| *convert_public_key(_env, p))
        .collect();

    assert_eq!(sigs.len(), pks.len());

    let sc_id = convert_field_element(_env, _sc_id);
    let end_cumulative_sc_tx_comm_tree_root =
        convert_field_element(_env, _end_cumulative_sc_tx_comm_tree_root);

    // Read custom fields if they are present
    let custom_fields_list = extract_custom_fields(_env, _custom_fields_list);
    (
        pks,
        sigs,
        sc_id,
        end_cumulative_sc_tx_comm_tree_root,
        bt_list,
        custom_fields_list,
    )
}

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSigProof_nativeDebugCircuit(
        _env: JNIEnv,
        _class: JClass,
        _bt_list: jobjectArray,
        _sc_id: JObject,
        _epoch_number: jint,
        _end_cumulative_sc_tx_comm_tree_root: JObject,
        _btr_fee: jlong,
        _ft_min_amount: jlong,
        _schnorr_sigs_list: jobjectArray,
        _schnorr_pks_list: jobjectArray,
        _threshold: jlong,
        _custom_fields_list: jobjectArray,
    ) -> jobject {
        let (pks, sigs, sc_id, end_cumulative_sc_tx_comm_tree_root, bt_list, custom_fields_list) =
            parse_naive_threshold_sig_circuit_data(
                &_env,
                _bt_list,
                _sc_id,
                _end_cumulative_sc_tx_comm_tree_root,
                _schnorr_sigs_list,
                _schnorr_pks_list,
                _custom_fields_list,
            );

        //create proof
        match debug_naive_threshold_sig_circuit(
            pks.as_slice(),
            sigs,
            sc_id,
            _epoch_number as u32,
            end_cumulative_sc_tx_comm_tree_root,
            _btr_fee as u64,
            _ft_min_amount as u64,
            bt_list,
            _threshold as u64,
            custom_fields_list,
        ) {
            Ok(failing_constraint) => {
                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                if let Some(failing_constraint) = failing_constraint {
                    let j_str = *_env
                        .new_string(failing_constraint)
                        .expect("Should be able to build Java String from Rust String");

                    _env.call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(j_str)],
                    )
                    .expect("Should be able to create new Optional from String")
                } else {
                    _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                        .expect("Should be able to create new value for Optional.empty()")
                }
                .l()
                .unwrap()
                .into_inner()
            }
            Err(e) => {
                log!(format!("Error debugging circuit: {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_schnorrnative_ValidatorKeysUpdatesList_nativeKeysRootHash(
        _env: JNIEnv,
        _class: JClass,
        _schnorr_signing_keys_list: jobjectArray,
        _schnorr_master_keys_list: jobjectArray,
        _max_pks: jlong,
    ) -> jobject {
        let signing_keys: Vec<_> = JObjectArrayIter::new(&_env, _schnorr_signing_keys_list)
            .map(|s| {
                let pk = *convert_public_key(&_env, s);
                FieldBasedSchnorrPk(pk.into_projective())
            })
            .collect();
        let master_keys: Vec<_> = JObjectArrayIter::new(&_env, _schnorr_master_keys_list)
            .map(|m| {
                let pk = *convert_public_key(&_env, m);
                FieldBasedSchnorrPk(pk.into_projective())
            })
            .collect();
        if signing_keys.len() != master_keys.len() {
            throw!(
                &_env,
                "java/lang/Exception",
                "signing_keys.len != master_keys.len",
                JObject::null().into_inner()
            );
        }

        let max_pks = _max_pks as usize;

        let v = ValidatorKeysUpdates::new(
            signing_keys.clone(),
            master_keys.clone(),
            signing_keys,
            master_keys,
            vec![Some(NULL_CONST.null_sig); max_pks],
            vec![Some(NULL_CONST.null_sig); max_pks],
            vec![Some(NULL_CONST.null_sig); max_pks],
            vec![Some(NULL_CONST.null_sig); max_pks],
            max_pks,
        );
        match v.get_curr_validators_keys_root() {
            Err(e) => throw!(
                &_env,
                "java/lang/Exception",
                format!("Cannot compute current validators key root: {:?}", e).as_str(),
                JObject::null().into_inner()
            ),
            Ok(keys_root) => return_field_element(&_env, keys_root),
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSignatureWKeyRotation_nativeDebugCircuit(
        _env: JNIEnv,
        _class: JClass,
        _keys_signatures_list: JObject,
        _withdrawal_certificate: JObject,
        _prev_withdrawal_certificate: JObject,
        _cert_signatures: jobjectArray,
        _max_pks: jlong,
        _threshold: jlong,
        _genesis_key_root_hash: JObject,
    ) -> jobject {
        let _schnorr_signing_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "signingKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );
        let _schnorr_master_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "masterKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );
        let _schnorr_updated_signing_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedSigningKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );
        let _schnorr_updated_master_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedMasterKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );

        let _updated_signing_keys_sk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedSigningKeysSkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );
        let _updated_signing_keys_mk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedSigningKeysMkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );
        let _updated_master_keys_sk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedMasterKeysSkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );
        let _updated_master_keys_mk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedMasterKeysMkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );

        let withdrawal_certificate = parse_wcert(_env, _withdrawal_certificate);
        let prev_withdrawal_certificate =
            cast_joption_to_rust_option(&_env, _prev_withdrawal_certificate)
                .map(|cert_object| parse_wcert(_env, cert_object));
        let genesis_key_root_hash = convert_field_element(&_env, _genesis_key_root_hash);

        let signing_keys = extract_public_key(&_env, _schnorr_signing_keys_list);
        let master_keys = extract_public_key(&_env, _schnorr_master_keys_list);
        let updated_signing_keys = extract_public_key(&_env, _schnorr_updated_signing_keys_list);
        let updated_master_keys = extract_public_key(&_env, _schnorr_updated_master_keys_list);

        let updated_signing_keys_sk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_signing_keys_sk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let updated_signing_keys_mk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_signing_keys_mk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let updated_master_keys_sk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_master_keys_sk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let updated_master_keys_mk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_master_keys_mk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let sigs: Vec<_> = JObjectArrayIter::new(&_env, _cert_signatures)
            .map(|s| convert_option_signature(&_env, s))
            .collect();

        let validator_keys_updates = ValidatorKeysUpdates::new(
            signing_keys,
            master_keys,
            updated_signing_keys,
            updated_master_keys,
            updated_signing_keys_sk_signatures,
            updated_signing_keys_mk_signatures,
            updated_master_keys_sk_signatures,
            updated_master_keys_mk_signatures,
            _max_pks as usize,
        );

        //create proof
        match debug_naive_threshold_sig_w_key_rotation_circuit(
            validator_keys_updates,
            sigs,
            withdrawal_certificate,
            prev_withdrawal_certificate,
            _threshold as u64,
            genesis_key_root_hash,
        ) {
            Ok(failing_constraint) => {
                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                if let Some(failing_constraint) = failing_constraint {
                    let j_str = *_env
                        .new_string(failing_constraint)
                        .expect("Should be able to build Java String from Rust String");

                    _env.call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(j_str)],
                    )
                    .expect("Should be able to create new Optional from String")
                } else {
                    _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                        .expect("Should be able to create new value for Optional.empty()")
                }
                .l()
                .unwrap()
                .into_inner()
            }
            Err(e) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    format!("Error debugging circuit: {:?}", e).as_str(),
                    JObject::null().into_inner()
                );
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSigProof_nativeCreateProof(
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
        _schnorr_pks_list: jobjectArray,
        _threshold: jlong,
        _custom_fields_list: jobjectArray,
        _segment_size: JObject,
        _proving_key_path: JString,
        _check_proving_key: jboolean,
        _zk: jboolean,
        _compressed_pk: jboolean,
        _compress_proof: jboolean,
    ) -> jobject {
        let (pks, sigs, sc_id, end_cumulative_sc_tx_comm_tree_root, bt_list, custom_fields_list) =
            parse_naive_threshold_sig_circuit_data(
                &_env,
                _bt_list,
                _sc_id,
                _end_cumulative_sc_tx_comm_tree_root,
                _schnorr_sigs_list,
                _schnorr_pks_list,
                _custom_fields_list,
            );

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&_env, _segment_size).map(|integer_object| {
                _env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        //Extract params_path str
        let proving_key_path = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        //create proof
        match create_naive_threshold_sig_proof(
            pks.as_slice(),
            sigs,
            sc_id,
            _epoch_number as u32,
            end_cumulative_sc_tx_comm_tree_root,
            _btr_fee as u64,
            _ft_min_amount as u64,
            bt_list,
            _threshold as u64,
            custom_fields_list,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            _check_proving_key == JNI_TRUE,
            _zk == JNI_TRUE,
            _compressed_pk == JNI_TRUE,
            _compress_proof == JNI_TRUE,
        ) {
            Ok((proof, quality)) => {
                //Return proof serialized
                let proof_serialized = _env
                    .byte_array_from_slice(proof.as_slice())
                    .expect("Should be able to convert Rust slice into jbytearray");

                //Create new CreateProofResult object
                let proof_result_class = _env
                    .find_class("com/horizen/certnative/CreateProofResult")
                    .expect("Should be able to find CreateProofResult class");

                let result = _env
                    .new_object(
                        proof_result_class,
                        "([BJ)V",
                        &[
                            JValue::Object(JObject::from(proof_serialized)),
                            JValue::Long(quality as i64),
                        ],
                    )
                    .expect("Should be able to create new CreateProofResult:(byte[], long) object");

                *result
            }
            Err(e) => {
                log!(format!(
                    "Error creating NaiveThresholdSignature proof {:?}",
                    e
                ));
                JObject::null().into_inner()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSignatureWKeyRotation_nativeCreateProof(
        _env: JNIEnv,
        _class: JClass,
        _keys_signatures_list: JObject,
        _withdrawal_certificate: JObject,
        _prev_withdrawal_certificate: JObject,
        _cert_signatures: jobjectArray,
        _max_pks: jlong,
        _threshold: jlong,
        _genesis_key_root_hash: JObject,
        _supported_degree: JObject,
        _proving_key_path: JString,
        _enforce_membership: jboolean,
        _zk: jboolean,
        _compressed_pk: jboolean,
        _compress_proof: jboolean,
    ) -> jobject {
        let _schnorr_signing_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "signingKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );
        let _schnorr_master_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "masterKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );
        let _schnorr_updated_signing_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedSigningKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );
        let _schnorr_updated_master_keys_list = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedMasterKeys",
            "com/horizen/schnorrnative/SchnorrPublicKey",
        );

        let _updated_signing_keys_sk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedSigningKeysSkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );
        let _updated_signing_keys_mk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedSigningKeysMkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );
        let _updated_master_keys_sk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedMasterKeysSkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );
        let _updated_master_keys_mk_signatures = parse_jobject_array_from_jobject(
            &_env,
            _keys_signatures_list,
            "updatedMasterKeysMkSignatures",
            "com/horizen/schnorrnative/SchnorrSignature",
        );

        let withdrawal_certificate = parse_wcert(_env, _withdrawal_certificate);
        let prev_withdrawal_certificate =
            cast_joption_to_rust_option(&_env, _prev_withdrawal_certificate)
                .map(|cert_object| parse_wcert(_env, cert_object));
        let genesis_key_root_hash = convert_field_element(&_env, _genesis_key_root_hash);

        let signing_keys = extract_public_key(&_env, _schnorr_signing_keys_list);
        let master_keys = extract_public_key(&_env, _schnorr_master_keys_list);
        let updated_signing_keys = extract_public_key(&_env, _schnorr_updated_signing_keys_list);
        let updated_master_keys = extract_public_key(&_env, _schnorr_updated_master_keys_list);

        let updated_signing_keys_sk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_signing_keys_sk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let updated_signing_keys_mk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_signing_keys_mk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let updated_master_keys_sk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_master_keys_sk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let updated_master_keys_mk_signatures: Vec<_> =
            JObjectArrayIter::new(&_env, _updated_master_keys_mk_signatures)
                .map(|s| convert_option_signature(&_env, s))
                .collect();
        let sigs: Vec<_> = JObjectArrayIter::new(&_env, _cert_signatures)
            .map(|s| convert_option_signature(&_env, s))
            .collect();

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&_env, _supported_degree).map(|integer_object| {
                _env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        //Extract params_path str
        let proving_key_path = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        let validator_keys_updates = ValidatorKeysUpdates::new(
            signing_keys,
            master_keys,
            updated_signing_keys,
            updated_master_keys,
            updated_signing_keys_sk_signatures,
            updated_signing_keys_mk_signatures,
            updated_master_keys_sk_signatures,
            updated_master_keys_mk_signatures,
            _max_pks as usize,
        );

        //create proof
        match create_naive_threshold_sig_w_key_rotation_proof(
            validator_keys_updates,
            sigs,
            withdrawal_certificate,
            prev_withdrawal_certificate,
            _threshold as u64,
            genesis_key_root_hash,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            _enforce_membership == JNI_TRUE,
            _zk == JNI_TRUE,
            _compressed_pk == JNI_TRUE,
            _compress_proof == JNI_TRUE,
        ) {
            Ok((proof, quality)) => {
                //Return proof serialized
                let proof_serialized = _env
                    .byte_array_from_slice(proof.as_slice())
                    .expect("Should be able to convert Rust slice into jbytearray");

                //Create new CreateProofResult object
                let proof_result_class = _env
                    .find_class("com/horizen/certnative/CreateProofResult")
                    .expect("Should be able to find CreateProofResult class");

                let result = _env
                    .new_object(
                        proof_result_class,
                        "([BJ)V",
                        &[
                            JValue::Object(JObject::from(proof_serialized)),
                            JValue::Long(quality as i64),
                        ],
                    )
                    .expect("Should be able to create new CreateProofResult:(byte[], long) object");
                *result
            }
            Err(e) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    format!("Cannot create proof: {:?}", e).as_str(),
                    JObject::null().into_inner()
                );
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetProofProvingSystemType(
        _env: JNIEnv,
        _class: JClass,
        _proof: jbyteArray,
    ) -> jint {
        //Extract proof
        let proof_bytes = _env
            .convert_byte_array(_proof)
            .expect("Should be able to convert to Rust byte array");

        match deserialize_from_buffer::<ProvingSystem>(&proof_bytes[..1], None, None) {
            Ok(ps) => get_proving_system_type_as_jint(&_env, ps),
            Err(e) => {
                log!(format!(
                    "Unable to read proving system type from proof: {:?}",
                    e
                ));
                1_i32
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSigProof_nativeVerifyProof(
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
        _custom_fields_list: jobjectArray,
        _sc_proof_bytes: jbyteArray,
        _check_proof: jboolean,
        _compressed_proof: jboolean,
        _verification_key_path: JString,
        _check_vk: jboolean,
        _compressed_vk: jboolean,
    ) -> jboolean {
        let bt_list = extract_backward_transfers(&_env, _bt_list);
        let sc_id = convert_field_element(&_env, _sc_id);
        let end_cumulative_sc_tx_comm_tree_root =
            convert_field_element(&_env, _end_cumulative_sc_tx_comm_tree_root);
        let constant = convert_field_element(&_env, _constant);
        let custom_fields_list =
            extract_custom_fields(&_env, _custom_fields_list).unwrap_or_default();

        //Extract proof
        let proof_bytes = _env
            .convert_byte_array(_sc_proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        //Extract vk path
        let vk_path = _env
            .get_string(_verification_key_path)
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
            custom_fields_list,
            proof_bytes,
            _check_proof == JNI_TRUE,
            _compressed_proof == JNI_TRUE,
            Path::new(vk_path.to_str().unwrap()),
            _check_vk == JNI_TRUE,
            _compressed_vk == JNI_TRUE,
        ) {
            Ok(result) => {
                if result {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
            Err(e) => {
                log!(format!(
                    "Unable to verify NaiveThresholdSignature proof: {:?}",
                    e
                ));
                JNI_FALSE
            } // CRYPTO_ERROR or IO_ERROR
        }
    }
);

ffi_export!(
    fn Java_com_horizen_certnative_NaiveThresholdSignatureWKeyRotation_nativeVerifyProof(
        _env: JNIEnv,
        // this is the class that owns our
        // static method. Not going to be
        // used, but still needs to have
        // an argument slot
        _class: JClass,
        _cert: JObject,
        _prev_cert: JObject,
        _constant: JObject,
        _sc_proof_bytes: jbyteArray,
        _check_proof: jboolean,
        _compressed_proof: jboolean,
        _verification_key_path: JString,
        _check_vk: jboolean,
        _compressed_vk: jboolean,
    ) -> jboolean {
        let (
            sc_id,
            epoch_number,
            bt_list,
            quality,
            mcb_sc_txs_com,
            ft_min_amount,
            btr_min_fee,
            custom_fields,
        ) = parse_wcert_fields(_env, _cert);
        let withdrawal_certificate = WithdrawalCertificateData::new(
            sc_id,
            epoch_number,
            bt_list.clone(),
            quality,
            mcb_sc_txs_com,
            ft_min_amount,
            btr_min_fee,
            custom_fields,
        );
        let prev_withdrawal_certificate =
            cast_joption_to_rust_option(&_env, _prev_cert).map(|_cert| parse_wcert(_env, _cert));
        let constant = convert_field_element(&_env, _constant);
        //Extract proof
        let proof_bytes = _env
            .convert_byte_array(_sc_proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        //Extract vk path
        let vk_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        //Verify proof
        match verify_naive_threshold_sig_w_key_rotation_proof(
            withdrawal_certificate,
            prev_withdrawal_certificate,
            bt_list,
            constant,
            proof_bytes,
            _check_proof == JNI_TRUE,
            _compressed_proof == JNI_TRUE,
            Path::new(vk_path.to_str().unwrap()),
            _check_vk == JNI_TRUE,
            _compressed_vk == JNI_TRUE,
        ) {
            Ok(result) => {
                if result {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
            Err(e) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    format!("Cannot verify proof: {:?}", e).as_str(),
                    JNI_FALSE
                );
            } // CRYPTO_ERROR or IO_ERROR
        }
    }
);

///////// COMMITMENT TREE
ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeInit(
        _env: JNIEnv,
        _class: JClass,
    ) -> jobject {
        // Create new CommitmentTree Rust side
        let commitment_tree = CommitmentTree::create();

        // Create and return new CommitmentTree Java side
        let commitment_tree_ptr: jlong = Box::into_raw(Box::new(commitment_tree)) as i64;

        _env.new_object(_class, "(J)V", &[JValue::Long(commitment_tree_ptr)])
            .expect("Should be able to create new CommitmentTree object")
            .into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeFreeCommitmentTree(
        _env: JNIEnv,
        _class: JClass,
        _commitment_tree: *mut CommitmentTree,
    ) {
        if _commitment_tree.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_commitment_tree) });
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeAddScCr(
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
        _constant_nullable: jbyteArray, // can be null if there is no constant
        _cert_verification_key: jbyteArray,
        _csw_verification_key_nullable: jbyteArray, // can be null if there is no key for CSWs
    ) -> jboolean {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            match FieldElement::deserialize(sc_id_bytes.as_slice()) {
                Ok(fe) => fe,
                Err(e) => {
                    log!(format!("ScId deserialization failed: {:?}", e));
                    return JNI_FALSE;
                }
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
        let custom_field_size = _env
            .get_array_length(_custom_field_elements_configs)
            .expect("Should be able to get _custom_field_elements_configs size");
        if custom_field_size > 0 {
            for i in 0..custom_field_size {
                let custom_field_config = _env
                    .get_object_array_element(_custom_field_elements_configs, i)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Should be able to get elem {} of custom_field_elements_configs array",
                            i
                        )
                    });

                let bits = _env
                    .call_method(custom_field_config, "getBits", "()B", &[])
                    .expect("Should be able to call getBitVectorSizeBits method")
                    .b()
                    .unwrap() as u8;

                custom_field_elements_configs.push(bits);
            }
        }
        let custom_field_elements_configs_opt = if !custom_field_elements_configs.is_empty() {
            Some(custom_field_elements_configs.as_slice())
        } else {
            None
        };

        let mut custom_bitvector_elements_configs = vec![];
        let custom_bitvector_elements_size = _env
            .get_array_length(_custom_bitvector_elements_configs)
            .expect("Should be able to get _custom_field_elements_configs size");
        if custom_bitvector_elements_size > 0 {
            for i in 0..custom_bitvector_elements_size {
                let custom_bitvector_element_config = _env.get_object_array_element(_custom_bitvector_elements_configs, i)
                .unwrap_or_else(|_| panic!("Should be able to get elem {} of custom_bitvector_elements_configs array", i));

                let bit_vector_size_bits = _env
                    .call_method(
                        custom_bitvector_element_config,
                        "getBitVectorSizeBits",
                        "()I",
                        &[],
                    )
                    .expect("Should be able to call getBitVectorSizeBits method")
                    .i()
                    .unwrap() as u32;

                let max_compressed_byte_size = _env
                    .call_method(
                        custom_bitvector_element_config,
                        "getMaxCompressedByteSize",
                        "()I",
                        &[],
                    )
                    .expect("Should be able to call getMaxCompressedByteSize method")
                    .i()
                    .unwrap() as u32;

                custom_bitvector_elements_configs.push(BitVectorElementsConfig {
                    bit_vector_size_bits,
                    max_compressed_byte_size,
                });
            }
        }

        let custom_bitvector_elements_configs_opt = if !custom_bitvector_elements_configs.is_empty()
        {
            Some(custom_bitvector_elements_configs.as_slice())
        } else {
            None
        };

        let btr_fee = _btr_fee as u64;

        let ft_min_amount = _ft_min_amount as u64;

        let custom_creation_data = _env
            .convert_byte_array(_custom_creation_data)
            .expect("Should be able to convert to Rust array");

        let custom_creation_data_opt = if !custom_creation_data.is_empty() {
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
                Err(e) => {
                    log!(format!("constant deserialization failed: {:?}", e));
                    return JNI_FALSE;
                }
            }
        };

        let cert_verification_key = _env
            .convert_byte_array(_cert_verification_key)
            .expect("Should be able to convert to Rust byte array");

        let mut _csw_verification_key_nullable_vec;
        let csw_verification_key_opt = if _csw_verification_key_nullable.is_null() {
            Option::None
        } else {
            _csw_verification_key_nullable_vec = _env
                .convert_byte_array(_csw_verification_key_nullable)
                .expect("Should be able to convert to Rust byte array");
            Some(_csw_verification_key_nullable_vec.as_slice())
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        if commitment_tree.add_scc(
            &sc_id,
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
            csw_verification_key_opt,
        ) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeAddFwt(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _amount: jlong,
        _pub_key: jbyteArray,
        _mc_return_address: jbyteArray,
        _tx_hash: jbyteArray,
        _out_idx: jint,
    ) -> jboolean {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
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
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        if commitment_tree.add_fwt(
            &sc_id,
            amount,
            &pub_key,
            &mc_return_address,
            &tx_hash,
            out_idx,
        ) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetFwtLeaves(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        match commitment_tree.get_fwt_leaves(&sc_id) {
            Some(leaves) => {
                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let initial_element = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(0)])
                    .expect("Should be able to create new long for FieldElement");

                let leaf_fe_array = _env
                    .new_object_array(leaves.len() as i32, field_class, initial_element)
                    .expect("Should be able to create array of FieldElements");

                for (idx, leaf) in leaves.iter().enumerate() {
                    let leaf_field_ptr = Box::into_raw(Box::new(*leaf)) as jlong;

                    let leaf_element = _env
                        .new_object(field_class, "(J)V", &[JValue::Long(leaf_field_ptr)])
                        .expect("Should be able to create new long for FieldElement");

                    _env.set_object_array_element(leaf_fe_array, idx as i32, leaf_element)
                        .expect("Should be able to add FieldElement leaf to an array");
                }

                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                let empty_res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::from(JObject::from(leaf_fe_array))],
                    )
                    .expect("Should be able to create new value for Optional");

                *empty_res.l().unwrap()
            }
            _ => {
                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");

                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetBtrLeaves(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        match commitment_tree.get_bwtr_leaves(&sc_id) {
            Some(leaves) => {
                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let initial_element = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(0)])
                    .expect("Should be able to create new long for FieldElement");

                let leaf_fe_array = _env
                    .new_object_array(leaves.len() as i32, field_class, initial_element)
                    .expect("Should be able to create array of FieldElements");

                for (idx, leaf) in leaves.iter().enumerate() {
                    let leaf_field_ptr = Box::into_raw(Box::new(*leaf)) as i64;

                    let leaf_element = _env
                        .new_object(field_class, "(J)V", &[JValue::Long(leaf_field_ptr)])
                        .expect("Should be able to create new long for FieldElement");

                    _env.set_object_array_element(leaf_fe_array, idx as i32, leaf_element)
                        .expect("Should be able to add FieldElement leaf to an array");
                }

                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                let empty_res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::from(JObject::from(leaf_fe_array))],
                    )
                    .expect("Should be able to create new value for Optional");

                *empty_res.l().unwrap()
            }
            _ => {
                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");

                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetCrtLeaves(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        match commitment_tree.get_cert_leaves(&sc_id) {
            Some(leaves) => {
                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let initial_element = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(0)])
                    .expect("Should be able to create new long for FieldElement");

                let leaf_fe_array = _env
                    .new_object_array(leaves.len() as i32, field_class, initial_element)
                    .expect("Should be able to create array of FieldElements");

                for (idx, leaf) in leaves.iter().enumerate() {
                    let leaf_field_ptr = Box::into_raw(Box::new(*leaf)) as i64;
                    let leaf_element = _env
                        .new_object(field_class, "(J)V", &[JValue::Long(leaf_field_ptr)])
                        .expect("Should be able to create new long for FieldElement");

                    _env.set_object_array_element(leaf_fe_array, idx as i32, leaf_element)
                        .expect("Should be able to add FieldElement leaf to an array");
                }

                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                let empty_res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::from(JObject::from(leaf_fe_array))],
                    )
                    .expect("Should be able to create new value for Optional");

                *empty_res.l().unwrap()
            }
            _ => {
                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");

                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeAddBtr(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _sc_fee: jlong,
        _mc_destination_address: jbyteArray,
        _sc_request_data: jobjectArray,
        _tx_hash: jbyteArray,
        _out_idx: jint,
    ) -> jboolean {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let sc_fee = _sc_fee as u64;

        let mut mc_destination_address = [0u8; 20];
        get_byte_array(
            &_env,
            &_mc_destination_address,
            &mut mc_destination_address[..],
        );

        let mut sc_request_data = vec![];
        let sc_request_data_size = _env
            .get_array_length(_sc_request_data)
            .expect("Should be able to get _custom_field_elements_configs size");
        if sc_request_data_size > 0 {
            for i in 0..sc_request_data_size {
                let o = _env
                    .get_object_array_element(_sc_request_data, i)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Should be able to get elem {} of custom_field_elements_configs array",
                            i
                        )
                    });

                let data = _env
                    .convert_byte_array(o.cast())
                    .expect("Should be able to convert to Rust byte array");

                sc_request_data.push(
                    FieldElement::deserialize(data.as_slice())
                        .expect("Can't parse the input sc_request_data into FieldElement"),
                );
            }
        }

        let mut tx_hash = [0u8; FIELD_SIZE];
        get_byte_array(&_env, &_tx_hash, &mut tx_hash[..]);

        let out_idx = _out_idx as u32;

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        if commitment_tree.add_bwtr(
            &sc_id,
            sc_fee,
            sc_request_data.iter().collect(),
            &mc_destination_address,
            &tx_hash,
            out_idx,
        ) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeAddCert(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _epoch_number: jint,
        _quality: jlong,
        _bt_list: jobjectArray,
        _custom_fields_nullable: jobjectArray, // can be null if there is no constant
        _end_cumulative_sc_tx_commitment_tree_root: jbyteArray,
        _btr_fee: jlong,
        _ft_min_amount: jlong,
    ) -> jboolean {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let epoch_number = _epoch_number as u32;

        let quality = _quality as u64;

        //Extract backward transfers
        let mut bt_list = vec![];

        let bt_list_size = _env
            .get_array_length(_bt_list)
            .expect("Should be able to get bt_list size");

        if bt_list_size > 0 {
            for i in 0..bt_list_size {
                let o = _env
                    .get_object_array_element(_bt_list, i)
                    .unwrap_or_else(|_| {
                        panic!("Should be able to get elem {} of bt_list array", i)
                    });

                let p = _env
                    .call_method(o, "getPublicKeyHash", "()[B", &[])
                    .expect("Should be able to call getPublicKeyHash method")
                    .l()
                    .unwrap()
                    .cast();

                let pk: [u8; 20] = _env
                    .convert_byte_array(p)
                    .expect("Should be able to convert to Rust byte array")
                    .try_into()
                    .expect("Should be able to write into fixed buffer of size 20");

                let a = _env
                    .call_method(o, "getAmount", "()J", &[])
                    .expect("Should be able to call getAmount method")
                    .j()
                    .unwrap() as u64;

                bt_list.push(BackwardTransfer {
                    pk_dest: pk,
                    amount: a,
                });
            }
        }

        let bt_list_opt = if !bt_list.is_empty() {
            Some(bt_list.as_slice())
        } else {
            None
        };

        let mut custom_fields = vec![];
        let custom_fields_opt = if _custom_fields_nullable.is_null() {
            Option::None
        } else {
            let custom_fields_size = _env
                .get_array_length(_custom_fields_nullable)
                .expect("Should be able to get custom_fields size");

            if custom_fields_size > 0 {
                for i in 0..custom_fields_size {
                    let o = _env
                        .get_object_array_element(_custom_fields_nullable, i)
                        .unwrap_or_else(|_| {
                            panic!("Should be able to get elem {} of custom_fields array", i)
                        });

                    let cf = _env
                        .convert_byte_array(o.cast())
                        .expect("Should be able to convert to Rust byte array");

                    custom_fields.push(
                        FieldElement::deserialize(cf.as_slice())
                            .expect("Can't parse the input custom_field into FieldElement"),
                    );
                }
            }
            Some(custom_fields.iter().collect())
        };

        let end_cumulative_sc_tx_commitment_tree_root = {
            let tree_root_bytes = parse_jbyte_array_to_vec(
                &_env,
                &_end_cumulative_sc_tx_commitment_tree_root,
                FIELD_SIZE,
            );
            FieldElement::deserialize(tree_root_bytes.as_slice()).expect(
                "Can't parse the input end_cumulative_sc_tx_commitment_tree_root into FieldElement",
            )
        };

        let btr_fee = _btr_fee as u64;

        let ft_min_amount = _ft_min_amount as u64;

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        if commitment_tree.add_cert(
            &sc_id,
            epoch_number,
            quality,
            bt_list_opt,
            custom_fields_opt,
            &end_cumulative_sc_tx_commitment_tree_root,
            btr_fee,
            ft_min_amount,
        ) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeAddCertLeaf(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _leaf: jbyteArray,
    ) -> jboolean {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let leaf_fe = {
            let leaf_bytes = parse_jbyte_array_to_vec(&_env, &_leaf, FIELD_SIZE);
            FieldElement::deserialize(leaf_bytes.as_slice())
                .expect("Can't parse the input leaf_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        if commitment_tree.add_cert_leaf(&sc_id, &leaf_fe) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeAddCsw(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _amount: jlong,
        _nullifier: jbyteArray,
        _mc_pk_hash: jbyteArray,
    ) -> jboolean {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let amount = _amount as u64;

        let nullifier = {
            let nullifier_bytes = parse_jbyte_array_to_vec(&_env, &_nullifier, FIELD_SIZE);
            FieldElement::deserialize(nullifier_bytes.as_slice())
                .expect("Can't parse the input nullifier_bytes into FieldElement")
        };

        let mut mc_pk_hash = [0u8; MC_PK_SIZE];
        get_byte_array(&_env, &_mc_pk_hash, &mut mc_pk_hash[..]);

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        if commitment_tree.add_csw(&sc_id, amount, &nullifier, &mc_pk_hash) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetScCrCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_scc(&sc_id) {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetFwtCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_fwt_commitment(&sc_id) {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeBtrCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_bwtr_commitment(&sc_id) {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetCertCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_cert_commitment(&sc_id) {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetCswCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_csw_commitment(&sc_id) {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetScCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_sc_commitment(&sc_id) {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetCommitment(
        _env: JNIEnv,
        _commitment_tree: JObject,
    ) -> jobject {
        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_commitment() {
            Some(sc_cr_commitment_fe) => {
                let field_ptr: jlong = Box::into_raw(Box::new(sc_cr_commitment_fe)) as i64;

                let field_class = _env
                    .find_class("com/horizen/librustsidechains/FieldElement")
                    .expect("Should be able to find FieldElement class");

                let jfe = _env
                    .new_object(field_class, "(J)V", &[JValue::Long(field_ptr)])
                    .expect("Should be able to create new long for FieldElement");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jfe)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetScCommitmentMerklePath(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_sc_commitment_merkle_path(&sc_id) {
            Some(merkle_path) => {
                let merkle_path_ptr: jlong = Box::into_raw(Box::new(merkle_path)) as i64;

                let merkle_path_class = _env
                    .find_class("com/horizen/merkletreenative/MerklePath")
                    .expect("Should be able to find MerklePath class");

                let jep = _env
                    .new_object(merkle_path_class, "(J)V", &[JValue::Long(merkle_path_ptr)])
                    .expect("Should be able to create new long for MerklePath");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetFwtMerklePath(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _leaf_index: jint,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let leaf_index = _leaf_index as usize;

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_fwt_merkle_path(&sc_id, leaf_index) {
            Some(merkle_path) => {
                let merkle_path_ptr: jlong = Box::into_raw(Box::new(merkle_path)) as i64;

                let merkle_path_class = _env
                    .find_class("com/horizen/merkletreenative/MerklePath")
                    .expect("Should be able to find MerklePath class");

                let jep = _env
                    .new_object(merkle_path_class, "(J)V", &[JValue::Long(merkle_path_ptr)])
                    .expect("Should be able to create new long for MerklePath");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetBtrMerklePath(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _leaf_index: jint,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let leaf_index = _leaf_index as usize;

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_bwtr_merkle_path(&sc_id, leaf_index) {
            Some(merkle_path) => {
                let merkle_path_ptr: jlong = Box::into_raw(Box::new(merkle_path)) as i64;

                let merkle_path_class = _env
                    .find_class("com/horizen/merkletreenative/MerklePath")
                    .expect("Should be able to find MerklePath class");

                let jep = _env
                    .new_object(merkle_path_class, "(J)V", &[JValue::Long(merkle_path_ptr)])
                    .expect("Should be able to create new long for MerklePath");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetCertMerklePath(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _leaf_index: jint,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let leaf_index = _leaf_index as usize;

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_cert_merkle_path(&sc_id, leaf_index) {
            Some(merkle_path) => {
                let merkle_path_ptr: jlong = Box::into_raw(Box::new(merkle_path)) as i64;

                let merkle_path_class = _env
                    .find_class("com/horizen/merkletreenative/MerklePath")
                    .expect("Should be able to find MerklePath class");

                let jep = _env
                    .new_object(merkle_path_class, "(J)V", &[JValue::Long(merkle_path_ptr)])
                    .expect("Should be able to create new long for MerklePath");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

// Sc Existence proof functions
ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetScExistenceProof(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_sc_existence_proof(&sc_id) {
            Some(sc_existence_proof) => {
                let proof_ptr: jlong = Box::into_raw(Box::new(sc_existence_proof)) as i64;

                let existence_proof_class = _env
                    .find_class("com/horizen/commitmenttreenative/ScExistenceProof")
                    .expect("Should be able to find ScExistenceProof class");

                let jep = _env
                    .new_object(existence_proof_class, "(J)V", &[JValue::Long(proof_ptr)])
                    .expect("Should be able to create new long for ScExistenceProof");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScExistenceProof_nativeSerialize(
        _env: JNIEnv,
        _proof: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<ScExistenceProof>(&_env, _proof, "existenceProofPointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScExistenceProof_nativeDeserialize(
        _env: JNIEnv,
        _class: JClass,
        _proof_bytes: jbyteArray,
    ) -> jobject {
        let proof_bytes = _env
            .convert_byte_array(_proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        match ScExistenceProof::deserialize(proof_bytes.as_slice()) {
            Ok(sc_existence_proof) => {
                let proof_ptr: jlong = Box::into_raw(Box::new(sc_existence_proof)) as i64;

                let existence_proof_class = _env
                    .find_class("com/horizen/commitmenttreenative/ScExistenceProof")
                    .expect("Should be able to find ScExistenceProof class");

                let jep = _env
                    .new_object(existence_proof_class, "(J)V", &[JValue::Long(proof_ptr)])
                    .expect("Should be able to create new long for ScExistenceProof");

                *jep
            }
            Err(e) => {
                log!(format!("ScExistenceProof deserialization failed: {:?}", e));
                std::ptr::null::<jobject>() as jobject
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScExistenceProof_nativeFreeScExistenceProof(
        _env: JNIEnv,
        _class: JClass,
        _sc_existence_proof: *mut ScExistenceProof,
    ) {
        if _sc_existence_proof.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_sc_existence_proof) });
    }
);

// Sc Absence proof functions
ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetScAbsenceProof(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
    ) -> jobject {
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        let commitment_tree = {
            let t = _env
                .get_field(_commitment_tree, "commitmentTreePointer", "J")
                .expect("Should be able to get field commitmentTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
        };

        let cls_optional = _env.find_class("java/util/Optional").unwrap();

        match commitment_tree.get_sc_absence_proof(&sc_id) {
            Some(sc_absence_proof) => {
                let proof_ptr: jlong = Box::into_raw(Box::new(sc_absence_proof)) as i64;

                let absence_proof_class = _env
                    .find_class("com/horizen/commitmenttreenative/ScAbsenceProof")
                    .expect("Should be able to find ScAbsenceProof class");

                let jep = _env
                    .new_object(absence_proof_class, "(J)V", &[JValue::Long(proof_ptr)])
                    .expect("Should be able to create new long for ScAbsenceProof");

                let res = _env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            _ => {
                let empty_res = _env
                    .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                    .expect("Should be able to create new value for Optional.empty()");
                *empty_res.l().unwrap()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScAbsenceProof_nativeSerialize(
        _env: JNIEnv,
        _proof: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<ScAbsenceProof>(&_env, _proof, "absenceProofPointer", None)
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScAbsenceProof_nativeDeserialize(
        _env: JNIEnv,
        _class: JClass,
        _proof_bytes: jbyteArray,
    ) -> jobject {
        let proof_bytes = _env
            .convert_byte_array(_proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        match ScAbsenceProof::deserialize(proof_bytes.as_slice()) {
            Ok(sc_absence_proof) => {
                let proof_ptr: jlong = Box::into_raw(Box::new(sc_absence_proof)) as i64;

                let absence_proof_class = _env
                    .find_class("com/horizen/commitmenttreenative/ScAbsenceProof")
                    .expect("Should be able to find ScAbsenceProof class");

                let jep = _env
                    .new_object(absence_proof_class, "(J)V", &[JValue::Long(proof_ptr)])
                    .expect("Should be able to create new long for ScAbsenceProof");

                *jep
            }
            Err(e) => {
                log!(format!("ScAbsenceProof deserialization failed: {:?}", e));
                std::ptr::null::<jobject>() as jobject
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScAbsenceProof_nativeFreeScAbsenceProof(
        _env: JNIEnv,
        _class: JClass,
        _sc_absence_proof: *mut ScAbsenceProof,
    ) {
        if _sc_absence_proof.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(_sc_absence_proof) });
    }
);

// Verify existence/absence functions.

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeVerifyScCommitment(
        _env: JNIEnv,
        _commitment_tree_class: JObject,
        _sc_commitment: JObject,
        _sc_commitment_proof: JObject,
        _commitment: JObject,
    ) -> bool {
        //Read sidechain commitment
        let sc_commitment_fe = {
            let i = _env
                .get_field(_sc_commitment, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer from scCommitment");

            read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
        };

        //Read commitment proof
        let sc_commitment_proof = {
            let i = _env
                .get_field(_sc_commitment_proof, "existenceProofPointer", "J")
                .expect("Should be able to get field existenceProofPointer from scCommitmentProof");

            read_raw_pointer(&_env, i.j().unwrap() as *const ScExistenceProof)
        };

        //Read commitment
        let commitment_fe = {
            let i = _env
                .get_field(_commitment, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer from commitment");

            read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
        };

        CommitmentTree::verify_sc_commitment(sc_commitment_fe, sc_commitment_proof, commitment_fe)
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeVerifyScAbsence(
        _env: JNIEnv,
        _commitment_tree: JObject,
        _sc_id: jbyteArray,
        _sc_absence_proof: JObject,
        _commitment: JObject,
    ) -> bool {
        // Read sidechain id
        let sc_id = {
            let sc_id_bytes = parse_jbyte_array_to_vec(&_env, &_sc_id, FIELD_SIZE);
            FieldElement::deserialize(sc_id_bytes.as_slice())
                .expect("Can't parse the input sc_id_bytes into FieldElement")
        };

        //Read commitment proof
        let sc_absence_proof = {
            let i = _env
                .get_field(_sc_absence_proof, "absenceProofPointer", "J")
                .expect("Should be able to get field absenceProofPointer from scAbsenceProof");

            read_raw_pointer(&_env, i.j().unwrap() as *const ScAbsenceProof)
        };

        //Read commitment
        let commitment_fe = {
            let i = _env
                .get_field(_commitment, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer from commitment");

            read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
        };

        CommitmentTree::verify_sc_absence(&sc_id, sc_absence_proof, commitment_fe)
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_Utils_nativeCalculateSidechainId(
        _env: JNIEnv,
        _utils: JClass,
        _tx_hash: jbyteArray,
        _idx: jint,
    ) -> jbyteArray {
        // Parse tx_hash into a [u8; 32]
        let tx_hash: [u8; 32] = _env
            .convert_byte_array(_tx_hash)
            .expect("Should be able to convert to Rust byte array")
            .try_into()
            .expect("Should be able to write into fixed buffer of size 32");

        let idx = _idx as u32;

        // Compute sc_id
        let sc_id = compute_sc_id(&tx_hash, idx).expect("Cannot compute sc id.");

        // Return sc_id bytes
        let sc_id_bytes =
            serialize_to_buffer(&sc_id, None).expect("Should be able to serialize sc_id");
        _env.byte_array_from_slice(sc_id_bytes.as_slice())
            .expect("Cannot write jobject.")
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_Utils_nativeCompressedBitvectorMerkleRoot(
        _env: JNIEnv,
        _utils: JClass,
        _compressed_bit_vector: jbyteArray,
    ) -> jbyteArray {
        // Parse compressed_bit_vector into a vector
        let compressed_bit_vector = _env
            .convert_byte_array(_compressed_bit_vector)
            .expect("Should be able to convert to Rust byte array");

        // Compute merkle_root
        let merkle_root =
            merkle_root_from_compressed_bytes_without_checks(compressed_bit_vector.as_slice())
                .expect("Cannot compute merkle root.");

        // Return merkle_root bytes
        let merkle_root_bytes = serialize_to_buffer(&merkle_root, None)
            .expect("Should be able to serialize merkle_root");
        _env.byte_array_from_slice(merkle_root_bytes.as_slice())
            .expect("Cannot write jobject.")
    }
);

ffi_export!(
    fn Java_com_horizen_librustsidechains_Utils_nativeCompressedBitvectorMerkleRootWithSizeCheck(
        _env: JNIEnv,
        _utils: JClass,
        _compressed_bit_vector: jbyteArray,
        _expected_uncompressed_size: jint,
    ) -> jbyteArray {
        // Parse compressed_bit_vector into a vector
        let compressed_bit_vector = _env
            .convert_byte_array(_compressed_bit_vector)
            .expect("Should be able to convert to Rust byte array");

        let expected_uncompressed_size = _expected_uncompressed_size as usize;

        // Compute merkle_root
        match merkle_root_from_compressed_bytes(
            compressed_bit_vector.as_slice(),
            expected_uncompressed_size,
        ) {
            Ok(merkle_root) => {
                // Return merkle_root bytes
                let merkle_root_bytes = serialize_to_buffer(&merkle_root, None)
                    .expect("Should be able to serialize merkle_root");
                _env.byte_array_from_slice(merkle_root_bytes.as_slice())
                    .expect("Cannot write jobject.")
            }
            Err(e) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    format!("Cannot compute merkle root with size check: {:?}", e).as_str(),
                    JObject::null().into_inner()
                );
            }
        }
    }
);

////////////LAZY SPARSE MERKLE TREE

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeInit(
        _env: JNIEnv,
        _class: JClass,
        _height: jint,
    ) -> jobject {
        // Create new InMemorySparseMerkleTree Rust side
        let mt = GingerSparseMHT::init(_height as u8);

        // Create and return new InMemorySparseMerkleTree Java side
        let mt_ptr: jlong = Box::into_raw(Box::new(mt)) as i64;

        _env.new_object(_class, "(J)V", &[JValue::Long(mt_ptr)])
            .expect("Should be able to create new InMemorySparseMerkleTree object")
            .into_inner()
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeIsPositionEmpty(
        _env: JNIEnv,
        _tree: JObject,
        _position: jlong,
    ) -> jboolean {
        // Read tree
        let tree = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerSparseMHT)
        };

        // Call corresponding function and return result if Ok(), otherwise throw Exception
        match tree.is_leaf_empty(_position as u32) {
            Ok(result) => {
                if result {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
            Err(e) => throw!(
                &_env,
                "java/lang/Exception",
                format!("Cannot check if position is empty: {}", e.to_string()).as_str(),
                JNI_FALSE
            ),
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeAddLeaves(
        _env: JNIEnv,
        _tree: JObject,
        _leaves: JObject,
    ) {
        //Read _leaves as HashMap<u32, FieldElement>
        let leaves_map = JMap::from_env(&_env, _leaves)
            .expect("Should be able to construct JMap from _leaves JObject");
        let mut leaves = HashMap::new();

        for (pos, fe) in leaves_map
            .iter()
            .expect("Should be able to get JMap iterator")
        {
            // Read FieldElement
            let field = {
                let f = _env
                    .get_field(fe, "fieldElementPointer", "J")
                    .expect("Should be able to get field fieldElementPointer");

                read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
            };

            // Read position
            let position = _env
                .get_field(pos, "value", "J")
                .expect("Should be able to get value member")
                .j()
                .unwrap() as u32;

            leaves.insert(position, *field);
        }

        // Read tree
        let tree = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut GingerSparseMHT)
        };

        // Update the tree with leaves
        match tree.insert_leaves(leaves) {
            Ok(_) => {}
            Err(e) => throw!(
                &_env,
                "java/lang/Exception",
                format!("Cannot insert leaves: {}", e.to_string()).as_str()
            ),
        };
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeRemoveLeaves(
        _env: JNIEnv,
        _tree: JObject,
        _positions: jlongArray,
    ) {
        //Read _positions as an array of jlongs
        let positions_len = _env
            .get_array_length(_positions)
            .expect("Should be able to read positions array size");
        let mut positions = HashSet::new();

        // Array can be empty
        for i in 0..positions_len {
            let long_obj = _env
                .get_object_array_element(_positions, i)
                .unwrap_or_else(|_| {
                    panic!("Should be able to read elem {} of the positions array", i)
                });

            // Read position
            let position = _env
                .get_field(long_obj, "value", "J")
                .expect("Should be able to get value member")
                .j()
                .unwrap() as u32;

            positions.insert(position);
        }

        // Read tree
        let tree = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut GingerSparseMHT)
        };

        // Update the tree with leaves
        match tree.remove_leaves(positions) {
            Ok(_) => {}
            Err(e) => throw!(
                &_env,
                "java/lang/Exception",
                format!("Cannot remove leaves: {}", e.to_string()).as_str()
            ),
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeFinalizeInPlace(
        _env: JNIEnv,
        _tree: JObject,
    ) {
        // Read tree
        let tree = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            read_mut_raw_pointer(&_env, t.j().unwrap() as *mut GingerSparseMHT)
        };

        // Update the root of the tree
        match tree.finalize_in_place() {
            Ok(_) => {}
            Err(e) => throw!(
                &_env,
                "java/lang/Exception",
                format!("Cannot finalize tree: {}", e.to_string()).as_str()
            ),
        };
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeRoot(
        _env: JNIEnv,
        _tree: JObject,
    ) -> jobject {
        // Read tree
        let tree = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerSparseMHT)
        };

        match tree.root() {
            Some(root) => return_field_element(&_env, root),
            None => throw!(
                &_env,
                "java/lang/Exception",
                "Unable to return root. Have you finalized the tree ?",
                JObject::null().into_inner()
            ),
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeGetMerklePath(
        _env: JNIEnv,
        _tree: JObject,
        _leaf_position: jlong,
    ) -> jobject {
        // Read tree
        let tree = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            read_raw_pointer(&_env, t.j().unwrap() as *const GingerSparseMHT)
        };

        match tree.get_merkle_path(_leaf_position as u32) {
            Some(path) => {
                let converted_path: GingerMHTPath = path.try_into().unwrap();
                *return_jobject(
                    &_env,
                    converted_path,
                    "com/horizen/merkletreenative/MerklePath",
                )
            }
            None => throw!(
                &_env,
                "java/lang/Exception",
                "Cannot compute path. Have you finalized the tree ?",
                JObject::null().into_inner()
            ),
        }
    }
);

ffi_export!(
    fn Java_com_horizen_merkletreenative_InMemorySparseMerkleTree_nativeFreeInMemorySparseMerkleTree(
        _env: JNIEnv,
        _tree: JObject,
    ) {
        // Read tree
        let tree_ptr = {
            let t = _env
                .get_field(_tree, "merkleTreePointer", "J")
                .expect("Should be able to get field merkleTreePointer");

            t.j().unwrap() as *mut GingerSparseMHT
        };

        if tree_ptr.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(tree_ptr) });
    }
);

// PGD CSW related functions

fn parse_sc_utxo_output(_env: &JNIEnv, _utxo_out: JObject) -> CswUtxoOutputData {
    // Parse spending_pub_key bytes
    let spending_pub_key = parse_fixed_size_byte_array_from_jobject::<SC_PUBLIC_KEY_LENGTH>(
        _env,
        _utxo_out,
        "spendingPubKey",
    );

    // Parse amount
    let amount: u64 = parse_long_from_jobject(_env, _utxo_out, "amount");

    // Parse nonce
    let nonce: u64 = parse_long_from_jobject(_env, _utxo_out, "nonce");

    // Parse custom hash bytes
    let custom_hash = parse_fixed_size_byte_array_from_jobject::<SC_CUSTOM_HASH_LENGTH>(
        _env,
        _utxo_out,
        "customHash",
    );

    CswUtxoOutputData {
        spending_pub_key,
        amount,
        nonce,
        custom_hash,
    }
}

ffi_export!(
    fn Java_com_horizen_scutxonative_ScUtxoOutput_nativeGetHash(
        _env: JNIEnv,
        _utxo_out: JObject,
    ) -> jobject {
        match parse_sc_utxo_output(&_env, _utxo_out)
            .hash(Some(&[FieldElement::from(BoxType::CoinBox as u8)]))
        {
            Ok(digest) => return_field_element(&_env, digest),
            Err(e) => {
                log!(format!("Error while computing Utxo Output hash: {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

fn parse_sc_ft_output(_env: &JNIEnv, _ft_out: JObject) -> CswFtOutputData {
    // Parse amount
    let amount: u64 = parse_long_from_jobject(&_env, _ft_out, "amount");

    // Parse receiver_pub_key bytes
    let receiver_pub_key = parse_fixed_size_byte_array_from_jobject::<SC_PUBLIC_KEY_LENGTH>(
        &_env,
        _ft_out,
        "receiverPubKey",
    );

    // Parse spending_pub_key bytes
    let payback_addr_data_hash = parse_fixed_size_byte_array_from_jobject::<MC_PK_SIZE>(
        &_env,
        _ft_out,
        "paybackAddrDataHash",
    );

    // Parse tx hash bytes
    let tx_hash =
        parse_fixed_size_byte_array_from_jobject::<SC_TX_HASH_LENGTH>(&_env, _ft_out, "txHash");

    // Parse out_idx
    let out_idx: u32 = parse_int_from_jobject(&_env, _ft_out, "outIdx");

    CswFtOutputData {
        amount,
        receiver_pub_key,
        payback_addr_data_hash,
        tx_hash,
        out_idx,
    }
}

ffi_export!(
    fn Java_com_horizen_fwtnative_ForwardTransferOutput_nativeGetHash(
        _env: JNIEnv,
        _ft_out: JObject,
    ) -> jobject {
        // Parse sc_ft_output
        let sc_ft_output = parse_sc_ft_output(&_env, _ft_out);

        let mut receiver_pub_key = sc_ft_output.receiver_pub_key;
        receiver_pub_key.reverse();

        match hash_fwt(
            sc_ft_output.amount,
            &receiver_pub_key,
            &sc_ft_output.payback_addr_data_hash,
            &sc_ft_output.tx_hash,
            sc_ft_output.out_idx,
        ) {
            Ok(digest) => return_field_element(&_env, digest),
            Err(e) => {
                log!(format!("Error while computing FT hash: {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

fn parse_wcert(_env: JNIEnv, _cert: JObject) -> WithdrawalCertificateData {
    let (
        sc_id,
        epoch_number,
        bt_list,
        quality,
        mcb_sc_txs_com,
        ft_min_amount,
        btr_min_fee,
        custom_fields,
    ) = parse_wcert_fields(_env, _cert);
    WithdrawalCertificateData::new(
        sc_id,
        epoch_number,
        bt_list,
        quality,
        mcb_sc_txs_com,
        ft_min_amount,
        btr_min_fee,
        custom_fields,
    )
}

fn parse_wcert_fields(
    _env: JNIEnv,
    _cert: JObject,
) -> (
    FieldElement,
    u32,
    Vec<BackwardTransfer>,
    u64,
    FieldElement,
    u64,
    u64,
    Vec<FieldElement>,
) {
    // Parse sc_id
    let sc_id = *parse_field_element_from_jobject(&_env, _cert, "scId");

    // Parse epoch number
    let epoch_number = parse_int_from_jobject(&_env, _cert, "epochNumber");

    //Extract backward transfers
    let bt_list_obj = parse_jobject_array_from_jobject(
        &_env,
        _cert,
        "btList",
        "com/horizen/certnative/BackwardTransfer",
    );
    let bt_list = extract_backward_transfers(&_env, bt_list_obj);

    // Extract custom fields
    let custom_fields_list_obj = parse_jobject_array_from_jobject(
        &_env,
        _cert,
        "customFields",
        "com/horizen/librustsidechains/FieldElement",
    );

    let custom_fields = extract_custom_fields(&_env, custom_fields_list_obj).unwrap_or_default();

    // Parse quality
    let quality = parse_long_from_jobject(&_env, _cert, "quality");

    // Parse mcb_sc_txs_com
    let mcb_sc_txs_com = *parse_field_element_from_jobject(&_env, _cert, "mcbScTxsCom");

    // Parse btr_fee
    let btr_min_fee = parse_long_from_jobject(&_env, _cert, "btrMinFee");

    // Parse ft_min_amount
    let ft_min_amount = parse_long_from_jobject(&_env, _cert, "ftMinAmount");

    (
        sc_id,
        epoch_number,
        bt_list,
        quality,
        mcb_sc_txs_com,
        ft_min_amount,
        btr_min_fee,
        custom_fields,
    )
}

ffi_export!(
    fn Java_com_horizen_certnative_WithdrawalCertificate_nativeGetHash(
        _env: JNIEnv,
        _cert: JObject,
    ) -> jobject {
        // Parse cert
        let cert = parse_wcert(_env, _cert);

        // Compute hash
        match cert.hash() {
            Ok(digest) => return_field_element(&_env, digest),
            Err(e) => {
                log!(format!("Error while computing cert hash: {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_cswnative_CswProof_nativeSetup(
        _env: JNIEnv,
        _class: JClass,
        _proving_system: JObject,
        _range_size: jint,
        _num_custom_fields: jint,
        _is_constant_present: jboolean,
        _segment_size: JObject,
        _proving_key_path: JString,
        _verification_key_path: JString,
        _zk: jboolean,
        _max_proof_plus_vk_size: jint,
        _compress_pk: jboolean,
        _compress_vk: jboolean,
    ) -> jboolean {
        // Get proving system type
        let proving_system = get_proving_system_type(&_env, _proving_system);

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&_env, _segment_size).map(|integer_object| {
                _env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        // Read paths
        let proving_key_path = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        let verification_key_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        let circ = CeasedSidechainWithdrawalCircuit::get_instance_for_setup(
            _range_size as u32,
            _num_custom_fields as u32,
            _is_constant_present == JNI_TRUE,
        );

        // Read zk value
        let zk = _zk == JNI_TRUE;

        // Generate snark keypair
        match generate_circuit_keypair(
            circ,
            proving_system,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            Path::new(verification_key_path.to_str().unwrap()),
            _max_proof_plus_vk_size as usize,
            zk,
            Some(_compress_pk == JNI_TRUE),
            Some(_compress_vk == JNI_TRUE),
        ) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                log!(format!("(Pk, Vk) generation failed: {:?}", e));
                JNI_FALSE
            }
        }
    }
);

fn parse_sys_data(_env: JNIEnv, _sys_data: JObject) -> (Option<FieldElement>, CswSysData) {
    let constant = parse_joption_from_jobject(&_env, _sys_data, "constant").map(|field_object| {
        let f = _env
            .get_field(field_object, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        *read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
    });
    let sys_data = CswSysData::new(
        // Map a JObject which is a Java's Optional<FieldElement> into Option<JObject>.
        // If Option is present, converts it into an Option<FieldElement>, otherwise converts it to None.
        parse_joption_from_jobject(&_env, _sys_data, "mcbScTxsComEnd").map(|field_object| {
            let f = _env
                .get_field(field_object, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            *read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        }),
        parse_joption_from_jobject(&_env, _sys_data, "scLastWcertHash").map(|field_object| {
            let f = _env
                .get_field(field_object, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            *read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        }),
        parse_long_from_jobject(&_env, _sys_data, "amount"),
        *parse_field_element_from_jobject(&_env, _sys_data, "nullifier"),
        parse_fixed_size_byte_array_from_jobject::<MC_PK_SIZE>(&_env, _sys_data, "receiver"),
    );
    (constant, sys_data)
}

fn parse_utxo_prover_data(_env: JNIEnv, _utxo_data: JObject) -> CswUtxoProverData {
    // Parse utxo output
    let output = {
        let utxo_out_obj = _env
            .get_field(
                _utxo_data,
                "output",
                "Lcom/horizen/scutxonative/ScUtxoOutput;",
            )
            .expect("Should be able to parse ScUtxoOutput")
            .l()
            .unwrap();
        parse_sc_utxo_output(&_env, utxo_out_obj)
    };

    // Parse input

    // Parse secret key
    let secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS] = {
        // Parse sk bytes
        let sk_bytes = parse_fixed_size_byte_array_from_jobject::<SC_SECRET_KEY_LENGTH>(
            &_env,
            _utxo_data,
            "utxoInputSecretKey",
        );

        // Interpret bytes as a LE integer and read a SimulatedScalarFieldElement out of it
        // reducing it if required
        let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

        // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
        let mut sk_bits = sk.write_bits();
        sk_bits.reverse();
        sk_bits.try_into().unwrap()
    };

    let input = CswUtxoInputData { output, secret_key };

    // Parse mst_path_to_output
    let mst_path_to_output: GingerMHTBinaryPath =
        parse_merkle_path_from_jobject(&_env, _utxo_data, "mstPathToOutput")
            .clone()
            .try_into()
            .unwrap();

    CswUtxoProverData {
        input,
        mst_path_to_output,
    }
}

fn parse_ft_prover_data(_env: JNIEnv, _ft_data: JObject) -> CswFtProverData {
    // Parse ForwardTransferOutput
    let ft_output = {
        let ft_out_obj = _env
            .get_field(
                _ft_data,
                "output",
                "Lcom/horizen/fwtnative/ForwardTransferOutput;",
            )
            .expect("Should be able to parse ForwardTransferOutput")
            .l()
            .unwrap();
        parse_sc_ft_output(&_env, ft_out_obj)
    };

    // Parse merkle_path_to_sc_hash
    let merkle_path_to_sc_hash: GingerMHTBinaryPath =
        parse_merkle_path_from_jobject(&_env, _ft_data, "merklePathToScHash")
            .clone()
            .try_into()
            .unwrap();

    // Parse ft_tree_path
    let ft_tree_path: GingerMHTBinaryPath =
        parse_merkle_path_from_jobject(&_env, _ft_data, "ftTreePath")
            .clone()
            .try_into()
            .unwrap();

    // Parse sc_txs_com_hashes
    let sc_txs_com_hashes_list_obj = parse_jobject_array_from_jobject(
        &_env,
        _ft_data,
        "scTxsComHashes",
        "com/horizen/librustsidechains/FieldElement",
    );

    let mut sc_txs_com_hashes = vec![];

    let sc_txs_com_hashes_size = _env
        .get_array_length(sc_txs_com_hashes_list_obj)
        .expect("Should be able to get sc_txs_com_hashes size");

    for i in 0..sc_txs_com_hashes_size {
        let o = _env
            .get_object_array_element(sc_txs_com_hashes_list_obj, i)
            .unwrap_or_else(|_| {
                panic!(
                    "Should be able to get elem {} of sc_txs_com_hashes array",
                    i
                )
            });

        let field = {
            let f = _env
                .get_field(o, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        sc_txs_com_hashes.push(*field);
    }

    // Parse secret key
    let ft_input_secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS] = {
        // Parse sk bytes
        let sk_bytes = parse_fixed_size_byte_array_from_jobject::<SC_SECRET_KEY_LENGTH>(
            &_env,
            _ft_data,
            "ftInputSecretKey",
        );

        // Interpret bytes as a LE integer and read a SimulatedScalarFieldElement out of it
        // reducing it if required
        let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

        // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
        let mut sk_bits = sk.write_bits();
        sk_bits.reverse();
        sk_bits.try_into().unwrap()
    };

    CswFtProverData {
        ft_output,
        ft_input_secret_key,
        mcb_sc_txs_com_start: *parse_field_element_from_jobject(
            &_env,
            _ft_data,
            "mcbScTxsComStart",
        ),
        merkle_path_to_sc_hash,
        ft_tree_path,
        sc_creation_commitment: *parse_field_element_from_jobject(
            &_env,
            _ft_data,
            "scCreationCommitment",
        ),
        scb_btr_tree_root: *parse_field_element_from_jobject(&_env, _ft_data, "scbBtrTreeRoot"),
        wcert_tree_root: *parse_field_element_from_jobject(&_env, _ft_data, "wCertTreeRoot"),
        sc_txs_com_hashes,
    }
}

ffi_export!(
    fn Java_com_horizen_cswnative_CswProof_nativeDebugCircuit(
        _env: JNIEnv,
        _class: JClass,
        _range_size: jint,
        _num_custom_fields: jint,
        _sys_data: JObject,
        _sc_id: JObject,
        _last_wcert: JObject,
        _utxo_data: JObject,
        _ft_data: JObject,
    ) -> jobject {
        // Parse cert if present
        let cert = if _last_wcert.into_inner().is_null() {
            None
        } else {
            Some(parse_wcert(_env, _last_wcert))
        };

        // Parse sys_data
        let (constant, sys_data) = parse_sys_data(_env, _sys_data);

        // Parse csw utxo prover data
        let csw_utxo_prover_data = if _utxo_data.into_inner().is_null() {
            None
        } else {
            Some(parse_utxo_prover_data(_env, _utxo_data))
        };

        // Parse csw ft prover data
        let csw_ft_prover_data = if _ft_data.into_inner().is_null() {
            None
        } else {
            Some(parse_ft_prover_data(_env, _ft_data))
        };

        // Parse sc_id
        let sc_id = {
            let f = _env
                .get_field(_sc_id, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        //debug circuit
        match debug_csw_circuit(
            *sc_id,
            constant,
            sys_data,
            cert,
            csw_utxo_prover_data,
            csw_ft_prover_data,
            _range_size as u32,
            _num_custom_fields as u32,
        ) {
            Ok(failing_constraint) => {
                let cls_optional = _env.find_class("java/util/Optional").unwrap();

                if let Some(failing_constraint) = failing_constraint {
                    let j_str = *_env
                        .new_string(failing_constraint)
                        .expect("Should be able to build Java String from Rust String");

                    _env.call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(j_str)],
                    )
                    .expect("Should be able to create new Optional from String")
                } else {
                    _env.call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
                        .expect("Should be able to create new value for Optional.empty()")
                }
                .l()
                .unwrap()
                .into_inner()
            }
            Err(e) => {
                log!(format!("Error debugging circuit: {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_cswnative_CswProof_nativeCreateProof(
        _env: JNIEnv,
        _class: JClass,
        _range_size: jint,
        _num_custom_fields: jint,
        _sys_data: JObject,
        _sc_id: JObject,
        _last_wcert: JObject,
        _utxo_data: JObject,
        _ft_data: JObject,
        _segment_size: JObject,
        _proving_key_path: JString,
        _check_proving_key: jboolean,
        _zk: jboolean,
        _compressed_pk: jboolean,
        _compress_proof: jboolean,
    ) -> jbyteArray {
        // Parse cert if present
        let cert = if _last_wcert.into_inner().is_null() {
            None
        } else {
            Some(parse_wcert(_env, _last_wcert))
        };

        // Parse sys_data
        let (constant, sys_data) = parse_sys_data(_env, _sys_data);

        // Parse csw utxo prover data
        let csw_utxo_prover_data = if _utxo_data.into_inner().is_null() {
            None
        } else {
            Some(parse_utxo_prover_data(_env, _utxo_data))
        };

        // Parse csw ft prover data
        let csw_ft_prover_data = if _ft_data.into_inner().is_null() {
            None
        } else {
            Some(parse_ft_prover_data(_env, _ft_data))
        };

        // Parse sc_id
        let sc_id = {
            let f = _env
                .get_field(_sc_id, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&_env, _segment_size).map(|integer_object| {
                _env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        //Extract params_path str
        let proving_key_path = _env
            .get_string(_proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        //create proof
        match create_csw_proof(
            *sc_id,
            constant,
            sys_data,
            cert,
            csw_utxo_prover_data,
            csw_ft_prover_data,
            _range_size as u32,
            _num_custom_fields as u32,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            _check_proving_key == JNI_TRUE,
            _zk == JNI_TRUE,
            _compressed_pk == JNI_TRUE,
            _compress_proof == JNI_TRUE,
        ) {
            Ok(proof) => _env
                .byte_array_from_slice(proof.as_slice())
                .expect("Should be able to convert Rust slice into jbytearray"),

            Err(e) => {
                log!(format!("Error creating proof {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_cswnative_CswProof_nativeVerifyProof(
        _env: JNIEnv,
        _class: JClass,
        _sys_data: JObject,
        _sc_id: JObject,
        _sc_proof_bytes: jbyteArray,
        _check_proof: jboolean,
        _compressed_proof: jboolean,
        _verification_key_path: JString,
        _check_vk: jboolean,
        _compressed_vk: jboolean,
    ) -> jboolean {
        // Parse sys_data
        let (constant, sys_data) = parse_sys_data(_env, _sys_data);

        // Parse sc_id
        let sc_id = {
            let f = _env
                .get_field(_sc_id, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
        };

        //Extract proof
        let proof_bytes = _env
            .convert_byte_array(_sc_proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        //Extract vk path
        let vk_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        //Verify proof
        match verify_csw_proof(
            sc_id,
            constant,
            sys_data,
            proof_bytes,
            _check_proof == JNI_TRUE,
            _compressed_proof == JNI_TRUE,
            Path::new(vk_path.to_str().unwrap()),
            _check_vk == JNI_TRUE,
            _compressed_vk == JNI_TRUE,
        ) {
            Ok(result) => {
                if result {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
            Err(e) => {
                log!(format!("Unable to verify CSW proof: {:?}", e));
                JNI_FALSE
            } // CRYPTO_ERROR or IO_ERROR
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScCommitmentCertPath_nativeFreeScCommitmentCertPath(
        env: JNIEnv,
        _class: JClass,
        path: *mut ScCommitmentCertPath,
    ) {
        ScCommitmentCertPath::free(path)
    }
);

ffi_export!(
    fn Java_com_horizen_sc2scnative_Sc2Sc_nativeSetup(
        env: JNIEnv,
        _class: JClass,
        proving_system: JObject,
        num_custom_fields: jint,
        segment_size: JObject,
        proving_key_path: JString,
        verification_key_path: JString,
        zk: jboolean,
        max_proof_plus_vk_size: jint,
        compress_pk: jboolean,
        compress_vk: jboolean,
    ) -> jboolean {
        // Get proving system type
        let proving_system = get_proving_system_type(&env, proving_system);

        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&env, segment_size).map(|integer_object| {
                env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        // Read paths
        let proving_key_path = env
            .get_string(proving_key_path)
            .expect("Should be able to read jstring as Rust String");

        let verification_key_path = env
            .get_string(verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        let circ = Sc2Sc::get_instance_for_setup(num_custom_fields as u32);

        // Read zk value
        let zk = zk == JNI_TRUE;

        // Generate snark keypair
        match generate_circuit_keypair(
            circ,
            proving_system,
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            Path::new(verification_key_path.to_str().unwrap()),
            max_proof_plus_vk_size as usize,
            zk,
            Some(compress_pk == JNI_TRUE),
            Some(compress_vk == JNI_TRUE),
        ) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                throw!(
                    &env,
                    "java/lang/Exception",
                    format!("(Pk, Vk) generation failed: {:?}", e).as_str(),
                    JNI_FALSE
                );
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_sc2scnative_Sc2Sc_nativeCreateProof(
        env: JNIEnv,
        _class: JClass,
        next_sc_tx_commitments_root: JObject,
        curr_sc_tx_commitments_root: JObject,
        msg_hash: JObject,
        next_withdrawal_certificate: JObject,
        curr_withdrawal_certificate: JObject,
        next_cert_commitment_path: JObject,
        curr_cert_commitment_path: JObject,
        msg_path: JObject,

        segment_size: JObject,
        proving_key_path: JString,
        check_proving_key: jboolean,
        zk: jboolean,
        compressed_pk: jboolean,
        compress_proof: jboolean,
    ) -> jobject {
        let next_sc_tx_commitments_root: &FieldElement =
            next_sc_tx_commitments_root.as_native_ref_unchecked(env);
        let curr_sc_tx_commitments_root: &FieldElement =
            curr_sc_tx_commitments_root.as_native_ref_unchecked(env);
        let msg_hash: &FieldElement = msg_hash.as_native_ref_unchecked(env);
        let next_withdrawal_certificate = parse_wcert(env, next_withdrawal_certificate);
        let curr_withdrawal_certificate = parse_wcert(env, curr_withdrawal_certificate);
        let next_cert_commitment_path: &ScCommitmentCertPath =
            next_cert_commitment_path.as_native_ref_unchecked(env);
        let curr_cert_commitment_path: &ScCommitmentCertPath =
            curr_cert_commitment_path.as_native_ref_unchecked(env);
        let msg_path: &GingerMHTPath = msg_path.as_native_ref_unchecked(env);
        // Get supported degree
        let supported_degree =
            cast_joption_to_rust_option(&env, segment_size).map(|integer_object| {
                env.call_method(integer_object, "intValue", "()I", &[])
                    .expect("Should be able to call intValue() on Optional<Integer>")
                    .i()
                    .unwrap() as usize
                    - 1
            });

        //Extract params_path str
        let proving_key_path = env
            .get_string(proving_key_path)
            .expect("Should be able to read jstring as Rust String");
        let check_proving_key = check_proving_key == JNI_TRUE;
        let zk = zk == JNI_TRUE;
        let compressed_pk = compressed_pk == JNI_TRUE;
        let compress_proof = compress_proof == JNI_TRUE;

        match create_native_sc2sc_proof(
            next_sc_tx_commitments_root.clone(),
            curr_sc_tx_commitments_root.clone(),
            msg_hash.clone(),
            next_withdrawal_certificate,
            curr_withdrawal_certificate,
            next_cert_commitment_path.clone(),
            curr_cert_commitment_path.clone(),
            msg_path.clone(),
            supported_degree,
            Path::new(proving_key_path.to_str().unwrap()),
            check_proving_key,
            zk,
            compressed_pk,
            compress_proof,
        ) {
            Ok(proof) => {
                //Return proof serialized
                let proof_serialized = env
                    .byte_array_from_slice(proof.as_slice())
                    .expect("Should be able to convert Rust slice into jbytearray");

                //Create new CreateProofResult object
                let proof_result_class = env
                    .find_class("com/horizen/sc2scnative/Sc2ScProof")
                    .expect("Should be able to find Sc2ScProof class");

                let result = env
                    .new_object(
                        proof_result_class,
                        "([B)V",
                        &[JValue::Object(JObject::from(proof_serialized))],
                    )
                    .expect("Should be able to create new Sc2ScProof:(byte[]) object");

                *result
            }
            Err(e) => {
                log!(format!("Error creating Sc2Sc proof {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_sc2scnative_Sc2ScProof_nativeVerify(
        env: JNIEnv,
        _class: JClass,
        proof_bytes: jbyteArray,
        next_sc_tx_commitments_root: JObject,
        curr_sc_tx_commitments_root: JObject,
        msg_hash: JObject,

        vk_path: JString,
        check_proof: jboolean,
        compressed_proof: jboolean,
        check_vk: jboolean,
        compressed_vk: jboolean,
    ) -> jboolean {
        //Extract proof
        let proof_bytes = env
            .convert_byte_array(proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        let next_sc_tx_commitments_root: &FieldElement =
            next_sc_tx_commitments_root.as_native_ref_unchecked(env);
        let curr_sc_tx_commitments_root: &FieldElement =
            curr_sc_tx_commitments_root.as_native_ref_unchecked(env);
        let msg_hash: &FieldElement = msg_hash.as_native_ref_unchecked(env);

        let vk_path = env
            .get_string(vk_path)
            .expect("Should be able to read jstring as Rust String");
        let check_proof = check_proof == JNI_TRUE;
        let compressed_proof = compressed_proof == JNI_TRUE;
        let check_vk = check_vk == JNI_TRUE;
        let compressed_vk = compressed_vk == JNI_TRUE;

        //Verify proof
        match verify_sc2sc_proof(
            next_sc_tx_commitments_root.clone(),
            curr_sc_tx_commitments_root.clone(),
            msg_hash.clone(),
            proof_bytes,
            check_proof,
            compressed_proof,
            Path::new(vk_path.to_str().unwrap()),
            check_vk,
            compressed_vk,
        ) {
            Ok(result) => {
                if result {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
            Err(e) => {
                log!(format!("Unable to verify Sc2Sc proof: {:?}", e));
                JNI_FALSE
            }
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScCommitmentCertPath_nativeApply(
        env: JNIEnv,
        path: JObject,
        sc_id: JObject,
        hash: JObject,
    ) -> jobject {
        let sc_id = sc_id.as_native_ref_unchecked(env);
        let hash = hash.as_native_ref_unchecked(env);
        let path: &ScCommitmentCertPath = path.as_native_ref_unchecked(env);

        let empty = optional_empty(env);

        if !path.is_valid() {
            return empty;
        }

        match path.compute_root(sc_id, hash) {
            Ok(root) => {
                let inner =
                    return_jobject(&env, root, "com/horizen/librustsidechains/FieldElement");
                let cls_optional = env.find_class("java/util/Optional").unwrap();
                let res = env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(inner)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            Err(_) => empty,
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScCommitmentCertPath_nativeVerify(
        env: JNIEnv,
        path: JObject,
        root: JObject,
        sc_id: JObject,
        hash: JObject,
    ) -> jboolean {
        let root = root.as_native_ref_unchecked(env);
        let sc_id = sc_id.as_native_ref_unchecked(env);
        let hash = hash.as_native_ref_unchecked(env);
        let path: &ScCommitmentCertPath = path.as_native_ref_unchecked(env);

        if !path.is_valid() {
            return JNI_FALSE;
        }

        if path.check_membership(root, sc_id, hash) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScCommitmentCertPath_nativeSerialize(
        env: JNIEnv,
        path: JObject,
    ) -> jbyteArray {
        serialize_from_jobject::<ScCommitmentCertPath>(
            &env,
            path,
            <ScCommitmentCertPath as JNINativeWrapper>::INNER_FIELD,
            None,
        )
    }
);

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_ScCommitmentCertPath_nativeDeserialize(
        env: JNIEnv,
        _class: JClass,
        path_bytes: jbyteArray,
        checked: jboolean,
    ) -> jobject {
        deserialize_to_jobject::<ScCommitmentCertPath>(
            &env,
            path_bytes,
            Some(checked),
            None,
            "com/horizen/commitmenttreenative/ScCommitmentCertPath",
        )
    }
);

fn optional_empty(env: JNIEnv) -> jobject {
    let cls_optional = env.find_class("java/util/Optional").unwrap();

    let empty_res = env
        .call_static_method(cls_optional, "empty", "()Ljava/util/Optional;", &[])
        .expect("Should be able to create new value for Optional.empty()");
    *empty_res.l().unwrap()
}

ffi_export!(
    fn Java_com_horizen_commitmenttreenative_CommitmentTree_nativeGetScCommitmentCertPath(
        env: JNIEnv,
        commitment_tree: JObject,
        sc_id: jbyteArray,
        cert_hash: jbyteArray,
    ) -> jobject {
        let sc_id = FieldElement::deserialize(
            parse_jbyte_array_to_vec(&env, &sc_id, FIELD_SIZE).as_slice(),
        )
        .expect("Can't parse the input sc_id_bytes into FieldElement");
        let cert_hash = FieldElement::deserialize(
            parse_jbyte_array_to_vec(&env, &cert_hash, FIELD_SIZE).as_slice(),
        )
        .expect("Can't parse the input cert_hash_bytes into FieldElement");

        let commitment_tree: &mut CommitmentTree = commitment_tree.as_native_ref_mut_unchecked(env);

        let empty = optional_empty(env);

        let cert_leaf_index = match commitment_tree
            .get_cert_leaves(&sc_id)
            .and_then(|certs| certs.iter().position(|h| h == &cert_hash))
        {
            Some(index) => index,
            None => return empty,
        };

        let cls_optional = env.find_class("java/util/Optional").unwrap();

        match ScCommitmentCertPath::from_commitment_cert_index(
            commitment_tree,
            sc_id,
            cert_leaf_index,
        ) {
            Ok(path) => {
                let jep = path.wrap_unchecked(env);

                let res = env
                    .call_static_method(
                        cls_optional,
                        "of",
                        "(Ljava/lang/Object;)Ljava/util/Optional;",
                        &[JValue::Object(jep)],
                    )
                    .unwrap();
                *res.l().unwrap()
            }
            Err(_) => {
                // Ignore it and return a generic None
                empty
            }
        }
    }
);
