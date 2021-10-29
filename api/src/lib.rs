#![allow(
    clippy::upper_case_acronyms,
    clippy::too_many_arguments,
    clippy::try_err,
    clippy::map_collect_result_unit,
    clippy::not_unsafe_ptr_arg_deref
)]

mod cctp_calls;
use cctp_calls::*;

use algebra::serialize::*;
use demo_circuit::{get_instance_for_setup, generate_circuit_keypair};
use cctp_primitives::proving_system::{ProvingSystem, init_dlog_keys};
use cctp_primitives::utils::{
    compute_sc_id, data_structures::*,
};
use cctp_primitives::commitment_tree::CommitmentTree;
use cctp_primitives::commitment_tree::proofs::{ScExistenceProof, ScAbsenceProof};
use cctp_primitives::bit_vector::merkle_tree::{merkle_root_from_compressed_bytes_without_checks, merkle_root_from_compressed_bytes};
use cctp_primitives::proving_system::{ZendooVerifierKey, check_proof_vk_size};
use type_mappings::{
    macros::*, instantiated::tweedle::*,
};

use common_api::{
    rust_jni::{exception::*, utils::*},
    *,
};

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jboolean, jbyte, jbyteArray, jlong, jint, jobject, jobjectArray, JNI_FALSE, JNI_TRUE},
    JNIEnv,
};

use std::convert::TryInto;

pub const MC_PK_SIZE: usize = 20;

//Naive threshold signature proof functions

ffi_export!(
    fn Java_com_horizen_sigproofnative_BackwardTransfer_nativeGetMcPkHashSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint
{
    MC_PK_SIZE as jint
});

ffi_export!(
    fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeGetConstant(
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

    parse_rust_struct_vec_from_jobject_array!(
        _env,
        _schnorr_pks_list,
        pks,
        "SchnorrPk",
        "publicKeyPointer"
    );

    //Extract threshold
    let threshold = _threshold as u64;

    //Compute constant
    map_to_jobject_or_throw_exc(
        _env,
        compute_pks_threshold_hash(pks.as_slice(), threshold),
        "com/horizen/common/librustsidechains/FieldElement",
        "com/horizen/sigproofnative/NaiveThresholdSigProofException",
        "Unable to compute pks_threshold_hash"
    )
});

ffi_export!(
    fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateMsgToSign(
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

            let pk: [u8; 20] = ok_or_throw_exc!(
                &_env,
                parse_fixed_jbyte_array(&_env, p, 20),
                "com/horizen/sigproofnative/NaiveThresholdSigProofException",
                format!("Unable to get {} BackwardTransfer", i).as_str(),
                JNI_NULL
            ).try_into().unwrap(); // Cannot fail if parse_fixed_jbyte_array passed

            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push((a, pk));
        }
    }

    let bt_list = bt_list.into_iter().map(|bt_raw| BackwardTransfer {
        pk_dest: bt_raw.1,
        amount: bt_raw.0
    }).collect::<Vec<_>>();

    let sc_id = parse_rust_struct_from_jobject::<FieldElement>(&_env, _sc_id, "fieldElementPointer");
    let end_cumulative_sc_tx_comm_tree_root = parse_rust_struct_from_jobject::<FieldElement>(&_env, _end_cumulative_sc_tx_comm_tree_root, "fieldElementPointer");

    //Compute message to sign:
    map_to_jobject_or_throw_exc(
        _env,
        compute_msg_to_sign_from_bt_list(
            sc_id,
            _epoch_number as u32,
            end_cumulative_sc_tx_comm_tree_root,
            _btr_fee as u64,
            _ft_min_amount as u64,
            bt_list
        ),
        "com/horizen/common/librustsidechains/FieldElement",
        "com/horizen/sigproofnative/NaiveThresholdSigProofException",
        "Unable to compute message to sign"
    )
});

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

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGenerateDLogKeys(
    _env: JNIEnv,
    _class: JClass,
    _proving_system: JObject,
    _max_segment_size: jint,
    _supported_segment_size: jint,
)
{
    // Get proving system type
    let proving_system = get_proving_system_type(&_env, _proving_system);

    // Generate DLOG keypair
    ok_or_throw_exc!(
        _env,
        init_dlog_keys(
            proving_system,
            _max_segment_size as usize,
            _supported_segment_size as usize,
        ),
        "com/horizen/provingsystemnative/ProvingSystemException",
        "Unable to initialize DLOG keys"
    )
});

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeCheckProofVkSize(
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
    let vk = ok_or_throw_exc!(
        &_env,
        read_from_file::<ZendooVerifierKey>(vk_path.to_str().unwrap(), Some(false), Some(true)),
        "com/horizen/provingsystemnative/ProvingSystemException",
        "Unable to read vk from file",
        JNI_FALSE
    );

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
});

ffi_export!(
    fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeSetup(
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
)
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
    ok_or_throw_exc!(
        _env,
        generate_circuit_keypair(
            circ,
            proving_system,
            proving_key_path.to_str().unwrap(),
            verification_key_path.to_str().unwrap(),
            _max_proof_size as usize,
            _max_vk_size as usize,
            zk,
            Some(_compress_pk == JNI_TRUE),
            Some(_compress_vk == JNI_TRUE),
        ),
        "com/horizen/sigproofnative/NaiveThresholdSigProofException",
        "Unable to setup (pk, vk) for NaiveThresholdSigProof"
    )
});

fn get_proving_system_type_as_jint(_env: &JNIEnv, ps: ProvingSystem) -> jint {
    match ps {
        ProvingSystem::Undefined => 0i32 as jint,
        ProvingSystem::Darlin => 1i32 as jint,
        ProvingSystem::CoboundaryMarlin => 2i32 as jint,
    }
}

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetProverKeyProvingSystemType(
    _env: JNIEnv,
    _class: JClass,
    _proving_key_path: JString,
) -> jint
{
    // Read paths
    let proving_key_path = _env.get_string(_proving_key_path)
        .expect("Should be able to read jstring as Rust String");

    let ps = ok_or_throw_exc!(
        &_env,
        read_from_file::<ProvingSystem>(proving_key_path.to_str().unwrap(), None, None),
        "com/horizen/provingsystemnative/ProvingSystemException",
        "Unable to read ProvingSystem type from file",
        -1i32 as jint
    );

    get_proving_system_type_as_jint(&_env, ps)
});

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetVerifierKeyProvingSystemType(
    _env: JNIEnv,
    _class: JClass,
    _verifier_key_path: JString,
) -> jint
{
    // Read paths
    let verifier_key_path = _env.get_string(_verifier_key_path)
        .expect("Should be able to read jstring as Rust String");

    let ps = ok_or_throw_exc!(
        &_env,
        read_from_file::<ProvingSystem>(verifier_key_path.to_str().unwrap(), None, None),
        "com/horizen/provingsystemnative/ProvingSystemException",
        "Unable to read ProvingSystem type from file",
        -1i32 as jint
    );

    get_proving_system_type_as_jint(&_env, ps)
});

ffi_export!(
    fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateProof(
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

            let pk: [u8; 20] = ok_or_throw_exc!(
                &_env,
                parse_fixed_jbyte_array(&_env, p, 20),
                "com/horizen/sigproofnative/NaiveThresholdSigProofException",
                format!("Unable to get {} BackwardTransfer", i).as_str(),
                JNI_NULL
            ).try_into().unwrap(); // Cannot fail if parse_fixed_jbyte_array passed

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

            read_raw_pointer(&_env, pk.j().unwrap() as *const SchnorrPk)
        };

        sigs.push(signature);
        pks.push(public_key);
    }

    let sc_id = {
        let f =_env.get_field(_sc_id, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
    };

    let end_cumulative_sc_tx_comm_tree_root = {
        let f =_env.get_field(_end_cumulative_sc_tx_comm_tree_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
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
        proving_key_path.to_str().unwrap(),
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
});

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGetProofProvingSystemType(
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
});

ffi_export!(
    fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeVerifyProof(
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

        read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
    };

    let end_cumulative_sc_tx_comm_tree_root = {
        let f =_env.get_field(_end_cumulative_sc_tx_comm_tree_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
    };

    //Extract constant
    let constant = {

        let c =_env.get_field(_constant, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(&_env, c.j().unwrap() as *const FieldElement)
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
        vk_path.to_str().unwrap(),
        _check_vk == JNI_TRUE,
        _compressed_vk == JNI_TRUE,

    ) {
        Ok(result) => if result { JNI_TRUE } else { JNI_FALSE },
        Err(_) => JNI_FALSE // CRYPTO_ERROR or IO_ERROR
    }
});

///////// COMMITMENT TREE
ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeInit(
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeFreeCommitmentTree(
    _env: JNIEnv,
    _class: JClass,
    _commitment_tree: *mut CommitmentTree
)
{
    if _commitment_tree.is_null()  { return }
    drop(unsafe { Box::from_raw(_commitment_tree) });
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddScCr(
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
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let amount = _amount as u64;

    let pub_key: [u8; FIELD_SIZE] = match parse_fixed_jbyte_array(&_env, _pub_key, FIELD_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read pub_key: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let tx_hash: [u8; FIELD_SIZE] = match parse_fixed_jbyte_array(&_env, _pub_key, FIELD_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read tx_hash: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

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
        match parse_field_element_from_jbyte_array(&_env, _constant_nullable) {
            Ok(fe) => Some(fe),
            Err(e) => throw!(
                &_env,
                "com/horizen/common/librustsidechains/FieldElementException",
                format!("Unable to read constant: {:?}", e).as_str(),
                JNI_FALSE
            )
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

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddFwt(
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
    let sc_id = ok_or_throw_exc!(
        &_env,
        parse_field_element_from_jbyte_array(&_env, _sc_id),
        "com/horizen/common/librustsidechains/FieldElementException",
        "Unable to read sc_id",
        JNI_FALSE
    );

    let amount = _amount as u64;

    let pub_key: [u8; FIELD_SIZE] = match parse_fixed_jbyte_array(&_env, _pub_key, FIELD_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read pub_key: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let tx_hash: [u8; FIELD_SIZE] = match parse_fixed_jbyte_array(&_env, _pub_key, FIELD_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read tx_hash: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let mc_return_address = match parse_fixed_jbyte_array(&_env, _mc_return_address, MC_PK_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read mc_return_address: {:?}", e).as_str(),
            JNI_FALSE
        )
    };
    
    let out_idx = _out_idx as u32;

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddBtr(
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
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let sc_fee = _sc_fee as u64;

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

    let tx_hash: [u8; FIELD_SIZE] = match parse_fixed_jbyte_array(&_env, _tx_hash, FIELD_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read tx_hash: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let mc_destination_address = match parse_fixed_jbyte_array(&_env, _mc_destination_address, MC_PK_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read mc_destination_address: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let out_idx = _out_idx as u32;

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddCert(
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
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_FALSE
        )
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

    let end_cumulative_sc_tx_commitment_tree_root = match parse_field_element_from_jbyte_array(&_env, _end_cumulative_sc_tx_commitment_tree_root) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read end_cumulative_sc_tx_commitment_tree_root: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let btr_fee = _btr_fee as u64;

    let ft_min_amount = _ft_min_amount as u64;

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddCertLeaf(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _leaf: jbyteArray
) -> jboolean
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let leaf_fe = match parse_field_element_from_jbyte_array(&_env, _leaf) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read leaf: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_cert_leaf(&sc_id, &leaf_fe) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCrtLeaves(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeAddCsw(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _amount: jlong,
    _nullifier: jbyteArray,
    _mc_pk_hash: jbyteArray
) -> jboolean
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let amount = _amount as u64;

    let nullifier = match parse_field_element_from_jbyte_array(&_env, _nullifier) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read nullifier: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let mc_pk_hash = match parse_fixed_jbyte_array(&_env, _mc_pk_hash, MC_PK_SIZE) {
        Ok(bytes) => bytes.try_into().unwrap(), // Cannot fail if parse_fixed_jbyte_array returned Ok
        Err(e) => throw!(
            &_env,
            "com/horizen/librustsidechains/DeserializationException",
            format!("Unable to read mc_pk_hash: {:?}", e).as_str(),
            JNI_FALSE
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
    };

    if commitment_tree.add_csw(&sc_id,
                               amount,
                               &nullifier,
                               &mc_pk_hash) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScCrCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetFwtCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeBtrCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCertCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCswCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetCommitment(
    _env: JNIEnv,
    _commitment_tree: JObject
) -> jobject
{
    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

// Sc Existance proof functions
ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScExistenceProof(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_ScExistenceProof_nativeSerialize(
    _env: JNIEnv,
    _proof: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<ScExistenceProof>(
        _env,
        _proof,
        "existenceProofPointer",
        None
    )
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_ScExistenceProof_nativeDeserialize(
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_ScExistenceProof_nativeFreeScExistenceProof(
    _env: JNIEnv,
    _class: JClass,
    _sc_existence_proof: *mut ScExistenceProof
)
{
    if _sc_existence_proof.is_null()  { return }
    drop(unsafe { Box::from_raw(_sc_existence_proof) });
});


// Sc Absence proof functions
ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeGetScAbsenceProof(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray
) -> jobject
{
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            JNI_NULL
        )
    };

    let commitment_tree = {

        let t =_env.get_field(_commitment_tree, "commitmentTreePointer", "J")
            .expect("Should be able to get field commitmentTreePointer");

        read_mut_raw_pointer(&_env, t.j().unwrap() as *mut CommitmentTree)
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_ScAbsenceProof_nativeSerialize(
    _env: JNIEnv,
    _proof: JObject,
) -> jbyteArray
{
    serialize_from_jobject::<ScAbsenceProof>(
        _env,
        _proof,
        "absenceProofPointer",
        None
    )
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_ScAbsenceProof_nativeDeserialize(
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
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_ScAbsenceProof_nativeFreeScAbsenceProof(
    _env: JNIEnv,
    _class: JClass,
    _sc_absence_proof: *mut ScAbsenceProof
)
{
    if _sc_absence_proof.is_null()  { return }
    drop(unsafe { Box::from_raw(_sc_absence_proof) });
});


// Verify existance/absence functions.

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeVerifyScCommitment(
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

        read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
    };

    //Read commitment proof
    let sc_commitment_proof = {
        let i =_env.get_field(_sc_commitment_proof, "existenceProofPointer", "J")
            .expect("Should be able to get field existenceProofPointer from scCommitmentProof");

        read_raw_pointer(&_env, i.j().unwrap() as *const ScExistenceProof)
    };

    //Read commitment
    let commitment_fe = {
        let i =_env.get_field(_commitment, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer from commitment");

        read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
    };

    CommitmentTree::verify_sc_commitment(sc_commitment_fe, sc_commitment_proof, commitment_fe)
});

ffi_export!(
    fn Java_com_horizen_commitmenttree_CommitmentTree_nativeVerifyScAbsence(
    _env: JNIEnv,
    _commitment_tree: JObject,
    _sc_id: jbyteArray,
    _sc_absence_proof: JObject,
    _commitment: JObject
) -> bool
{
    // Read sidechain id
    let sc_id = match parse_field_element_from_jbyte_array(&_env, _sc_id) {
        Ok(fe) => fe,
        Err(e) => throw!(
            &_env,
            "com/horizen/common/librustsidechains/FieldElementException",
            format!("Unable to read sc_id: {:?}", e).as_str(),
            false
        )
    };

    //Read commitment proof
    let sc_absence_proof = {
        let i =_env.get_field(_sc_absence_proof, "absenceProofPointer", "J")
            .expect("Should be able to get field absenceProofPointer from scAbsenceProof");

        read_raw_pointer(&_env, i.j().unwrap() as *const ScAbsenceProof)
    };

    //Read commitment
    let commitment_fe = {
        let i =_env.get_field(_commitment, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer from commitment");

        read_raw_pointer(&_env, i.j().unwrap() as *const FieldElement)
    };

    CommitmentTree::verify_sc_absence(&sc_id, sc_absence_proof, commitment_fe)
});

ffi_export!(
    fn Java_com_horizen_librustsidechains_Utils_nativeCalculateSidechainId(
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
});

ffi_export!(
    fn Java_com_horizen_librustsidechains_Utils_nativeCompressedBitvectorMerkleRoot(
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
});

ffi_export!(
    fn Java_com_horizen_librustsidechains_Utils_nativeCompressedBitvectorMerkleRootWithSizeCheck(
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
            throw!(&_env, "java/lang/Exception", "Cannot compute merkle root with size check.", JObject::null().into_inner());
        }
    }
});