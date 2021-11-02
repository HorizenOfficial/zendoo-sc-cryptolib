use super::*;
use crate::cctp_calls::naive_threshold_sig::*;
use cctp_primitives::{proving_system::ProvingSystem, utils::data_structures::BackwardTransfer};
use demo_circuit::{get_instance_for_setup, generate_circuit_keypair};
use std::convert::TryInto;

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