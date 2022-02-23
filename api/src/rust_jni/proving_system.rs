use cctp_primitives::proving_system::{ProvingSystem, init_dlog_keys, ZendooVerifierKey, compute_proof_vk_size};

use super::*;

pub(crate) fn get_proving_system_type(_env: &JNIEnv, _proving_system: JObject) -> ProvingSystem {
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

pub(crate) fn get_proving_system_type_as_jint(_env: &JNIEnv, ps: ProvingSystem) -> jint {
    match ps {
        ProvingSystem::Undefined => 0_i32,
        ProvingSystem::Darlin => 1_i32,
        ProvingSystem::CoboundaryMarlin => 2_i32,
    }
}

ffi_export!(
    fn Java_com_horizen_provingsystemnative_ProvingSystem_nativeGenerateDLogKeys(
        _env: JNIEnv,
        _class: JClass,
        _proving_system: JObject,
        _segment_size: jint,
    ) {
        // Get proving system type
        let proving_system = get_proving_system_type(&_env, _proving_system);

        // Generate DLOG keypair
        ok_or_throw_exc!(
            _env,
            init_dlog_keys(proving_system, _segment_size as usize),
            "com/horizen/provingsystemnative/ProvingSystemException",
            "Unable to initialize DLOG keys"
        )
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
        let vk = ok_or_throw_exc!(
            &_env,
            read_from_file::<ZendooVerifierKey>(vk_path, Some(false), Some(true)),
            "io/horizen/common/librustsidechains/DeserializationException",
            format!(
                "Unable to read vk at {:?}. Semantic checks: {}, Compressed: {}",
                vk_path, false, true
            ),
            JNI_FALSE
        );

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
        
        let ps = ok_or_throw_exc!(
            &_env,
            read_from_file::<ProvingSystem>(proving_key_path, None, None),
            "io/horizen/common/librustsidechains/DeserializationException",
            format!(
                "Unable to read proving system type from pk at {:?}",
                proving_key_path,
            ),
            1_i32
        );

        get_proving_system_type_as_jint(&_env, ps)
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

        let ps = ok_or_throw_exc!(
            &_env,
            read_from_file::<ProvingSystem>(verifier_key_path, None, None),
            "io/horizen/common/librustsidechains/DeserializationException",
            format!(
                "Unable to read proving system type from vk at {:?}",
                verifier_key_path,
            ),
            1_i32
        );

        get_proving_system_type_as_jint(&_env, ps)
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

        let ps = ok_or_throw_exc!(
            &_env,
            deserialize_from_buffer::<ProvingSystem>(&proof_bytes[..1], None, None),
            "io/horizen/common/librustsidechains/DeserializationException",
            "Unable to read proving system type from proof",
            1_i32
        );
    
        get_proving_system_type_as_jint(&_env, ps)
    }
);