use std::convert::TryInto;

use cctp_primitives::{
    utils::compute_sc_id,
    bit_vector::merkle_tree::{merkle_root_from_compressed_bytes_without_checks, merkle_root_from_compressed_bytes},
    commitment_tree::{sidechain_tree_alive::FWT_MT_HEIGHT, CMT_MT_HEIGHT},
    MC_PK_SIZE,
};
use common_api::{
    rust_jni::{exception::*, utils::*},
    *,
};

use demo_circuit::*;

use crate::log;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong, jobject, jobjectArray};
use jni::sys::{JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

pub mod cert;
pub mod csw;
pub mod fwt;
pub mod utxo;
pub mod proving_system;
pub mod commitment_tree;

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
        let tx_hash: [u8; 32] = ok_or_throw_exc!(
            &_env,
            parse_fixed_jbyte_array(&_env, _tx_hash, 32),
            "io/horizen/common/NativeParsingException",
            "Unable to parse tx_hash",
            JNI_NULL
        )
        .try_into()
        .unwrap();

        // Compute sc_id and return its bytes
        map_to_jbytearray_or_throw_exc(
            _env,
            compute_sc_id(&tx_hash, _idx as u32),
            None,
            "sc id",
            "io/horizen/common/NativeOperationException",
            "Unable to compute sc id"
        )
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

        // Compute merkle_root and return its bytes
        map_to_jbytearray_or_throw_exc(
            _env,
            merkle_root_from_compressed_bytes_without_checks(compressed_bit_vector.as_slice()),
            None,
            "bit vector merkle root",
            "io/horizen/common/NativeOperationException",
            "Unable to compute bit vector merkle root starting from compressed bit vector"
        )
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

        // Compute merkle_root and return its bytes
        map_to_jbytearray_or_throw_exc(
            _env,
            merkle_root_from_compressed_bytes(
                compressed_bit_vector.as_slice(),
                expected_uncompressed_size,
            ),
            None,
            "bit vector merkle root",
            "io/horizen/common/NativeOperationException",
            "Unable to compute bit vector merkle root with size check starting from compressed bit vector"
        )
    }
);