use super::*;
use cctp_primitives::bit_vector::merkle_tree::{
    merkle_root_from_compressed_bytes, merkle_root_from_compressed_bytes_without_checks,
};
use cctp_primitives::utils::compute_sc_id;
use std::convert::TryInto;

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
            Err(_) => {
                throw!(
                    &_env,
                    "java/lang/Exception",
                    "Cannot compute merkle root with size check.",
                    JObject::null().into_inner()
                );
            }
        }
    }
);
