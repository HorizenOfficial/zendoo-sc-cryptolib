use algebra::ToBits;
use demo_circuit::constraints::CeasedSidechainWithdrawalCircuit;

use super::*;
use crate::{rust_jni::{
    utxo::parse_sc_utxo_output,
    fwt::parse_sc_ft_output,
    proving_system::get_proving_system_type,
    cert::parse_wcert,
}, cctp_calls::csw::{debug_csw_circuit, create_csw_proof, verify_csw_proof}};

// Map a JObject which is a Java's Optional<FieldElement> into Option<JObject>.
// If Option is present, converts it into an Option<FieldElement>, otherwise converts it to None.
fn parse_opt_field_element_from_jobject<'a>(
    _env: &'a JNIEnv,
    _obj: JObject<'a>,
    field_name: &'a str
) -> Option<FieldElement> {
    parse_joption_from_jobject(&_env, _obj, field_name).map(|field_object|
        *parse_rust_struct_from_jobject::<FieldElement>(&_env, field_object, "fieldElementPointer")
    )
}

fn parse_sys_data(_env: JNIEnv, _sys_data: JObject) -> Result<(Option<FieldElement>, CswSysData), Error> {
    let constant = parse_rust_struct_from_composite_jobject(
        &_env,
        _sys_data,
        "constant",
        "io/horizen/common/librustsidechains/FieldElement",
        "fieldElementPointer"
    );

    let sys_data = CswSysData::new(
        parse_opt_field_element_from_jobject(&_env, _sys_data, "mcbScTxsComEnd"),
        parse_opt_field_element_from_jobject(&_env, _sys_data, "scLastWcertHash"),
        parse_long_from_jobject(&_env, _sys_data, "amount") as u64,
        *parse_rust_struct_from_composite_jobject::<FieldElement>(
            &_env,
            _sys_data,
            "nullifier",
            "io/horizen/common/librustsidechains/FieldElement",
            "fieldElementPointer"
        ),
        parse_fixed_size_byte_array_from_jobject::<MC_PK_SIZE>(&_env, _sys_data, "receiver")?,
    );

    Ok((*constant, sys_data))
}

fn parse_utxo_prover_data(_env: JNIEnv, _utxo_data: JObject) -> Result<CswUtxoProverData, Error> {
    // Parse utxo output
    let output = {
        let utxo_out_obj = parse_jobject_from_jobject(
            &_env,
            _utxo_data,
            "output",
            "com/horizen/scutxonative/ScUtxoOutput"
        );
        parse_sc_utxo_output(&_env, utxo_out_obj)
    }?;

    // Parse input

    // Parse secret key
    let secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS] = {
        // Parse sk bytes
        let sk_bytes = parse_fixed_size_byte_array_from_jobject::<SC_SECRET_KEY_LENGTH>(
            &_env,
            _utxo_data,
            "utxoInputSecretKey",
        )?;

        // Interpret bytes as a LE integer and read a SimulatedScalarFieldElement out of it
        // reducing it if required
        let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

        // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
        let mut sk_bits = sk.write_bits();
        sk_bits.reverse();
        sk_bits.try_into().unwrap() // Cannot fail as we have parsed exactly the required amount of bits
    };

    let input = CswUtxoInputData { output, secret_key };

    // Parse mst_path_to_output
    let mst_path_to_output = *parse_rust_struct_from_composite_jobject::<GingerMHTBinaryPath>(
        &_env,
        _utxo_data,
        "mstPathToOutput",
        "io/horizen/common/merkletreenative/FieldBasedMerklePath",
        "merklePathPointer"
    );

    Ok(
        CswUtxoProverData {
            input,
            mst_path_to_output,
        }
    )

}

fn parse_ft_prover_data(_env: JNIEnv, _ft_data: JObject) -> Result<CswFtProverData, Error> {
    // Parse ForwardTransferOutput
    let ft_output = {
        let ft_out_obj = parse_jobject_from_jobject(
            &_env,
            _ft_data,
            "output",
            "com/horizen/fwtnative/ForwardTransferOutput"
        );

        parse_sc_ft_output(&_env, ft_out_obj)
    }?;

    // Parse merkle_path_to_sc_hash
    let merkle_path_to_sc_hash  = *parse_rust_struct_from_composite_jobject::<GingerMHTBinaryPath>(
        &_env,
        _ft_data,
        "merklePathToScHash",
        "io/horizen/common/merkletreenative/FieldBasedMerklePath",
        "merklePathPointer"
    );

    // Parse ft_tree_path
    let ft_tree_path  = *parse_rust_struct_from_composite_jobject::<GingerMHTBinaryPath>(
        &_env,
        _ft_data,
        "ftTreePath",
        "io/horizen/common/merkletreenative/FieldBasedMerklePath",
        "merklePathPointer"
    );

    // Parse sc_txs_com_hashes
    let sc_txs_com_hashes_list_obj = parse_jobject_array_from_jobject(
        &_env,
        _ft_data,
        "scTxsComHashes",
        "com/horizen/librustsidechains/FieldElement",
    );

    let mut sc_txs_com_hashes = vec![];

    parse_rust_struct_vec_from_jobject_array!(
        &_env,
        sc_txs_com_hashes_list_obj,
        sc_txs_com_hashes,
        "sc_txs_com_hashes",
        "fieldElementPointer"
    );

    // Parse secret key
    let ft_input_secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS] = {
        // Parse sk bytes
        let sk_bytes = parse_fixed_size_byte_array_from_jobject::<SC_SECRET_KEY_LENGTH>(
            &_env,
            _ft_data,
            "ftInputSecretKey",
        )?;

        // Interpret bytes as a LE integer and read a SimulatedScalarFieldElement out of it
        // reducing it if required
        let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

        // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
        let mut sk_bits = sk.write_bits();
        sk_bits.reverse();
        sk_bits.try_into().unwrap() // Cannot fail as we have parsed exactly the required amount of bits
    };

    Ok(
        CswFtProverData {
            ft_output,
            ft_input_secret_key,
            mcb_sc_txs_com_start: *parse_rust_struct_from_composite_jobject::<FieldElement>(
                &_env,
                _ft_data,
                "mcbScTxsComStart",
                "io/horizen/common/librustsidechains/FieldElement",
                "fieldElementPointer"
            ),
            merkle_path_to_sc_hash,
            ft_tree_path,
            sc_creation_commitment: *parse_rust_struct_from_composite_jobject::<FieldElement>(
                &_env,
                _ft_data,
                "scCreationCommitment",
                "io/horizen/common/librustsidechains/FieldElement",
                "fieldElementPointer"
            ),
            scb_btr_tree_root: *parse_rust_struct_from_composite_jobject::<FieldElement>(
                &_env,
                _ft_data,
                "scbBtrTreeRoot",
                "io/horizen/common/librustsidechains/FieldElement",
                "fieldElementPointer"
            ),
            wcert_tree_root: *parse_rust_struct_from_composite_jobject::<FieldElement>(
                &_env,
                _ft_data,
                "wCertTreeRoot",
                "io/horizen/common/librustsidechains/FieldElement",
                "fieldElementPointer"
            ),
            sc_txs_com_hashes: sc_txs_com_hashes.into_iter().cloned().collect(),
        }
    )
}

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
    ) {
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
        ok_or_throw_exc!(
            _env,
            generate_circuit_keypair(
                circ,
                proving_system,
                supported_degree,
                proving_key_path.to_str().unwrap(),
                verification_key_path.to_str().unwrap(),
                _max_proof_plus_vk_size as usize,
                zk,
                Some(_compress_pk == JNI_TRUE),
                Some(_compress_vk == JNI_TRUE),
            ),
            // TODO: Consider if it's worth to be more expressive here and introduce a SerializationException
            // to be thrown if (pk, vk) generation is successfull but serialization to file fails.
            "com/horizen/provingsystemnative/ProvingSystemException",
            "Unable to generate (pk, vk) for CSW proof"
        )
    }
);

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
        let (constant, sys_data) = ok_or_throw_exc!(
            &_env,
            parse_sys_data(_env, _sys_data),
            "io/horizen/common/librustsidechains/NativeParsingException",
            "Unable to parse csw sys data",
            JNI_NULL
        );

        // Parse csw utxo prover data
        let csw_utxo_prover_data = if _utxo_data.into_inner().is_null() {
            None
        } else {
            let utxo_prover_data = ok_or_throw_exc!(
                &_env,
                parse_utxo_prover_data(_env, _utxo_data),
                "io/horizen/common/librustsidechains/NativeParsingException",
                "Unable to parse utxo prover data",
                JNI_NULL
            );
            Some(utxo_prover_data)
        };

        // Parse csw ft prover data
        let csw_ft_prover_data = if _ft_data.into_inner().is_null() {
            None
        } else {
            let ft_prover_data = ok_or_throw_exc!(
                &_env,
                parse_ft_prover_data(_env, _ft_data),
                "io/horizen/common/librustsidechains/NativeParsingException",
                "Unable to parse ft prover data",
                JNI_NULL
            );
            Some(ft_prover_data)
        };

        // Parse sc_id
        let sc_id = parse_rust_struct_from_jobject::<FieldElement>(&_env, _sc_id, "fieldElementPointer");

        //debug circuit
        let failing_constraint = ok_or_throw_exc!(
            &_env,
            debug_csw_circuit(
                *sc_id,
                constant,
                sys_data,
                cert,
                csw_utxo_prover_data,
                csw_ft_prover_data,
                _range_size as u32,
                _num_custom_fields as u32,
            ),
            "com/horizen/provingsystemnative/ProvingSystemException",
            "Error while debugging circuit",
            JNI_NULL
        );

        // Convert to Optional<String>
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
        let (constant, sys_data) = ok_or_throw_exc!(
            &_env,
            parse_sys_data(_env, _sys_data),
            "io/horizen/common/librustsidechains/NativeParsingException",
            "Unable to parse csw sys data",
            JNI_NULL
        );

        // Parse csw utxo prover data
        let csw_utxo_prover_data = if _utxo_data.into_inner().is_null() {
            None
        } else {
            let utxo_prover_data = ok_or_throw_exc!(
                &_env,
                parse_utxo_prover_data(_env, _utxo_data),
                "io/horizen/common/librustsidechains/NativeParsingException",
                "Unable to parse utxo prover data",
                JNI_NULL
            );
            Some(utxo_prover_data)
        };

        // Parse csw ft prover data
        let csw_ft_prover_data = if _ft_data.into_inner().is_null() {
            None
        } else {
            let ft_prover_data = ok_or_throw_exc!(
                &_env,
                parse_ft_prover_data(_env, _ft_data),
                "io/horizen/common/librustsidechains/NativeParsingException",
                "Unable to parse ft prover data",
                JNI_NULL
            );
            Some(ft_prover_data)
        };

        // Parse sc_id
        let sc_id = parse_rust_struct_from_jobject::<FieldElement>(&_env, _sc_id, "fieldElementPointer");

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
        map_to_jbytearray_or_throw_exc(
            _env,
            create_csw_proof(
                *sc_id,
                constant,
                sys_data,
                cert,
                csw_utxo_prover_data,
                csw_ft_prover_data,
                _range_size as u32,
                _num_custom_fields as u32,
                supported_degree,
                proving_key_path.to_str().unwrap(),
                _check_proving_key == JNI_TRUE,
                _zk == JNI_TRUE,
                _compressed_pk == JNI_TRUE,
            ),
            Some(_compress_proof == JNI_TRUE),
            "csw proof",
            // TODO: Consider if it's worth to be more expressive here and explicitly throw a DeserializationException
            //       if pk deserialization fails, instead of reporting it under a ProvingSystemException    
            "com/horizen/provingsystemnative/ProvingSystemException",
            "Unable to create CSW proof"
        )
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
        let (constant, sys_data) = ok_or_throw_exc!(
            &_env,
            parse_sys_data(_env, _sys_data),
            "io/horizen/common/librustsidechains/NativeParsingException",
            "Unable to parse csw sys data",
            JNI_FALSE
        );

        // Parse sc_id
        let sc_id = parse_rust_struct_from_jobject::<FieldElement>(&_env, _sc_id, "fieldElementPointer");

        //Extract proof
        let proof_bytes = _env
            .convert_byte_array(_sc_proof_bytes)
            .expect("Should be able to convert to Rust byte array");

        //Extract vk path
        let vk_path = _env
            .get_string(_verification_key_path)
            .expect("Should be able to read jstring as Rust String");

        //Verify proof
        map_to_jboolean_or_throw_exc(
            _env,
            verify_csw_proof(
                sc_id,
                constant,
                sys_data,
                proof_bytes,
                _check_proof == JNI_TRUE,
                _compressed_proof == JNI_TRUE,
                vk_path.to_str().unwrap(),
                _check_vk == JNI_TRUE,
                _compressed_vk == JNI_TRUE,
            ),
            // TODO: Consider if it's worth to be more expressive here and explicitly throw a DeserializationException
            //       if pk or proof deserialization fails, instead of reporting it under a ProvingSystemException    
            "com/horizen/provingsystemnative/ProvingSystemException",
            "Error while verifying CSW proof"
        )
    }
);