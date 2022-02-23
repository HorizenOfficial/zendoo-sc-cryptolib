use super::*;
use crate::cctp_calls::cert::*;

pub(crate) fn parse_wcert(_env: JNIEnv, _cert: JObject) -> WithdrawalCertificateData {
    // Parse sc_id
    let sc_id = *parse_rust_struct_from_jobject::<FieldElement>(&_env, _cert, "scId");

    // Parse epoch number
    let epoch_number = parse_int_from_jobject(&_env, _cert, "epochNumber");

    //Extract backward transfers
    let bt_list_obj = parse_jobject_array_from_jobject(
        &_env,
        _cert,
        "btList",
        "com/horizen/certnative/BackwardTransfer",
    );
    let mut bt_list = vec![];

    let bt_list_size = _env
        .get_array_length(bt_list_obj)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env
                .get_object_array_element(bt_list_obj, i)
                .unwrap_or_else(|_| panic!("Should be able to get elem {} of bt_list array", i));

            let p = _env
                .call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method")
                .l()
                .unwrap()
                .cast();

            let pk: [u8; MC_PK_SIZE] = _env
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

    // Extract custom fields
    let custom_fields_list_obj = parse_jobject_array_from_jobject(
        &_env,
        _cert,
        "customFields",
        "com/horizen/librustsidechains/FieldElement",
    );

    let mut custom_fields = vec![];

    let custom_fields_size = _env
        .get_array_length(custom_fields_list_obj)
        .expect("Should be able to get custom_fields size");

    if custom_fields_size > 0 {
        for i in 0..custom_fields_size {
            let o = _env
                .get_object_array_element(custom_fields_list_obj, i)
                .unwrap_or_else(|_| {
                    panic!("Should be able to get elem {} of custom_fields array", i)
                });

            let field = {
                let f = _env
                    .get_field(o, "fieldElementPointer", "J")
                    .expect("Should be able to get field fieldElementPointer");

                read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
            };

            custom_fields.push(*field);
        }
    }

    // Parse quality
    let quality = parse_long_from_jobject(&_env, _cert, "quality");

    // Parse mcb_sc_txs_com
    let mcb_sc_txs_com = *parse_field_element_from_jobject(&_env, _cert, "mcbScTxsCom");

    // Parse btr_fee
    let btr_min_fee = parse_long_from_jobject(&_env, _cert, "btrMinFee");

    // Parse ft_min_amount
    let ft_min_amount = parse_long_from_jobject(&_env, _cert, "ftMinAmount");

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
    let mut bt_list = vec![];

    let bt_list_size = _env
        .get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env
                .get_object_array_element(_bt_list, i)
                .unwrap_or_else(|_| panic!("Should be able to get elem {} of bt_list array", i));

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

    //Extract Schnorr signatures and the corresponding Schnorr pks
    let mut sigs = vec![];
    let mut pks = vec![];

    let sigs_list_size = _env
        .get_array_length(_schnorr_sigs_list)
        .expect("Should be able to get schnorr_sigs_list size");

    let pks_list_size = _env
        .get_array_length(_schnorr_pks_list)
        .expect("Should be able to get schnorr_pks_list size");

    assert_eq!(sigs_list_size, pks_list_size);

    for i in 0..sigs_list_size {
        //Get i-th sig
        let sig_object = _env
            .get_object_array_element(_schnorr_sigs_list, i)
            .unwrap_or_else(|_| panic!("Should be able to get elem {} of schnorr_sigs_list", i));

        let pk_object = _env
            .get_object_array_element(_schnorr_pks_list, i)
            .unwrap_or_else(|_| panic!("Should be able to get elem {} of schnorr_pks_list", i));

        let signature = {
            let sig = _env
                .get_field(sig_object, "signaturePointer", "J")
                .expect("Should be able to get field signaturePointer");

            read_nullable_raw_pointer(sig.j().unwrap() as *const SchnorrSig).copied()
        };

        let public_key = {
            let pk = _env
                .get_field(pk_object, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(&_env, pk.j().unwrap() as *const SchnorrPk)
        };

        sigs.push(signature);
        pks.push(*public_key);
    }

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
            NaiveTresholdSignature::get_instance_for_setup(max_pks, _num_custom_fields as usize);

        // Read zk value
        let zk = _zk == JNI_TRUE;

        // Generate snark keypair
        match generate_circuit_keypair(
            circ,
            proving_system,
            supported_degree,
            proving_key_path.to_str().unwrap(),
            verification_key_path.to_str().unwrap(),
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

        //Extract constant
        let constant = {
            let c = _env
                .get_field(_constant, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(&_env, c.j().unwrap() as *const FieldElement)
        };

        // Read custom fields if they are present
        let mut custom_fields_list = vec![];

        let custom_fields_list_size = _env
            .get_array_length(_custom_fields_list)
            .expect("Should be able to get custom_fields_list size");

        if custom_fields_list_size > 0 {
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

                custom_fields_list.push(*field);
            }
        }

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
    fn Java_com_horizen_certnative_WithdrawalCertificate_nativeGetHash(
        _env: JNIEnv,
        _cert: JObject,
    ) -> jobject {
        // Parse cert
        let cert = parse_wcert(_env, _cert);

        // Convert custom fields in the expected form
        let custom_fields_hash = if cert.custom_fields.is_empty() {
            None
        } else {
            Some(hash_vec(cert.custom_fields).unwrap())
        };

        // Compute hash
        match get_cert_data_hash_from_bt_root_and_custom_fields_hash(
            &cert.ledger_id,
            cert.epoch_id,
            cert.quality,
            cert.bt_root,
            custom_fields_hash,
            &cert.mcb_sc_txs_com,
            cert.btr_min_fee,
            cert.ft_min_amount,
        ) {
            Ok(digest) => return_field_element(&_env, digest),
            Err(e) => {
                log!(format!("Error while computing cert hash: {:?}", e));
                JObject::null().into_inner()
            }
        }
    }
);