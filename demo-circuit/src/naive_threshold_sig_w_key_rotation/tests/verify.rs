use super::super::*;
use super::*;

#[serial]
#[test]
fn verify_malicious_proof() {
    // prover uses faulty inputs to try to trick the verifier
    const THRESHOLD: usize = 4;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
    let (
        _signing_keys_sks,
        _master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD - 1, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = (THRESHOLD - 1) as u64;

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        (THRESHOLD - 1) as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    let proof =
        CoboundaryMarlin::prove(&params.0, &ck_g1, circuit, false, None).unwrap();

    // verifier genesis constant
    let verifier_genesis_constant = FieldHash::init_constant_length(2, None)
        .update(genesis_validator_keys_tree_root)
        .update(FieldElement::from(THRESHOLD as u64))
        .finalize()
        .unwrap();

    let public_inputs = [
        verifier_genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        get_cert_data_hash(&prev_withdrawal_certificate),
    ];

    assert!(!CoboundaryMarlin::verify(&params.1, &ck_g1, &public_inputs, &proof).unwrap());
}
#[derive(Debug)]
enum MaliciousKeyRotations {
    SigningKey,
    MasterKey,
}

const VARIANTS: [MaliciousKeyRotations; 2] = [
    MaliciousKeyRotations::SigningKey,
    MaliciousKeyRotations::MasterKey,
];

#[serial]
#[test]
fn malicious_current_keys() {
    const THRESHOLD: usize = 4;

    let (
        mut signing_keys_sks,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        mut wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, true);
    let mut rng = thread_rng();
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
    let correct_signing_keys = signing_keys_sks.clone();
    let original_validator_key_updates = validator_key_updates.clone();
    let original_signatures = wcert_signatures.clone();
    for test_type in VARIANTS.iter() {
        for &resign_certificate in [false, true].iter() {
            // When a current signing key is crafted, we consider 2 cases:
            // - The certificate is not signed with the crafted key: in this case we check that
            //  the threshold requirement is no longer met (unless the crafted key was among the
            //  ones not employed for valid signatures)
            // - The certificate is signed with the crafted key: in this case we check the mismatch
            //  between the merkle root of the current keys found in the certificate and the
            //  one computed from the crafted set.
            // In case a current master ket is crafted, then there is no need to distinguish between
            // these 2 cases, as master keys are not employed to sign certificates
            signing_keys_sks = correct_signing_keys.clone();
            validator_key_updates = original_validator_key_updates.clone();
            wcert_signatures = original_signatures.clone();
            let key_to_be_changed = rng.gen_range(0..MAX_PKS);
            // `should_signature_fail` is true if the circuit is expected to be unsatisfied because
            // there are not enough valid signatures, false otherwise
            let should_signature_fail = match *test_type {
                MaliciousKeyRotations::SigningKey => {
                    signing_keys_sks[key_to_be_changed] = sk;
                    validator_key_updates.signing_keys[key_to_be_changed] = pk;
                    validator_key_updates.updated_signing_keys[key_to_be_changed] = pk;
                    if resign_certificate {
                        let msg_to_sign = cert_to_msg(&withdrawal_certificate);

                        wcert_signatures = create_signatures(
                            MAX_PKS,
                            &signing_keys_sks[..THRESHOLD],
                            &validator_key_updates.signing_keys[..THRESHOLD],
                            msg_to_sign,
                        );
                        // Enough valid signatures, so `should_signature_fail=false`
                        false
                    } else {
                        if key_to_be_changed < THRESHOLD {
                            // signatures will fail only if the changed key was already employed
                            // for a valid signature
                            true
                        } else {
                            false
                        }
                    }
                },
                MaliciousKeyRotations::MasterKey => {
                    validator_key_updates.master_keys[key_to_be_changed] = pk;
                    validator_key_updates.updated_master_keys[key_to_be_changed] = pk;
                    if resign_certificate {
                        // no need to resign certificate for master keys as they are not employed to sign
                        continue
                    }
                    false // master key are not employed to sign certificates, so signature will never fail
                }
            };

            let mut prev_withdrawal_certificate = create_withdrawal_certificate();
            prev_withdrawal_certificate.custom_fields[0] = genesis_validator_keys_tree_root;

            let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
                validator_key_updates.clone(),
                wcert_signatures.clone(),
                withdrawal_certificate.clone(),
                Some(prev_withdrawal_certificate.clone()),
                THRESHOLD as u64,
                genesis_validator_keys_tree_root,
            );
            assert!(circuit_res.is_ok());
            let circuit = circuit_res.unwrap();

            debug_naive_threshold_circuit(&circuit, true, if should_signature_fail {
                Some("threshold check/conditional_equals")
            } else {
                // in this case there are enough valid signatures, so the circuit is expected to be
                // unsatisfied because of a mismatch between the Merkle-root found in the
                // certificate and the one computed from the crafted set of keys
                Some("enforce current root equals the one in prev cert if present/conditional_equals")
            });

            // Now try without previous withdrawal certificate
            let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
                validator_key_updates.clone(),
                wcert_signatures.clone(),
                withdrawal_certificate.clone(),
                None,
                THRESHOLD as u64,
                genesis_validator_keys_tree_root,
            );
            assert!(circuit_res.is_ok());
            let circuit = circuit_res.unwrap();

            debug_naive_threshold_circuit(&circuit, true, if should_signature_fail {
                Some("threshold check/conditional_equals")
            } else {
                // in this case there are enough valid signatures, so the circuit is expected to be
                // unsatisfied because of a mismatch between the genesis key root and the one
                // computed from the crafted set of keys
                Some("enforce current root equals genesis one if prev cert is not present/conditional_equals")
            });
        }

    }
}

#[serial]
#[test]
fn malicious_key_rotations() {
    const THRESHOLD: usize = 4;

    let (
        signing_keys_sks,
        _master_keys_sks,
        genesis_validator_keys_tree_root,
        _,
        mut withdrawal_certificate,
        mut wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    let mut rng = thread_rng();
    let original_validator_key_updates = validator_key_updates.clone();
    let original_signatures = wcert_signatures.clone();
    let original_certificate = withdrawal_certificate.clone();

    for test_type in VARIANTS.iter() {
        for &change_signature in [false, true].iter() {
            // when change_signature is true, we assume that the attacker has compromised the
            // signing key of a validator and wants to change either the signing key or
            // the master key to new keys unknown to the compromised validator; therefore,
            // the attacker can correctly compute the signatures on new crafted keys with the
            // compromised old signing key
            validator_key_updates = original_validator_key_updates.clone();
            wcert_signatures = original_signatures.clone();
            withdrawal_certificate = original_certificate.clone();

            let (pk, _sk) = SchnorrSigScheme::keygen(&mut thread_rng());
            let (master_pk, master_sk) = SchnorrSigScheme::keygen(&mut thread_rng());
            let key_to_be_changed = rng.gen_range(0..MAX_PKS);
            let failing_constraint = match *test_type {
                MaliciousKeyRotations::SigningKey => {
                    validator_key_updates.updated_signing_keys[key_to_be_changed] = pk;
                    if change_signature {
                        let updated_msg = ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(&pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap();
                        validator_key_updates.updated_signing_keys_sk_signatures[key_to_be_changed] =
                            SchnorrSigScheme::sign(&mut rng, &validator_key_updates.signing_keys[key_to_be_changed], &signing_keys_sks[key_to_be_changed], updated_msg).unwrap();
                        validator_key_updates.updated_signing_keys_mk_signatures[key_to_be_changed] =
                            SchnorrSigScheme::sign(&mut rng, &master_pk, &master_sk, updated_msg).unwrap();
                        // in this case the attacker can correctly compute
                        // `updated_signing_keys_sk_signatures[key_to_be_changed]`, so we expect
                        // the signature with the old master key to be invalid
                        format!("check key changes/check updated signing key should be signed old master key {}/conditional verify signature/conditional_equals", key_to_be_changed)
                    } else {
                        // instead here both the signatures should be invalid, so we check for
                        // the failure of the signature with the old signing key
                        format!("check key changes/check updated signing key should be signed old signing key {}/conditional verify signature/conditional_equals", key_to_be_changed)
                    }
                },
                MaliciousKeyRotations::MasterKey => {
                    validator_key_updates.updated_master_keys[key_to_be_changed] = pk;
                    if change_signature {
                        let updated_msg = ValidatorKeysUpdates::get_msg_to_sign_for_master_key_update(&pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap();
                        validator_key_updates.updated_master_keys_sk_signatures[key_to_be_changed] =
                            SchnorrSigScheme::sign(&mut rng, &validator_key_updates.signing_keys[key_to_be_changed], &signing_keys_sks[key_to_be_changed], updated_msg).unwrap();
                        validator_key_updates.updated_master_keys_mk_signatures[key_to_be_changed] =
                            SchnorrSigScheme::sign(&mut rng, &master_pk, &master_sk, updated_msg).unwrap();
                        // in this case the attacker can correctly compute
                        // `updated_master_keys_sk_signatures[key_to_be_changed]`, so we expect
                        // the signature with the old master key to be invalid
                        format!("check key changes/check updated master key should be signed old master key {}/conditional verify signature/conditional_equals", key_to_be_changed)
                    } else {
                        // instead here both the signatures should be invalid, so we check for
                        // the failure of the signature with the old signing key
                        format!("check key changes/check updated master key should be signed old signing key {}/conditional verify signature/conditional_equals", key_to_be_changed)
                    }
                }
            };

            if change_signature {
                // in this case we suppose the attacker knows the signing key, so the
                // validators keys root can also be changed
                withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root().unwrap();

                let msg_to_sign = cert_to_msg(&withdrawal_certificate);

                wcert_signatures = create_signatures(
                    MAX_PKS,
                    &signing_keys_sks[..THRESHOLD],
                    &validator_key_updates.signing_keys[..THRESHOLD],
                    msg_to_sign,
                );
            }

            let mut prev_withdrawal_certificate = create_withdrawal_certificate();
            prev_withdrawal_certificate.custom_fields[0] = genesis_validator_keys_tree_root;

            let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
                validator_key_updates.clone(),
                wcert_signatures.clone(),
                withdrawal_certificate.clone(),
                Some(prev_withdrawal_certificate.clone()),
                THRESHOLD as u64,
                genesis_validator_keys_tree_root,
            );
            assert!(circuit_res.is_ok());
            let circuit = circuit_res.unwrap();

            debug_naive_threshold_circuit(&circuit, true, Some(failing_constraint.as_str()));

            // Now try without previous withdrawal certificate
            let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
                validator_key_updates.clone(),
                wcert_signatures.clone(),
                withdrawal_certificate.clone(),
                None,
                THRESHOLD as u64,
                genesis_validator_keys_tree_root,
            );
            assert!(circuit_res.is_ok());
            let circuit = circuit_res.unwrap();

            debug_naive_threshold_circuit(&circuit, true, Some(failing_constraint.as_str()));
        }
    }

    // check that the Merkle root of the updated set of keys is checked against the validator root
    // in the current certificate: in this test we correctly update either a signing key or a master
    // key but we don't update the Merkle root in the custom field of the current certificate
    for test_type in VARIANTS.iter() {
        validator_key_updates = original_validator_key_updates.clone();

        match *test_type {
            MaliciousKeyRotations::SigningKey => rotate_key(
                &signing_keys_sks[0],
                &validator_key_updates.signing_keys[0],
                &_master_keys_sks[0],
                &validator_key_updates.master_keys[0],
                &mut validator_key_updates.updated_signing_keys_sk_signatures[0],
                &mut validator_key_updates.updated_signing_keys_mk_signatures[0],
                None,
                &mut validator_key_updates.updated_signing_keys[0],
                |pk| ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap()
            ),
            MaliciousKeyRotations::MasterKey => rotate_key(
                &signing_keys_sks[0],
                &validator_key_updates.signing_keys[0],
                &_master_keys_sks[0],
                &validator_key_updates.master_keys[0],
                &mut validator_key_updates.updated_master_keys_sk_signatures[0],
                &mut validator_key_updates.updated_master_keys_mk_signatures[0],
                None,
                &mut validator_key_updates.updated_master_keys[0],
                |pk| ValidatorKeysUpdates::get_msg_to_sign_for_master_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap()
            ),
        }

        let mut prev_withdrawal_certificate = create_withdrawal_certificate();
        prev_withdrawal_certificate.custom_fields[0] = genesis_validator_keys_tree_root;

        let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
            validator_key_updates.clone(),
            original_signatures.clone(),
            original_certificate.clone(),
            Some(prev_withdrawal_certificate.clone()),
            THRESHOLD as u64,
            genesis_validator_keys_tree_root,
        );
        assert!(circuit_res.is_ok());
        let circuit = circuit_res.unwrap();

        debug_naive_threshold_circuit(&circuit, true, Some("enforce new root equals the one in curr cert/conditional_equals"));

        // Now try without previous withdrawal certificate
        let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
            validator_key_updates.clone(),
            wcert_signatures.clone(),
            withdrawal_certificate.clone(),
            None,
            THRESHOLD as u64,
            genesis_validator_keys_tree_root,
        );
        assert!(circuit_res.is_ok());
        let circuit = circuit_res.unwrap();

        debug_naive_threshold_circuit(&circuit, true, Some("enforce new root equals the one in curr cert/conditional_equals"));
    }
}

/*#[serial]
#[test]
fn malicious_master_key_rotation() {
    const THRESHOLD: usize = 4;
    let (
        signing_keys_sks,
        _master_keys_sks,
        genesis_validator_keys_tree_root,
        withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD);
    let mut rng = thread_rng();
    let original_validator_key_updates = validator_key_updates.clone();
    // Change one signer but use malicious master key
    let (pk, _sk) = SchnorrSigScheme::keygen(&mut thread_rng());
    let (master_pk, master_sk) = SchnorrSigScheme::keygen(&mut thread_rng());
    let updated_msg = updated_key_msg(pk);
    validator_key_updates.updated_signing_keys[0] = pk;
    validator_key_updates.updated_signing_keys_sk_signatures[0] =
        SchnorrSigScheme::sign(&mut rng, &validator_key_updates.signing_keys[0], &signing_keys_sks[0], updated_msg).unwrap();
    validator_key_updates.updated_signing_keys_mk_signatures[0] =
        SchnorrSigScheme::sign(&mut rng, &master_pk, &master_sk, updated_msg).unwrap();
    let mut prev_withdrawal_certificate = create_withdrawal_certificate();
    prev_withdrawal_certificate.custom_fields[0] = genesis_validator_keys_tree_root;
    prev_withdrawal_certificate.quality = THRESHOLD as u64;
    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks[..THRESHOLD],
        &validator_key_updates.signing_keys[..THRESHOLD],
        msg_to_sign,
    );
    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures.clone(),
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();
    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated signing key should be signed old master key 0/conditional verify signature/conditional_equals"));
    // Now try without previous withdrawal certificate
    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures.clone(),
        withdrawal_certificate.clone(),
        None,
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();
    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated signing key should be signed old master key 0/conditional verify signature/conditional_equals"));
    validator_key_updates = original_validator_key_updates.clone();
    let updated_msg = updated_key_msg(master_pk);
    validator_key_updates.updated_master_keys[0] = master_pk;
    validator_key_updates.updated_master_keys_sk_signatures[0] =
        SchnorrSigScheme::sign(&mut rng, &validator_key_updates.signing_keys[0], &signing_keys_sks[0], updated_msg).unwrap();
    validator_key_updates.updated_master_keys_mk_signatures[0] =
        SchnorrSigScheme::sign(&mut rng, &master_pk, &master_sk, updated_msg).unwrap();
    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures.clone(),
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();
    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated master key should be signed old master key 0/conditional verify signature/conditional_equals"));
    // Now try without previous withdrawal certificate
    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        None,
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();
    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated master key should be signed old master key 0/conditional verify signature/conditional_equals"));
}*/


#[serial]
#[test]
fn multiple_custom_fields() {
    const THRESHOLD: usize = 4;
    const CUSTOM_FIELDS: usize = 5;

    let (
        signing_keys_sks,
        _master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();

    let mut rng = thread_rng();
    while withdrawal_certificate.custom_fields.len() < CUSTOM_FIELDS {
        withdrawal_certificate.custom_fields.push(rng.gen());
        prev_withdrawal_certificate.custom_fields.push(rng.gen());
    }

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
            &signing_keys_sks[..THRESHOLD],
        &validator_key_updates.signing_keys[..THRESHOLD],
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);
}

#[serial]
#[test]
fn bad_custom_fields() {
    const THRESHOLD: usize = 4;
    const CUSTOM_FIELDS: usize = 5;

    let (
        signing_keys_sks,
        _master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();

    let mut rng = thread_rng();
    while withdrawal_certificate.custom_fields.len() < CUSTOM_FIELDS {
        withdrawal_certificate.custom_fields.push(rng.gen());
        prev_withdrawal_certificate.custom_fields.push(rng.gen());
    }
    withdrawal_certificate.custom_fields[0] = rng.gen();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks[..THRESHOLD],
        &validator_key_updates.signing_keys[..THRESHOLD],
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("enforce new root equals the one in curr cert/conditional_equals"));
}

// check that it is not possible to perform a replay attack even if a validator chooses as a
// signing/master key a key `k` that was already used in previous epochs.
// Indeed, in this case, the attacker may try to re-use the signatures computed by the validator in
// a previous epoch to update key `k` to another key `new_k`, with the extent of changing again
// key `k` to `new_k` also in the current epoch
#[serial]
#[test]
fn test_replay_attack() {
    const THRESHOLD: usize = 4;
    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        _,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, true);

    let mut updated_signing_key_sk = signing_keys_sks[0];
    rotate_key(
        &signing_keys_sks[0],
        &validator_key_updates.signing_keys[0],
        &master_keys_sks[0],
        &validator_key_updates.master_keys[0],
        &mut validator_key_updates.updated_signing_keys_sk_signatures[0],
        &mut validator_key_updates.updated_signing_keys_mk_signatures[0],
        Some(&mut updated_signing_key_sk),
        &mut validator_key_updates.updated_signing_keys[0],
        |pk| ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
    );

    withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root()
        .unwrap();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks,
        &validator_key_updates.signing_keys,
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        None,
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let old_signing_key = validator_key_updates.signing_keys[0];
    let old_update_signature_with_sk = validator_key_updates.updated_signing_keys_sk_signatures[0];
    let old_update_signature_with_mk = validator_key_updates.updated_signing_keys_mk_signatures[0];
    let old_epoch_id = withdrawal_certificate.epoch_id;

    // in the next epoch the validator sets back the signing key to the previous one
    let prev_withdrawal_certificate = withdrawal_certificate;
    withdrawal_certificate = create_withdrawal_certificate();
    validator_key_updates.signing_keys[0] = validator_key_updates.updated_signing_keys[0];
    validator_key_updates.master_keys[0] = validator_key_updates.updated_master_keys[0];
    validator_key_updates.updated_signing_keys[0] = old_signing_key;
    let mut rng = thread_rng();
    let updated_msg = ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(&validator_key_updates.updated_signing_keys[0], withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap();
    validator_key_updates.updated_signing_keys_sk_signatures[0] =
        SchnorrSigScheme::sign(&mut rng, &validator_key_updates.signing_keys[0], &updated_signing_key_sk, updated_msg).unwrap();
    validator_key_updates.updated_signing_keys_mk_signatures[0] =
        SchnorrSigScheme::sign(&mut rng, &validator_key_updates.master_keys[0], &master_keys_sks[0], updated_msg).unwrap();

    withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root()
        .unwrap();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks,
        &validator_key_updates.signing_keys,
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    // now the attacker can try to mount the replay attack, re-updating the old signing key to the
    // previous signing key
    let to_be_restored_signing_key = validator_key_updates.signing_keys[0];
    let prev_withdrawal_certificate = withdrawal_certificate;
    withdrawal_certificate = create_withdrawal_certificate();
    validator_key_updates.signing_keys[0] = validator_key_updates.updated_signing_keys[0];
    validator_key_updates.master_keys[0] = validator_key_updates.updated_master_keys[0];
    validator_key_updates.updated_signing_keys[0] = to_be_restored_signing_key;
    validator_key_updates.updated_signing_keys_sk_signatures[0] = old_update_signature_with_sk;
    validator_key_updates.updated_signing_keys_mk_signatures[0] = old_update_signature_with_mk;

    withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root()
        .unwrap();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks,
        &validator_key_updates.signing_keys,
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated signing key should be signed old signing key 0/conditional verify signature/conditional_equals"));
    // test that the attack does not work because of the current `epoch_id` being employed to
    // compute the signatures for key rotations: this is checked by forcing the `epoch_id` of the
    // current certificate to be the same as the one being employed to compute the old signatures
    withdrawal_certificate.epoch_id = old_epoch_id;
    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks,
        &validator_key_updates.signing_keys,
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);
}

// check that it is not possible for an attacker to employ a legitimate update of the signing key
// performed by the validator to force a master key update in the same epoch (and vice versa).
// In other words, these test verifies that the `SIGNING_KEY_TAG`/`MASTER_KEY_TAG`, which are
// employed to compute signatures to rotate signing/master keys, respectively, makes signatures
// computed to update a signing key to a new key `k` not re-usable to also update the master key
// to the same key `k` (and vice versa)
#[serial]
#[test]
fn test_key_update_from_other_key_update() {
    const THRESHOLD: usize = 5;
    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    // legitimate signing key update
    rotate_key(
        &signing_keys_sks[0],
        &validator_key_updates.signing_keys[0],
        &master_keys_sks[0],
        &validator_key_updates.master_keys[0],
        &mut validator_key_updates.updated_signing_keys_sk_signatures[0],
        &mut validator_key_updates.updated_signing_keys_mk_signatures[0],
        None,
        &mut validator_key_updates.updated_signing_keys[0],
        |pk| ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
    );

    // attacker tries to update also master key to the same key
    validator_key_updates.updated_master_keys[0] = validator_key_updates.updated_signing_keys[0];
    validator_key_updates.updated_master_keys_sk_signatures[0] = validator_key_updates.updated_signing_keys_sk_signatures[0];
    validator_key_updates.updated_master_keys_mk_signatures[0] = validator_key_updates.updated_signing_keys_mk_signatures[0];

    withdrawal_certificate.custom_fields[0] = validator_key_updates
        .get_upd_validators_keys_root()
        .unwrap();

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = THRESHOLD as u64;

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks,
        &validator_key_updates.signing_keys,
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated master key should be signed old signing key 0/conditional verify signature/conditional_equals"));

    // we also try the other way round: attacker tries to update the signing key from a legitimate update to the master key
    rotate_key(
        &signing_keys_sks[0],
        &validator_key_updates.signing_keys[0],
        &master_keys_sks[0],
        &validator_key_updates.master_keys[0],
        &mut validator_key_updates.updated_master_keys_sk_signatures[0],
        &mut validator_key_updates.updated_master_keys_mk_signatures[0],
        None,
        &mut validator_key_updates.updated_master_keys[0],
        |pk| ValidatorKeysUpdates::get_msg_to_sign_for_master_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
    );

    // attacker tries to update also signing key to the same key
    validator_key_updates.updated_signing_keys[0] = validator_key_updates.updated_master_keys[0];
    validator_key_updates.updated_signing_keys_sk_signatures[0] = validator_key_updates.updated_master_keys_sk_signatures[0];
    validator_key_updates.updated_signing_keys_mk_signatures[0] = validator_key_updates.updated_master_keys_mk_signatures[0];

    withdrawal_certificate.custom_fields[0] = validator_key_updates
        .get_upd_validators_keys_root()
        .unwrap();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks,
        &validator_key_updates.signing_keys,
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated signing key should be signed old signing key 0/conditional verify signature/conditional_equals"));
}