use super::utils::*;
use super::*;
use cctp_primitives::proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH;

#[serial]
#[test]
fn works() {
    const ITER: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();

    for i in 1..=ITER {
        println!("First cert {} sigs", i);
        let (
            _,
            _,
            genesis_validator_keys_tree_root,
            _,
            withdrawal_certificate,
            wcert_signatures,
            validator_key_updates,
        ) = setup_certificate_data(MAX_PKS, i, true);

        let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
            validator_key_updates,
            wcert_signatures,
            withdrawal_certificate.clone(),
            None,
            i as u64,
            genesis_validator_keys_tree_root,
        );
        assert!(circuit_res.is_ok());
        let circuit = circuit_res.unwrap();

        debug_naive_threshold_circuit(&circuit, false, None);

        let proof =
            CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None)
                .unwrap();

        let public_inputs = [
            circuit.genesis_constant,
            get_cert_data_hash(&withdrawal_certificate),
            PHANTOM_CERT_DATA_HASH,
        ];

        assert!(
            CoboundaryMarlin::verify(&params.1.clone(), &ck_g1, &public_inputs, &proof).unwrap()
        );
    }
}

#[serial]
#[test]
fn with_prev_cert_fails() {
    let num_sigs: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, num_sigs, true);
    let prev_withdrawal_certificate = create_withdrawal_certificate();

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate),
        num_sigs as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();


    debug_naive_threshold_circuit(&circuit, true, Some("enforce current root equals the one in prev cert if present/conditional_equals"));

    let proof_res =
        CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None);
    assert!(proof_res.is_err());
}

#[serial]
#[test]
fn wrong_genesis_constant() {
    let num_sigs: usize = 5;

    let mut rng = thread_rng();
    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
    let (_, _, genesis_validator_keys_tree_root, _, withdrawal_certificate, wcert_signatures, validator_key_updates) =
        setup_certificate_data(MAX_PKS, num_sigs, true);

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate.clone(),
        None,
        num_sigs as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();

    circuit.genesis_validator_keys_tree_root = rng.gen();

    debug_naive_threshold_circuit(&circuit, true, Some("genesis_constant: expected == actual/conditional_equals"));

    let proof_res =
        CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None);
    assert!(proof_res.is_err());
}

#[serial]
#[test]
fn wrong_cert_signed() {
    const NUM_SIGS: usize = 5;

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        _withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, NUM_SIGS, true);

    let wrong_withdrawal_cert = create_withdrawal_certificate();

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        wrong_withdrawal_cert,
        None,
        NUM_SIGS as u64,
        genesis_validator_keys_tree_root,
    );

    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("threshold check/conditional_equals"));
}

#[serial]
#[test]
fn signing_key_rotation_works() {
    const NUM_SIGS: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        _,
        mut withdrawal_certificate,
        wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, NUM_SIGS, true);

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

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        None,
        NUM_SIGS as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("enforce new root equals the one in curr cert/conditional_equals"));

    let proof_res =
        CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None);
    assert!(proof_res.is_err());

    withdrawal_certificate.custom_fields[0] = validator_key_updates
        .get_upd_validators_keys_root()
        .unwrap();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks[..NUM_SIGS],
        &validator_key_updates.signing_keys[..NUM_SIGS],
        msg_to_sign,
    );

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate.clone(),
        None,
        NUM_SIGS as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let proof_res =
        CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None);

    let proof = proof_res.unwrap();

    let public_inputs = [
        circuit.genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        PHANTOM_CERT_DATA_HASH,
    ];

    assert!(CoboundaryMarlin::verify(&params.1.clone(), &ck_g1, &public_inputs, &proof).unwrap());
}

#[serial]
#[test]
fn master_key_rotation_works() {
    const NUM_SIGS: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        _,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, NUM_SIGS, true);

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
        validator_key_updates.clone(),
        wcert_signatures,
        withdrawal_certificate.clone(),
        None,
        NUM_SIGS as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let proof_res =
        CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None);
    assert!(proof_res.is_ok());

    let proof = proof_res.unwrap();
    withdrawal_certificate.quality = MAX_PKS as u64;

    let public_inputs = [
        circuit.genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        PHANTOM_CERT_DATA_HASH,
    ];

    assert!(CoboundaryMarlin::verify(&params.1.clone(), &ck_g1, &public_inputs, &proof).unwrap());
}

#[serial]
#[test]
fn below_threshold() {
    const NUM_SIGS: usize = 5;

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, NUM_SIGS - 1, true);

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        None,
        NUM_SIGS as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, true, Some("threshold check/conditional_equals"));
}

#[serial]
#[test]
fn below_threshold_faulty_signature() {
    const NUM_SIGS: usize = 2;

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, NUM_SIGS, true);

    //wcert_signatures[0] = Some(SchnorrSig::new(thread_rng().gen(), thread_rng().gen()));

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        None,
        NUM_SIGS as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();
    let mut rng = thread_rng();
    let to_be_changed_signature =  rng.gen_range(0..NUM_SIGS);
    circuit.wcert_signatures[to_be_changed_signature] = SchnorrSig::new(rng.gen(), rng.gen());
    debug_naive_threshold_circuit(&circuit, true, Some("valid_signatures == quality/conditional_equals"));
}
