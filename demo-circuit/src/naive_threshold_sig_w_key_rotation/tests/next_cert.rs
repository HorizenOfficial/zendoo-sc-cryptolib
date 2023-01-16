use algebra::{Field, PrimeField, ToBits, UniformRand};
use cctp_primitives::proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH;
use super::utils::*;
use super::*;

#[serial]
#[test]
fn no_key_rotation_works() {
    const ITER: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, ITER, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = ITER as u64;

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        ITER as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let proof =
        CoboundaryMarlin::prove(&params.0, &ck_g1, circuit.clone(), false, None).unwrap();

    let public_inputs = [
        circuit.genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        get_cert_data_hash(&prev_withdrawal_certificate),
    ];

    assert!(CoboundaryMarlin::verify(&params.1, &ck_g1, &public_inputs, &proof).unwrap());
}

#[serial]
#[test]
fn signing_key_rotation_works() {
    const ITER: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();

    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, ITER, false);

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

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = ITER as u64;

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
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        ITER as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let proof =
        CoboundaryMarlin::prove(&params.0, &ck_g1, circuit.clone(), false, None).unwrap();

    withdrawal_certificate.quality = MAX_PKS as u64;

    let public_inputs = [
        circuit.genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        get_cert_data_hash(&prev_withdrawal_certificate),
    ];

    assert!(CoboundaryMarlin::verify(&params.1, &ck_g1, &public_inputs, &proof).unwrap());
}

#[serial]
#[test]
fn master_key_rotation_works() {
    const ITER: usize = 5;

    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();

    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, ITER, false);

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

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = ITER as u64;

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
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        ITER as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let proof =
        CoboundaryMarlin::prove(&params.0, &ck_g1, circuit.clone(), false, None).unwrap();

    withdrawal_certificate.quality = MAX_PKS as u64;

    let public_inputs = [
        circuit.genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        get_cert_data_hash(&prev_withdrawal_certificate),
    ];

    assert!(CoboundaryMarlin::verify(&params.1, &ck_g1, &public_inputs, &proof).unwrap());
}

#[serial]
#[test]
fn multiple_certs_with_rotations() {
    const THRESHOLD: usize = 5;

    let mut rng = thread_rng();
    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
    let (
        mut signing_keys_sks,
        mut master_keys_sks,
        genesis_validator_keys_tree_root,
        mut prev_withdrawal_certificate,
        mut withdrawal_certificate,
        mut wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, true);

    let mut updated_signing_keys_sks = signing_keys_sks.clone();
    let mut updated_master_keys_sks = master_keys_sks.clone();
    let threshold = THRESHOLD;

    let mut scb_validators_keys_root = validator_key_updates.get_upd_validators_keys_root().unwrap();
    withdrawal_certificate.custom_fields[0] = scb_validators_keys_root;



    let genesis_constant = FieldHash::init_constant_length(2, None)
        .update(genesis_validator_keys_tree_root)
        .update(FieldElement::from(threshold as u64))
        .finalize().unwrap();

    for i in 1..=MAX_PKS {
        println!("iteration {}", i);
        let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
            validator_key_updates.clone(),
            wcert_signatures.clone(),
            withdrawal_certificate.clone(),
            prev_withdrawal_certificate.clone(),
            threshold as u64,
            genesis_validator_keys_tree_root,
        );
        assert!(circuit_res.is_ok());
        let circuit = circuit_res.unwrap();

        debug_naive_threshold_circuit(&circuit, false, None);

        let proof =
            CoboundaryMarlin::prove(&params.0.clone(), &ck_g1, circuit.clone(), false, None)
                .unwrap();

        let public_inputs = [
            genesis_constant,
            get_cert_data_hash(&withdrawal_certificate),
            match prev_withdrawal_certificate {
                Some(certificate) => get_cert_data_hash(&certificate),
                None => PHANTOM_CERT_DATA_HASH,
            },
        ];

        assert!(
            CoboundaryMarlin::verify(&params.1.clone(), &ck_g1, &public_inputs, &proof).unwrap()
        );
        signing_keys_sks = updated_signing_keys_sks.clone();
        master_keys_sks = updated_master_keys_sks.clone();
        validator_key_updates.signing_keys = validator_key_updates.updated_signing_keys.clone();
        validator_key_updates.master_keys = validator_key_updates.updated_master_keys.clone();

        validator_key_updates
            .updated_signing_keys_sk_signatures
            .iter_mut()
            .for_each(|s| *s = NULL_CONST.null_sig);
        validator_key_updates
            .updated_signing_keys_mk_signatures
            .iter_mut()
            .for_each(|s| *s = NULL_CONST.null_sig);
        validator_key_updates
            .updated_master_keys_sk_signatures
            .iter_mut()
            .for_each(|s| *s = NULL_CONST.null_sig);
        validator_key_updates
            .updated_master_keys_mk_signatures
            .iter_mut()
            .for_each(|s| *s = NULL_CONST.null_sig);

        let sig_key_changes = rng.gen::<usize>() % MAX_PKS + 1;
        prev_withdrawal_certificate = Some(withdrawal_certificate.clone());
        withdrawal_certificate = create_withdrawal_certificate();

        println!("sig_key_changes = {}", sig_key_changes);

        for i in 0..sig_key_changes {
            rotate_key(
                &signing_keys_sks[i],
                &validator_key_updates.signing_keys[i],
                &master_keys_sks[i],
                &validator_key_updates.master_keys[i],
                &mut validator_key_updates.updated_signing_keys_sk_signatures[i],
                &mut validator_key_updates.updated_signing_keys_mk_signatures[i],
                Some(&mut updated_signing_keys_sks[i]),
                &mut validator_key_updates.updated_signing_keys[i],
                |pk| ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
            );

            rotate_key(
                &signing_keys_sks[i],
                &validator_key_updates.signing_keys[i],
                &master_keys_sks[i],
                &validator_key_updates.master_keys[i],
                &mut validator_key_updates.updated_master_keys_sk_signatures[i],
                &mut validator_key_updates.updated_master_keys_mk_signatures[i],
                Some(&mut updated_master_keys_sks[i]),
                &mut validator_key_updates.updated_master_keys[i],
                |pk| ValidatorKeysUpdates::get_msg_to_sign_for_master_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
            );
        }

        scb_validators_keys_root = validator_key_updates
            .get_upd_validators_keys_root()
            .unwrap();
        withdrawal_certificate.custom_fields[0] = scb_validators_keys_root;
        let valid_sigs = rng.gen_range(threshold..MAX_PKS);
        withdrawal_certificate.quality = valid_sigs as u64;
        let msg_to_sign = cert_to_msg(&withdrawal_certificate);
        wcert_signatures = create_signatures(
            MAX_PKS,
            &signing_keys_sks[..valid_sigs],
            &validator_key_updates.signing_keys[..valid_sigs],
            msg_to_sign,
        );
    }
}

#[serial]
#[test]
fn all_keys_rotated() {
    let ck_g1 = init_g1_committer_key();
    let setup_circuit = NaiveThresholdSignatureWKeyRotation::get_instance_for_setup(MAX_PKS, 1);
    let params = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();
    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, MAX_PKS, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = MAX_PKS as u64;

    let mut updated_signing_sks = signing_keys_sks.clone();
    let mut updated_master_sks = master_keys_sks.clone();
    for i in 0..MAX_PKS {
        rotate_key(
            &signing_keys_sks[i],
            &validator_key_updates.signing_keys[i],
            &master_keys_sks[i],
            &validator_key_updates.master_keys[i],
            &mut validator_key_updates.updated_signing_keys_sk_signatures[i],
            &mut validator_key_updates.updated_signing_keys_mk_signatures[i],
            Some(&mut updated_signing_sks[i]),
            &mut validator_key_updates.updated_signing_keys[i],
            |pk| ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
        );
        rotate_key(
            &signing_keys_sks[i],
            &validator_key_updates.signing_keys[i],
            &master_keys_sks[i],
            &validator_key_updates.master_keys[i],
            &mut validator_key_updates.updated_master_keys_sk_signatures[i],
            &mut validator_key_updates.updated_master_keys_mk_signatures[i],
            Some(&mut updated_master_sks[i]),
            &mut validator_key_updates.updated_master_keys[i],
            |pk| ValidatorKeysUpdates::get_msg_to_sign_for_master_key_update(pk, withdrawal_certificate.epoch_id, withdrawal_certificate.ledger_id).unwrap(),
        );
    }

    withdrawal_certificate.custom_fields[0]  = validator_key_updates
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
        withdrawal_certificate.clone(),
        Some(prev_withdrawal_certificate.clone()),
        MAX_PKS as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let circuit = circuit_res.unwrap();

    debug_naive_threshold_circuit(&circuit, false, None);

    let proof =
        CoboundaryMarlin::prove(&params.0, &ck_g1, circuit.clone(), false, None).unwrap();

    let public_inputs = [
        circuit.genesis_constant,
        get_cert_data_hash(&withdrawal_certificate),
        get_cert_data_hash(&prev_withdrawal_certificate),
    ];

    assert!(CoboundaryMarlin::verify(&params.1, &ck_g1, &public_inputs, &proof).unwrap());
}

#[serial]
#[test]
fn try_to_use_outdated_keys() {
    const THRESHOLD: usize = 3;

    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = THRESHOLD as u64;

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

    withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root().unwrap();
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

    let debug_res = debug_circuit(circuit.clone());
    assert!(debug_res.is_ok());

    debug_naive_threshold_circuit(&circuit, false, None);

    // Now try to use an outdated key
    // first attempt: avoid updating the current set of keys
    let old_signing_keys = validator_key_updates.signing_keys.clone();
    prev_withdrawal_certificate = withdrawal_certificate.clone();

    withdrawal_certificate = create_withdrawal_certificate();
    // we need to recompute the signatures since epoch_id of the current certificate is different
    // from previous one
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
    withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root().unwrap();
    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks[..THRESHOLD],
        &validator_key_updates.signing_keys[..THRESHOLD],
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

    debug_naive_threshold_circuit(&circuit, true, Some("enforce current root equals the one in prev cert if present/conditional_equals"));

    // second attempt: try to use the correct set of keys in the certificate but old signing
    // keys to sign the certificate
    validator_key_updates.updated_signing_keys_sk_signatures[0] = NULL_CONST.null_sig;
    validator_key_updates.updated_signing_keys_mk_signatures[0] = NULL_CONST.null_sig;
    validator_key_updates.signing_keys = validator_key_updates.updated_signing_keys.clone();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks[..THRESHOLD],
        &old_signing_keys[..THRESHOLD],
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

    debug_naive_threshold_circuit(&circuit, true, Some("threshold check/conditional_equals"));
}

#[serial]
#[test]
fn bad_cert_hashes() {
    const THRESHOLD: usize = 3;

    let mut rng = thread_rng();
    let (
        _signing_keys_sks,
        _master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = THRESHOLD as u64;

    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );
    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();

    let correct_cert_hash = circuit.cert_data_hash;
    circuit.cert_data_hash = rng.gen();

    debug_naive_threshold_circuit(&circuit, true, Some("require(sc_wcert_hash == H(wcert)/conditional_equals"));


    circuit.cert_data_hash = correct_cert_hash;
    circuit.prev_cert_data_hash = rng.gen();

    debug_naive_threshold_circuit(&circuit, true, Some("require(sc_prev_wcert_hash == H(prev_wcert)/conditional_equals"));

}

#[serial]
#[test]
fn test_wrong_first_certificate_flag() {
    const THRESHOLD: usize = MAX_PKS/2;

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, true);


    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates.clone(),
        wcert_signatures.clone(),
        withdrawal_certificate.clone(),
        None,
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );

    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();

    // provers sets is_first_certificate to false when it should be true
    circuit.is_first_certificate = false;

    debug_naive_threshold_circuit(&circuit, true,
                                  Some("require(sc_prev_wcert_hash == H(prev_wcert)/conditional_equals"));

    let prev_withdrawal_certificate = create_withdrawal_certificate();
    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        Some(prev_withdrawal_certificate),
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );

    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();

    // prover sets is_first_certificate to true when it should be false
    circuit.is_first_certificate = true;

    debug_naive_threshold_circuit(&circuit, true,
                          Some("require(sc_prev_wcert_hash == H(prev_wcert)/conditional_equals"));
}

#[serial]
#[test]
fn test_wrong_threshold() {
    const THRESHOLD: usize = MAX_PKS/2;

    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, true);


    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        None,
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );

    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();

    circuit.threshold = FieldElement::zero();
    // Update b to ensure that b = valid_signatures - threshold
    let b_bits = (FieldElement::from(circuit.valid_signatures as u64) - circuit.threshold).write_bits();
    let to_skip = FieldElement::size_in_bits() - circuit.b.len();
    circuit.b = b_bits[to_skip..].to_vec();

    debug_naive_threshold_circuit(&circuit, true,
                                  Some("genesis_constant: expected == actual/conditional_equals"));
}

#[serial]
#[test]
fn test_wrong_quality() {
    const THRESHOLD: usize = MAX_PKS/2;
    let mut rng = thread_rng();
    let (
        _,
        _,
        genesis_validator_keys_tree_root,
        _,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, MAX_PKS-1, true);


    let circuit_res = NaiveThresholdSignatureWKeyRotation::new(
        validator_key_updates,
        wcert_signatures,
        withdrawal_certificate,
        None,
        THRESHOLD as u64,
        genesis_validator_keys_tree_root,
    );

    assert!(circuit_res.is_ok());
    let mut circuit = circuit_res.unwrap();

    // set a different quality to check that it is forced to be equal to valid signatures
    circuit.withdrawal_certificate.quality += 1;

    debug_naive_threshold_circuit(&circuit, true, Some("valid_signatures == quality/conditional_equals"));

    // try decreasing by 1 correct quality
    circuit.withdrawal_certificate.quality -= 2;
    // decrease also by 1 the number of valid signatures
    circuit.wcert_signatures[0] = SchnorrSig::new(FieldElement::rand(&mut rng), FieldElement::rand(&mut rng));
    // Update b to ensure that b = valid_signatures - threshold
    let b_bits = (FieldElement::from(circuit.valid_signatures as u64 - 1) - circuit.threshold).write_bits();
    let to_skip = FieldElement::size_in_bits() - circuit.b.len();
    circuit.b = b_bits[to_skip..].to_vec();

    debug_naive_threshold_circuit(&circuit, true, Some("require(sc_wcert_hash == H(wcert)/conditional_equals"));
}

#[serial]
#[test]
fn test_wrong_ledger_id_in_key_update() {
    const THRESHOLD: usize = 3;

    let mut rng = thread_rng();
    let (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        mut withdrawal_certificate,
        _wcert_signatures,
        mut validator_key_updates,
    ) = setup_certificate_data(MAX_PKS, THRESHOLD, false);

    let mut prev_withdrawal_certificate = prev_withdrawal_certificate.unwrap();
    prev_withdrawal_certificate.quality = THRESHOLD as u64;

    let invalid_ledger_id = FieldElement::rand(&mut rng);
    // rotate signing key with invalid ledger id
    rotate_key(
        &signing_keys_sks[0],
        &validator_key_updates.signing_keys[0],
        &master_keys_sks[0],
        &validator_key_updates.master_keys[0],
        &mut validator_key_updates.updated_signing_keys_sk_signatures[0],
        &mut validator_key_updates.updated_signing_keys_mk_signatures[0],
        None,
        &mut validator_key_updates.updated_signing_keys[0],
        |pk| ValidatorKeysUpdates::get_msg_to_sign_for_signing_key_update(pk, withdrawal_certificate.epoch_id, invalid_ledger_id).unwrap(),
    );

    withdrawal_certificate.custom_fields[0] = validator_key_updates
        .get_upd_validators_keys_root()
        .unwrap();

    let msg_to_sign = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        MAX_PKS,
        &signing_keys_sks[..THRESHOLD],
        &validator_key_updates.signing_keys[..THRESHOLD],
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

    // try to rotate also master key with invalid ledger id
    validator_key_updates.updated_signing_keys[0] = validator_key_updates.signing_keys[0];
    rotate_key(
        &signing_keys_sks[0],
        &validator_key_updates.signing_keys[0],
        &master_keys_sks[0],
        &validator_key_updates.master_keys[0],
        &mut validator_key_updates.updated_master_keys_sk_signatures[0],
        &mut validator_key_updates.updated_master_keys_mk_signatures[0],
        None,
        &mut validator_key_updates.updated_master_keys[0],
        |pk| ValidatorKeysUpdates::get_msg_to_sign_for_master_key_update(pk, withdrawal_certificate.epoch_id, invalid_ledger_id).unwrap(),
    );

    withdrawal_certificate.custom_fields[0] = validator_key_updates
        .get_upd_validators_keys_root()
        .unwrap();

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

    debug_naive_threshold_circuit(&circuit, true, Some("check key changes/check updated master key should be signed old signing key 0/conditional verify signature/conditional_equals"));
}
