use super::*;
use cctp_primitives::utils::get_cert_data_hash_from_bt_root_and_custom_fields_hash;

const LEDGER_ID: u64 = 42; // fixed ledger id to be employed in all the certificates to simulate
    // they belong to the same sidechain

pub(crate) fn create_withdrawal_certificate() -> WithdrawalCertificateData {
    let mut rng = thread_rng();
    WithdrawalCertificateData {
        ledger_id: FieldElement::from(LEDGER_ID),
        epoch_id: rng.gen(),
        bt_root: rng.gen(),
        mcb_sc_txs_com: rng.gen(),
        btr_min_fee: rng.gen(),
        ft_min_amount: rng.gen(),
        quality: 0,
        custom_fields: vec![rng.gen()],
    }
}

pub(crate) fn generate_keys(
    max_pks: usize,
) -> (Vec<FieldBasedSchnorrPk<G2Projective>>, Vec<SchnorrSk>) {
    let mut pks = Vec::with_capacity(max_pks);
    let mut sks = Vec::with_capacity(max_pks);
    let mut rng = thread_rng();

    for _ in 0..max_pks {
        let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
        pks.push(pk);
        sks.push(sk);
    }
    (pks, sks)
}

pub(crate) fn create_signatures(
    max_pks: usize,
    signing_keys: &[SchnorrSk],
    verifying_keys: &[FieldBasedSchnorrPk<G2Projective>],
    msg_to_sign: FieldElement,
) -> Vec<Option<SchnorrSig>> {
    let mut signatures = vec![None; max_pks];
    let mut rng = thread_rng();
    for (i, sig) in signatures.iter_mut().take(signing_keys.len()).enumerate() {
        *sig = Some(
            SchnorrSigScheme::sign(&mut rng, &verifying_keys[i], &signing_keys[i], msg_to_sign)
                .unwrap(),
        );
    }
    signatures
}

pub(crate) fn init_g1_committer_key() -> CommitterKeyG1 {
    let _ = load_g1_committer_key(MAX_SEGMENT_SIZE - 1);
    let ck_g1 = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();
    assert_eq!(ck_g1.comm_key.len(), SUPPORTED_SEGMENT_SIZE);
    ck_g1
}

pub(crate) fn get_cert_data_hash(
    withdrawal_certificate: &WithdrawalCertificateData,
) -> FieldElement {
    //Compute cert_data_hash
    let custom_fields_hash = hash_vec(withdrawal_certificate.custom_fields.clone()).unwrap();
    get_cert_data_hash_from_bt_root_and_custom_fields_hash(
        &withdrawal_certificate.ledger_id,
        withdrawal_certificate.epoch_id,
        withdrawal_certificate.quality,
        withdrawal_certificate.bt_root,
        Some(custom_fields_hash),
        &withdrawal_certificate.mcb_sc_txs_com,
        withdrawal_certificate.btr_min_fee,
        withdrawal_certificate.ft_min_amount,
    )
    .unwrap()
}

pub(crate) fn cert_to_msg(withdrawal_certificate: &WithdrawalCertificateData) -> FieldElement {
    create_msg_to_sign(
        &withdrawal_certificate.ledger_id,
        withdrawal_certificate.epoch_id,
        &withdrawal_certificate.mcb_sc_txs_com,
        withdrawal_certificate.btr_min_fee,
        withdrawal_certificate.ft_min_amount,
        &withdrawal_certificate.bt_root,
        Some(withdrawal_certificate.custom_fields.clone()),
    )
    .unwrap()
}

pub(crate) fn rotate_key<F: Fn(&FieldBasedSchnorrPk<G2Projective>) -> FieldElement>(
    signing_key_sk: &SchnorrSk,
    signing_key_pk: &FieldBasedSchnorrPk<G2Projective>,
    master_key_sk: &SchnorrSk,
    master_key_pk: &FieldBasedSchnorrPk<G2Projective>,
    updated_sk_signatures: &mut FieldBasedSchnorrSignature<FieldElement, G2Projective>,
    updated_mk_signatures: &mut FieldBasedSchnorrSignature<FieldElement, G2Projective>,
    updated_signing_sks: Option<&mut SchnorrSk>,
    updated_signing_pks: &mut FieldBasedSchnorrPk<G2Projective>,
    updated_key_msg: F,
) {
    let mut rng = thread_rng();
    let (updated_pk, updated_sk) = SchnorrSigScheme::keygen(&mut rng);
    let updated_msg =  updated_key_msg(&updated_pk);
    *updated_sk_signatures =
        SchnorrSigScheme::sign(&mut rng, signing_key_pk, signing_key_sk, updated_msg).unwrap();
    *updated_mk_signatures =
        SchnorrSigScheme::sign(&mut rng, master_key_pk, master_key_sk, updated_msg).unwrap();
    *updated_signing_pks = updated_pk;
    if let Some(sk) = updated_signing_sks {
        *sk = updated_sk;
    }
}

pub(crate) fn setup_certificate_data(
    max_pks: usize,
    num_sigs: usize,
    is_first_cert: bool,
) -> (
    Vec<SchnorrSk>,
    Vec<SchnorrSk>,
    FieldElement,
    Option<WithdrawalCertificateData>,
    WithdrawalCertificateData,
    Vec<Option<SchnorrSig>>,
    ValidatorKeysUpdates,
) {
    let mut withdrawal_certificate = create_withdrawal_certificate();
    let (signing_keys_pks, signing_keys_sks) = generate_keys(max_pks);
    let (master_keys_pks, master_keys_sks) = generate_keys(max_pks);
    let genesis_validator_keys_tree_root =
        ValidatorKeysUpdates::get_validators_key_root(max_pks, &signing_keys_pks, &master_keys_pks)
            .unwrap();

    let prev_withdrawal_certificate = if is_first_cert {
        None
    } else {
        let mut certificate = create_withdrawal_certificate();
        certificate.custom_fields[0] = genesis_validator_keys_tree_root;
        Some(certificate)
    };

    let validator_key_updates = ValidatorKeysUpdates::new(
        signing_keys_pks.clone(),
        master_keys_pks.clone(),
        signing_keys_pks.clone(),
        master_keys_pks.clone(),
        vec![Some(NULL_CONST.null_sig); max_pks],
        vec![Some(NULL_CONST.null_sig); max_pks],
        vec![Some(NULL_CONST.null_sig); max_pks],
        vec![Some(NULL_CONST.null_sig); max_pks],
        max_pks,
    );

    withdrawal_certificate.custom_fields[0] = validator_key_updates.get_upd_validators_keys_root().unwrap();
    withdrawal_certificate.quality = num_sigs as u64;

    let message = cert_to_msg(&withdrawal_certificate);
    let wcert_signatures = create_signatures(
        max_pks,
        &signing_keys_sks[..num_sigs],
        &signing_keys_pks[..num_sigs],
        message,
    );

    (
        signing_keys_sks,
        master_keys_sks,
        genesis_validator_keys_tree_root,
        prev_withdrawal_certificate,
        withdrawal_certificate,
        wcert_signatures,
        validator_key_updates,
    )
}

pub(crate) fn debug_naive_threshold_circuit(
    circuit: &NaiveThresholdSignatureWKeyRotation,
    should_fail: bool,
    expected_failing_constraint: Option<&str>
) {
    let debug_res = debug_circuit(circuit.clone());
    assert!(debug_res.is_ok());
    let failing_constraint = debug_res.unwrap();
    if should_fail {
        assert!(failing_constraint.is_some());
        assert_eq!(failing_constraint.unwrap(), expected_failing_constraint.unwrap());
    } else {
        assert!(failing_constraint.is_none(), "no constraint expected to fail, found {:?}", failing_constraint);
    }

}
