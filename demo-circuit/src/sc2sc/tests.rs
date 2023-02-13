use algebra::Field;
use cctp_primitives::{
    commitment_tree::CommitmentTree,
    type_mapping::{CoboundaryMarlin, FieldElement}, proving_system::verifier::UserInputs,
};

use primitives::FieldBasedMerkleTreePath;
use r1cs_core::debug_circuit;
use rand::{rngs::ThreadRng, thread_rng, Rng, RngCore};
use rstest::*;
use serial_test::serial;

use crate::{
    test_utils::{
        self, init_g1_committer_key, CommitmentScBuilder, RandomWithdrawalCertificateDataBuilder,
    },
    GingerMHTBinaryPath,
};

use super::{Sc2Sc, ScCommitmentCertPath, MIN_CUSTOM_FIELDS, MSG_MT_HEIGHT};

impl ScCommitmentCertPath {
    /// Add implementation to simplify the extraction from a commitment
    pub(crate) fn from_commitment(
        cmt: &mut CommitmentTree,
        sc_id: FieldElement,
        cert_hash: FieldElement,
    ) -> Option<Self> {
        let cert_index = cmt
            .get_cert_leaves(&sc_id)
            .and_then(|certs| certs.iter().position(|h| h == &cert_hash))?;
        Self::from_commitment_cert_index(cmt, sc_id, cert_index).ok()
    }
}

fn assert_circuit(circuit: Sc2Sc, zk_rng: Option<&mut dyn RngCore>) {
    let ck_g1 = init_g1_committer_key();
    let setup_circuit = Sc2Sc::get_instance_for_setup(MIN_CUSTOM_FIELDS as u32);
    let (pk, vk) = CoboundaryMarlin::index(&ck_g1, setup_circuit).unwrap();

    assert_eq!(None, debug_circuit(circuit.clone()).unwrap());
    let proof =
        CoboundaryMarlin::prove(&pk, &ck_g1, circuit.clone(), zk_rng.is_some(), zk_rng).unwrap();
    assert!(CoboundaryMarlin::verify(&vk, &ck_g1, circuit.public_input().get_circuit_inputs().unwrap().as_slice(), &proof).unwrap());
}

#[fixture]
fn rng() -> ThreadRng {
    thread_rng()
}

type CommitmentPair = (CommitmentScBuilder, CommitmentScBuilder);

#[fixture]
fn base_commitments(#[default(42)] epoch: u32) -> (CommitmentScBuilder, CommitmentScBuilder) {
    let curr_cmt = CommitmentScBuilder::default()
        .with_epoch(epoch)
        .with_n_withdrawal_certificates(1)
        .with_certificates_builder(RandomWithdrawalCertificateDataBuilder::new(
            MIN_CUSTOM_FIELDS,
        ));
    let next_cmt = CommitmentScBuilder::default()
        .with_epoch(epoch + 1)
        .with_n_withdrawal_certificates(1)
        .with_certificates_builder(RandomWithdrawalCertificateDataBuilder::new(
            MIN_CUSTOM_FIELDS,
        ));

    (curr_cmt, next_cmt)
}

#[rstest]
#[serial]
fn simplest_case(
    mut rng: impl Rng,
    base_commitments: CommitmentPair,
    #[values(true, false)] zk: bool,
) {
    let sc_id: FieldElement = rng.gen();
    // Just one message in the root
    let (msg_root, msg_hash, msg_path) = test_utils::messages(&mut rng, 1, 0);

    let (curr, next) = base_commitments;

    let mut curr = curr
        .with_certificate_msg_root(msg_root)
        .generate_sc_data(None, &mut rng, sc_id);
    let (curr_cert, curr_cert_path, curr_sc_tx_commitment) =
        curr.get_withdrawal_certificate_info(0);

    let mut next = next
        .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
        .generate_sc_data(None, &mut rng, sc_id);
    let (next_cert, next_cert_path, next_sc_tx_commitment) =
        next.get_withdrawal_certificate_info(0);

    let sc2sc = Sc2Sc::new(
        next_sc_tx_commitment,
        curr_sc_tx_commitment,
        msg_hash,
        next_cert,
        curr_cert,
        next_cert_path,
        curr_cert_path,
        msg_path,
    );

    assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
}

#[rstest]
#[serial]
fn happy_path(
    mut rng: impl Rng,
    base_commitments: CommitmentPair,
    #[values(true, false)] zk: bool,
) {
    // In this case we add some other data and more sidechains in both curr and next
    let sc_id: FieldElement = rng.gen();
    let (msg_root, msg_hash, msg_path) = test_utils::messages(&mut rng, 22, 4);

    let (curr, next) = base_commitments;
    let curr_helper = curr
        .with_certificate_msg_root(msg_root)
        .with_n_forward_transfer(24)
        .with_n_backward_transfer(12)
        .with_n_withdrawal_certificates(3)
        .generate_sc_data(None, &mut rng, sc_id);
    let other_sc_id = rng.gen();
    // Add another sc
    let mut curr = CommitmentScBuilder::default()
        .with_n_forward_transfer(1)
        .with_n_backward_transfer(1)
        .generate_sc_data(Some(curr_helper), &mut rng, other_sc_id);

    let (curr_cert, curr_cert_path, curr_sc_tx_commitment) =
        curr.get_withdrawal_certificate_info(2);

    let next_helper = next
        .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
        .generate_sc_data(None, &mut rng, sc_id);
    let other_sc_id = rng.gen();
    // Add another sc
    let mut next = CommitmentScBuilder::default()
        .with_n_forward_transfer(1)
        .with_n_backward_transfer(1)
        .generate_sc_data(Some(next_helper), &mut rng, other_sc_id);

    let (next_cert, next_cert_path, next_sc_tx_commitment) =
        next.get_withdrawal_certificate_info(0);

    let sc2sc = Sc2Sc::new(
        next_sc_tx_commitment,
        curr_sc_tx_commitment,
        msg_hash,
        next_cert,
        curr_cert,
        next_cert_path,
        curr_cert_path,
        msg_path,
    );

    assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
}

mod should_not_possible_to_create_a_circuit_if {
    use super::*;

    #[test]
    #[should_panic(expected = "same custom fields")]
    fn certificates_have_not_the_same_numbers_of_custom_fields() {
        let curr_cert = RandomWithdrawalCertificateDataBuilder::new(MIN_CUSTOM_FIELDS).build();
        let next_cert = RandomWithdrawalCertificateDataBuilder::new(MIN_CUSTOM_FIELDS + 1).build();

        Sc2Sc::new(
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            next_cert,
            curr_cert,
            ScCommitmentCertPath::default(),
            ScCommitmentCertPath::default(),
            GingerMHTBinaryPath::new(vec![(FieldElement::default(), false); MSG_MT_HEIGHT]),
        );
    }

    #[test]
    #[should_panic(expected = "need at least")]
    fn certificates_have_less_than_minimum_custom_fields() {
        let curr_cert = RandomWithdrawalCertificateDataBuilder::new(MIN_CUSTOM_FIELDS - 1).build();
        let next_cert = RandomWithdrawalCertificateDataBuilder::new(MIN_CUSTOM_FIELDS - 1).build();

        Sc2Sc::new(
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            next_cert,
            curr_cert,
            ScCommitmentCertPath::default(),
            ScCommitmentCertPath::default(),
            GingerMHTBinaryPath::new(vec![(FieldElement::default(), false); MSG_MT_HEIGHT]),
        );
    }
}

#[rstest]
#[case::minimum(MIN_CUSTOM_FIELDS)]
#[case::lot_of(MIN_CUSTOM_FIELDS + 42)]
#[should_panic(expected = "need at least")]
#[case::should_fail_with_less_than_minimum(MIN_CUSTOM_FIELDS - 1)]
fn setup_a_circuit_with_some_custom_fields(#[case] n_custom_fields: usize) {
    Sc2Sc::get_instance_for_setup(n_custom_fields as u32);
}

mod sc_commitment_cert_path {
    use super::*;

    #[rstest]
    fn should_validate_a_path(mut rng: impl Rng) {
        let sc_id: FieldElement = rng.gen();
        let mut cmt = CommitmentScBuilder::default()
            .with_n_withdrawal_certificates(1)
            .generate_sc_data(None, &mut rng, sc_id);
        
        let (cert, path, root) = cmt.get_withdrawal_certificate_info(0);

        assert!(path.check_membership(&root, &sc_id, &cert.hash().unwrap()))
    }

    #[rstest]
    fn should_compute_root(mut rng: impl Rng) {
        let sc_id: FieldElement = rng.gen();
        let mut cmt = CommitmentScBuilder::default()
            .with_n_withdrawal_certificates(1)
            .generate_sc_data(None, &mut rng, sc_id);
        
        let (cert, path, root) = cmt.get_withdrawal_certificate_info(0);

        assert_eq!(root, path.compute_root(&sc_id, &cert.hash().unwrap()).unwrap())
    }

    mod reject_invalid {
        use super::*;

        #[rstest]
        fn root(mut rng: impl Rng) {
            let sc_id: FieldElement = rng.gen();
            let mut cmt = CommitmentScBuilder::default()
                .with_n_withdrawal_certificates(1)
                .generate_sc_data(None, &mut rng, sc_id);
            
            let (cert, path, _root) = cmt.get_withdrawal_certificate_info(0);
    
            assert!(!path.check_membership(&rng.gen(), &sc_id, &cert.hash().unwrap()))
        }
    
        #[rstest]
        fn sc_id(mut rng: impl Rng) {
            let sc_id: FieldElement = rng.gen();
            let mut cmt = CommitmentScBuilder::default()
                .with_n_withdrawal_certificates(1)
                .generate_sc_data(None, &mut rng, sc_id);
            
            let (cert, path, root) = cmt.get_withdrawal_certificate_info(0);
    
            assert!(!path.check_membership(&root, &rng.gen(), &cert.hash().unwrap()))
        }

        #[rstest]
        fn cert_hash(mut rng: impl Rng) {
            let sc_id: FieldElement = rng.gen();
            let mut cmt = CommitmentScBuilder::default()
                .with_n_withdrawal_certificates(1)
                .generate_sc_data(None, &mut rng, sc_id);
            
            let (_cert, path, root) = cmt.get_withdrawal_certificate_info(0);
    
            assert!(!path.check_membership(&root, &sc_id, &rng.gen()))
        }
    }
}

mod should_fail {
    use super::*;

    #[rstest]
    #[serial]
    #[should_panic(expected = "curr_cert.epoch + 1 == next_cert.epoch")]
    fn if_not_contiguos_epochs(
        mut rng: impl Rng,
        base_commitments: CommitmentPair,
        #[values(true, false)] zk: bool,
    ) {
        let sc_id: FieldElement = rng.gen();
        // Just one message in the root
        let (msg_root, msg_hash, msg_path) = test_utils::messages(&mut rng, 1, 0);

        let (curr, next) = base_commitments;

        let mut curr = curr
            .with_certificate_msg_root(msg_root)
            .generate_sc_data(None, &mut rng, sc_id);
        let (curr_cert, curr_cert_path, curr_sc_tx_commitment) =
            curr.get_withdrawal_certificate_info(0);

        let mut next = next
            .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
            .with_epoch(1234) // Change next epoch
            .generate_sc_data(None, &mut rng, sc_id);
        let (next_cert, next_cert_path, next_sc_tx_commitment) =
            next.get_withdrawal_certificate_info(0);

        let sc2sc = Sc2Sc::new(
            next_sc_tx_commitment,
            curr_sc_tx_commitment,
            msg_hash,
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        );

        assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
    }

    enum TestChangeTxPathAction {
        ScTxCommitmentRoot,
        FTRootHash,
        BTRootHash,
        SSC,
        CertPath,
        ScCommitmentPath,
    }

    #[rstest]
    #[serial]
    #[case::sc_tx_commitment_root(TestChangeTxPathAction::ScTxCommitmentRoot)]
    #[case::forward_transfer_root(TestChangeTxPathAction::FTRootHash)]
    #[case::backward_transfer_root(TestChangeTxPathAction::BTRootHash)]
    #[case::start_side_chain(TestChangeTxPathAction::SSC)]
    #[case::withdrawal_certificate_path(TestChangeTxPathAction::CertPath)]
    #[case::sidechain_commitment_path(TestChangeTxPathAction::ScCommitmentPath)]
    #[should_panic(expected = "Check current epoch sc_tx_commitment_root")]
    fn if_invalid_current_sc_commitment_path(
        mut rng: impl Rng,
        base_commitments: CommitmentPair,
        #[values(true, false)] zk: bool,
        #[case] action: TestChangeTxPathAction,
    ) {
        let sc_id: FieldElement = rng.gen();
        // Just one message in the root
        let (msg_root, msg_hash, msg_path) = test_utils::messages(&mut rng, 1, 0);

        let (curr, next) = base_commitments;

        let mut curr = curr
            .with_certificate_msg_root(msg_root)
            .generate_sc_data(None, &mut rng, sc_id);
        let (curr_cert, mut curr_cert_path, mut curr_sc_tx_commitment) =
            curr.get_withdrawal_certificate_info(0);

        let mut next = next
            .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
            .generate_sc_data(None, &mut rng, sc_id);
        let (next_cert, next_cert_path, next_sc_tx_commitment) =
            next.get_withdrawal_certificate_info(0);

        use TestChangeTxPathAction::*;
        match action {
            ScTxCommitmentRoot => {
                curr_sc_tx_commitment += FieldElement::one();
            }
            FTRootHash => {
                curr_cert_path.fwt_root += FieldElement::one();
            }
            BTRootHash => {
                curr_cert_path.bwt_root += FieldElement::one();
            }
            SSC => {
                curr_cert_path.ssc += FieldElement::one();
            }
            CertPath => {
                let mut raw = curr_cert_path.cert_path.get_raw_path().clone();
                raw[0].0 += FieldElement::one();
                curr_cert_path.cert_path = GingerMHTBinaryPath::new(raw);
            }
            ScCommitmentPath => {
                let mut raw = curr_cert_path.sc_commitment_path.get_raw_path().clone();
                raw[0].0 += FieldElement::one();
                curr_cert_path.sc_commitment_path = GingerMHTBinaryPath::new(raw);
            }
        }

        let sc2sc = Sc2Sc::new(
            next_sc_tx_commitment,
            curr_sc_tx_commitment,
            msg_hash,
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        );

        assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
    }

    #[rstest]
    #[serial]
    #[case::sc_tx_commitment_root(TestChangeTxPathAction::ScTxCommitmentRoot)]
    #[case::forward_transfer_root(TestChangeTxPathAction::FTRootHash)]
    #[case::backward_transfer_root(TestChangeTxPathAction::BTRootHash)]
    #[case::start_side_chain(TestChangeTxPathAction::SSC)]
    #[case::withdrawal_certificate_path(TestChangeTxPathAction::CertPath)]
    #[case::sidechain_commitment_path(TestChangeTxPathAction::ScCommitmentPath)]
    #[should_panic(expected = "Check next epoch sc_tx_commitment_root")]
    fn if_invalid_next_sc_commitment_path(
        mut rng: impl Rng,
        base_commitments: CommitmentPair,
        #[values(true, false)] zk: bool,
        #[case] action: TestChangeTxPathAction,
    ) {
        let sc_id: FieldElement = rng.gen();
        // Just one message in the root
        let (msg_root, msg_hash, msg_path) = test_utils::messages(&mut rng, 1, 0);

        let (curr, next) = base_commitments;

        let mut curr = curr
            .with_certificate_msg_root(msg_root)
            .generate_sc_data(None, &mut rng, sc_id);
        let (curr_cert, curr_cert_path, curr_sc_tx_commitment) =
            curr.get_withdrawal_certificate_info(0);

        let mut next = next
            .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
            .generate_sc_data(None, &mut rng, sc_id);
        let (next_cert, mut next_cert_path, mut next_sc_tx_commitment) =
            next.get_withdrawal_certificate_info(0);

        use TestChangeTxPathAction::*;
        match action {
            ScTxCommitmentRoot => {
                next_sc_tx_commitment += FieldElement::one();
            }
            FTRootHash => {
                next_cert_path.fwt_root += FieldElement::one();
            }
            BTRootHash => {
                next_cert_path.bwt_root += FieldElement::one();
            }
            SSC => {
                next_cert_path.ssc += FieldElement::one();
            }
            CertPath => {
                let mut raw = curr_cert_path.cert_path.get_raw_path().clone();
                raw[0].0 += FieldElement::one();
                next_cert_path.cert_path = GingerMHTBinaryPath::new(raw);
            }
            ScCommitmentPath => {
                let mut raw = curr_cert_path.sc_commitment_path.get_raw_path().clone();
                raw[0].0 += FieldElement::one();
                next_cert_path.sc_commitment_path = GingerMHTBinaryPath::new(raw);
            }
        }

        let sc2sc = Sc2Sc::new(
            next_sc_tx_commitment,
            curr_sc_tx_commitment,
            msg_hash,
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        );

        assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
    }

    enum TestChangeMsgAction {
        Root,
        Hash,
        Path,
    }

    #[rstest]
    #[case::root(TestChangeMsgAction::Root)]
    #[case::hash(TestChangeMsgAction::Hash)]
    #[case::path(TestChangeMsgAction::Path)]
    #[serial]
    #[should_panic(expected = "(msg_hash, msg_path) == curr_cert.SC2SC_message_tree_root")]
    fn if_invalid_msg_data(
        mut rng: impl Rng,
        base_commitments: CommitmentPair,
        #[values(true, false)] zk: bool,
        #[case] action: TestChangeMsgAction,
    ) {
        let sc_id: FieldElement = rng.gen();

        use TestChangeMsgAction::*;
        let (msg_root, msg_hash, msg_path) = match (action, test_utils::messages(&mut rng, 1, 0)) {
            (Root, (r, h, p)) => (r + FieldElement::one(), h, p),
            (Hash, (r, h, p)) => (r, h + FieldElement::one(), p),
            (Path, (r, h, p)) => (r, h, {
                let mut raw = p.get_raw_path().clone();
                raw[0].0 += FieldElement::one();
                GingerMHTBinaryPath::new(raw)
            }),
        };

        let (curr, next) = base_commitments;

        let mut curr = curr
            .with_certificate_msg_root(msg_root)
            .generate_sc_data(None, &mut rng, sc_id);
        let (curr_cert, curr_cert_path, curr_sc_tx_commitment) =
            curr.get_withdrawal_certificate_info(0);

        let mut next = next
            .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
            .generate_sc_data(None, &mut rng, sc_id);
        let (next_cert, next_cert_path, next_sc_tx_commitment) =
            next.get_withdrawal_certificate_info(0);

        let sc2sc = Sc2Sc::new(
            next_sc_tx_commitment,
            curr_sc_tx_commitment,
            msg_hash,
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        );

        assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
    }

    #[rstest]
    #[serial]
    #[should_panic(expected = "next_cert.previous_top_quality_hash == H(curr_cert_hash)")]
    fn if_some_in_curr_cert_change(
        mut rng: impl Rng,
        base_commitments: CommitmentPair,
        #[values(true, false)] zk: bool,
    ) {
        let sc_id: FieldElement = rng.gen();
        // Just one message in the root
        let (msg_root, msg_hash, msg_path) = test_utils::messages(&mut rng, 1, 0);

        let (curr, next) = base_commitments;

        let mut curr = curr
            .with_certificate_msg_root(msg_root)
            .generate_sc_data(None, &mut rng, sc_id);
        let (mut curr_cert, curr_cert_path, curr_sc_tx_commitment) =
            curr.get_withdrawal_certificate_info(0);

        let mut next = next
            .with_max_quality_certificate_hash(curr_cert.hash().unwrap())
            .generate_sc_data(None, &mut rng, sc_id);
        let (next_cert, next_cert_path, next_sc_tx_commitment) =
            next.get_withdrawal_certificate_info(0);

        curr_cert.btr_min_fee += 1;

        let sc2sc = Sc2Sc::new(
            next_sc_tx_commitment,
            curr_sc_tx_commitment,
            msg_hash,
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        );

        assert_circuit(sc2sc, if zk { Some(&mut rng) } else { None });
    }
}
