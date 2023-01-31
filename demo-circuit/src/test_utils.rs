use std::convert::TryInto;

use cctp_primitives::{
    commitment_tree::CommitmentTree,
    proving_system::init::{get_g1_committer_key, load_g1_committer_key},
    type_mapping::{CommitterKeyG1, FieldElement, GingerMHT},
};
use primitives::FieldBasedMerkleTree;
use rand::{prelude::Distribution, thread_rng, Rng};

use crate::{
    common::{
        WithdrawalCertificateData, MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS,
        MSG_ROOT_HASH_CUSTOM_FIELDS_POS,
    },
    sc2sc::{ScCommitmentCertPath, MSG_MT_HEIGHT},
    GingerMHTBinaryPath, MAX_SEGMENT_SIZE, SUPPORTED_SEGMENT_SIZE,
};

pub(crate) fn init_g1_committer_key() -> CommitterKeyG1 {
    let _ = load_g1_committer_key(MAX_SEGMENT_SIZE - 1);
    let ck_g1 = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();
    assert_eq!(ck_g1.comm_key.len(), SUPPORTED_SEGMENT_SIZE);
    ck_g1
}

// TODO: Maybe this file could be moved in zendoo-cctp-lib.

#[derive(Clone)]
pub(crate) struct RandomWithdrawalCertificateDataBuilder {
    ledger_id: Option<FieldElement>,
    epoch_id: Option<u32>,
    bt_root: Option<FieldElement>,
    quality: Option<u64>,
    mcb_sc_txs_com: Option<FieldElement>,
    ft_min_amount: Option<u64>,
    btr_min_fee: Option<u64>,
    custom_fields: Vec<Option<FieldElement>>,
}

impl Distribution<WithdrawalCertificateData> for RandomWithdrawalCertificateDataBuilder {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> WithdrawalCertificateData {
        let custom_fields = self.custom_fields.clone();
        WithdrawalCertificateData {
            ledger_id: self.ledger_id.unwrap_or_else(|| rng.gen()),
            epoch_id: self.epoch_id.unwrap_or_else(|| rng.gen()),
            bt_root: self.bt_root.unwrap_or_else(|| rng.gen()),
            quality: self.quality.unwrap_or_else(|| rng.gen()),
            mcb_sc_txs_com: self.mcb_sc_txs_com.unwrap_or_else(|| rng.gen()),
            ft_min_amount: self.ft_min_amount.unwrap_or_else(|| rng.gen()),
            btr_min_fee: self.btr_min_fee.unwrap_or_else(|| rng.gen()),
            custom_fields: custom_fields
                .iter()
                .map(|v| v.unwrap_or_else(|| rng.gen()))
                .collect(),
        }
    }
}

#[allow(unused)]
impl RandomWithdrawalCertificateDataBuilder {
    pub(crate) fn new(n_custom_field: usize) -> Self {
        Self {
            ledger_id: None,
            epoch_id: None,
            bt_root: None,
            quality: None,
            mcb_sc_txs_com: None,
            ft_min_amount: None,
            btr_min_fee: None,
            custom_fields: vec![None; n_custom_field],
        }
    }

    pub(crate) fn build(&self) -> WithdrawalCertificateData {
        let mut rng = thread_rng();
        self.sample(&mut rng)
    }

    pub(crate) fn with_ledger_id(&mut self, v: FieldElement) -> &mut Self {
        self.ledger_id = Some(v);
        self
    }

    pub(crate) fn with_epoch_id(&mut self, v: u32) -> &mut Self {
        self.epoch_id = Some(v);
        self
    }

    pub(crate) fn with_bt_root(&mut self, v: FieldElement) -> &mut Self {
        self.bt_root = Some(v);
        self
    }

    pub(crate) fn with_quality(&mut self, v: u64) -> &mut Self {
        self.quality = Some(v);
        self
    }

    pub(crate) fn with_mcb_sc_txs_com(&mut self, v: FieldElement) -> &mut Self {
        self.mcb_sc_txs_com = Some(v);
        self
    }

    pub(crate) fn with_ft_min_amount(&mut self, v: u64) -> &mut Self {
        self.ft_min_amount = Some(v);
        self
    }

    pub(crate) fn with_btr_min_fee(&mut self, v: u64) -> &mut Self {
        self.btr_min_fee = Some(v);
        self
    }

    pub(crate) fn with_custom_fields(&mut self, v: Vec<FieldElement>) -> &mut Self {
        self.custom_fields = v.into_iter().map(|field| Some(field)).collect();
        self
    }

    pub(crate) fn with_custom_field(&mut self, pos: usize, v: FieldElement) -> &mut Self {
        self.custom_fields
            .resize((pos + 1).max(self.custom_fields.len()), None);
        self.custom_fields[pos] = Some(v);
        self
    }
}

impl Default for RandomWithdrawalCertificateDataBuilder {
    fn default() -> Self {
        Self::new(1)
    }
}

#[derive(Default)]
pub(crate) struct CommitmentScBuilder {
    epoch: u32,
    n_forward_transfer: usize,
    n_backward_transfer: usize,
    n_withdrawal_certificates: usize,
    certificate_builder: Option<RandomWithdrawalCertificateDataBuilder>,
}

impl CommitmentScBuilder {
    pub(crate) fn with_epoch(mut self, epoch: u32) -> Self {
        self.epoch = epoch;
        self
    }

    pub(crate) fn with_n_forward_transfer(mut self, n_forward_transfer: usize) -> Self {
        self.n_forward_transfer = n_forward_transfer;
        self
    }

    pub(crate) fn with_n_backward_transfer(mut self, n_backward_transfer: usize) -> Self {
        self.n_backward_transfer = n_backward_transfer;
        self
    }

    pub(crate) fn with_n_withdrawal_certificates(
        mut self,
        n_withdrawal_certificates: usize,
    ) -> Self {
        self.n_withdrawal_certificates = n_withdrawal_certificates;
        self
    }

    pub(crate) fn with_certificate_msg_root(mut self, msg_root: FieldElement) -> Self {
        self.get_mut_certificates_builder()
            .with_custom_field(MSG_ROOT_HASH_CUSTOM_FIELDS_POS, msg_root);
        self
    }

    pub(crate) fn with_max_quality_certificate_hash(mut self, hash: FieldElement) -> Self {
        self.get_mut_certificates_builder()
            .with_custom_field(MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS, hash);
        self
    }

    pub(crate) fn with_certificates_builder(
        mut self,
        builder: RandomWithdrawalCertificateDataBuilder,
    ) -> Self {
        self.certificate_builder = Some(builder);
        self
    }

    pub(crate) fn generate_sc_data(
        &self,
        cmt: Option<CommitmentHelper>,
        rng: &mut (impl Rng + ?Sized),
        sc_id: FieldElement,
    ) -> CommitmentHelper {
        let mut cmt = cmt.unwrap_or_default();
        let mut cert_builder = self.certificate_builder.clone().unwrap_or_default();
        cert_builder.with_ledger_id(sc_id).with_epoch_id(self.epoch);

        cmt.add_random_forward_transert_to_sc(rng, &sc_id, self.n_forward_transfer);
        cmt.add_random_backward_transert_to_sc(rng, &sc_id, self.n_backward_transfer);
        cmt.add_random_withdrawal_certificates_to_sc(
            rng,
            &sc_id,
            cert_builder,
            self.n_withdrawal_certificates,
        );
        cmt.set_random_start_sc(rng, &sc_id);

        cmt
    }

    fn get_mut_certificates_builder(&mut self) -> &mut RandomWithdrawalCertificateDataBuilder {
        if self.certificate_builder.is_none() {
            self.certificate_builder = Some(RandomWithdrawalCertificateDataBuilder::default());
        }
        self.certificate_builder.as_mut().unwrap()
    }
}

pub(crate) struct CommitmentHelper {
    cmt: CommitmentTree,
    certs: Vec<WithdrawalCertificateData>,
}

impl CommitmentHelper {
    pub(crate) fn add_random_forward_transert_to_sc(
        &mut self,
        rng: &mut (impl Rng + ?Sized),
        sc_id: &FieldElement,
        n: usize,
    ) {
        (0..n).for_each(|_| {
            self.cmt.add_bwtr_leaf(sc_id, &rng.gen());
        });
    }

    pub(crate) fn add_random_backward_transert_to_sc(
        &mut self,
        rng: &mut (impl Rng + ?Sized),
        sc_id: &FieldElement,
        n: usize,
    ) {
        (0..n).for_each(|_| {
            self.cmt.add_fwt_leaf(sc_id, &rng.gen());
        });
    }

    pub(crate) fn add_random_withdrawal_certificates_to_sc(
        &mut self,
        rng: &mut (impl Rng + ?Sized),
        sc_id: &FieldElement,
        builder: RandomWithdrawalCertificateDataBuilder,
        n: usize,
    ) {
        let mut certs: Vec<_> = (0..n).map(|_| builder.sample(rng)).collect();
        certs.iter().for_each(|c| {
            self.cmt.add_cert_leaf(&sc_id, &c.hash().unwrap());
        });
        self.certs.append(&mut certs);
    }

    pub(crate) fn get_withdrawal_certificate_info(
        &mut self,
        pos: usize,
    ) -> (
        WithdrawalCertificateData,
        ScCommitmentCertPath,
        FieldElement,
    ) {
        let cert = self.get_withdrawal_certificate(pos).clone();
        let path = self.get_certificate_path(&cert);
        let sc_tx_commitment = self.get_commitment();
        (cert, path, sc_tx_commitment)
    }

    pub(crate) fn get_withdrawal_certificate(&self, id: usize) -> &WithdrawalCertificateData {
        &self.certs[id]
    }

    pub(crate) fn set_random_start_sc(
        &mut self,
        rng: &mut (impl Rng + ?Sized),
        sc_id: &FieldElement,
    ) {
        self.cmt.set_scc(&sc_id, &rng.gen());
    }

    pub(crate) fn get_certificate_path(
        &mut self,
        cert: &WithdrawalCertificateData,
    ) -> ScCommitmentCertPath {
        let hash = cert.hash().unwrap();
        ScCommitmentCertPath::from_commitment(&mut self.cmt, cert.ledger_id, hash)
            .expect("Cannot extract path for certificate")
    }

    pub(crate) fn get_commitment(&mut self) -> FieldElement {
        self.cmt
            .get_commitment()
            .expect("Cannot get sc_tx_commitment")
    }
}

impl Default for CommitmentHelper {
    fn default() -> Self {
        Self {
            cmt: CommitmentTree::create(),
            certs: Default::default(),
        }
    }
}

/// Generate a messages tree with `n` leafs and return for the `pos`'s the root, msg hash
/// and merkle path from leaf to root
pub(crate) fn messages(
    rng: &mut (impl Rng + ?Sized),
    n: usize,
    pos: usize,
) -> (FieldElement, FieldElement, GingerMHTBinaryPath) {
    let mut msg_tree = GingerMHT::init(MSG_MT_HEIGHT, 1 << MSG_MT_HEIGHT).unwrap();
    (0..n).for_each(|_| {
        msg_tree.append(rng.gen()).unwrap();
    });
    msg_tree.finalize_in_place().unwrap();
    let msg_hash = msg_tree.get_leaves()[pos];
    let msg_path = msg_tree
        .get_merkle_path(pos)
        .expect("Msg tree is not finalized yet");
    (
        msg_tree.root().expect("Massage tree is not finalizaed yet"),
        msg_hash,
        msg_path.try_into().expect("Should be a binary tree"),
    )
}
