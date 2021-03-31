package com.horizen.commitmenttree;

import org.junit.Test;
import static org.junit.Assert.*;
import com.horizen.commitmenttree.CommitmentTree;
import com.horizen.sigproofnative.BackwardTransfer;
import com.horizen.librustsidechains.FieldElement;

import java.util.Optional;
import java.util.Random;

public class CommitmentTreeTest {
    private byte[] generateFieldElementBytes() {
        try (FieldElement tmp = FieldElement.createRandom()) {
            return tmp.serializeFieldElement();
        }
    }

    private byte[] generateRandomBytes(int len) {
        byte[] bytes = new byte[len];
        new Random().nextBytes(bytes);
        return bytes;
    }

    @Test
    public void createAndFree() {
        CommitmentTree commTree = CommitmentTree.init();
        commTree.freeCommitmentTree();
    }

    @Test
    public void addScCreation() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("ScCr commitment expected to be missed.", commTree.getScCrCommitment(scId).isPresent());

        long amount = 100;
        byte[] pubKey = generateRandomBytes(32);
        int withdrawalEpochLength = 1000;
        byte[] customData = generateRandomBytes(1024);
        Optional<byte[]> constant = Optional.of(generateFieldElementBytes());
        byte[] certVk = new byte[1]; // todo
        Optional<byte[]> btrVk = Optional.empty();
        Optional<byte[]> cswVk = Optional.empty();
        byte[] txHash = generateRandomBytes(32);
        int outIdx = 0;

        assertTrue("Sidechain creation output expected to be added.",
                commTree.addScCr(scId, amount, pubKey, withdrawalEpochLength,
                        customData, constant, certVk, btrVk, cswVk, txHash, outIdx)
        );

        Optional<FieldElement> commitmentOpt = commTree.getScCrCommitment(scId);
        assertTrue("ScCr commitment expected to be present.", commitmentOpt.isPresent());
        commTree.freeCommitmentTree();
    }

    @Test
    public void addForwardTransfer() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("Forward transfer output expected to be missed.", commTree.getFwtCommitment(scId).isPresent());

        long ftrAmount = 100;
        byte[] ftrPublicKey = generateFieldElementBytes();
        byte[] ftrTransactionHash = generateFieldElementBytes();
        int fwtOutId = 200;
        assertTrue("Forward transfer output expected to be added.",
                commTree.addFwt(scId, ftrAmount, ftrPublicKey, ftrTransactionHash, fwtOutId));

        Optional<FieldElement> commitmentOpt = commTree.getFwtCommitment(scId);
        assertTrue("Forward transfer expected to be present.", commitmentOpt.isPresent());
        commTree.freeCommitmentTree();
    }

    @Test
    public void addBackwardTransfer() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("Backward transfer output expected to be missed.", commTree.getBtrCommitment(scId).isPresent());

        long bwtAmount = 120;
        byte[] bwtPublicKeyHash = generateRandomBytes(20);
        byte[] bwtRequestData = generateFieldElementBytes();
        byte[] bwtTransactionHash = generateFieldElementBytes();;
        int bwtOutId = 220;
        assertTrue("Backward transfer output expected to be added.", commTree.addBtr(scId, bwtAmount, bwtPublicKeyHash, bwtRequestData, bwtTransactionHash, bwtOutId));

        Optional<FieldElement> commitmentOpt = commTree.getBtrCommitment(scId);
        assertTrue("Backward transfer expected to be present.", commitmentOpt.isPresent());
        commTree.freeCommitmentTree();
    }

    @Test
    public void addCeasedSidechainWithdrawal() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("Ceased Sidechain Withdrawal output expected to be missed.", commTree.getCswCommitment(scId).isPresent());

        long cswAmount = 140;
        byte[] cswPublicKeyHash = generateRandomBytes(20);;
        byte[] cswNullifier = generateFieldElementBytes();
        byte[] cswCertificate  = generateFieldElementBytes();
        assertTrue("Ceased Sidechain Withdrawal output expected to be added.", commTree.addCsw(scId, cswAmount, cswNullifier, cswPublicKeyHash, cswCertificate));

        Optional<FieldElement> commitmentOpt = commTree.getCswCommitment(scId);
        assertTrue("Ceased Sidechain Withdrawal expected to be present.", commitmentOpt.isPresent());
        commTree.freeCommitmentTree();
    }

    @Test
    public void addCertificate() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("Certificate expected to be missed.", commTree.getCertCommitment(scId).isPresent());

        int cert_epoch = 220;
        long cert_quality = 50;
        byte[] certDataHash = generateFieldElementBytes();
        byte[] certMerkelRoot = generateFieldElementBytes();
        byte[] certCumulativeCommTreeHash = generateFieldElementBytes();

        assertTrue("Certificate output expected to be added.", commTree.addCert(scId, cert_epoch, cert_quality, certDataHash, new BackwardTransfer[0], certMerkelRoot, certCumulativeCommTreeHash));
        Optional<FieldElement> commitmentOpt = commTree.getCertCommitment(scId);
        assertTrue("Certificate expected to be present.", commitmentOpt.isPresent());
        commTree.freeCommitmentTree();
    }

    @Test
    public void addCertificateLeaf() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("Certificate expected to be missed.", commTree.getCertCommitment(scId).isPresent());

        byte[] leaf = generateFieldElementBytes();
        assertTrue("Certificate leaf expected to be added.", commTree.addCertLeaf(scId, leaf));

        Optional<FieldElement> commitmentOpt = commTree.getCertCommitment(scId);
        assertTrue("Certificate expected to be present.", commitmentOpt.isPresent());
        commTree.freeCommitmentTree();
    }

    @Test
    public void existanceProofTest() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[] scId = generateFieldElementBytes();

        assertFalse("Forward transfer output expected to be missed.", commTree.getFwtCommitment(scId).isPresent());

        long ftrAmount = 100;
        byte[] ftrPublicKeyHash = generateFieldElementBytes();
        byte[] ftrTransactionHash = generateFieldElementBytes();
        int fwtOutId = 200;
        assertTrue("Forward transfer output expected to be added.",
                commTree.addFwt(scId, ftrAmount, ftrPublicKeyHash, ftrTransactionHash, fwtOutId));

        Optional<FieldElement> commitmentOpt = commTree.getCommitment();
        assertTrue("Tree commitment expected to be present.", commitmentOpt.isPresent());
        Optional<ScExistenceProof> existenceOpt = commTree.getScExistenceProof(scId);
        assertTrue("Existence proof expected to be present.", existenceOpt.isPresent());
        Optional<FieldElement> scCommitmentOpt = commTree.getScCommitment(scId);
        assertTrue("Sidechain commitment expected to be present.", scCommitmentOpt.isPresent());
        assertTrue("Commitment verification expected to be successful", CommitmentTree.verifyScCommitment(scCommitmentOpt.get(), existenceOpt.get(), commitmentOpt.get()));

        commitmentOpt.get().freeFieldElement();
        existenceOpt.get().freeScExistenceProof();
        scCommitmentOpt.get().freeFieldElement();

        // Existence proof
        scId[1]++; // Changing scId to absent one.
        assertFalse("Existence proof expected to be missed", commTree.getScExistenceProof(scId).isPresent());


        commTree.freeCommitmentTree();
    }

    @Test
    public void absenceProofTest() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[][] scId = new byte[5][];

        // Initialize array of consecutive Sidechain Ids
        for (int i = 0 ; i < scId.length; i++) {
            scId[i] = new byte[FieldElement.getFieldElementSize()];
            scId[i][0] = (byte) i;
        }

        Optional<FieldElement> commitmentOpt = commTree.getCommitment();
        assertTrue("Forward transfer expected to be present.", commitmentOpt.isPresent());

        // Get absence proof in empty CommitmentTree
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[0]).isPresent());
        Optional<ScAbsenceProof> absenceOpt = commTree.getScAbsenceProof(scId[0]);
        // TODO Uncomment this code when rust library will be able to operate with absence proof on empty commitment tree.
        //assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        //assertTrue("Absence verification expected to be successful", commTree.verifyScAbsence(scId[0], absenceOpt.get() ,commitmentOpt.get()));

        long ftrAmount = 100;
        byte[] ftrPublicKey = generateFieldElementBytes();
        byte[] ftrTransactionHash = generateFieldElementBytes();
        int fwtOutId = 200;
        assertTrue("Forward transfer output expected to be added.",
                commTree.addFwt(scId[1], ftrAmount, ftrPublicKey, ftrTransactionHash, fwtOutId));

        // Try to get Absence proof of existed element
        assertTrue("Existance proof should be present", commTree.getScExistenceProof(scId[1]).isPresent());
        absenceOpt = commTree.getScAbsenceProof(scId[1]);
        assertFalse("Absence proof should not be present.", absenceOpt.isPresent());

        long bwtAmount = 120;
        byte[] bwtPublicKeyHash = generateRandomBytes(20);
        byte[] bwtRequestData = generateFieldElementBytes();
        byte[] bwtTransactionHash = generateFieldElementBytes();;
        int bwtOutId = 220;
        assertTrue("Backward transfer output expected to be added.", commTree.addBtr(scId[3], bwtAmount, bwtPublicKeyHash, bwtRequestData, bwtTransactionHash, bwtOutId));

        // Get absence proof with right neighbor
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[0]).isPresent());
        absenceOpt = commTree.getScAbsenceProof(scId[0]);
        commitmentOpt = commTree.getCommitment();
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        assertTrue("Absence verification expected to be successful", commTree.verifyScAbsence(scId[0], absenceOpt.get() ,commitmentOpt.get()));

        // Get absence proof with both neighbors
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[2]).isPresent());
        absenceOpt = commTree.getScAbsenceProof(scId[2]);
        commitmentOpt = commTree.getCommitment();
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        assertTrue("Absence verification expected to be successful", commTree.verifyScAbsence(scId[2], absenceOpt.get() ,commitmentOpt.get()));

        // Get absence proof with left neighbor
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[4]).isPresent());
        absenceOpt = commTree.getScAbsenceProof(scId[4]);
        commitmentOpt = commTree.getCommitment();
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        assertTrue("Absence verification expected to be successful", commTree.verifyScAbsence(scId[4], absenceOpt.get() ,commitmentOpt.get()));

        commTree.freeCommitmentTree();
    }
}