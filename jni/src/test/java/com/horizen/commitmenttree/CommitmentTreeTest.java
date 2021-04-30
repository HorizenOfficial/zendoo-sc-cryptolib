package com.horizen.commitmenttree;

import org.junit.Test;
import static org.junit.Assert.*;
import com.horizen.commitmenttree.CommitmentTree;
import com.horizen.sigproofnative.BackwardTransfer;
import com.horizen.librustsidechains.FieldElement;

import java.util.Arrays;
import java.util.List;
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

        FieldElement leaf1 = FieldElement.createRandom();
        FieldElement leaf2 = FieldElement.createRandom();
        assertTrue("Certificate leaf expected to be added.", commTree.addCertLeaf(scId, leaf1.serializeFieldElement()));
        assertTrue("Certificate leaf expected to be added.", commTree.addCertLeaf(scId, leaf2.serializeFieldElement()));

        Optional<FieldElement> commitmentOpt = commTree.getCertCommitment(scId);
        assertTrue("Certificate expected to be present.", commitmentOpt.isPresent());
        Optional<List<FieldElement>> leafListOpt = commTree.getCrtLeaves(scId);
        assertTrue("Certificate leaf expected to be present.", leafListOpt.isPresent());
        assertTrue("Certificate leaf list expected to have one element.", leafListOpt.get().size() == 2);
        assertTrue("Certificate leaf1 is differ", Arrays.equals(leafListOpt.get().get(0).serializeFieldElement(), leaf1.serializeFieldElement()));
        assertTrue("Certificate leaf2 is differ", Arrays.equals(leafListOpt.get().get(1).serializeFieldElement(), leaf2.serializeFieldElement()));

        leaf1.freeFieldElement();
        leaf2.freeFieldElement();
        commTree.freeCommitmentTree();
        leafListOpt.get().get(0).freeFieldElement();
        leafListOpt.get().get(1).freeFieldElement();
    }

    @Test
    public void existenceProofTest() {
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
    public void existenceProofSerializationTest() {
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

        byte[] existenceProofBytes = existenceOpt.get().serialize();
        ScExistenceProof deserializedExistanceProof = ScExistenceProof.deserialize(existenceProofBytes);

        assertTrue("Deserialized existence proof should be serialized to same bytes", Arrays.equals(deserializedExistanceProof.serialize(), existenceProofBytes));
        assertTrue("Commitment verification of original proof expected to be successful", CommitmentTree.verifyScCommitment(scCommitmentOpt.get(), existenceOpt.get(), commitmentOpt.get()));
        assertTrue("Commitment verification of deserialized proof expected to be successful", CommitmentTree.verifyScCommitment(scCommitmentOpt.get(), deserializedExistanceProof, commitmentOpt.get()));
        commitmentOpt.get().freeFieldElement();
        existenceOpt.get().freeScExistenceProof();
        scCommitmentOpt.get().freeFieldElement();
        deserializedExistanceProof.freeScExistenceProof();
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
        assertTrue("Commitment expected to be present.", commitmentOpt.isPresent());

        // Get absence proof in empty CommitmentTree
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[0]).isPresent());
        Optional<ScAbsenceProof> absenceOpt = commTree.getScAbsenceProof(scId[0]);
        // TODO Uncomment this code when rust library will be able to operate with absence proof on empty commitment tree.
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        assertTrue("Absence verification expected to be successful", CommitmentTree.verifyScAbsence(scId[0], absenceOpt.get() ,commitmentOpt.get()));

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
        assertTrue("Absence verification expected to be successful", CommitmentTree.verifyScAbsence(scId[0], absenceOpt.get() ,commitmentOpt.get()));

        // Get absence proof with both neighbors
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[2]).isPresent());
        absenceOpt = commTree.getScAbsenceProof(scId[2]);
        commitmentOpt = commTree.getCommitment();
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        assertTrue("Absence verification expected to be successful", CommitmentTree.verifyScAbsence(scId[2], absenceOpt.get() ,commitmentOpt.get()));

        // Get absence proof with left neighbor
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[4]).isPresent());
        absenceOpt = commTree.getScAbsenceProof(scId[4]);
        commitmentOpt = commTree.getCommitment();
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());
        assertTrue("Absence verification expected to be successful", CommitmentTree.verifyScAbsence(scId[4], absenceOpt.get() ,commitmentOpt.get()));

        commTree.freeCommitmentTree();
    }

    @Test
    public void absenceProofSerializationTest() {
        CommitmentTree commTree = CommitmentTree.init();
        byte[][] scId = new byte[3][];

        // Initialize array of consecutive Sidechain Ids
        for (int i = 0 ; i < scId.length; i++) {
            scId[i] = new byte[FieldElement.getFieldElementSize()];
            scId[i][0] = (byte) i;
        }

        long ftrAmount = 100;
        byte[] ftrPublicKey = generateFieldElementBytes();
        byte[] ftrTransactionHash = generateFieldElementBytes();
        int fwtOutId = 200;
        assertTrue("Forward transfer output expected to be added.",
                commTree.addFwt(scId[0], ftrAmount, ftrPublicKey, ftrTransactionHash, fwtOutId));

        long bwtAmount = 120;
        byte[] bwtPublicKeyHash = generateRandomBytes(20);
        byte[] bwtRequestData = generateFieldElementBytes();
        byte[] bwtTransactionHash = generateFieldElementBytes();;
        int bwtOutId = 220;
        assertTrue("Backward transfer output expected to be added.", commTree.addBtr(scId[2], bwtAmount, bwtPublicKeyHash, bwtRequestData, bwtTransactionHash, bwtOutId));

        // Get absence proof with both neighbors
        assertFalse("Existance proof should not be present", commTree.getScExistenceProof(scId[1]).isPresent());
        Optional<ScAbsenceProof> absenceOpt = commTree.getScAbsenceProof(scId[1]);
        Optional<FieldElement> commitmentOpt = commTree.getCommitment();
        assertTrue("Absence proof expected to be present.", absenceOpt.isPresent());

        byte[] absenceProofBytes = absenceOpt.get().serialize();
        ScAbsenceProof deserializedAbsenceProof = ScAbsenceProof.deserialize(absenceProofBytes);

        assertTrue("Deserialized absence proof should be serialized to same bytes", Arrays.equals(deserializedAbsenceProof.serialize(), absenceProofBytes));
        assertTrue("Absence verification of original proof expected to be successful", CommitmentTree.verifyScAbsence(scId[1], absenceOpt.get() ,commitmentOpt.get()));
        assertTrue("Absence verification of deserialized proof expected to be successful", CommitmentTree.verifyScAbsence(scId[1], deserializedAbsenceProof ,commitmentOpt.get()));

        commTree.freeCommitmentTree();
    }

    @Test
    public void emptyTreeCommitmentRegressionTest() {
        // Data was taken from zend_oo test file src/gtest/test_libzendoo.cpp
        // Test case: NakedZendooFeatures_EmptyTreeCommitmentCalculation
        CommitmentTree commTree = CommitmentTree.init();

        byte[] expectedEmptyTreeCommitment = {
                (byte)0xfe, 0x2e, (byte)0xe3, (byte)0x93, 0x61, (byte)0xdc, 0x29, (byte)0xcc,
                0x54, (byte)0xbb, 0x6a, 0x1a, (byte)0x89, 0x3e, 0x66, (byte)0xbd,
                (byte)0xc1, 0x15, 0x0f, (byte)0x8c, (byte)0xa6, 0x5e, 0x75, 0x7d,
                (byte)0xf1, 0x42, (byte)0xb4, (byte)0xc4, 0x73, (byte)0x92, 0x41, 0x3b
        };
        Optional<FieldElement> commitmentOpt =  commTree.getCommitment();
        assertTrue("Commitment expected to be present for the empty CommitmentTree", commitmentOpt.isPresent());

        byte[] commitment = commitmentOpt.get().serializeFieldElement();

        assertArrayEquals("Different empty tree commitment found. Regression failed.",
                expectedEmptyTreeCommitment, commitment);
    }
}