package com.horizen.sc2scnative;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Optional;
import java.util.Random;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import com.horizen.TestUtils;
import com.horizen.certnative.WithdrawalCertificate;
import com.horizen.commitmenttreenative.CommitmentTree;
import com.horizen.commitmenttreenative.CustomBitvectorElementsConfig;
import com.horizen.commitmenttreenative.CustomFieldElementsConfig;
import com.horizen.commitmenttreenative.ScCommitmentCertPath;
import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.merkletreenative.InMemoryAppendOnlyMerkleTree;
import com.horizen.merkletreenative.MerklePath;
import com.horizen.provingsystemnative.ProvingSystem;
import com.horizen.provingsystemnative.ProvingSystemType;

public class Sc2ScProofTest {
    private static int MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS = Constants.MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS();
    private static int MSG_ROOT_HASH_CUSTOM_FIELDS_POS = Constants.MSG_ROOT_HASH_CUSTOM_FIELDS_POS();
    private static int MIN_CUSTOM_FIELDS = Constants.MIN_CUSTOM_FIELDS();
    private static int MSG_MT_HEIGHT = Constants.MSG_MT_HEIGHT();

    static boolean zk = false;

    static ProvingSystemType psType = ProvingSystemType.COBOUNDARY_MARLIN;
    static int customFieldsNum = 3;
    static String pkPath = "./test_sc2sc_pk";
    static String vkPath = "./test_sc2sc_vk";

    static int maxProofPlusVkSize = 9 * 1024;

    private InMemoryAppendOnlyMerkleTree msgTree;
    private CommitmentTree currentCt = CommitmentTree.init();
    private CommitmentTree nextCt = CommitmentTree.init();

    @BeforeClass
    public static void initKeys() throws Exception {
        ProvingSystem.generateDLogKeys(psType, TestUtils.DLOG_KEYS_SIZE);
        assertTrue(Sc2Sc.setup(psType, customFieldsNum, Optional.of(TestUtils.CERT_SEGMENT_SIZE),
                pkPath, vkPath, zk, maxProofPlusVkSize));
    }

    @AfterClass
    public static void deleteKeys() {
        // Delete proving keys and verification keys
        new File(pkPath).delete();
        new File(vkPath).delete();
    }

    @Before
    public void setUp() {
        msgTree = InMemoryAppendOnlyMerkleTree.init(MSG_MT_HEIGHT, 1 << MSG_MT_HEIGHT);
        currentCt = CommitmentTree.init();
        nextCt = CommitmentTree.init();
    }

    @After
    public void tearDown() {
        try {
            msgTree.close();
            currentCt.close();
            nextCt.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void shouldThrowExceptionIfPkSizeIsTooLarge() {
        Exception ex = assertThrows(Exception.class, () -> {
            Sc2Sc.setup(psType, customFieldsNum, Optional.of(TestUtils.CERT_SEGMENT_SIZE),
                    pkPath, vkPath, zk, 1);
        });
        assertTrue(ex.getMessage().contains("Circuit is too complex"));
    }

    @Test
    public void shouldUseTheGivenProvingSystemType() {
        assertEquals(psType, ProvingSystem.getVerifierKeyProvingSystemType(vkPath));
    }

    @Test
    public void provingKeyAndVerificationKeyShouldBeChoerent() {
        assertEquals(ProvingSystem.getVerifierKeyProvingSystemType(vkPath),
                ProvingSystem.getVerifierKeyProvingSystemType(pkPath));
    }

    @Test
    public void shouldThrowExceptionIfWeUseNotEnoughtCustomFields() {
        Exception ex = assertThrows(Exception.class, () -> {
            Sc2Sc.setup(psType, 1, Optional.of(TestUtils.CERT_SEGMENT_SIZE),
                    pkPath, vkPath, zk, maxProofPlusVkSize);
        });
        assertTrue(ex.getMessage().contains("need at least"));
    }

    private byte[] generateRandomBytes(Random r, int len) {
        byte[] bytes = new byte[len];
        r.nextBytes(bytes);
        return bytes;
    }

    private byte[] generateFieldRandomBytes(Random r) {
        try (FieldElement f = FieldElement.createRandom(r)) {
            return f.serializeFieldElement();
        }
    }

    private void addRandomScc(Random r, CommitmentTree ct, byte[] scId) {
        assertTrue(ct.addScCr(scId,
                r.nextLong(),
                generateFieldRandomBytes(r),
                generateFieldRandomBytes(r),
                r.nextInt(),
                r.nextInt(),
                (byte) r.nextInt(),
                new CustomFieldElementsConfig[0],
                new CustomBitvectorElementsConfig[0],
                r.nextLong(),
                r.nextLong(),
                generateRandomBytes(r, 1024),
                Optional.empty(),
                generateRandomBytes(r, 2000),
                Optional.empty()));
    }

    private byte[] root(CommitmentTree ct) {
        try (FieldElement root = ct.getCommitment().get()) {
            return root.serializeFieldElement();
        }
    }

    private byte[] appendRandomMsgHash(Random r) {
        try (FieldElement msgHash = FieldElement.createRandom(r)) {
            msgTree.append(msgHash);
            return msgHash.serializeFieldElement();
        }
    }

    private MerklePath getMsgPath(int leafIndex) {
        msgTree.finalizeTreeInPlace();
        return msgTree.getMerklePath(leafIndex);
    }

    private byte[] getMsgRoot() {
        msgTree.finalizeTreeInPlace();
        try (FieldElement root = msgTree.root()) {
            return root.serializeFieldElement();
        }
    }

    @Test
    public void happyPath() throws Exception {
        Random r = new Random();
        RandomProofData proofData = generateRandomProof(r, 42);

        assertNotNull("Proof creation must be successful", proofData.proof);

        assertEquals(psType, proofData.proof.getProofProvingSystemType());

        assertTrue(
                proofData.proof.verify(
                        proofData.nextScTxCommitmentsRoot,
                        proofData.currentScTxCommitmentsRoot,
                        proofData.msgHash,
                        vkPath));
    }

    private byte[] changeBytes(byte[] data) {
        data[0] = (byte) (data[0] + 1);
        return data;
    }

    @Test
    public void shouldNotVerifyInvalidInput() throws Exception {
        Random r = new Random();
        RandomProofData proofData = generateRandomProof(r, 42);

        assertFalse(
                proofData.proof.verify(
                        changeBytes(proofData.nextScTxCommitmentsRoot),
                        proofData.currentScTxCommitmentsRoot,
                        proofData.msgHash,
                        vkPath));

        assertFalse(
                proofData.proof.verify(
                        proofData.nextScTxCommitmentsRoot,
                        changeBytes(proofData.currentScTxCommitmentsRoot),
                        proofData.msgHash,
                        vkPath));

        assertFalse(
                proofData.proof.verify(
                        proofData.nextScTxCommitmentsRoot,
                        proofData.currentScTxCommitmentsRoot,
                        changeBytes(proofData.msgHash),
                        vkPath));

    }

    // Generate a RandomProofData with just a a certificate for epoch and epoch + 1.
    private RandomProofData generateRandomProof(Random r, int epoch) throws Exception {
        // We'll create tx commitment for a epoch with one certificate and
        // another one for next epoch with another certificate. From this
        // commitments we'll extract the path and then create a circuit.
        byte[] scId = generateFieldRandomBytes(r);
        byte[] msgHash = appendRandomMsgHash(r);
        byte[] msgRoot = getMsgRoot();

        WithdrawalCertificate currWithdrawalCertificate = WithdrawalCertificate.getRandom(
                r, 0, MIN_CUSTOM_FIELDS);
        currWithdrawalCertificate.setScId(scId);
        currWithdrawalCertificate.setEpochNumber(epoch);

        currWithdrawalCertificate.setCustomField(MSG_ROOT_HASH_CUSTOM_FIELDS_POS, msgRoot);
        byte[] currCertHash = currWithdrawalCertificate.getHashBytes();

        addRandomScc(r, currentCt, scId);
        currentCt.addCertLeaf(scId, currCertHash);

        byte[] currentScTxCommitmentsRoot = root(currentCt);

        WithdrawalCertificate nextWithdrawalCertificate = WithdrawalCertificate.getRandom(
                r, 0, MIN_CUSTOM_FIELDS);
        nextWithdrawalCertificate.setScId(scId);
        nextWithdrawalCertificate.setEpochNumber(epoch + 1);

        nextWithdrawalCertificate.setCustomField(MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS, currCertHash);
        byte[] nextCertHash = nextWithdrawalCertificate.getHashBytes();

        addRandomScc(r, nextCt, scId);
        nextCt.addCertLeaf(scId, nextCertHash);
        byte[] nextScTxCommitmentsRoot = root(nextCt);

        try (
                ScCommitmentCertPath currentPath = currentCt.getScCommitmentCertPath(scId, currCertHash).get();
                ScCommitmentCertPath nextPath = nextCt.getScCommitmentCertPath(scId, nextCertHash).get();
                MerklePath msgPath = getMsgPath(0);) {
            Sc2ScProof proof = Sc2Sc.createProof(
                    nextScTxCommitmentsRoot,
                    currentScTxCommitmentsRoot,
                    msgHash,
                    nextWithdrawalCertificate,
                    currWithdrawalCertificate,
                    nextPath,
                    currentPath,
                    msgPath,
                    pkPath,
                    Optional.of(TestUtils.CERT_SEGMENT_SIZE),
                    zk);
            return new RandomProofData(nextScTxCommitmentsRoot, currentScTxCommitmentsRoot, msgHash, proof);
        }
    }

    private static class RandomProofData {
        public byte[] nextScTxCommitmentsRoot;
        public byte[] currentScTxCommitmentsRoot;
        public byte[] msgHash;

        public Sc2ScProof proof;

        public RandomProofData(byte[] nextScTxCommitmentsRoot, byte[] currentScTxCommitmentsRoot,
                byte[] msgHash, Sc2ScProof proof) {
            this.nextScTxCommitmentsRoot = nextScTxCommitmentsRoot;
            this.currentScTxCommitmentsRoot = currentScTxCommitmentsRoot;
            this.msgHash = msgHash;
            this.proof = proof;
        }
    }
}
