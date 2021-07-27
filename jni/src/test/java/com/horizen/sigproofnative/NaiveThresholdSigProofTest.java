package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSecretKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.sigproofnative.*;
import com.horizen.provingsystemnative.ProvingSystem;
import com.horizen.provingsystemnative.ProvingSystemType;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Optional;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class NaiveThresholdSigProofTest {

    static int keyCount = 7;
    static long threshold = 5;
    static int backwardTransferCout = 10;
    static boolean zk = false;

    static int epochNumber = 10;
    static long btrFee = 100L;
    static long ftMinAmount = 200L;

    static int maxProofSize = 7000;
    static int maxVkSize = 4000;

    FieldElement scId;
    FieldElement endCumulativeScTxCommTreeRoot;

    List<SchnorrPublicKey> publicKeyList = new ArrayList<>();
    List<SchnorrSignature> signatureList = new ArrayList<>();
    List<BackwardTransfer> btList = new ArrayList<>();
    
    static String snarkPkPath = "./test_snark_pk";
    static String snarkVkPath = "./test_snark_vk";
    static int maxSegmentSize = 1 << 17;
    static int supportedSegmentSize = 1 << 15;
    static ProvingSystemType psType = ProvingSystemType.COBOUNDARY_MARLIN;
    
    @BeforeClass
    public static void initKeys() {
        assertTrue(ProvingSystem.generateDLogKeys(psType, maxSegmentSize, supportedSegmentSize));
        assertTrue(NaiveThresholdSigProof.setup(psType, keyCount, snarkPkPath, snarkVkPath, zk, maxProofSize, maxVkSize));
        assertFalse(NaiveThresholdSigProof.setup(psType, keyCount, snarkPkPath, snarkVkPath, zk, 1, maxVkSize));
        assertFalse(NaiveThresholdSigProof.setup(psType, keyCount, snarkPkPath, snarkVkPath, zk, maxProofSize, 1));
        assertEquals(
                psType,
                ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPath)
        );
        assertEquals(
                ProvingSystem.getProverKeyProvingSystemType(snarkPkPath),
                ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPath)
        );
    }

    @Test
    public void testCreateRandomProof() throws Exception {
        Random r = new Random();

        scId = FieldElement.createRandom();
        endCumulativeScTxCommTreeRoot = FieldElement.createRandom();

        backwardTransferCout = r.nextInt(backwardTransferCout + 1);
        // Create dummy Backward Transfers
        for(int i = 0; i < backwardTransferCout; i++) {

            byte[] publicKeyHash = new byte[BackwardTransfer.MC_PK_HASH_SIZE];
            r.nextBytes(publicKeyHash);
            long amount = r.nextLong();

            btList.add(new BackwardTransfer(publicKeyHash, amount));
        }

        List<SchnorrKeyPair> keyPairList = new ArrayList<>();

        for (int i = 0; i<keyCount; i++) {
            SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

            keyPairList.add(keyPair);
            publicKeyList.add(keyPair.getPublicKey());
        }

        for (int i = 0; i<keyCount; i++) {
            if (i < threshold) {
                FieldElement msgToSign = NaiveThresholdSigProof.createMsgToSign(
                    btList.toArray(new BackwardTransfer[0]),
                    scId,
                    epochNumber,
                    endCumulativeScTxCommTreeRoot,
                    btrFee,
                    ftMinAmount
                );
                signatureList.add(keyPairList.get(i).signMessage(msgToSign));
            } else {
                signatureList.add(new SchnorrSignature());
            }
        }

        //Free memory from the secret keys
        for (SchnorrKeyPair kp: keyPairList)
            kp.getSecretKey().freeSecretKey();

        createAndVerifyProof();
    }

    private void createAndVerifyProof() {

        CreateProofResult proofResult = NaiveThresholdSigProof.createProof(
            btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
            btrFee, ftMinAmount, signatureList, publicKeyList, threshold,
            snarkPkPath, false, zk
        );

        assertNotNull("Proof creation must be successful", proofResult);

        byte[] proof = proofResult.getProof();
        assertEquals(psType, ProvingSystem.getProofProvingSystemType(proof));

        long quality = proofResult.getQuality();

        FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
        assertNotNull("Constant creation must be successful", constant);

        boolean isProofVerified = NaiveThresholdSigProof.verifyProof(
            btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
            btrFee, ftMinAmount, constant, quality, proof, true, snarkVkPath, true
        );

        assertTrue("Proof must be verified", isProofVerified);

        quality = threshold - 1;
        isProofVerified = NaiveThresholdSigProof.verifyProof(
            btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
            btrFee, ftMinAmount, constant, quality, proof, true, snarkVkPath, true
        );

        assertFalse("Proof must not be verified", isProofVerified);
    }

    @After
    public void freeData() {
        for (SchnorrPublicKey pk: publicKeyList)
            pk.freePublicKey();
        publicKeyList.clear();

        for (SchnorrSignature sig: signatureList)
            sig.freeSignature();
        signatureList.clear();

        scId.freeFieldElement();
        endCumulativeScTxCommTreeRoot.freeFieldElement();
    }

    @AfterClass
    public static void deleteKeys(){
        // Delete proving key and verification key
        new File(snarkPkPath).delete();
        new File(snarkVkPath).delete();
    }
}