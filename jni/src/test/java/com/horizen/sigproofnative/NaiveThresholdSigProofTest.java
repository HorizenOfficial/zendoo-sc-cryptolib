package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class NaiveThresholdSigProofTest {

    static int keyCount = 3;
    static int threshold = 2;

    byte[] endEpochBlockHash = new byte[32];
    byte[] prevEndEpochBlockHash = new byte[32];

    static int backwardTransferCout = 5;

    List<SchnorrKeyPair> keyPairList = new ArrayList<>();
    List<SchnorrPublicKey> publicKeyList = new ArrayList<>();
    List<SchnorrSignature> signatureList = new ArrayList<>();

    List<BackwardTransfer> btList = new ArrayList<>();

    @Before
    public void testGenerate() {

        for(int i = 0; i < backwardTransferCout; i++) {

            byte[] publicKeyHash = new byte[32];
            long amount = i;

            btList.add(new BackwardTransfer(publicKeyHash, amount));
        }


        for (int i = 0; i<keyCount; i++) {
            SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

            keyPairList.add(keyPair);
            publicKeyList.add(keyPair.getPublicKey());
        }

        for (int i = 0; i<keyCount; i++) {
            if (i < threshold) {
                FieldElement msgToSign = NaiveThresholdSigProof.createMsgToSign(btList.toArray(new BackwardTransfer[0]),
                        endEpochBlockHash, prevEndEpochBlockHash);
                signatureList.add(keyPairList.get(i).signMessage(msgToSign));
            } else {
                signatureList.add(new SchnorrSignature());
            }
        }

    }

    @Test
    public void testCreateProof() {

        ClassLoader classLoader = getClass().getClassLoader();
        String provingKeyPath = new File(classLoader.getResource("sample_params").getFile()).getAbsolutePath();
        byte[] proof = NaiveThresholdSigProof.createProof(btList, endEpochBlockHash, prevEndEpochBlockHash,
                signatureList, publicKeyList, threshold, provingKeyPath);

        assertNotNull("Proof must be not null.", proof);

        String verificationKeyPath = new File(classLoader.getResource("sample_vk").getFile()).getAbsolutePath();
        long quality = threshold;
        boolean isProofVerified = NaiveThresholdSigProof.verifyProof(btList, publicKeyList, endEpochBlockHash,
                prevEndEpochBlockHash, threshold, quality, proof, verificationKeyPath);

        assertTrue("Proof must be verified", isProofVerified);

        quality = threshold - 1;
        isProofVerified = NaiveThresholdSigProof.verifyProof(btList, publicKeyList, endEpochBlockHash,
                prevEndEpochBlockHash, threshold, quality, proof, verificationKeyPath);

        assertFalse("Proof must not be verified", isProofVerified);
    }
}