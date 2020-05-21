package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSecretKey;
import com.horizen.schnorrnative.SchnorrSignature;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class NaiveThresholdSigProofTest {

    static int keyCount = 3;
    static long threshold = 2;
    static int backwardTransferCout = 10;

    byte[] endEpochBlockHash = new byte[32];
    byte[] prevEndEpochBlockHash = new byte[32];

    List<SchnorrPublicKey> publicKeyList = new ArrayList<>();
    List<SchnorrSignature> signatureList = new ArrayList<>();
    List<BackwardTransfer> btList = new ArrayList<>();

    @Test
    public void testcreateProof() {

        endEpochBlockHash = new byte[] {
            64, 26, 114, 59, 75, -60, 118, 24, 67, -1, -75, 14, 117, 29, -44, -37, -12, -42, -116, 2, -63, -50, 5,
            75, 3, 20, 78, -114, 94, -127, -118, 50
        };

        prevEndEpochBlockHash = new byte[] {
            -68, -19, -86, -14, -53, -39, -69, 2, -128, -110, 2, -122, 116, -15, -10, -1, 104, -34, 26, -7, 62, -50,
            118, 39, -106, -1, -4, -122, 116, -11, 73, -83
        };

        byte[][] secretKeyList = {
            {
                -83, -58, 93, -35, 2, 46, -106, 48, 6, -31, -32, 60, 117, 12, -128, 44, 20, 123, -7, 6, 81, 43, -33,
                -88, 114, -82, -34, -82, 87, -8, 113, 123, -9, 81, -96, -100, 43, 14, -15, 126, 76, -21, 32, 63, -67,
                -2, 79, 52, -122, -99, 42, -82, -64, 71, -46, 83, 46, 48, -79, 62, 99, 3, -85, 64, -56, -56, -32, 123,
                -125, 100, -98, -17, -69, 27, -22, 14, -10, -114, 120, 2, 61, -9, -1, 79, -15, -105, 117, 80, 114, 29,
                37, -17, 125, 2, 1, 0
            },
            {
                58, 67, 55, 82, -123, -1, -14, -127, -21, -99, 100, 83, -94, -8, 112, -96, 97, -127, 91, -100, -72, 36,
                -20, 59, -96, -60, 72, 108, -104, 55, -44, 96, -4, -34, -54, 72, -50, 27, 59, 76, -112, -90, -31, 14, 9,
                58, -58, -78, 28, -35, -26, -69, -39, -95, -46, -9, 20, 22, -48, 70, -16, -90, 110, 23, 65, 32, 97, 21,
                -2, 3, -79, 117, -103, 121, 64, -10, -38, 122, 22, 0, -85, 85, -96, 22, -52, 66, -55, -44, 83, -67,
                -117, -12, 60, 110, 1, 0
            },
            {
                44, -26, 67, -62, 116, -91, 118, -122, -76, 84, -40, 51, -52, -31, -94, 26, -21, -25, -126, 118, -40,
                -96, 45, 111, 108, -105, -128, -114, 88, -57, -66, -94, -111, 25, 60, 36, 118, -53, -60, 11, 110, -71,
                -88, 4, 102, -33, 44, 106, -122, 16, 126, -32, 127, 64, 60, 2, 82, 81, -114, -33, 61, -78, 35, -55, 66,
                -120, -83, 60, -68, -89, -44, 40, -38, -5, -76, 54, -71, 68, 76, 124, 99, 121, -30, 5, 98, 10, 9, -13,
                67, 42, -79, -70, 90, -96, 1, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                -31, 71, 29, -47, 6, -52, 88, -86, 43, 57, -62, -87, 127, 56, -78, -65, -121, 114, 39, 22, -2, 64, -37,
                127, -102, -74, -78, 15, -118, 41, 87, 58, 59, -5, -51, -94, 90, -73, -28, -108, -50, 92, -30, -111, 110,
                27, 113, -11, 81, -86, -109, -72, -127, 7, 47, 32, 83, 0, 86, -37, 117, 23, 101, 121, 52, -83, -118, -120,
                79, -52, 111, -32, 16, 71, 83, -56, -106, -9, -3, -114, 6, -16, -21, 68, 107, -46, -50, 47, 51, -37, -4,
                103, -11, 106, 0, 0, 28, 64, -60, 12, -43, 66, -69, 123, 113, -56, -112, -126, -34, -80, -15, 63, 78, 51,
                79, -26, 104, -128, -17, 9, -62, 86, 29, 118, -29, 123, -119, -100, -121, -21, 106, 108, 88, 31, 17, 75,
                31, 42, 22, -67, 100, -19, -20, 74, 10, 109, -92, 69, 54, -23, -98, -106, -94, 83, -94, -51, -65, 122,
                53, 64, -37, -57, 68, -128, -54, 100, 64, 116, 87, -89, 124, 41, -19, 11, -42, 46, -75, -26, 113, 30,
                107, -96, 100, 119, 127, -79, -97, 102, 0, -41, 0, 0
            },
            {
                88, 17, -31, -75, 9, -15, -66, 17, 77, 57, -50, -46, -10, 87, -122, 15, -32, 103, -77, -113, 49, -74,
                -94, -7, -29, -21, -122, -62, -105, 40, -10, 5, 97, 37, 82, -103, -74, -15, -75, 88, 47, -6, 41, -93,
                70, -81, -22, -92, -103, -28, -88, -123, -40, -89, 86, 56, -13, 72, 64, 82, 126, 102, 117, -17, 107,
                -3, 83, 12, -104, -41, 49, -62, 0, -113, 25, -114, 104, -103, -101, 33, -100, 45, -34, 82, -8, -34,
                -106, 49, 87, 58, -52, 113, -91, 4, 0, 0, 35, 65, 44, -71, 79, 9, 24, -77, 100, -74, -3, 57, 121, 100,
                -50, -3, 33, 4, -104, -127, 78, 72, -66, 76, 66, 65, -80, 43, -32, 20, 56, -89, 120, -84, -81, -19, 3,
                -9, -103, 78, 18, -76, 47, -114, -26, 62, 102, 20, 93, 2, -116, -108, 57, 101, -35, 5, -116, 74, -18,
                88, 58, -128, 24, 25, 58, 69, -97, 105, -68, 82, 18, 11, 42, -73, 117, -52, -27, -46, -7, -90, 57, 51,
                43, -64, -122, -96, 63, -42, 118, -31, 121, -95, -71, -82, 0, 0
            }
        };

        // Create dummy Backward Transfers
        for(int i = 0; i < backwardTransferCout; i++) {

            byte[] publicKeyHash = new byte[20];
            long amount = 0;

            btList.add(new BackwardTransfer(publicKeyHash, amount));
        }

        // Deserialize secret keys and get the corresponding public keys
        for (int i = 0; i<keyCount; i++) {

            SchnorrSecretKey sk = SchnorrSecretKey.deserialize(secretKeyList[i]);
            assertNotNull("sk" + i + "deserialization must not fail", sk);

            SchnorrPublicKey pk = new SchnorrKeyPair(sk).getPublicKey();
            assertTrue("Public key verification failed.", pk.verifyKey());

            publicKeyList.add(pk);
            sk.freeSecretKey();
        }

        // Deserialize Schnorr Signatures
        for (int i = 0; i<keyCount; i++) {
            if (i < threshold) {
                SchnorrSignature sig = SchnorrSignature.deserialize(serializedSignatureList[i]);
                assertNotNull("sig" + i + "deserialization must not fail", sig);
                signatureList.add(sig);
            } else {
                SchnorrSignature sig = new SchnorrSignature();
                signatureList.add(sig);
            }
        }

        createAndVerifyProof();
    }

    @Test
    public void testCreateRandomProof(){
        Random r = new Random();

        r.nextBytes(endEpochBlockHash);

        r.nextBytes(prevEndEpochBlockHash);

        // Create dummy Backward Transfers
        for(int i = 0; i < backwardTransferCout; i++) {

            byte[] publicKeyHash = new byte[20];
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
                FieldElement msgToSign = NaiveThresholdSigProof.createMsgToSign(btList.toArray(new BackwardTransfer[0]),
                        endEpochBlockHash, prevEndEpochBlockHash);
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

        ClassLoader classLoader = getClass().getClassLoader();

        FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
        assertNotNull("Constant creation must be successfull", constant);

        String provingKeyPath = new File(classLoader.getResource("sample_params").getFile()).getAbsolutePath();
        CreateProofResult proofResult = NaiveThresholdSigProof.createProof(btList, endEpochBlockHash, prevEndEpochBlockHash,
                signatureList, publicKeyList, threshold, constant, provingKeyPath);

        assertNotNull("Proof creation must be successfull", proofResult);

        String verificationKeyPath = new File(classLoader.getResource("sample_vk").getFile()).getAbsolutePath();
        byte[] proof = proofResult.getProof();
        long quality = proofResult.getQuality();
        boolean isProofVerified = NaiveThresholdSigProof.verifyProof(btList, endEpochBlockHash,
                prevEndEpochBlockHash, constant, quality, proof, verificationKeyPath);

        assertTrue("Proof must be verified", isProofVerified);

        quality = threshold - 1;
        isProofVerified = NaiveThresholdSigProof.verifyProof(btList, endEpochBlockHash,
                prevEndEpochBlockHash, constant, quality, proof, verificationKeyPath);

        assertFalse("Proof must not be verified", isProofVerified);
    }

    @After
    public void testFree(){
        for (SchnorrPublicKey pk: publicKeyList)
            pk.freePublicKey();
        publicKeyList.clear();

        for (SchnorrSignature sig: signatureList)
            sig.freeSignature();
        signatureList.clear();

    }
}