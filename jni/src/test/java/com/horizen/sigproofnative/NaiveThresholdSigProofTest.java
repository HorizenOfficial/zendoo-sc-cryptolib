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
    public void testcreateProof() throws Exception {

        endEpochBlockHash = new byte[] {
            -32, -64, -17, -49, 83, 109, -5, 40, 112, -121, 66, 4, -27, -81, -75, -44, -107, -40, 63, 56, -29, -15, 121,
            -25, 26, 1, 109, 94, 97, -46, -55, 15
        };

        prevEndEpochBlockHash = new byte[] {
            -77, 14, -30, 42, 8, -5, -24, 22, 35, -56, -118, -86, -41, 124, -118, -61, -21, -113, -116, 109, 86, -43,
            121, -21, -43, 94, 59, 0, -55, -128, -3, -8
        };

        byte[][] secretKeyList = {
            {
                -87, -91, -102, -128, 61, -75, -68, 78, 113, 98, -25, 5, -77, -9, 56, -80, -97, -15, -31, -104, 102,
                101, 122, 25, -54, -59, -51, -51, 16, 62, -6, -126, 113, 78, -114, 123, -115, -113, -14, -119, -119, 26,
                58, -35, -34, -97, -16, -93, 100, -83, -9, -104, -46, -24, -4, 44, -74, 88, 116, -53, 74, -127, 94, 64,
                -128, 52, 87, 32, -18, -56, -10, -25, 4, 25, 73, -101, 18, -92, -53, -49, 100, 27, -113, -114, 16, -36,
                -3, 95, -128, 53, 27, -88, -42, -105, 0, 0
            },
            {
                39, 124, -30, 25, 122, -101, -9, 28, -17, -41, -89, 95, -32, 85, 25, -77, 4, 78, 22, -25, -27, -79, -8,
                -35, -41, 69, -68, 84, 97, -8, -58, -18, 124, -76, 38, 24, 91, -101, 60, 107, 17, -26, -21, -96, 7, -36,
                -121, -96, -126, 69, -111, 117, 125, 76, 27, -40, 62, -29, -22, -58, 49, 76, 61, 95, 78, 124, 115, -61,
                101, 34, -34, 56, 9, -28, 81, 97, -118, 122, 33, -128, -102, -78, 84, 21, -109, 120, 72, -72, -86, -57,
                35, 39, 106, -48, 0, 0
            },
            {
                10, -16, -72, 77, 36, 1, 88, 17, 51, -49, -84, -16, 101, -36, -108, -46, 99, 13, -71, 53, -27, -54, -62,
                120, -64, -44, -5, 102, -69, -58, 11, -110, 127, 5, -62, -1, -31, 67, 53, -54, 119, 97, -36, 37, 121,
                -16, 87, -128, 69, -9, 68, 32, 31, 100, 44, 7, -106, 114, 32, 75, 84, 121, -35, -54, -119, 70, -120, 75,
                72, 18, -10, 45, 77, -91, 75, -10, 40, 92, -89, 113, 109, 109, -119, 21, 84, 11, -58, 96, 124, -69, -97,
                111, -88, 120, 0, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                37, -31, -109, 96, 16, 120, 106, -49, 2, -20, -21, -48, -62, -37, -35, -14, -17, -40, -50, 1, 34, 52,
                -61, 97, 76, 122, 84, 52, -75, 108, 72, 16, 106, -115, -113, 46, 118, 112, -128, 56, -66, -100, 66, 89,
                78, -126, -37, 15, -72, 119, 53, 83, -14, 84, 85, -2, 56, 64, 85, 87, 118, -79, -102, 30, -123, -17, 15,
                4, -84, -112, 15, -75, -75, 39, 70, -49, 30, -85, 113, -86, -107, -61, -98, 5, -46, 27, -65, -99, 69,
                -20, -24, -51, -96, -35, 0, 0, -12, -111, 66, 105, 93, -104, 28, -45, 73, -15, 28, -62, -7, 102, -107,
                120, -88, -22, 65, 117, 63, -89, 104, 125, -79, 96, -111, -15, -127, -110, 10, 94, -81, -95, 39, -83,
                -30, 38, -7, 48, -6, 62, -104, -88, -87, 95, -13, 122, 82, 10, 21, 78, 122, 60, -92, 63, 32, -53, 54,
                -115, -48, 79, 49, 3, -117, 81, -111, -8, -118, -40, 14, -27, -83, 24, 12, -113, -62, -6, 103, -16, 100,
                -124, 73, -56, 2, -22, -5, 64, 56, 48, 53, -76, 76, 121, 0, 0
            },
            {
                -124, -8, -14, 126, 53, -101, 85, 16, -22, -29, -59, -110, 20, 45, 85, 28, 117, -15, 11, -66, 23, -121,
                -49, -25, 60, -84, 53, 67, -7, 62, -95, -53, -88, 57, -70, -28, -64, 82, -72, 37, -125, -125, 70, -4,
                86, 11, 79, 115, 71, 104, -64, -63, -11, -101, 13, -91, -52, 117, -12, 56, 0, 113, -35, -115, -107, 18,
                -53, 58, 56, -10, 42, 126, -35, -57, 0, 124, -12, 47, -15, -19, -52, 34, -67, -14, 16, -111, -82, -83,
                19, 105, -121, -90, 101, -92, 0, 0, -103, 95, 40, -65, -59, -110, 102, -21, 80, -6, 117, 49, -119, -65,
                124, 94, 86, -65, -24, 111, 72, -123, 96, -127, 115, -3, 122, -4, -54, 68, 44, -53, 31, -119, -84, 1,
                115, 10, 78, -20, -24, -39, 22, -60, -109, -65, 45, -91, 26, 84, 0, -31, -49, -14, -8, 19, 19, -116,
                -32, 3, 34, 49, 78, -95, -65, 10, -57, 60, 65, 92, -61, -106, -10, -6, 69, -52, 45, -42, 41, 28, -1,
                -37, 80, 63, -53, 2, 16, -45, -92, 114, -30, -105, -100, -36, 0, 0
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

            try(SchnorrSecretKey sk = SchnorrSecretKey.deserialize(secretKeyList[i]))
            {
                assertNotNull("sk" + i + "deserialization must not fail", sk);

                SchnorrPublicKey pk = new SchnorrKeyPair(sk).getPublicKey();
                assertTrue("Public key verification failed.", pk.verifyKey());

                publicKeyList.add(pk);
            }
        }

        // Deserialize Schnorr Signatures
        for (int i = 0; i<keyCount; i++) {
            if (i < threshold) {
                SchnorrSignature sig = SchnorrSignature.deserialize(serializedSignatureList[i], true);
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
    public void testcreateProofWithoutBWT() throws Exception {

        endEpochBlockHash = new byte[] {
            102, 107, 20, 22, -35, -54, 46, -67, 78, 65, 82, 95, 92, 39, 50, -28, 23, -89, 12, 103, 96, -28, 100, 68,
            102, 84, 12, 106, -124, 21, 32, 56
        };

        prevEndEpochBlockHash = new byte[] {
            -80, -5, -9, 102, -26, 8, -38, -19, -49, 29, 74, 51, -18, -104, 48, -22, 106, -8, 44, 57, 54, -126, -123,
            96, -98, 22, 68, -102, -21, 125, 66, 67
        };

        byte[][] secretKeyList = {
            {
                -52, 85, -107, -41, -76, -89, 34, -31, 95, 120, 70, 16, 3, 85, 93, 10, -17, -78, 113, -35, -94, 121,
                -104, -38, 127, -13, 71, -105, -71, 36, -115, 14, -112, 75, 87, -14, -36, 44, -7, -9, 114, 81, 96, -102,
                50, -104, -70, 17, -15, -26, -63, -39, 119, -73, 121, -79, 120, -97, 38, -4, 14, -31, 126, 114, -13, 50,
                10, 64, 100, 117, 47, -9, 19, -121, 99, -83, -21, 14, 16, 17, -101, -12, 9, 55, -63, -92, -18, 43, 64,
                -37, -112, -54, 6, 113, 1, 0
            },
            {
                46, 8, -27, 15, -122, 27, -12, 74, 24, -71, 3, -99, 78, 43, -58, 92, -24, 0, -107, 0, 119, 22, -26, 26,
                8, -123, -29, -56, -93, -80, 4, -99, 18, -87, 19, -118, -121, -58, 50, 73, -91, 98, -36, 52, -66, -107,
                45, 1, -31, -79, 121, -97, 2, 63, -73, -50, -61, 19, 36, -36, 11, -60, -58, 24, 70, 6, 27, 26, -26, 122,
                6, -98, 56, -19, -117, -16, 92, 101, 51, 93, 55, -110, -67, 3, 34, 102, 93, -100, -74, -77, -21, -88,
                107, 24, 0, 0
            },
            {
                -100, 120, 48, -128, 24, 86, 91, -118, 65, 20, -38, -125, -118, 121, 11, -111, -117, -48, 53, -13, 4,
                108, -122, 19, 26, -85, 89, 92, 49, 58, 49, 36, 45, 8, -90, -125, 51, 92, -82, 127, 116, 126, -39, -38,
                2, 64, 22, 117, 65, -7, 23, 75, 83, 88, 68, -33, -18, 121, 58, -62, 47, 122, -101, -107, 35, -9, -64,
                -96, -69, -103, -88, -55, 102, -17, -33, 5, 26, 37, 34, 11, 23, -64, -88, 59, 123, -14, 102, -65, -53,
                -97, 120, 117, -111, -113, 0, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                -43, -61, -93, -31, -65, 40, 126, 68, -82, 34, -103, 36, 28, 100, -124, 65, -121, 28, 81, 92, 27, 113,
                69, -20, 74, -40, 116, -7, 75, 21, -119, -21, 30, -65, -113, 2, -16, 84, 4, 57, -68, -69, 0, -24, -64,
                110, 74, 101, 73, 78, 70, 31, 51, 9, -114, 37, -14, -69, 89, -45, -108, 0, -61, -94, -37, -78, -111, 75,
                -66, -9, 87, 127, 59, -75, 15, -55, -93, -91, 107, 26, -116, -119, 94, -78, -128, 125, 91, 61, -95, -4,
                -52, -109, -93, -6, 0, 0, 12, 36, 13, 89, 14, 97, -25, 87, -97, -53, 79, 72, -6, -6, -112, 105, 95, 96,
                13, 45, -66, 112, -80, -93, 50, 16, 76, -55, 40, -94, 87, -20, 4, 32, -103, 12, 17, -90, -78, -60, -25,
                39, 89, 127, 109, 27, -42, -78, 59, 53, 51, 124, 50, 53, 100, -45, -79, -56, -58, 98, 62, 90, -89, 69,
                26, 108, -83, 97, 94, -59, 122, -74, -21, 78, 36, 6, -126, -86, -50, -104, 53, -53, -88, -26, 118, -106,
                29, -59, -79, -122, -121, 126, -73, 71, 0, 0
            },
            {
                122, -41, 75, 79, 3, -29, 125, 63, 117, -74, -55, -97, -14, 52, 45, 58, -124, -20, 67, 64, -36, -29, -52,
                -76, -83, -1, -68, -6, -13, -88, -47, 107, 9, -54, 90, -2, 120, -33, -14, -83, -124, 16, 34, -4, -75,
                -114, -97, 89, 110, -103, -47, 69, -122, -46, 50, 117, 67, -8, 27, 106, 105, 114, 1, -78, -113, 82, -41,
                111, -59, -128, -20, 17, -4, -56, -122, -82, -53, -107, 85, 32, 45, -21, 26, 52, -120, 68, 5, 50, 114,
                -97, 5, 94, 16, -70, 0, 0, -107, 68, 106, 85, -33, -128, 118, 33, 32, 102, -9, 13, 96, -104, -90, -77,
                27, 96, -17, -34, -34, -47, 108, 7, -72, -118, 98, -57, 13, -85, -32, -54, -83, -88, -52, -75, 96, -127,
                104, 95, -120, -5, 85, -110, -67, 107, -65, -66, 23, 114, 20, 36, 80, 26, -90, 102, 18, 34, -109, 86,
                -33, 115, -126, -92, 47, -7, -116, 11, -84, -95, -51, 57, -98, 95, -39, 72, 11, 7, -126, -71, -19, 109,
                -8, -34, 84, -14, -33, 22, -88, -119, 35, 93, -5, -118, 0, 0
            }
        };

        // Deserialize secret keys and get the corresponding public keys
        for (int i = 0; i<keyCount; i++) {

            try(SchnorrSecretKey sk = SchnorrSecretKey.deserialize(secretKeyList[i]))
            {
                assertNotNull("sk" + i + "deserialization must not fail", sk);

                SchnorrPublicKey pk = new SchnorrKeyPair(sk).getPublicKey();
                assertTrue("Public key verification failed.", pk.verifyKey());

                publicKeyList.add(pk);
            }
        }

        // Deserialize Schnorr Signatures
        for (int i = 0; i<keyCount; i++) {
            if (i < threshold) {
                SchnorrSignature sig = SchnorrSignature.deserialize(serializedSignatureList[i], true);
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
    public void testCreateRandomProof() throws Exception {
        Random r = new Random();

        r.nextBytes(endEpochBlockHash);

        r.nextBytes(prevEndEpochBlockHash);

        backwardTransferCout = r.nextInt(backwardTransferCout + 1);
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

        String provingKeyPath = new File(classLoader.getResource("sample_params").getFile()).getAbsolutePath();
        CreateProofResult proofResult = NaiveThresholdSigProof.createProof(btList, endEpochBlockHash, prevEndEpochBlockHash,
                signatureList, publicKeyList, threshold, provingKeyPath, false);

        assertNotNull("Proof creation must be successfull", proofResult);

        String verificationKeyPath = new File(classLoader.getResource("sample_vk").getFile()).getAbsolutePath();

        byte[] proof = proofResult.getProof();
        long quality = proofResult.getQuality();

        FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
        assertNotNull("Constant creation must be successfull", constant);

        boolean isProofVerified = NaiveThresholdSigProof.verifyProof(btList, endEpochBlockHash,
                prevEndEpochBlockHash, constant, quality, proof, true, verificationKeyPath, true);

        assertTrue("Proof must be verified", isProofVerified);

        quality = threshold - 1;
        isProofVerified = NaiveThresholdSigProof.verifyProof(btList, endEpochBlockHash,
                prevEndEpochBlockHash, constant, quality, proof, true, verificationKeyPath, true);

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