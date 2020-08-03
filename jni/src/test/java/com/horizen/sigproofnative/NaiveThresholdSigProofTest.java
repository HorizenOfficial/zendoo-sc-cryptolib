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
            108, 120, -57, 100, 26, 42, -15, 100, 48, 110, -10, -128, -79, 35, -118, -19, -104, -80, 2, -4, 11, 26, -67,
            14, 8, 70, 43, -103, 77, 11, 5, 13
        };

        prevEndEpochBlockHash = new byte[] {
            -112, 103, -71, 61, 27, 70, 111, 101, 11, -41, -74, 40, -5, 85, 87, -33, 116, -56, 11, 7, 90, 105, -63,
            28, -119, 26, 90, 6, -125, -97, 109, 47
        };

        byte[][] secretKeyList = {
            {
                117, 43, 79, 35, -58, -64, -84, 97, 94, 112, -39, 52, -112, 120, 6, -64, -28, -67, -71, 81, 100, 77, -94,
                -107, -75, -82, 99, 106, -48, -17, -1, -11, -48, 14, 24, 52, -31, -121, -115, -82, -8, 44, -10, -93, 98,
                13, 98, -123, -122, 69, 60, 48, -31, -94, 90, -111, 72, 89, 41, -115, -112, -55, 117, 9, 120, 40, -90,
                -85, 1, 126, 44, 115, 14, 79, -103, -111, -39, -59, 18, 46, -53, -74, 15, 66, -111, -49, -122, 127, -37,
                124, -121, 117, -83, -120, 1, 0
            },
            {
                67, 57, -58, 77, -70, 35, -116, 77, -121, -43, 92, -31, 108, 22, 29, 5, 126, -100, -61, -17, -93, -107,
                -7, 20, 123, 124, -59, -107, 85, 120, 123, 16, 47, -58, 75, -59, -38, -89, -94, 116, -52, -84, 87, -83,
                -10, -97, -83, -39, -91, -18, 4, 30, -55, 97, 104, -71, -62, -59, 5, -56, -9, -70, 10, -120, -92, -102,
                -39, -83, -122, -83, 68, -9, -62, 30, 36, -3, -124, 86, -107, 37, 120, -9, -87, 73, -51, 39, -89, -57,
                60, -71, -88, 102, -43, 64, 1, 0
            },
            {
                25, -81, 57, -36, -51, -12, 109, -9, 92, -98, 5, 103, 108, -6, 74, 73, -72, -58, -16, -87, 34, 19, 106,
                41, 0, -94, -127, 96, -41, -105, -16, 46, -86, -78, -6, -30, -100, 69, -24, -105, -19, -72, -33, -22,
                -42, 81, -33, 68, -62, 113, 29, 63, 1, -52, -17, 30, -42, -97, 36, -97, -11, 58, -5, -123, 93, -86, -21,
                -122, 65, -67, -30, -123, 38, 5, -121, -82, -3, -40, -9, 47, -43, -74, -90, -86, 106, 116, -108, -123,
                -102, -49, 4, 79, -117, 41, 0, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                -123, -95, 102, -55, -94, 13, -88, 50, -127, -26, -50, 107, -54, -84, 45, -94, -122, 99, -122, 99, -89,
                126, 45, -128, 37, -22, -104, -83, 1, 114, -123, 73, -83, -53, 34, -58, -126, 31, -122, 28, -97, -11,
                -24, -65, -26, -48, 124, -18, 99, -42, -45, 87, -57, -64, -4, -56, 14, 4, -26, -70, 94, -6, 48, 8, 60,
                97, -111, 122, 62, -34, 36, -72, 114, 63, -61, 74, 120, 59, -85, 32, -32, -92, 0, -35, -77, 83, -85,
                -71, 35, -94, 78, 86, 0, 126, 0, 0, -58, 48, 16, -49, 90, -107, 1, -36, -77, 112, -76, -1, 46, 121,
                -82, 95, 105, 45, -124, 95, -72, -42, -6, 71, -18, 80, 39, -72, -103, -125, 108, -71, -37, -20, -125,
                -13, -56, -121, -71, 5, 21, 94, -120, -22, 77, -119, 26, -80, -105, -102, -86, 71, 4, -59, -57, 45, -29,
                -71, -96, 33, 85, -88, 24, -102, -7, -120, -128, -95, 18, -117, -50, -9, 122, 62, 16, 78, -103, -67, 126,
                -38, -13, -110, -5, -39, 123, -42, 81, 88, -123, -45, 36, 90, -13, -117, 0, 0
            },
            {
                -33, -80, -32, 7, 100, 116, -78, -29, -64, -127, 52, 35, -107, -26, 108, -38, 76, 6, -91, -52, 30, -70,
                -36, 78, -103, 115, 121, 19, -107, -94, 51, -38, 32, -14, -10, -101, 73, -34, -18, 101, 70, 56, 10, -84,
                -67, -27, -19, 62, 86, 79, 4, -24, -19, 75, -88, 52, 78, -64, 88, 67, -24, 66, -122, -35, 9, -66, 64, 64,
                -39, -71, 26, -51, -75, -111, -121, 66, -101, 44, 115, -70, -121, -15, -45, 61, -106, 45, -30, -43, 36,
                -6, 36, 25, 92, 78, 0, 0, -97, 11, -64, -33, -86, 124, 93, -110, 67, 35, 92, 76, 100, 8, 76, 60, 116,
                -67, 58, 59, -47, -52, -94, 24, -28, -23, -56, -109, -127, 10, 95, 92, -115, -72, -15, -54, -80, -8,
                -41, -75, 17, -36, 47, 46, 33, 48, -75, -57, -11, -78, 20, 91, 56, 58, -1, 71, 118, -70, 7, 89, -51,
                -65, 7, 9, -18, -26, 107, -76, -13, 123, 52, 22, -124, -114, 43, 116, 126, 31, 42, -61, -122, -104, 4,
                11, -128, 119, -9, -7, -79, 7, -51, 8, 83, 89, 0, 0
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
    public void testcreateProofWithoutBWT() throws Exception {

        endEpochBlockHash = new byte[] {
            61, -127, 80, -103, 117, -119, -44, -90, 52, -56, 79, -18, -64, -92, -42, -61, -89, 8, -107, 114, -6, -58,
            87, 123, 54, 3, 100, 121, -26, -80, -122, -90
        };

        prevEndEpochBlockHash = new byte[] {
            95, 99, 89, 78, -113, 46, 99, -61, -11, -11, -24, 104, -51, -109, -48, 11, 119, 94, 104, -104, 38, -84,
            126, 22, -119, -96, -57, -67, 38, 109, 73, -22
        };

        byte[][] secretKeyList = {
            {
                -63, 75, 3, -102, -107, 40, -92, 126, -93, 78, -33, -110, 98, -23, 115, -111, 39, -37, -88, 56, -25, 44,
                -59, 15, 106, -95, 105, 73, 14, 38, 81, -94, -36, -41, 57, -7, -104, 96, -38, -30, 15, -61, 36, -109,
                -74, -38, 70, -97, 67, -19, 74, -122, 98, -95, 27, -33, -44, 83, -20, 12, -44, -107, -81, -7, 24, -73,
                118, 70, 5, -41, 13, 109, -106, -8, 39, 79, 24, 94, -5, -61, 47, 124, -107, -99, -25, -81, -3, -104,
                -78, -76, 62, -45, -66, 74, 0, 0
            },
            {
                4, 80, -48, 29, 28, 54, -89, 82, 40, -76, -78, -111, 30, 51, 82, -64, -97, -33, 46, 91, 25, -20, 72,
                117, 84, 38, -53, 40, 26, 125, 77, -22, -16, -83, -23, 0, 52, -27, 57, -17, 83, -60, 59, 125, 97, 94,
                -118, -10, 33, -5, -79, 15, 105, -119, -99, 125, 107, -123, -27, 89, -56, -99, -114, 62, 31, 82, -80,
                108, 104, -114, -60, -70, 34, 118, 97, -90, 15, -92, 2, -65, -82, 78, 119, -119, 107, 103, 3, 115, 15,
                -76, -30, -98, -91, 14, 1, 0
            },
            {
                16, -108, 42, -111, 35, -85, 34, -91, -83, -68, -36, 89, -39, 2, -67, -15, -48, -64, -109, 2, -22, 87,
                127, 16, 72, -116, -39, -13, 76, -100, 83, -103, -32, 78, 6, -13, -127, -2, -10, -33, -9, 32, 67, 17,
                12, -77, 70, 112, 101, -28, 76, 42, -93, 31, -108, -42, -26, -45, 96, -45, 119, -56, 118, 68, -61, -27,
                94, 22, -30, -120, -111, -115, -99, -86, 97, -98, -49, 23, 8, -9, 88, 50, -46, 48, -83, 65, -88, 120,
                -25, -92, 76, -112, -76, 82, 1, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                25, -17, 9, 92, -67, -25, 113, 99, -75, 110, -63, -63, 23, -107, -107, 8, 83, -94, 43, 55, 96, 71,
                -7, 37, -103, -28, -74, 125, -115, 125, 66, 33, -62, 54, 34, -6, 38, 26, -86, 62, 37, 26, -90, -46, -21,
                -47, 101, -105, 48, 62, 23, -64, -49, 20, -45, 41, -116, 21, -112, -79, -5, -56, -4, -33, -65, 76, -31,
                89, 15, 3, -41, -88, 48, -105, -98, -115, -49, -23, 98, -69, 105, 2, 13, 76, -107, 88, -61, 15, -122,
                73, 19, -117, -124, -16, 0, 0, 124, -66, 28, -41, -12, -12, 108, 19, 88, 107, 106, -5, 52, 122, 101,
                -59, -73, -99, 24, 43, -81, -93, 72, -83, -126, 24, 102, -125, -115, -27, 75, 92, 17, -61, -14, -58, 46,
                -104, 101, 94, -124, 117, 1, -66, 48, -127, -103, 32, -3, -81, 115, -21, 67, 126, 36, -74, 56, 113, 31,
                -123, 30, 8, -82, -115, 100, -89, 93, -105, -35, -82, 98, 34, 58, 77, 79, 56, 94, -111, -124, 17, 4,
                -13, -108, -121, 30, -89, 96, 43, 67, -55, 38, -61, -123, -119, 0, 0
            },
            {
                -72, 57, 95, -103, 95, 18, -39, -31, 116, 33, -76, -46, -121, 79, -123, 45, 119, 104, 1, -50, -95, 14,
                -93, 41, -63, 82, -61, 22, 65, -103, 115, -106, 69, -4, -40, -80, 45, -66, 105, 30, -55, 9, -86, -60,
                48, 100, -81, -1, 45, 111, -55, -93, 5, 33, -101, -56, 56, 10, 110, 22, -66, -57, 21, -102, -44, 54,
                -119, 121, -32, 51, -4, 70, -74, -26, 91, -20, 8, -43, -5, 75, -73, 12, -43, 46, -4, 98, 49, -20, 97, 8,
                87, 53, -65, 119, 0, 0, -16, 35, -123, 124, -6, 10, 61, -27, 123, 4, -66, 71, -92, -125, 108, -76, 104,
                79, -74, 42, 125, -59, 89, 126, 124, -21, 67, -56, 22, -109, -39, -30, 4, 53, 5, 111, -96, 82, 123, 77,
                86, 103, -75, 28, -79, -98, 108, -73, 55, 117, -22, -126, -7, 103, -10, 28, -73, 14, -37, -47, 56, -49,
                -34, 52, -117, 18, -99, -49, -73, -61, -114, -59, 43, -28, -30, 39, 29, -111, -98, -119, -40, 15, -75,
                24, 35, 118, 38, 85, -53, 8, 70, 80, 74, -117, 0, 0
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
                signatureList, publicKeyList, threshold, provingKeyPath);

        assertNotNull("Proof creation must be successfull", proofResult);

        String verificationKeyPath = new File(classLoader.getResource("sample_vk").getFile()).getAbsolutePath();

        byte[] proof = proofResult.getProof();
        long quality = proofResult.getQuality();

        FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
        assertNotNull("Constant creation must be successfull", constant);

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