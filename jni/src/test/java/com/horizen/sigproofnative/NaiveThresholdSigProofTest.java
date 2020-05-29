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
            -74, -64, -96, -97, -11, -73, 121, 67, 101, 70, -73, -126, -70, -58, 97, 37, 91, -69, 52, 83, 88, -56, 102,
            53, 114, -73, -102, 54, 75, 115, 40, 98
        };

        prevEndEpochBlockHash = new byte[] {
            -36, 98, -40, 70, -126, 44, 85, -64, -8, 15, 17, 4, 30, -101, -62, 111, -26, 47, -7, -109, 92, -126, 33,
            68, -57, -66, 92, 114, 23, -62, 17, 78
        };

        byte[][] secretKeyList = {
            {
                -59, 53, 29, -21, -91, -27, 118, -71, 45, 97, 27, 125, -7, 49, 43, 49, 104, -107, -101, -111, -19,
                -111, -75, -37, -47, -82, 45, 93, 54, -69, -102, 17, 20, -107, 14, -42, -70, -34, 124, -98, 115, 117,
                -86, 31, -16, 10, 2, 6, 30, 1, -3, -115, -39, -9, -63, 81, -94, 38, 31, -47, -38, -121, 59, 40, 91,
                127, 77, -12, 116, -2, 126, 111, 84, -3, 47, 124, -41, 126, 123, 76, -65, -107, -62, -80, -102, -41,
                -61, -104, 26, -59, -60, 109, 72, 44, 1, 0

            },
            {
                -65, 112, 49, 1, -109, 105, 64, -43, -48, -126, -52, 18, 28, 49, 32, -108, 72, -48, -116, -56, -8, 115,
                86, 55, 19, 97, 11, 6, 16, 45, -17, 31, 123, 69, -25, -96, 126, -84, -76, -86, 127, -21, 5, -19, 60, 3,
                82, -33, -73, 31, -95, 45, 121, -61, -14, -85, -35, -76, -92, -97, -107, 106, -79, 38, -113, -64, -18,
                -82, 108, 127, -1, -92, 43, 29, -91, -84, 117, 56, 52, 75, -83, 33, 124, -100, 44, -88, -78, -91, 127,
                -103, -1, -80, 61, 111, 0, 0
            },
            {
                12, 65, 108, -87, 29, 75, 120, -70, 47, 123, -38, -116, 122, -8, -105, 3, -26, -64, -26, 3, 91, -80, 4,
                63, -3, 7, 95, -113, -112, 84, 56, 95, 37, 71, 7, 25, -85, -37, -118, -2, -21, 126, 49, 37, 49, 86, 33,
                -117, 16, 122, -103, 46, -121, 3, 38, -111, 69, 37, -98, -96, 87, -109, 72, -26, 51, -68, -88, 52, -102,
                119, -15, 106, 32, 107, 54, 14, 120, -19, -104, 116, 50, 12, 17, 80, -42, 64, -123, -70, -84, -56, 35,
                -4, 57, 127, 1, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                -42, 95, -60, 33, -73, -100, -98, -31, 74, 75, -13, 10, 57, -67, -112, -8, -80, 27, -125, 56, 48, 42,
                12, 107, 119, -111, 15, 114, -30, 93, 15, 40, 21, 3, -80, -94, -42, 85, -126, 35, 110, -104, 35, -13,
                -62, 91, 100, 34, 6, 93, -51, 107, 60, 110, 64, -57, 29, -48, -71, -57, 81, -111, -28, 57, 0, -9, 109,
                87, 15, 31, 26, 60, 37, 16, -72, 69, 87, -90, -24, -41, -61, 99, -49, 104, -102, 125, 103, -15, 44, -42,
                95, 4, -40, 79, 0, 0, -21, 9, 19, 15, -102, -18, 113, -43, -89, -74, 55, -65, -122, 113, -11, 44, -74,
                43, -125, -2, 12, -83, -54, -62, 75, 86, 69, -36, 13, -65, -1, 103, 45, 118, 21, 81, -112, 34, 71, 124,
                -95, -109, -67, -78, 78, 56, -77, 6, -25, -115, -84, -113, -16, 34, -20, 29, -94, 114, 117, -102, -35,
                126, 0, 123, 23, 98, -70, -119, -23, -104, -84, -31, 19, -51, -104, 26, -74, 46, -20, -69, -119, -36,
                107, 39, 104, -54, -117, 112, 23, 58, -26, 35, -21, 63, 0, 0
            },
            {
                -117, 61, 79, 82, 23, -34, 92, 67, 2, -34, 78, 44, 91, -37, 55, -8, 33, -81, 111, -13, -82, 62, -76, 35,
                -85, -63, 74, -87, -44, 105, -110, -40, 109, -103, -110, 20, 6, -60, -64, -28, -92, 126, -58, 95, -55,
                -104, 31, 1, -21, 64, -99, -64, -106, -73, -82, -104, 64, 35, -126, -30, 98, 49, 29, 118, -15, -51, -14,
                -83, -78, 20, 40, 49, -91, -1, -53, 1, 9, -128, 61, -14, -97, 47, 10, 107, 41, -100, -80, -116, -120,
                -86, -49, 72, 23, 83, 0, 0, 62, -89, -111, -69, -38, 79, -68, -43, 11, 46, 99, -104, -48, 104, -84, -72,
                23, -48, -111, 20, 90, -37, -84, -111, 92, 123, -41, -43, -32, -74, 36, 98, -77, -69, -95, -48, -91, 1,
                -44, 89, 11, 87, -47, -76, -81, 120, 36, -57, -30, 14, -71, -33, -91, 50, -30, -118, 21, 65, -79, -23,
                100, 21, -116, 119, 97, 20, -8, -63, -5, 106, -67, 81, -125, -1, 49, -67, 6, 126, 70, 28, 64, 68, -74,
                -12, -80, -58, -82, -18, 109, -64, -77, 20, 15, -69, 0, 0
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
    public void testcreateProofWithoutBWT() {

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