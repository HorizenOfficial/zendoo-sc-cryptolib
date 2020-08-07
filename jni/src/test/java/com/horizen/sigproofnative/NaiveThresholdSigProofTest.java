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
            72, -102, 34, -122, 97, -105, 108, 58, 122, 53, 94, -50, 17, -59, -4, -29, -45, 107, 61, 82, -12, 43, 114,
                -24, 48, 64, 60, 110, -75, -25, -65, -25
        };

        prevEndEpochBlockHash = new byte[] {
            6, -60, -121, 58, 59, 3, 57, 115, 25, -71, 82, -13, -84, -115, -73, 126, 19, 36, -11, 43, 65, 109, 32, -86,
                -109, 45, -1, -52, -31, -5, 106, 55
        };

        byte[][] secretKeyList = {
            {
                66, 122, -83, 100, -113, -124, 108, -71, 30, -45, 25, 28, 123, 117, 95, -20, -46, -44, 79, -42, 88, 112,
                108, -84, 127, -19, 1, 83, -64, -121, -55, 126, 73, 11, -103, 119, 56, 61, -91, -126, 80, -42, -107,
                -75, -75, 57, 56, 64, 56, -18, 52, -25, 12, 7, -100, 5, 97, -113, -36, 82, 40, -100, 80, -2, 116,
                20, -99, 76, -104, 50, 104, -11, -52, -59, -36, 28, -68, -106, -77, 59, 55, -82, 1, 33, -6, -73, 11,
                107, 7, 124, 108, 90, -119, 18, 0, 0
            },
            {
                -49, 52, -7, -51, 103, -71, 54, 60, -94, -4, 76, -71, 66, -11, -2, -48, 3, 53, 39, -101, -14, -15, -72,
                -29, -34, -47, -51, -22, 67, -45, -38, 110, -14, -107, -97, 21, 104, 126, 6, -99, -1, 97, 70, 19,
                12, 32, -36, -15, 10, 107, -101, -53, -125, 99, -99, -4, 83, 67, 58, 91, 50, -81, 87, -80, -108,
                -42, -36, 88, -53, 85, -113, -96, 92, -16, -118, -94, 25, -1, -121, 103, 36, 97, 73, -116, -69, 47,
                -98, -54, 31, 66, 112, -18, 27, -123, 1, 0
            },
            {
                80, 78, -87, 50, -94, -19, -110, 94, -103, 30, -59, 64, -41, -91, 87, -43, 73, 120, -21, -53, 34, -5,
                -31, -19, 97, 115, -106, -124, -19, 73, 95, -73, 69, 77, -104, 40, 47, 33, -16, 90, -60, -98, -1,
                81, -44, -113, 49, 51, -4, -79, 30, 58, -60, -42, -43, -61, 100, 113, 22, 31, -126, 85, -95, 24,
                -85, 97, 112, -48, -101, -101, -102, -53, 51, -30, -46, 60, 93, 118, -68, -17, -30, -97, 40, 33,
                3, 10, 37, -100, -29, -96, -21, -62, 56, -76, 1, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                115, -6, 38, 115, 115, -63, 32, 110, 85, 109, 91, 116, -23, 102, 76, 114, -17, 6, 54, -68, 1, -70,
                126, 76, 45, -103, -92, 62, 81, 27, 6, -101, 124, 10, -42, -105, 125, -25, -4, 104, -100, -16, 40,
                90, -81, 49, -61, 77, 76, -100, 45, -120, -120, 0, 44, -51, -67, -75, 91, 55, -41, -79, 109, -15,
                -66, -84, -117, -69, 107, -82, -72, -88, -49, 103, -90, -91, 1, -121, -94, -30, 36, 122, -56, -31,
                37, 122, 42, -112, -112, -103, -14, -98, -10, -4, 0, 0, -21, -79, -58, 124, -50, -12, -111, -101,
                -108, 96, 33, -111, 9, 57, -122, -49, 44, -94, 91, 19, -74, -71, -78, -54, 125, -81, 86, -100, -35,
                127, 23, 15, 50, 91, 103, -113, 0, -84, -38, -48, 55, 109, 46, -70, -88, -66, -124, -46, 64, 35, 78,
                76, -72, -55, -5, 36, -111, -112, -123, 64, 49, 6, 84, -47, 112, 20, 14, 83, -94, 46, -66, 88, 34,
                61, -57, 51, 105, 53, -17, -94, 92, 127, 78, 104, 98, -113, -52, 124, 58, 38, -11, 74, -65, -117,
                0, 0
            },
            {
                25, -100, -104, -69, 76, -68, 68, 84, -65, -22, 119, -106, 87, 31, -120, 123, -5, 17, -88, -27, 27,
                -36, -120, -75, -1, 102, 91, -29, -82, 61, -53, -86, 50, 113, 61, 33, -110, -73, -113, -44, -111,
                21, -99, 110, -121, 37, -35, 35, 5, 87, 53, -75, -109, 114, -105, 98, 52, 21, -91, 25, 74, 13, 64,
                34, 11, -122, 114, 95, 115, 4, -113, 111, -96, -118, 110, -115, -9, -39, -78, 54, 78, 90, 59, 82,
                35, -38, 61, -119, 121, 47, -121, 31, -46, -12, 0, 0, -42, -126, 80, 53, 77, -65, -30, 44, -107,
                -18, 63, 2, 74, 72, 99, 93, 80, -90, 42, -85, -60, 63, -98, -66, 103, -38, -60, -124, 15, -125,
                -76, 56, -31, 58, 96, 12, 115, -114, -110, -61, -31, 119, 61, 111, 67, 123, -25, 37, 38, 90, 68,
                122, -67, -10, -91, -86, 101, 107, 115, -97, 4, 6, 59, -37, -56, 65, 8, 64, 54, -118, -104, -74,
                21, 34, -100, -75, 115, -32, 105, 43, -5, -124, 114, 8, -59, -18, -91, 119, -58, 127, -65, 16,
                -78, 84, 0, 0
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