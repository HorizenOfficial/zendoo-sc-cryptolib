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
    static int threshold = 2;
    static int backwardTransferCout = 5;

    byte[] endEpochBlockHash = new byte[32];
    byte[] prevEndEpochBlockHash = new byte[32];

    List<SchnorrPublicKey> publicKeyList = new ArrayList<>();
    List<SchnorrSignature> signatureList = new ArrayList<>();
    List<BackwardTransfer> btList = new ArrayList<>();

    @Test
    public void testcreateProof() {

        endEpochBlockHash = new byte[] {
            -48, -13, 79, 107, -43, 65, -103, -81, -88, -114, -94, 74, -19, 79, -68, -88, 22, -83, -97, 125, 28, -76,
            -121, -90, -17, 123, -123, 80, -62, -36, -47, -93
        };

        prevEndEpochBlockHash = new byte[] {
            77, -20, -70, 101, 37, 51, 64, 69, 119, -124, 109, -13, 44, -101, -121, -69, 102, 84, -31, 70, -125, -9, -39,
            97, 100, 84, 21, -17, 28, -22, 86, 107
        };

        byte[][] secretKeyList = {
            {
                -50, -128, 123, -18, 63, -75, -74, 106, -53, 91, 111, 88, 66, 105, 69, 11, -80, -13, -113, 54, 78, -97, 85,
                75, -77, -31, -83, 107, -56, -38, -99, 108, 25, 108, 16, -46, 41, -124, -92, -115, -102, 73, 102, 39, -47,
                -92, 95, -115, 67, -108, -128, 121, -58, -21, 42, 66, 117, 97, -118, 90, -109, 46, -78, -22, -37, 24, 111,
                -40, 21, -14, 55, 55, -89, -11, -15, -34, 120, 86, 90, -99, -14, 75, 32, -92, -92, 119, -64, -61, 14, -13,
                -20, 53, 68, 108, 1, 0
            },
            {
                -48, -3, 82, -50, -74, 38, 17, -122, 85, -101, -103, 36, -52, -101, -8, -124, -5, -54, -68, -99, 15, -35,
                16, -38, -11, 82, -79, 58, 53, 62, 63, -7, 99, 57, -25, -21, 76, -63, 106, -6, 103, -7, 36, -78, 123, 44,
                -85, -104, -58, 123, -61, -33, -14, -17, 96, -11, 99, 82, 33, -48, 57, -44, -106, -54, 28, 99, -51, -94,
                112, 72, -7, -9, -10, -56, -17, -2, -65, 59, 123, -104, 115, 54, -125, -112, 42, 109, -93, 49, 20, -13, 11,
                -60, 46, 1, 1, 0
            },
            {
                -77, 51, 95, -26, 79, -2, 76, -70, -49, -12, 88, -57, -92, -63, 116, 89, 9, -120, -28, -120, -8, 39, 91, 65,
                -34, -115, -50, 95, -54, 45, -92, 69, -100, 69, 81, -102, -7, 71, 101, 69, 91, 93, -31, -89, -47, -27, -28,
                82, 72, -24, 4, 76, -82, -113, -101, 27, 35, 115, -95, -74, 30, 103, 71, -125, -120, 24, -73, -107, 97, 125,
                2, 82, 37, 23, 39, 110, -56, -108, -44, 30, 52, 48, -48, 62, -1, 92, 43, 82, -37, 39, -44, 46, 21, -20, 0, 0
            }
        };

        byte[][] serializedSignatureList = {
            {
                -18, -106, 109, -27, 43, 15, 8, 29, 123, -7, -2, -128, -91, 41, -49, 63, 14, -121, 54, -103, -125, -121,
                -82, -109, -29, 38, 101, -89, -87, 22, 126, -50, 113, 94, -80, 116, -104, 55, 112, -28, -69, 21, -22, 40,
                -69, 47, 116, 2, -78, 81, -65, 107, 122, 121, -117, 106, -15, -126, 37, -112, 83, 126, -108, -66, 0, -82,
                43, -125, -122, 112, -82, -124, 109, 102, -53, -6, -90, -108, -104, -122, -120, 116, 93, -49, 94, -104, 19,
                83, 56, 22, 91, 66, -41, -106, 0, 0, -36, 99, 41, -68, -59, -125, -20, -17, -32, 41, -4, -53, 75, 16, 58,
                -19, 58, 7, 101, -111, 63, 124, 114, 73, -29, 116, -80, 37, 79, 44, -100, 30, -120, 0, -32, -85, 57, 63, 22,
                8, 119, 94, -21, -110, -79, 90, 26, -23, -31, 126, -61, 45, -69, 124, -66, -77, -6, -9, 107, -118, 113, -68,
                -68, -20, -88, -14, -92, -126, 81, -120, -56, -11, 121, -39, -4, -40, -54, 43, -32, 47, 124, -67, -45, -62,
                -91, 15, -35, 63, -56, -19, 48, 46, -99, 121, 0, 0
            },
            {
                -90, -71, 86, -123, 56, -67, -1, 114, -101, -105, 44, -78, -5, 32, -39, 48, 90, -72, 21, 69, -13, 13, -119,
                9, 11, -28, 93, -102, 75, 7, -32, 2, 68, 51, -123, 75, 30, 26, 39, 53, 31, -122, -73, 59, 71, -92, 94, -63,
                -123, -29, 61, -29, 61, -90, -120, -104, -10, -45, 58, -109, -35, 74, -73, 3, -18, -21, 65, 44, -25, 64,
                114, -111, 118, 74, -81, -44, 15, 73, -14, -87, -67, 57, 2, -31, -35, -102, 10, 31, -70, 35, 61, 7, 4, 7, 0,
                0, -12, 97, 123, 85, 97, 39, 92, 100, -17, 112, -3, -100, -120, 10, 104, 12, -126, -90, 22, 123, 9, 9, -61,
                -90, 21, -74, -47, -71, 42, -122, -46, 5, -2, 97, -37, -110, 80, 54, 97, 20, -64, -38, 100, 100, 27, -8,
                -58, -46, 5, 116, 122, -79, 20, -17, -33, -31, -100, 13, -2, 55, -84, 34, 76, 114, -77, 68, 85, 5, 3, -90,
                -1, -96, -78, -110, -117, 51, -43, -14, -10, -99, -22, 16, 26, 81, 8, 82, -117, -119, -13, 35, 83, -69, -39,
                24, 0, 0
            }
        };

        // Create dummy Backward Transfers
        for(int i = 0; i < backwardTransferCout; i++) {

            byte[] publicKeyHash = new byte[32];
            long amount = i;

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

            byte[] publicKeyHash = new byte[32];
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