package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSecretKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.sigproofnative.*;
import com.horizen.provingsystemnative.ProvingSystem;
import com.horizen.provingsystemnative.ProvingSystem.ProvingSystemType;
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

public class NaiveThresholdSigProofTest {

    static int keyCount = 3;
    static long threshold = 2;
    static int backwardTransferCout = 10;

    static int epochNumber = 10;
    static long btrFee = 100L;
    static long ftMinFee = 200L;
    FieldElement endCumulativeScTxCommTreeRoot;

    List<SchnorrPublicKey> publicKeyList = new ArrayList<>();
    List<SchnorrSignature> signatureList = new ArrayList<>();
    List<BackwardTransfer> btList = new ArrayList<>();
    
    static String dlogKeyPath = "./test_dlog_pk";
    static String snarkPkPath = "./test_snark_pk";
    static String snarkVkPath = "./test_snark_vk";
    static int segmentSize = 1 << 17;
    static ProvingSystemType psType = ProvingSystemType.COBOUNDARY_MARLIN;

//    @Test
//    public void testcreateProof() throws Exception {
//
//        endEpochBlockHash = new byte[] {
//            -99, -37, 85, -97, 75, 56, -110, 21, 107, -17, 76, 31, -48, -43, -26, 24, 44, 74, -6, 66, 71, 23, 106, 4,
//            -118, -99, 28, 43, -98, 39, -104, 91
//        };
//
//        prevEndEpochBlockHash = new byte[] {
//            74, -27, -37, 59, 25, -25, -29, 68, 3, 118, -62, 58, 99, -37, 112, 39, 73, -54, -18, -116, 114, -112, -3,
//            32, -19, 117, 117, 60, -56, 70, -69, -85
//        };
//
//        byte[][] secretKeyList = {
//            {
//                -46, 18, 42, 94, 0, 61, -66, 104, 55, -42, 56, -9, -108, 88, -20, 7, 24, 23, 102, 55, 8, -22, -61, -78,
//                83, -53, -84, -30, -103, -19, -23, 19, 8, 75, -54, 5, 68, 67, 11, -43, 105, 92, 87, -26, -1, 13, -85, 13,
//                -60, -11, 47, 55, -101, -50, -28, 6, -33, 112, -76, 82, -7, 67, 0, 36, -94, -30, 7, -60, 51, -72, -122,
//                -111, 76, -50, 95, -47, 72, 68, -7, -56, 80, -45, 52, 56, 34, -77, 80, -58, 68, 90, 87, -109, 36, -97,
//                0, 0
//            },
//            {
//                -81, 126, 94, -70, -111, 52, 22, -118, -68, 44, -78, 18, -96, -104, -123, -28, 99, -93, 17, -32, -59,
//                -10, 38, -54, 39, -74, -87, -121, -126, 71, 66, -57, 121, 7, 121, 78, -102, -61, -74, 44, 102, 39, 90,
//                -90, -109, -86, 12, -26, -69, -41, -58, 59, -94, 66, 46, -118, -35, 65, 47, 35, 58, 83, 123, 64, -99,
//                11, -50, 1, 81, -104, -74, 20, 76, -103, 45, -22, 12, 49, 1, -67, -23, -71, -68, 56, -47, 24, -18, -96,
//                -113, 23, -17, -28, 78, 6, 0, 0
//            },
//            {
//                51, 48, 94, -38, 100, 27, 60, -77, 28, -78, -32, 15, 126, 60, 75, 117, 126, 78, -25, -36, 93, -75, 119,
//                27, -70, -90, -62, 85, -97, 74, -22, -85, 70, 27, 93, -86, -113, 84, 21, 100, 73, 66, 20, -63, 93, 12,
//                -83, 90, 117, -13, 2, 108, 95, 34, 54, 116, -86, -45, -107, -118, -63, -71, 85, -37, -6, 20, -118, -77,
//                -13, 122, 96, -60, -45, 35, -53, 118, -65, -29, 2, 13, -35, 78, -106, -123, -14, 14, -84, 31, -24, -25,
//                75, -119, -52, -84, 0, 0
//            }
//        };
//
//        byte[][] serializedSignatureList = {
//            {
//                90, -4, 119, 23, -2, -115, 42, 7, 37, -61, -104, -76, -35, -114, 4, 94, -3, -111, -59, -82, -54, 71, 94,
//                31, 2, -119, 101, -23, -1, 122, -114, 119, -95, -83, 38, 61, 116, -3, 120, 78, -14, 4, -42, 118, -78,
//                -50, -2, 47, 14, -100, 100, -104, 27, -100, 53, -20, 49, 117, 32, 34, -7, -118, 87, 75, -91, 2, -18, 10,
//                74, 127, 55, -38, -121, -39, 47, -46, 122, -64, -103, -100, -68, -45, 29, 96, 74, -73, 45, -89, 42, -7,
//                4, -116, -52, 119, 0, 0, 99, 29, 5, 29, -81, -58, -114, -49, -16, 84, 27, -85, -50, -89, 127, -78, 82,
//                -93, -77, -19, -26, -94, -76, -46, -101, -89, 18, 20, -9, 67, 84, -89, 14, 58, -79, 89, -108, -116, 44,
//                66, -42, 104, 30, 48, -70, 61, 43, -38, 103, -91, 47, 19, 103, -98, -15, 113, -59, -114, 108, -122, 89,
//                -114, -31, 52, -38, -13, -80, -112, 39, 12, -123, -10, 5, -98, 105, -33, 59, 111, 53, -111, 4, 62, 55,
//                107, -106, 63, 63, -91, 54, 54, 104, 104, -1, 33, 0, 0
//            },
//            {
//                83, 104, 71, -62, 77, 11, 10, 6, -2, -23, -111, -67, 28, -98, 61, -73, -48, 43, 88, 109, 15, -76, -114,
//                -64, 36, -30, 59, 121, 95, 119, -115, 83, -89, 64, 80, -64, 32, -84, -48, 42, 32, 108, -113, -74, 60,
//                -124, -17, 36, -98, 13, -105, -106, 120, -116, -105, 104, -88, -52, -98, 77, -32, -106, 116, 43, -85,
//                14, -94, -69, 75, 94, -17, -48, -97, 96, 96, -41, 26, -100, -72, -5, -13, 4, -115, -55, -22, -103, 29,
//                39, -96, -99, 67, -85, -113, 101, 0, 0, 47, -36, 100, -36, -104, 92, 78, -20, 51, -56, 3, 81, -3, 20,
//                48, -79, -1, -128, -9, 6, -88, 36, -43, -16, -102, -93, 46, 51, 20, 38, -59, -75, -110, -16, 19, -108,
//                -55, 4, 91, -35, 91, 18, 43, -40, -83, -84, -112, 36, -9, -96, -112, 107, -8, -41, -102, 96, 114, 97,
//                113, -53, -25, -97, 36, 123, -118, -112, 62, -81, 118, -54, -124, 4, 94, 120, 19, -79, -37, 58, 47, -121,
//                -97, 60, 91, 95, -58, 10, -80, -52, -97, 86, -17, -82, -1, 86, 0, 0
//            }
//        };
//
//        // Create dummy Backward Transfers
//        for(int i = 0; i < backwardTransferCout; i++) {
//
//            byte[] publicKeyHash = new byte[20];
//            long amount = 0;
//
//            btList.add(new BackwardTransfer(publicKeyHash, amount));
//        }
//
//        // Deserialize secret keys and get the corresponding public keys
//        for (int i = 0; i<keyCount; i++) {
//
//            try(SchnorrSecretKey sk = SchnorrSecretKey.deserialize(secretKeyList[i]))
//            {
//                assertNotNull("sk" + i + "deserialization must not fail", sk);
//
//                SchnorrPublicKey pk = new SchnorrKeyPair(sk).getPublicKey();
//                assertTrue("Public key verification failed.", pk.verifyKey());
//
//                publicKeyList.add(pk);
//            }
//        }
//
//        // Deserialize Schnorr Signatures
//        for (int i = 0; i<keyCount; i++) {
//            if (i < threshold) {
//                SchnorrSignature sig = SchnorrSignature.deserialize(serializedSignatureList[i]);
//                assertNotNull("sig" + i + "deserialization must not fail", sig);
//                signatureList.add(sig);
//            } else {
//                SchnorrSignature sig = new SchnorrSignature();
//                signatureList.add(sig);
//            }
//        }
//
//        createAndVerifyProof();
//    }

//    @Test
//    public void testcreateProofWithoutBWT() throws Exception {
//
//        endEpochBlockHash = new byte[] {
//            8, 57, 79, -51, 58, 30, -66, -86, -112, -119, -25, -20, -84, 54, -83, 50, 69, -48, -93, -122, -55, -125,
//            -127, -33, -113, 76, 119, 48, 95, 6, -115, 17
//        };
//
//        prevEndEpochBlockHash = new byte[] {
//            -84, 64, -121, -94, 30, -48, -49, 7, 107, -51, 4, -115, -26, 6, 119, -125, 112, 98, -86, -22, 70, 66, 95,
//            11, -97, -78, 50, 37, 95, -69, -109, 1
//        };
//
//        byte[][] secretKeyList = {
//            {
//                21, -117, 57, 88, -24, 6, 73, -8, -100, -125, 72, -24, 10, 84, -119, -125, 117, -106, -65, -94, -56,
//                -17, -106, -122, -108, -40, 115, 97, 18, -99, 76, -114, 85, -74, 69, 39, -45, -63, -111, 5, -69, -126,
//                -4, -126, 29, 96, 45, 84, 36, -123, -18, -68, -120, 22, 44, 70, -104, -61, -128, -31, 86, 125, 32, -24,
//                -21, -67, 83, -27, 86, -56, -86, -35, 81, 51, 113, -50, -84, -90, 5, -61, 34, 17, 20, -27, 83, -48, -97,
//                79, -116, -121, 83, 35, 87, 54, 0, 0
//            },
//            {
//                61, -90, -17, 32, -84, -41, 96, -58, 122, -78, 53, 120, -73, 91, -38, -13, -89, -8, 101, -112, -75, 68,
//                -7, 85, 125, -79, 51, 67, -81, -34, 90, 70, -30, 94, -20, 62, -77, 30, 118, 86, 91, 61, -2, -100, 42,
//                79, 90, 49, -46, -120, 113, -89, 73, 47, -69, 28, 31, -5, -109, -87, -96, -75, -78, 126, 56, -30, -12,
//                -96, -127, 56, -68, -10, 55, -93, -121, -102, -53, 59, 28, 37, -99, 39, -11, -118, -6, -115, -70, -70,
//                -4, 80, -86, 123, 22, 109, 1, 0
//            },
//            {
//                -76, 50, -67, 96, -13, -4, 16, -35, -44, -47, 19, 22, -35, -55, 109, 80, 123, -118, -93, -81, -92, 94,
//                34, 115, -87, 28, -8, 45, -13, -26, -63, 22, 42, -105, -120, 30, 67, -93, -67, 103, 55, -117, -34, 42,
//                99, 80, -84, -33, 22, -119, -26, 0, -82, 20, 109, -19, -12, 101, 27, -115, -81, 101, 87, 77, 25, -25,
//                -22, 76, 75, 3, 124, 115, 38, -12, -70, -126, -31, 65, 51, 56, -20, 9, 63, 85, 15, -113, -54, 117, -107,
//                36, 66, -117, -23, -90, 1, 0
//            }
//        };
//
//        byte[][] serializedSignatureList = {
//            {
//                96, 123, -99, -105, -24, -114, 54, 44, 124, 77, -55, -12, -84, 49, 7, -112, 70, -44, 79, -82, -110, 19,
//                -54, -34, -100, -62, -14, -46, 110, 107, 103, -44, -121, 47, 18, -55, 17, -88, -60, 22, 118, -94, -119,
//                92, 56, -117, -67, -31, -125, -68, 90, -21, -19, 6, -73, 5, 96, -102, 105, 61, -92, 98, -88, 127, -12,
//                121, -117, -68, -34, -121, 117, -72, 107, -121, 5, 100, 95, 37, 96, -77, 82, 123, 45, 3, 23, -100, 81,
//                86, -38, 28, 5, 100, 84, -65, 0, 0, -88, 77, -35, -113, 61, -14, 99, -11, -78, -106, 76, -88, -14, -99,
//                -64, -47, 115, -56, -6, 99, -4, 24, -98, 86, 91, 65, -117, -14, -85, -22, 104, -87, -85, -66, -107, -35,
//                -23, 114, 7, -2, -107, -80, 47, 33, 53, 102, 12, -40, 110, 41, 3, 45, 57, 29, -117, -67, -42, -114, -98,
//                -95, -37, -18, 71, -38, -30, 62, 73, -66, 62, 115, -79, 18, -102, -62, 9, -62, 54, 29, 58, -58, -44, 20,
//                -46, -12, -106, 61, -18, -107, 48, -43, 98, -1, 33, -21, 0, 0
//            },
//            {
//                38, -26, -94, -117, -34, -114, 42, 37, 41, 47, 95, -16, -123, -57, 71, 127, 90, 31, -116, 104, 51, -77,
//                -74, 61, 38, -63, -26, -1, 88, 126, 103, 26, 50, -13, 40, 53, -8, -30, 70, 80, -17, 63, -28, -107, -92,
//                38, -61, 111, -44, 74, 41, 40, -11, -77, -22, -69, -56, -82, 79, 33, 75, 114, 15, -26, -117, -92, 29,
//                20, 105, -96, -69, 103, 82, 89, -128, -10, -103, -5, 21, -60, -32, 117, 114, -32, -127, -74, 106, -101,
//                -80, 70, 2, 1, -63, 21, 0, 0, 40, 121, -85, -103, 85, -100, -116, -70, 114, 113, -128, 52, 105, -101,
//                60, 113, 63, -91, -82, 24, -63, -84, -105, -36, -107, -1, -102, 5, -67, 28, -55, -39, -109, 23, 38, -9,
//                74, -113, -49, 84, 117, -102, -16, 48, -86, 92, -60, 13, -67, 89, 109, -19, -105, 40, -114, 91, -36,
//                -109, -22, 20, 109, -114, -112, 107, -60, -69, -3, 74, 113, -53, -93, -54, 36, -102, -123, 81, -8, -54,
//                -28, 80, 99, -51, 71, 66, 113, -104, -60, -75, 114, -22, 22, -95, 82, -90, 0, 0
//            }
//        };
//
//        // Deserialize secret keys and get the corresponding public keys
//        for (int i = 0; i<keyCount; i++) {
//
//            try(SchnorrSecretKey sk = SchnorrSecretKey.deserialize(secretKeyList[i]))
//            {
//                assertNotNull("sk" + i + "deserialization must not fail", sk);
//
//                SchnorrPublicKey pk = new SchnorrKeyPair(sk).getPublicKey();
//                assertTrue("Public key verification failed.", pk.verifyKey());
//
//                publicKeyList.add(pk);
//            }
//        }
//
//        // Deserialize Schnorr Signatures
//        for (int i = 0; i<keyCount; i++) {
//            if (i < threshold) {
//                SchnorrSignature sig = SchnorrSignature.deserialize(serializedSignatureList[i]);
//                assertNotNull("sig" + i + "deserialization must not fail", sig);
//                signatureList.add(sig);
//            } else {
//                SchnorrSignature sig = new SchnorrSignature();
//                signatureList.add(sig);
//            }
//        }
//
//        createAndVerifyProof();
//    }
    
    @BeforeClass
    public static void initKeys() {
        assertTrue(ProvingSystem.generateDLogKeys(psType, segmentSize, dlogKeyPath, Optional.empty()));
        assertTrue(NaiveThresholdSigProof.setup(psType, keyCount, snarkPkPath, snarkVkPath));
    }

    //@Test
    public void testCreateRandomProof() throws Exception {
        Random r = new Random();

        endCumulativeScTxCommTreeRoot = FieldElement.createRandom();

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
                FieldElement msgToSign = NaiveThresholdSigProof.createMsgToSign(
                    btList.toArray(new BackwardTransfer[0]),
                    epochNumber,
                    endCumulativeScTxCommTreeRoot,
                    btrFee,
                    ftMinFee
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
            psType, btList, epochNumber, endCumulativeScTxCommTreeRoot,
            btrFee, ftMinFee, signatureList, publicKeyList, threshold,
            snarkPkPath, false
        );

        assertNotNull("Proof creation must be successfull", proofResult);

        byte[] proof = proofResult.getProof();
        long quality = proofResult.getQuality();

        FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
        assertNotNull("Constant creation must be successfull", constant);

        boolean isProofVerified = NaiveThresholdSigProof.verifyProof(
            psType, btList, epochNumber, endCumulativeScTxCommTreeRoot,
            btrFee, ftMinFee, constant, quality, proof, true, snarkVkPath, true
        );

        assertTrue("Proof must be verified", isProofVerified);

        quality = threshold - 1;
        isProofVerified = NaiveThresholdSigProof.verifyProof(
            psType, btList, epochNumber, endCumulativeScTxCommTreeRoot,
            btrFee, ftMinFee, constant, quality, proof, true, snarkVkPath, true
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

        endCumulativeScTxCommTreeRoot.freeFieldElement();
    }

    @AfterClass
    public static void deleteKeys(){
        // Delete dlog key
        new File(dlogKeyPath).delete();

        // Delete proving key and verification key
        new File(snarkPkPath).delete();
        new File(snarkVkPath).delete();
    }
}