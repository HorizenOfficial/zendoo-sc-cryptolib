// package com.horizen.certnative;

// import com.horizen.librustsidechains.FieldElement;
// import com.horizen.schnorrnative.SchnorrKeyPair;
// import com.horizen.schnorrnative.SchnorrPublicKey;
// import com.horizen.schnorrnative.SchnorrSignature;
// import com.horizen.provingsystemnative.ProvingSystem;
// import com.horizen.provingsystemnative.ProvingSystemType;
// import org.junit.BeforeClass;
// import org.junit.After;
// import org.junit.AfterClass;
// import org.junit.Test;

// import java.io.File;
// import java.util.ArrayList;
// import java.util.List;
// import java.util.Random;

// import static org.junit.Assert.assertNotNull;
// import static org.junit.Assert.assertTrue;
// import static org.junit.Assert.assertFalse;
// import static org.junit.Assert.assertEquals;

// public class NaiveThresholdSigProofTest {

//     static int keyCount = 7;
//     static int customFieldsNum = 1;
//     static long threshold = 5;
//     static int backwardTransferCout = 10;
//     static boolean zk = false;

//     static int epochNumber = 10;
//     static long btrFee = 100L;
//     static long ftMinAmount = 200L;

//     static int maxProofPlusVkSize = 9 * 1024;

//     FieldElement scId;
//     FieldElement endCumulativeScTxCommTreeRoot;

//     List<SchnorrPublicKey> publicKeyList = new ArrayList<>();
//     List<SchnorrSignature> signatureList = new ArrayList<>();
//     List<BackwardTransfer> btList = new ArrayList<>();
//     List<FieldElement> customFields = new ArrayList<>();
    
//     static String snarkPkPathNoCustomFields = "./test_snark_pk";
//     static String snarkVkPathNoCustomFields = "./test_snark_vk";
//     static String snarkPkPathCustomFields = "./test_snark_pk_with_custom_fields";
//     static String snarkVkPathCustomFields = "./test_snark_vk_with_custom_fields";
//     static int maxSegmentSize = 1 << 17;
//     static int supportedSegmentSize = 1 << 15;
//     static ProvingSystemType psType = ProvingSystemType.COBOUNDARY_MARLIN;
    
//     @BeforeClass
//     public static void initKeys() {
//         assertTrue(ProvingSystem.generateDLogKeys(psType, maxSegmentSize, supportedSegmentSize));
//         assertTrue(NaiveThresholdSigProof.setup(psType, keyCount, 0, snarkPkPathNoCustomFields, snarkVkPathNoCustomFields, zk, maxProofPlusVkSize));
//         assertTrue(NaiveThresholdSigProof.setup(psType, keyCount, customFieldsNum, snarkPkPathCustomFields, snarkVkPathCustomFields, zk, maxProofPlusVkSize));
//         assertFalse(NaiveThresholdSigProof.setup(psType, keyCount, 0, snarkPkPathNoCustomFields, snarkVkPathNoCustomFields, zk, 1));
//         assertEquals(
//                 psType,
//                 ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPathNoCustomFields)
//         );
//         assertEquals(
//                 ProvingSystem.getProverKeyProvingSystemType(snarkPkPathNoCustomFields),
//                 ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPathNoCustomFields)
//         );
//     }

//     @Test
//     public void testCreateVerifyRandomProofWithoutCustomFields() throws Exception {
//         testCreateVerifyRandomProof(0, snarkPkPathNoCustomFields, snarkVkPathNoCustomFields);
//     }

//     @Test
//     public void testCreateVerifyRandomProofWithCustomFields() throws Exception {
//         testCreateVerifyRandomProof(customFieldsNum, snarkPkPathCustomFields, snarkVkPathCustomFields);
//     }

//     private void testCreateVerifyRandomProof(int numCustomFields, String snarkPkPath, String snarkVkPath) throws Exception {
//         Random r = new Random();

//         scId = FieldElement.createRandom();
//         endCumulativeScTxCommTreeRoot = FieldElement.createRandom();

//         backwardTransferCout = r.nextInt(backwardTransferCout + 1);
//         // Create dummy Backward Transfers
//         for(int i = 0; i < backwardTransferCout; i++)
//             btList.add(BackwardTransfer.getRandom(r));

//         // Compute keys and signatures
//         List<SchnorrKeyPair> keyPairList = new ArrayList<>();

//         for (int i = 0; i<keyCount; i++) {
//             SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

//             assertNotNull("Key pair generation was unsuccessful.", keyPair);
//             assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

//             keyPairList.add(keyPair);
//             publicKeyList.add(keyPair.getPublicKey());
//         }

//         // Generate random custom fields if requested
//         if (numCustomFields > 0) {
//             for (int i = 0; i < numCustomFields; i++)
//                 customFields.add(FieldElement.createRandom());
//         }

//         for (int i = 0; i<keyCount; i++) {
//             if (i < threshold) {
//                 FieldElement msgToSign = NaiveThresholdSigProof.createMsgToSign(
//                     btList.toArray(new BackwardTransfer[0]),
//                     scId,
//                     epochNumber,
//                     endCumulativeScTxCommTreeRoot,
//                     btrFee,
//                     ftMinAmount,
//                     customFields
//                 );
//                 signatureList.add(keyPairList.get(i).signMessage(msgToSign));
//             } else {
//                 signatureList.add(new SchnorrSignature());
//             }
//         }

//         //Free memory from the secret keys
//         for (SchnorrKeyPair kp: keyPairList)
//             kp.getSecretKey().freeSecretKey();

//         // Create and verify proof

//         // Positive test
//         CreateProofResult proofResult = NaiveThresholdSigProof.createProof(
//             btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
//             btrFee, ftMinAmount, signatureList, publicKeyList, threshold,
//             customFields, snarkPkPath, false, zk
//         );

//         assertNotNull("Proof creation must be successful", proofResult);

//         byte[] proof = proofResult.getProof();
//         assertEquals(psType, ProvingSystem.getProofProvingSystemType(proof));

//         long quality = proofResult.getQuality();

//         FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
//         assertNotNull("Constant creation must be successful", constant);

//         boolean isProofVerified = NaiveThresholdSigProof.verifyProof(
//             btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
//             btrFee, ftMinAmount, constant, quality, customFields, proof, true, snarkVkPath, true
//         );

//         assertTrue("Proof must be verified", isProofVerified);

//         // Negative test
//         quality = threshold - 1;
//         isProofVerified = NaiveThresholdSigProof.verifyProof(
//             btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
//             btrFee, ftMinAmount, constant, quality, customFields, proof, true, snarkVkPath, true
//         );

//         assertFalse("Proof must not be verified", isProofVerified);
//     }

//     @After
//     public void freeData() {
//         for (SchnorrPublicKey pk: publicKeyList)
//             pk.freePublicKey();
//         publicKeyList.clear();

//         for (SchnorrSignature sig: signatureList)
//             sig.freeSignature();
//         signatureList.clear();

//         for (FieldElement fe: customFields)
//             fe.freeFieldElement();
//         customFields.clear();

//         scId.freeFieldElement();
//         endCumulativeScTxCommTreeRoot.freeFieldElement();
//     }

//     @AfterClass
//     public static void deleteKeys(){
//         // Delete proving keys and verification keys
//         new File(snarkPkPathNoCustomFields).delete();
//         new File(snarkVkPathNoCustomFields).delete();
//         new File(snarkPkPathCustomFields).delete();
//         new File(snarkVkPathCustomFields).delete();
//     }
// }