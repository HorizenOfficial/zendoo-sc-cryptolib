package com.horizen.certnative;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.schnorrnative.ValidatorKeysUpdatesList;
import com.horizen.provingsystemnative.ProvingSystem;
import com.horizen.provingsystemnative.ProvingSystemType;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class NaiveThresholdSignatureWKeyRotationProofTest {

    static int keyCount = 4;
    static int customFieldsNum = 3;
    static long threshold = 4;
    static int backwardTransferCount = 10;
    static boolean zk = false;

    static int prevEpochNumber = 9;
    static int epochNumber = 10;
    static long prevBtrFee = 100L;
    static long btrFee = 100L;
    static long prevFtMinAmount = 200L;
    static long ftMinAmount = 200L;

    static int maxProofPlusVkSize = 9 * 1024;

    ValidatorKeysUpdatesList keysSignaturesList;
    WithdrawalCertificate withdrawalCertificate;
    WithdrawalCertificate prevWithdrawalCertificate;

    FieldElement scId;
    FieldElement prevScId;
    FieldElement genesisKeyRootHash;
    FieldElement validatorsKeysRoot;
    FieldElement prevValidatorsKeysRoot;

    static String snarkPkPathCustomFields = "./test_cert_keyrot_snark_pk";
    static String snarkVkPathCustomFields = "./test_cert_keyrot_snark_vk";
    static ProvingSystemType psType = ProvingSystemType.COBOUNDARY_MARLIN;
    
    @BeforeClass
    public static void initKeys() throws Exception {
        ProvingSystem.generateDLogKeys(psType, TestUtils.DLOG_KEYS_SIZE);
        assertTrue(NaiveThresholdSignatureWKeyRotation.setup(psType, keyCount, 1, Optional.of(TestUtils.CERT_SEGMENT_SIZE), snarkPkPathCustomFields, snarkVkPathCustomFields, zk, maxProofPlusVkSize));
        assertTrue(NaiveThresholdSignatureWKeyRotation.setup(psType, keyCount, customFieldsNum, Optional.of(TestUtils.CERT_SEGMENT_SIZE), snarkPkPathCustomFields, snarkVkPathCustomFields, zk, maxProofPlusVkSize));
        try {
            assertFalse(NaiveThresholdSignatureWKeyRotation.setup(psType, keyCount, 1, Optional.of(TestUtils.CERT_SEGMENT_SIZE), snarkPkPathCustomFields, snarkVkPathCustomFields, zk, 1));
            assertTrue(false); // Must be unreachable
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Circuit is too complex"));
        }
        assertEquals(
                psType,
                ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPathCustomFields)
        );
        assertEquals(
                ProvingSystem.getProverKeyProvingSystemType(snarkPkPathCustomFields),
                ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPathCustomFields)
        );
    }

    private ValidatorKeysUpdatesList setupValidatorKeysUpdatesList(
        List<SchnorrKeyPair> signingKeyPairList,
        List<SchnorrKeyPair> masterKeyPairList,
        int epochId,
        FieldElement ledgerId
    ) {
        List<SchnorrPublicKey> signingPublicKeyList = new ArrayList<>();
        List<SchnorrPublicKey> masterPublicKeyList = new ArrayList<>();
        List<SchnorrPublicKey> updatedSigningKeyList = new ArrayList<>();
        List<SchnorrPublicKey> updatedMasterKeyList = new ArrayList<>();
        List<SchnorrSignature> updatedSigningKeysSkSignaturesList = new ArrayList<>();
        List<SchnorrSignature> updatedSigningKeysMkSignaturesList = new ArrayList<>();
        List<SchnorrSignature> updatedMasterKeysSkSignaturesList = new ArrayList<>();
        List<SchnorrSignature> updatedMasterKeysMkSignaturesList = new ArrayList<>();

        // Initialize keys
        for (int i = 0; i<signingKeyPairList.size(); i++) {
            SchnorrKeyPair keyPair = signingKeyPairList.get(i);
            signingPublicKeyList.add(keyPair.getPublicKey());
            updatedSigningKeyList.add(keyPair.getPublicKey());

            SchnorrKeyPair masterKeyPair = masterKeyPairList.get(i);

            assertNotNull("Key pair generation was unsuccessful.", masterKeyPair);
            assertTrue("Public key verification failed.", masterKeyPair.getPublicKey().verifyKey());

            masterPublicKeyList.add(masterKeyPair.getPublicKey());
            updatedMasterKeyList.add(masterKeyPair.getPublicKey());

            updatedSigningKeysSkSignaturesList.add(new SchnorrSignature());
            updatedSigningKeysMkSignaturesList.add(new SchnorrSignature());
            updatedMasterKeysSkSignaturesList.add(new SchnorrSignature());
            updatedMasterKeysMkSignaturesList.add(new SchnorrSignature());
        }

        return new ValidatorKeysUpdatesList(
            signingPublicKeyList,
            masterPublicKeyList,
            updatedSigningKeyList,
            updatedMasterKeyList,
            updatedSigningKeysSkSignaturesList,
            updatedSigningKeysMkSignaturesList,
            updatedMasterKeysSkSignaturesList,
            updatedMasterKeysMkSignaturesList,
            keyCount,
            epochId,
            ledgerId
        );
    }

    private List<SchnorrKeyPair> setupKeyPairList(int keyCount) {
        List<SchnorrKeyPair> keyPairList = new ArrayList<>();
        for (int i = 0; i<keyCount; i++) {
            SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

            keyPairList.add(keyPair);
        }
        return keyPairList;
    }

    private List<BackwardTransfer> getBackwardTransferList(int count) {
        Random r = new Random();
        List<BackwardTransfer> btList = new ArrayList<>();
        for(int i = 0; i < count; i++)
            btList.add(BackwardTransfer.getRandom(r));
        return btList;
    }

    private List<SchnorrSignature> createSignatures(
        WithdrawalCertificate aWithdrawalCertificate,
        List<SchnorrKeyPair> keyPairList
    ) {
        List<SchnorrSignature> signatureList = new ArrayList<>();
        FieldElement msgToSign = NaiveThresholdSignatureWKeyRotation.createMsgToSign(aWithdrawalCertificate);
        for (int i = 0; i<keyCount; i++) {
            if (i < threshold) {
                signatureList.add(keyPairList.get(i).signMessage(msgToSign));
            } else {
                signatureList.add(new SchnorrSignature());
            }
        }
        return signatureList;
    }

    @Test
    public void testSigningKeyRotationWithPrevCert() throws Exception {
        testSigningKeyRotation(true);
    }

    @Test
    public void testSigningKeyRotationFirstCert() throws Exception {
        testSigningKeyRotation(false);
    }

    public void testSigningKeyRotation(boolean usePrevCert) throws Exception {
        Random r = new Random();

        // Setup
        scId = FieldElement.createRandom();
        prevScId = FieldElement.createRandom();
        List<SchnorrKeyPair> signingKeyPairList = setupKeyPairList(keyCount);
        List<SchnorrKeyPair> masterKeyPairList = setupKeyPairList(keyCount);
        ValidatorKeysUpdatesList testKeysSignaturesList = setupValidatorKeysUpdatesList(
            signingKeyPairList, masterKeyPairList, epochNumber, scId
        );

        FieldElement testPrevValidatorsKeysRoot = testKeysSignaturesList.getKeysRootHash();
        FieldElement testValidatorsKeysRoot = testKeysSignaturesList.getUpdatedKeysRootHash();
        FieldElement testGenesisKeyRootHash = testPrevValidatorsKeysRoot;
        FieldElement constant = NaiveThresholdSignatureWKeyRotation.getConstant(testGenesisKeyRootHash, threshold);

        // Create dummy Backward Transfers
        List<BackwardTransfer> btList = getBackwardTransferList(backwardTransferCount);
        List<BackwardTransfer> prevBtList = getBackwardTransferList(backwardTransferCount);

        List<FieldElement> customFields = new ArrayList<>();
        List<FieldElement> prevCustomFields = new ArrayList<>();
        // Generate random custom fields if requested
        customFields.add(testValidatorsKeysRoot);
        prevCustomFields.add(testPrevValidatorsKeysRoot);

        WithdrawalCertificate aWithdrawalCertificate = new WithdrawalCertificate(
            scId, epochNumber, btList, (long)keyCount, testValidatorsKeysRoot,
            ftMinAmount, btrFee, customFields
        );
        WithdrawalCertificate aPrevWithdrawalCertificate = new WithdrawalCertificate(
            prevScId, prevEpochNumber, prevBtList, (long)keyCount, testPrevValidatorsKeysRoot,
            prevFtMinAmount, prevBtrFee, prevCustomFields
        );

        // Rotate a signing key
        SchnorrKeyPair newSigningKeyPair = SchnorrKeyPair.generate();
        FieldElement newSigningKeyHash = newSigningKeyPair.getPublicKey().getHash();
        testKeysSignaturesList.getUpdatedSigningKeysSkSignatures()[0] = signingKeyPairList.get(0).signMessage(newSigningKeyHash);
        testKeysSignaturesList.getUpdatedSigningKeysMkSignatures()[0] = masterKeyPairList.get(0).signMessage(newSigningKeyHash);
        testKeysSignaturesList.getUpdatedSigningKeys()[0] = newSigningKeyPair.getPublicKey();

        aWithdrawalCertificate.getCustomFields()[0] = testKeysSignaturesList.getUpdatedKeysRootHash();

        List<SchnorrSignature> signatureList = createSignatures(aWithdrawalCertificate, signingKeyPairList);

        Optional<WithdrawalCertificate> prevCert = Optional.empty();
        if (usePrevCert) {
            prevCert = Optional.of(aPrevWithdrawalCertificate);
        }

        Optional<String> failingConstraint = NaiveThresholdSignatureWKeyRotation.debugCircuit(
            testKeysSignaturesList,
            aWithdrawalCertificate,
            prevCert,
            signatureList,
            keyCount,
            threshold,
            testGenesisKeyRootHash
        );
        if (failingConstraint.isPresent()) {
            throw new Exception(failingConstraint.get());
        }
        assertFalse(failingConstraint.isPresent());
    }

    @Test
    public void testMasterKeyRotationWithPrevCert() throws Exception {
        testMasterKeyRotation(true);
    }

    @Test
    public void testMasterKeyRotationFirstCert() throws Exception {
        testMasterKeyRotation(false);
    }

    public void testMasterKeyRotation(boolean usePrevCert) throws Exception {
        Random r = new Random();

        // Setup
        scId = FieldElement.createRandom();
        prevScId = FieldElement.createRandom();
        List<SchnorrKeyPair> signingKeyPairList = setupKeyPairList(keyCount);
        List<SchnorrKeyPair> masterKeyPairList = setupKeyPairList(keyCount);
        ValidatorKeysUpdatesList testKeysSignaturesList = setupValidatorKeysUpdatesList(
            signingKeyPairList, masterKeyPairList, epochNumber, scId
        );

        FieldElement testPrevValidatorsKeysRoot = testKeysSignaturesList.getKeysRootHash();
        FieldElement testValidatorsKeysRoot = testKeysSignaturesList.getUpdatedKeysRootHash();
        FieldElement testGenesisKeyRootHash = testPrevValidatorsKeysRoot;
        FieldElement constant = NaiveThresholdSignatureWKeyRotation.getConstant(testGenesisKeyRootHash, threshold);

        // Create dummy Backward Transfers
        List<BackwardTransfer> btList = getBackwardTransferList(backwardTransferCount);
        List<BackwardTransfer> prevBtList = getBackwardTransferList(backwardTransferCount);
        List<FieldElement> customFields = new ArrayList<>();
        List<FieldElement> prevCustomFields = new ArrayList<>();
        // Generate random custom fields if requested
        customFields.add(testValidatorsKeysRoot);
        prevCustomFields.add(testPrevValidatorsKeysRoot);

        WithdrawalCertificate aWithdrawalCertificate = new WithdrawalCertificate(
            scId, epochNumber, btList, (long)keyCount, testValidatorsKeysRoot,
            ftMinAmount, btrFee, customFields
        );
        WithdrawalCertificate aPrevWithdrawalCertificate = new WithdrawalCertificate(
            prevScId, prevEpochNumber, prevBtList, (long)keyCount, testPrevValidatorsKeysRoot,
            prevFtMinAmount, prevBtrFee, prevCustomFields
        );

        // Rotate a master key
        SchnorrKeyPair newMasterKeyPair = SchnorrKeyPair.generate();
        FieldElement newKeyHash = newMasterKeyPair.getPublicKey().getHash();
        testKeysSignaturesList.getUpdatedMasterKeysSkSignatures()[0] = signingKeyPairList.get(0).signMessage(newKeyHash);
        testKeysSignaturesList.getUpdatedMasterKeysMkSignatures()[0] = masterKeyPairList.get(0).signMessage(newKeyHash);
        testKeysSignaturesList.getUpdatedMasterKeys()[0] = newMasterKeyPair.getPublicKey();

        aWithdrawalCertificate.getCustomFields()[0] = testKeysSignaturesList.getUpdatedKeysRootHash();
        List<SchnorrSignature> signatureList = createSignatures(aWithdrawalCertificate, signingKeyPairList);

        Optional<WithdrawalCertificate> prevCert = Optional.empty();
        if (usePrevCert) {
            prevCert = Optional.of(aPrevWithdrawalCertificate);
        }

        Optional<String> failingConstraint = NaiveThresholdSignatureWKeyRotation.debugCircuit(
            testKeysSignaturesList,
            aWithdrawalCertificate,
            prevCert,
            signatureList,
            keyCount,
            threshold,
            testGenesisKeyRootHash
        );
        if (failingConstraint.isPresent()) {
            throw new Exception(failingConstraint.get());
        }
        assertFalse(failingConstraint.isPresent());
    }

    @Test
    public void testCreateVerifyRandomProofWithCustomFields() throws Exception {
        testCreateVerifyRandomProof(customFieldsNum, snarkPkPathCustomFields, snarkVkPathCustomFields, true);
    }

    @Test
    public void testCreateVerifyRandomProofNoPrevCert() throws Exception {
        testCreateVerifyRandomProof(customFieldsNum, snarkPkPathCustomFields, snarkVkPathCustomFields, false);
    }

    private void testCreateVerifyRandomProof(int numCustomFields, String snarkPkPath, String snarkVkPath, boolean usePrevCert) throws Exception {
        Random r = new Random();

        scId = FieldElement.createRandom();
        prevScId = FieldElement.createRandom();

        backwardTransferCount = r.nextInt(backwardTransferCount + 1);
        List<BackwardTransfer> btList = getBackwardTransferList(backwardTransferCount);
        List<BackwardTransfer> prevBtList = getBackwardTransferList(backwardTransferCount);

        // Compute keys and signatures
        List<SchnorrKeyPair> signingKeyPairList = setupKeyPairList(keyCount);
        List<SchnorrKeyPair> masterKeyPairList = setupKeyPairList(keyCount);
        keysSignaturesList = setupValidatorKeysUpdatesList(
            signingKeyPairList, masterKeyPairList, epochNumber, scId
        );

        prevValidatorsKeysRoot = keysSignaturesList.getKeysRootHash();
        validatorsKeysRoot = keysSignaturesList.getUpdatedKeysRootHash();
        genesisKeyRootHash = prevValidatorsKeysRoot;
        FieldElement constant = NaiveThresholdSignatureWKeyRotation.getConstant(genesisKeyRootHash, threshold);
        assertNotNull("Constant creation must be successful", constant);

        List<FieldElement> customFields = new ArrayList<>();
        List<FieldElement> prevCustomFields = new ArrayList<>();
        // Generate random custom fields if requested
        if (numCustomFields > 0) {
            for (int i = 0; i < numCustomFields; i++) {
                customFields.add(FieldElement.createRandom());
                prevCustomFields.add(FieldElement.createRandom());
            }
            customFields.set(0, validatorsKeysRoot);
            prevCustomFields.set(0, prevValidatorsKeysRoot);
        }

        withdrawalCertificate = new WithdrawalCertificate(
            scId, epochNumber, btList, (long)keyCount, validatorsKeysRoot,
            ftMinAmount, btrFee, customFields
        );
        prevWithdrawalCertificate = new WithdrawalCertificate(
            prevScId, prevEpochNumber, prevBtList, (long)keyCount, prevValidatorsKeysRoot,
            prevFtMinAmount, prevBtrFee, prevCustomFields
        );

        List<SchnorrSignature> signatureList = createSignatures(withdrawalCertificate, signingKeyPairList);

        //Free memory from the secret keys
        for (SchnorrKeyPair kp: signingKeyPairList)
            kp.getSecretKey().freeSecretKey();

        // Debug circuit with valid data
        Optional<WithdrawalCertificate> prevCert = Optional.empty();
        if (usePrevCert) {
            prevCert = Optional.of(prevWithdrawalCertificate);
        }
        Optional<String> failingConstraint = NaiveThresholdSignatureWKeyRotation.debugCircuit(
            keysSignaturesList,
            withdrawalCertificate,
            prevCert,
            signatureList,
            keyCount,
            threshold,
            genesisKeyRootHash
        );
        if (failingConstraint.isPresent()) {
            throw new Exception(failingConstraint.get());
        }
        assertFalse(failingConstraint.isPresent());

        // Create and verify proof

        // Positive test
        CreateProofResult proofResult = NaiveThresholdSignatureWKeyRotation.createProof(
            keysSignaturesList,
            withdrawalCertificate,
            prevCert,
            signatureList,
            keyCount,
            threshold,
            genesisKeyRootHash,
            Optional.of(TestUtils.CERT_SEGMENT_SIZE),
            snarkPkPath,
            false,
            zk
        );

        assertNotNull("Proof creation must be successful", proofResult);

        byte[] proof = proofResult.getProof();
        assertEquals(psType, ProvingSystem.getProofProvingSystemType(proof));

        long quality = proofResult.getQuality();

        boolean isProofVerified = NaiveThresholdSignatureWKeyRotation.verifyProof(
            withdrawalCertificate,
            prevCert,
            constant,
            proof,
            true,
            snarkVkPath,
            true
        );

        assertTrue("Proof must be verified", isProofVerified);

        // Negative test
        withdrawalCertificate.setQuality(threshold - 1);
        isProofVerified = NaiveThresholdSignatureWKeyRotation.verifyProof(
            withdrawalCertificate,
            prevCert,
            constant,
            proof,
            true,
            snarkVkPath,
            true
        );

        assertFalse("Proof must not be verified", isProofVerified);
    }

    @After
    public void freeData() {
        if (prevScId != null) {
            prevScId.freeFieldElement();
            prevScId = null;
        }
        if (scId != null) {
            scId.freeFieldElement();
            scId = null;
        }
        if (prevValidatorsKeysRoot != null) {
            prevValidatorsKeysRoot.freeFieldElement();
            prevValidatorsKeysRoot = null;
        }
        if (validatorsKeysRoot != null) {
            validatorsKeysRoot.freeFieldElement();
            validatorsKeysRoot = null;
        }
        if (genesisKeyRootHash != null) {
            genesisKeyRootHash.freeFieldElement();
            genesisKeyRootHash = null;
        }
    }

    @AfterClass
    public static void deleteKeys(){
        // Delete proving keys and verification keys
        new File(snarkPkPathCustomFields).delete();
        new File(snarkVkPathCustomFields).delete();
    }
}