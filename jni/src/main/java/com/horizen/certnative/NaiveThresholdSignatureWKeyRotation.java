package com.horizen.certnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.schnorrnative.ValidatorKeysUpdatesList;
import com.horizen.provingsystemnative.ProvingSystemType;

import java.util.List;
import java.util.Optional;
import java.util.Arrays;

public class NaiveThresholdSignatureWKeyRotation {

    static {
        Library.load();
    }

    public static FieldElement createMsgToSign(
        WithdrawalCertificate withdrawalCertificate
    ) {
        return NaiveThresholdSigProof.createMsgToSign(
            withdrawalCertificate.getBtList(),
            withdrawalCertificate.getScId(),
            withdrawalCertificate.getEpochNumber(),
            withdrawalCertificate.getMcbScTxsCom(),
            withdrawalCertificate.getBtrMinFee(),
            withdrawalCertificate.getFtMinAmount(),
            Arrays.asList(withdrawalCertificate.getCustomFields())
        );
    }

    private static native FieldElement nativeGetConstant(
        FieldElement genesisKeyRootHash,
        long threshold
    ) throws Exception;

    public static FieldElement getConstant(
            FieldElement genesisKeyRootHash,
            long threshold
    ) throws Exception
    {
        return nativeGetConstant(genesisKeyRootHash, threshold);
    }

    private static native boolean nativeSetup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize,
        boolean compressPk,
        boolean compressVk
    ) throws Exception;

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param segmentSize - the segment size to be used to generate (pk, vk). Must be smaller equal than
     *                      the segment size passed to the ProvingSystem.generateDLogKeys() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path to which saving the proving key
     * @param verificationKeyPath - file path to which saving the verification key
     * @param zk - used to estimate the proof and vk size, tells if the proof will be created using zk or not
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk
     * @param compressPk - if the proving key must be saved to provingKeyPath in compressed form
     * @param compressVk - if the verification key must be saved to verificationKeyPath in compressed form
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize,
        boolean compressPk,
        boolean compressVk
    ) throws Exception
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, segmentSize, provingKeyPath,
            verificationKeyPath, zk, maxProofPlusVkSize, compressPk, compressVk
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support 
     * @param segmentSize - the segment size to be used to generate (pk, vk). Must be smaller equal than
     *                      the segment size passed to the ProvingSystem.generateDLogKeys() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param zk - used to estimate the proof and vk size, tells if the proof will be created using zk or not
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize
    ) throws Exception
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, segmentSize,provingKeyPath,
            verificationKeyPath, zk, maxProofPlusVkSize, true, true
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param segmentSize - the segment size to be used to generate (pk, vk). Must be smaller equal than
     *                      the segment size passed to the ProvingSystem.generateDLogKeys() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk, estimated assuming not to use zk property
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise.
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        int maxProofPlusVkSize
    ) throws Exception
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, segmentSize, provingKeyPath,
            verificationKeyPath, false, maxProofPlusVkSize, true, true
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support 
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk, estimated assuming not to use zk property
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise.
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        String provingKeyPath,
        String verificationKeyPath,
        int maxProofPlusVkSize
    ) throws Exception
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, Optional.empty(), provingKeyPath,
            verificationKeyPath, false, maxProofPlusVkSize, true, true
        );
    }

    private static native Optional<String> nativeDebugCircuit(
        ValidatorKeysUpdatesList keysSignaturesList,
        WithdrawalCertificate withdrawalCertificate,
        Optional<WithdrawalCertificate> prevWithdrawalCertificate,
        SchnorrSignature[] certSignatures,
        long maxPks,
        long threshold,
        FieldElement genesisKeyRootHash
    ) throws Exception;

    /**
     * Checks if possible to create a valid proof with the supplied data. Useful to understand
     * the reason for which proof creation fails (usually some inconsistency with input data).
     *
     * @param keysSignaturesList - the collection of keys and signatures for this epoch
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param certSignatures - the list of signatures over the message by the validators
     * @param maxPks - maximum number of public keys and signatures
     * @param threshold - minimum number of signatures that must be verified for the certificate to be accepted
     * @param genesisKeysRootHash - The root hash of the first block
     * @return an Optional containing the name of the first failing constraint if the supplied data don't satisfy
     *         all the circuit's constraints, and nothing if all constraints are satisfied.
     */
    public static Optional<String> debugCircuit(
            ValidatorKeysUpdatesList keysSignaturesList,
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            List<SchnorrSignature> certSignatures,
            long maxPks,
            long threshold,
            FieldElement genesisKeysRootHash
    ) throws Exception
    {
        return nativeDebugCircuit(
            keysSignaturesList,
            withdrawalCertificate,
            prevWithdrawalCertificate,
            certSignatures.toArray(new SchnorrSignature[0]),
            maxPks,
            threshold,
            genesisKeysRootHash
        );
    }

    private static native CreateProofResult nativeCreateProof(
            ValidatorKeysUpdatesList keysSignaturesList,
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            SchnorrSignature[] certSignatures,
            long maxPks,
            long threshold,
            FieldElement genesisKeysRootHash,
            Optional<Integer> supportedDegree,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk,
            boolean compressed_pk,
            boolean compress_proof
    ) throws Exception;

    /**
     * Compute proof for given parameters
     * @param keysSignaturesList - the collection of keys and signatures for this epoch
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param certSignaturesList - the list of signatures over the message by the validators
     * @param maxPks - maximum number of public keys and signatures
     * @param threshold - minimum number of signatures that must be verified for the certificate to be accepted
     * @param genesisKeysRootHash - The root hash of the first block
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key
     * @param checkProvingKey - enable semantic checks on the proving key (WARNING: very expensive)
     * @param zk - if proof must be created using zk property or not
     * @param compressed_pk - if the pk read from provingKeyPath is in compressed form or not
     * @param compress_proof - whether to return the proof bytes in compressed form or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes and the quality of the certificate (i.e. in this case, number of valid signatures),
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
            ValidatorKeysUpdatesList keysSignaturesList,
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            List<SchnorrSignature> certSignaturesList,
            long maxPks,
            long threshold,
            FieldElement genesisKeysRootHash,
            Optional<Integer> supportedDegree,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk,
            boolean compressedPk,
            boolean compressProof
    ) throws Exception
    {
        return nativeCreateProof(
                keysSignaturesList,
                withdrawalCertificate,
                prevWithdrawalCertificate,
                certSignaturesList.toArray(new SchnorrSignature[0]),
                maxPks,
                threshold,
                genesisKeysRootHash,
                supportedDegree,
                provingKeyPath,
                checkProvingKey,
                zk,
                compressedPk,
                compressProof
        );
    }

    /**
     * Compute proof for given parameters
     * @param keysSignaturesList - the collection of keys and signatures for this epoch
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param certSignaturesList - the list of signatures over the message by the validators
     * @param maxPks - maximum number of public keys and signatures
     * @param threshold - minimum number of signatures that must be verified for the certificate to be accepted
     * @param genesisKeysRootHash - The root hash of the first block
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param checkProvingKey - enable semantic checks on the proving key (WARNING: very expensive)
     * @param zk - if proof must be created using zk property or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes (in compressed form),
     *         and the quality of the certificate (i.e. in this case, number of valid signatures)
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
            ValidatorKeysUpdatesList keysSignaturesList,
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            List<SchnorrSignature> certSignaturesList,
            long maxPks,
            long threshold,
            FieldElement genesisKeysRootHash,
            Optional<Integer> supportedDegree,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk
    ) throws Exception
    {
        return createProof(
            keysSignaturesList,
            withdrawalCertificate,
            prevWithdrawalCertificate,
            certSignaturesList,
            maxPks,
            threshold,
            genesisKeysRootHash,
            supportedDegree,
            provingKeyPath,
            checkProvingKey,
            zk,
            true,
            true
        );
    }

    /**
     * Compute proof for given parameters
     * @param keysSignaturesList - the collection of keys and signatures for this epoch
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param certSignaturesList - the list of signatures over the message by the validators
     * @param maxPks - maximum number of public keys and signatures
     * @param threshold - minimum number of signatures that must be verified for the certificate to be accepted
     * @param genesisKeysRootHash - The root hash of the first block
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param zk - if proof must be created using zk property or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes (in compressed form),
     *         and the quality of the certificate (i.e. in this case, number of valid signatures);
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
            ValidatorKeysUpdatesList keysSignaturesList,
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            List<SchnorrSignature> certSignaturesList,
            long maxPks,
            long threshold,
            FieldElement genesisKeysRootHash,
            Optional<Integer> supportedDegree,
            String provingKeyPath,
            boolean zk
    ) throws Exception
    {
        return createProof(
            keysSignaturesList,
            withdrawalCertificate,
            prevWithdrawalCertificate,
            certSignaturesList,
            maxPks,
            threshold,
            genesisKeysRootHash,
            supportedDegree,
            provingKeyPath,
            false,
            zk,
            true,
            true
        );
    }

    /**
     * Compute proof for given parameters
     * @param keysSignaturesList - the collection of keys and signatures for this epoch
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param certSignaturesList - the list of signatures over the message by the validators
     * @param maxPks - maximum number of public keys and signatures
     * @param threshold - minimum number of signatures that must be verified for the certificate to be accepted
     * @param genesisKeysRootHash - The root hash of the first block
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param zk - if proof must be created using zk property or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes (in compressed form),
     *         and the quality of the certificate (i.e. in this case, number of valid signatures);
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
            ValidatorKeysUpdatesList keysSignaturesList,
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            List<SchnorrSignature> certSignaturesList,
            long maxPks,
            long threshold,
            FieldElement genesisKeysRootHash,
            String provingKeyPath,
            boolean zk
    ) throws Exception
    {
        return createProof(
            keysSignaturesList,
            withdrawalCertificate,
            prevWithdrawalCertificate,
            certSignaturesList,
            maxPks,
            threshold,
            genesisKeysRootHash,
            Optional.empty(),
            provingKeyPath,
            false,
            zk,
            true,
            true
        );
    }

    private static native boolean nativeVerifyProof(
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            FieldElement genesisConstant,
            byte[] proof,
            boolean checkProof,
            boolean compressedProof,
            String verificationKeyPath,
            boolean checkVerificationKey,
            boolean compressedVk
    ) throws Exception;

    /**
     * Verify proof using the supplied parameters
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param genesisConstant - The root hash of the first block
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param checkProof - enable semantic checks on the proof
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @param checkVerificationKey - enable semantic checks on the verification key
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     */
    public static boolean verifyProof(
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            FieldElement genesisConstant,
            byte[] proof,
            boolean checkProof,
            String verificationKeyPath,
            boolean checkVerificationKey
    ) throws Exception
    {
        return nativeVerifyProof(
            withdrawalCertificate,
            prevWithdrawalCertificate,
            genesisConstant,
            proof,
            checkProof,
            true,
            verificationKeyPath,
            checkVerificationKey,
            true
        );
    }

    /**
     * Verify proof using the supplied parameters
     * @param withdrawalCertificate - the withdrawal certificate to test
     * @param prevWithdrawalCertificate - the previous withdrawal certificate to test
     * @param genesisConstant - The root hash of the first block
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     */
    public static boolean verifyProof(
            WithdrawalCertificate withdrawalCertificate,
            Optional<WithdrawalCertificate> prevWithdrawalCertificate,
            FieldElement genesisConstant,
            byte[] proof,
            String verificationKeyPath
    ) throws Exception
    {
        return nativeVerifyProof(
                withdrawalCertificate,
                prevWithdrawalCertificate,
                genesisConstant,
                proof,
                true,
                true,
                verificationKeyPath,
                false,
                true
        );
    }
}