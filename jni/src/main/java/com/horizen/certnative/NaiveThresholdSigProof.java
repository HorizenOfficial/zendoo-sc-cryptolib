package com.horizen.certnative;

import com.horizen.librustsidechains.Library;
import com.horizen.provingsystemnative.ProvingSystemType;
import io.horizen.common.librustsidechains.FieldElement;
import io.horizen.common.schnorrnative.SchnorrPublicKey;
import io.horizen.common.schnorrnative.SchnorrSignature;

import java.util.List;
import java.util.Optional;

public class NaiveThresholdSigProof {

    static {
        Library.load();
    }

    private static native FieldElement nativeGetConstant(
            SchnorrPublicKey[] schnorrPublicKeys,
            long threshold
    );

    /**
     * Compute constant parameter
     * @param schnorrPublicKeys - Schnorr signature keys, part of the constant computation
     * @param threshold - minimum number of valid Schnorr signatures, part of the constant computation
     * @return the constant as FieldElement, computed as PoseidonHash(PoseidonHash(schnorrPublicKeys), threshold),
     *         or null pointer if some error occured.
     */
    public static FieldElement getConstant(
            List<SchnorrPublicKey> schnorrPublicKeys,
            long threshold
    )
    {
        return nativeGetConstant(schnorrPublicKeys.toArray(new SchnorrPublicKey[0]), threshold);
    }

    private static native FieldElement nativeCreateMsgToSign(
            BackwardTransfer[] bt,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            FieldElement[] customFields
    );

    /**
     * Compute message to be signed
     * @param bt - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param customFields - additional parameters. Can be empty.
     * @return The message to be signed, computed as PoseidonHash(scId, epochNumber, MR(bt), endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount, [H(customFields)])
     *         or null pointer if some error occured.
     */
    public static FieldElement createMsgToSign(
            BackwardTransfer[] bt,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            List<FieldElement> customFields
    )
    {
        return nativeCreateMsgToSign(bt, scId, epochNumber, endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount, customFields.toArray(new FieldElement[0]));
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
    );

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
    )
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
    )
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
    )
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
    )
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, Optional.empty(), provingKeyPath,
            verificationKeyPath, false, maxProofPlusVkSize, true, true
        );
    }

    private static native Optional<String> nativeDebugCircuit(
        BackwardTransfer[] bt,
        FieldElement scId,
        int epochNumber,
        FieldElement endCumulativeScTxCommTreeRoot,
        long btrFee,
        long ftMinAmount,
        SchnorrSignature[] schnorrSignatures,
        SchnorrPublicKey[] schnorrPublicKeys,
        long threshold,
        FieldElement[] customFields
    );

    /**
     * Checks if possible to create a valid proof with the supplied data. Useful to understand
     * the reason for which proof creation fails (usually some inconsistency with input data).
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param schnorrSignatureList - list of Schnorr signatures to be verified using the corresponding public keys passed in SchnorrPublicKeyList
     * @param schnorrPublicKeyList - list of Schnorr public keys corresponding to schnorrSignaturesList
     * @param threshold - Minimum number of signatures that must be verified for the certificate to be accepted
     * @param customFields - additional parameters. Can be empty.
     * @return an Optional containing the name of the first failing constraint if the supplied data don't satisfy
     *         all the circuit's constraints, and nothing if all constraints are satisfied.
     */
    public static Optional<String> debugCircuit(
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            List<SchnorrSignature> schnorrSignatureList,
            List<SchnorrPublicKey> schnorrPublicKeyList,
            long threshold,
            List<FieldElement> customFields
    )
    {
        return nativeDebugCircuit(
            btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            schnorrSignatureList.toArray(new SchnorrSignature[0]),
            schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
            threshold, customFields.toArray(new FieldElement[0])
        );
    }

    private static native CreateProofResult nativeCreateProof(
            BackwardTransfer[] bt,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            SchnorrSignature[] schnorrSignatures,
            SchnorrPublicKey[] schnorrPublicKeys,
            long threshold,
            FieldElement[] customFields,
            Optional<Integer> segmentSize,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk,
            boolean compressed_pk,
            boolean compress_proof
    );

    /**
     * Compute proof for given parameters
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param schnorrSignatureList - list of Schnorr signatures to be verified using the corresponding public keys passed in SchnorrPublicKeyList
     * @param schnorrPublicKeyList - list of Schnorr public keys corresponding to schnorrSignaturesList
     * @param threshold - Minimum number of signatures that must be verified for the certificate to be accepted
     * @param customFields - additional parameters. Can be empty.
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
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            List<SchnorrSignature> schnorrSignatureList,
            List<SchnorrPublicKey> schnorrPublicKeyList,
            long threshold,
            List<FieldElement> customFields,
            Optional<Integer> segmentSize,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk,
            boolean compressed_pk,
            boolean compress_proof
    )
    {
        return nativeCreateProof(
            btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            schnorrSignatureList.toArray(new SchnorrSignature[0]),
            schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
            threshold, customFields.toArray(new FieldElement[0]),
            segmentSize, provingKeyPath, checkProvingKey, zk,
            compressed_pk, compress_proof
        );
    }

    /**
     * Compute proof for given parameters
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param schnorrSignatureList - list of Schnorr signatures to be verified using the corresponding public keys passed in SchnorrPublicKeyList
     * @param schnorrPublicKeyList - list of Schnorr public keys corresponding to schnorrSignaturesList
     * @param threshold - Minimum number of signatures that must be verified for the certificate to be accepted
     * @param customFields - additional parameters. Can be empty.
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
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            List<SchnorrSignature> schnorrSignatureList,
            List<SchnorrPublicKey> schnorrPublicKeyList,
            long threshold,
            List<FieldElement> customFields,
            Optional<Integer> segmentSize,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk
    )
    {
        return nativeCreateProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                schnorrSignatureList.toArray(new SchnorrSignature[0]),
                schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, customFields.toArray(new FieldElement[0]),
                segmentSize, provingKeyPath, checkProvingKey, zk, true, true
        );
    }

    /**
     * Compute proof for given parameters
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param schnorrSignatureList - list of Schnorr signatures to be verified using the corresponding public keys passed in SchnorrPublicKeyList
     * @param schnorrPublicKeyList - list of Schnorr public keys corresponding to schnorrSignaturesList
     * @param threshold - Minimum number of signatures that must be verified for the certificate to be accepted
     * @param customFields - additional optional parameters. Can be empty
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
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            List<SchnorrSignature> schnorrSignatureList,
            List<SchnorrPublicKey> schnorrPublicKeyList,
            long threshold,
            List<FieldElement> customFields,
            Optional<Integer> segmentSize,
            String provingKeyPath,
            boolean zk
    )
    {
        return nativeCreateProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                schnorrSignatureList.toArray(new SchnorrSignature[0]),
                schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, customFields.toArray(new FieldElement[0]),
                segmentSize, provingKeyPath, false, zk, true, true
        );
    }

    /**
     * Compute proof for given parameters
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param schnorrSignatureList - list of Schnorr signatures to be verified using the corresponding public keys passed in SchnorrPublicKeyList
     * @param schnorrPublicKeyList - list of Schnorr public keys corresponding to schnorrSignaturesList
     * @param threshold - Minimum number of signatures that must be verified for the certificate to be accepted
     * @param customFields - additional optional parameters. Can be empty
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
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            List<SchnorrSignature> schnorrSignatureList,
            List<SchnorrPublicKey> schnorrPublicKeyList,
            long threshold,
            List<FieldElement> customFields,
            String provingKeyPath,
            boolean zk
    )
    {
        return nativeCreateProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                schnorrSignatureList.toArray(new SchnorrSignature[0]),
                schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, customFields.toArray(new FieldElement[0]),
                Optional.empty(), provingKeyPath, false, zk, true, true
        );
    }

    private static native boolean nativeVerifyProof(
            BackwardTransfer[] btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            FieldElement constant,
            long quality,
            FieldElement[] customFields,
            byte[] proof,
            boolean checkProof,
            boolean compressedProof,
            String verificationKeyPath,
            boolean checkVerificationKey,
            boolean compressedVk
    );

    /**
     * Verify proof using the supplied parameters
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param constant - constant parameter, as defined by getConstant() method
     * @param quality - quality parameter, as returned by the createProof() function (in this case the number of valid signatures)
     * @param customFields - additional parameters. Can be empty.
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param checkProof - enable semantic checks on the proof
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @param checkVerificationKey - enable semantic checks on the verification key
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     */
    public static boolean verifyProof(
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            FieldElement constant,
            long quality,
            List<FieldElement> customFields,
            byte[] proof,
            boolean checkProof,
            String verificationKeyPath,
            boolean checkVerificationKey
    )
    {
        return nativeVerifyProof(
            btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            constant, quality, customFields.toArray(new FieldElement[0]),
            proof, checkProof, true, verificationKeyPath, checkVerificationKey, true
        );
    }

    /**
     * Verify proof using the supplied parameters
     * @param btList - the list of backward transfer for a given certificate
     * @param scId - the id of the corresponding sidechain
     * @param epochNumber - the epoch number for the certificate
     * @param endCumulativeScTxCommTreeRoot - the value of the cumulative sidechain transaction commitment tree at epoch end
     * @param btrFee - fee for BackwardTransfer
     * @param ftMinAmount - minimum amount for Forward Transfer
     * @param constant - constant parameter, as defined by getConstant() method
     * @param quality - quality parameter, as returned by the createProof() function (in this case the number of valid signatures)
     * @param customFields - additional parameters. Can be empty.
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     */
    public static boolean verifyProof(
            List<BackwardTransfer> btList,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            FieldElement constant,
            long quality,
            List<FieldElement> customFields,
            byte[] proof,
            String verificationKeyPath
    )
    {
        return nativeVerifyProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                constant, quality, customFields.toArray(new FieldElement[0]), proof, true, true,
                verificationKeyPath, false, true
        );
    }
}