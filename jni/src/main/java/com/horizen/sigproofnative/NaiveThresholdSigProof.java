package com.horizen.sigproofnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.provingsystemnative.ProvingSystemType;

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
     * @param customFields - additional optional parameters
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
            Optional<List<FieldElement>> customFields
    )
    {
        // Passing an empty array, Rust side, instead of an Option, will slightly simplify the process of unpacking.
        FieldElement[] customFieldsArray = (customFields.isPresent()) ? customFields.get().toArray(new FieldElement[0]): new FieldElement[] {};
        return nativeCreateMsgToSign(bt, scId, epochNumber, endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount, customFieldsArray);
    }

    private static native boolean nativeSetup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofSize,
        int maxVkSize,
        boolean compressPk,
        boolean compressVk
    );

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support 
     * @param provingKeyPath - file path to which saving the proving key
     * @param verificationKeyPath - file path to which saving the verification key
     * @param zk - used to estimate the proof and vk size, tells if the proof will be created using zk or not
     * @param maxProofSize - maximum allowed proof size
     * @param maxVkSize - maximum allowed vk size
     * @param compressPk - if the proving key must be saved to provingKeyPath in compressed form
     * @param compressVk - if the verification key must be saved to verificationKeyPath in compressed form
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofSize,
        int maxVkSize,
        boolean compressPk,
        boolean compressVk
    )
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, provingKeyPath, verificationKeyPath,
            zk, maxProofSize, maxVkSize, compressPk, compressVk
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support 
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param zk - used to estimate the proof and vk size, tells if the proof will be created using zk or not
     * @param maxProofSize - maximum allowed proof size
     * @param maxVkSize - maximum allowed vk size
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofSize,
        int maxVkSize
    )
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, provingKeyPath, verificationKeyPath,
            zk, maxProofSize, maxVkSize, true, true
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param maxPks - maximum number of public keys (and so signatures) the circuit must support
     * @param numCustomFields - exact number of custom fields the circuit must support 
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param maxProofSize - maximum allowed proof size, estimated assuming to not use zk property.
     * @param maxVkSize - maximum allowed vk size,  estimated assuming to not use zk property.
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise.
     */
    public static boolean setup(
        ProvingSystemType psType,
        long maxPks,
        int numCustomFields,
        String provingKeyPath,
        String verificationKeyPath,
        int maxProofSize,
        int maxVkSize
    )
    {
        return nativeSetup(
            psType, maxPks, numCustomFields, provingKeyPath, verificationKeyPath,
            false, maxProofSize, maxVkSize, true, true
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
     * @param customFields - additional optional parameters
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
            Optional<List<FieldElement>> customFields,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk,
            boolean compressed_pk,
            boolean compress_proof
    )
    {
        // Passing an empty array, Rust side, instead of an Option, will slightly simplify the process of unpacking.
        FieldElement[] customFieldsArray = (customFields.isPresent()) ? customFields.get().toArray(new FieldElement[0]): new FieldElement[] {};

        return nativeCreateProof(
            btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            schnorrSignatureList.toArray(new SchnorrSignature[0]),
            schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
            threshold, customFieldsArray, provingKeyPath, checkProvingKey, zk,
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
     * @param customFields - additional optional parameters
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
            Optional<List<FieldElement>> customFields,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk
    )
    {
        // Passing an empty array, Rust side, instead of an Option, will slightly simplify the process of unpacking.
        FieldElement[] customFieldsArray = (customFields.isPresent()) ? customFields.get().toArray(new FieldElement[0]): new FieldElement[] {};

        return nativeCreateProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                schnorrSignatureList.toArray(new SchnorrSignature[0]),
                schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, customFieldsArray, provingKeyPath, checkProvingKey, zk,
                true, true
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
     * @param customFields - additional optional parameters
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
            Optional<List<FieldElement>> customFields,
            String provingKeyPath,
            boolean zk
    )
    {
        // Passing an empty array, Rust side, instead of an Option, will slightly simplify the process of unpacking.
        FieldElement[] customFieldsArray = (customFields.isPresent()) ? customFields.get().toArray(new FieldElement[0]): new FieldElement[] {};

        return nativeCreateProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                schnorrSignatureList.toArray(new SchnorrSignature[0]),
                schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, customFieldsArray, provingKeyPath, false, zk,
                true, true
        );
    }

    // TODO: check type of `constant` and `endCumulativeScTxCommTreeRoot`. Why not a byte[]?
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
     * @param customFields - additional optional parameters
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
            Optional<List<FieldElement>> customFields,
            byte[] proof,
            boolean checkProof,
            String verificationKeyPath,
            boolean checkVerificationKey
    )
    {
        // Passing an empty array, Rust side, instead of an Option, will slightly simplify the process of unpacking.
        FieldElement[] customFieldsArray = (customFields.isPresent()) ? customFields.get().toArray(new FieldElement[0]): new FieldElement[] {};

        return nativeVerifyProof(
            btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            constant, quality, customFieldsArray, proof, checkProof, true,
            verificationKeyPath, checkVerificationKey, true
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
     * @param customFields - additional optional parameters
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
            Optional<List<FieldElement>> customFields,
            byte[] proof,
            String verificationKeyPath
    )
    {
        // Passing an empty array, Rust side, instead of an Option, will slightly simplify the process of unpacking.
        FieldElement[] customFieldsArray = (customFields.isPresent()) ? customFields.get().toArray(new FieldElement[0]): new FieldElement[] {};

        return nativeVerifyProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                constant, quality, customFieldsArray, proof, true, true,
                verificationKeyPath, false, true
        );
    }
}