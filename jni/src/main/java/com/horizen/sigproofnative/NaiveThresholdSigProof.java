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