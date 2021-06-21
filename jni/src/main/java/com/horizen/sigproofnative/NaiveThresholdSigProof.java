package com.horizen.sigproofnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.provingsystemnative.ProvingSystemType;
import com.horizen.provingsystemnative.ProvingSystem;

import java.util.List;

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
            long ftMinAmount
    );

    public static FieldElement createMsgToSign(
            BackwardTransfer[] bt,
            FieldElement scId,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount
    )
    {
        return nativeCreateMsgToSign(bt, scId, epochNumber, endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount);
    }

    private static native boolean nativeSetup(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath,
            boolean compressPk,
            boolean compressVk
    );

    public static boolean setup(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath,
            boolean compressPk,
            boolean compressVk
    )
    {
        return nativeSetup(psType, maxPks, provingKeyPath, verificationKeyPath, compressPk, compressVk);
    }

    public static boolean setup(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath
    )
    {
        return nativeSetup(psType, maxPks, provingKeyPath, verificationKeyPath, true, true);
    }

    public static boolean setupAndCheckProofVkSize(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath,
            boolean zk,
            int supportedSegmentSize,
            int maxProofSize,
            int maxVkSize,
            boolean compressPk,
            boolean compressVk
    )
    {
        if (!nativeSetup(psType, maxPks, provingKeyPath, verificationKeyPath, compressPk, compressVk)) {
            return false;
        }

        return ProvingSystem.checkProofVkSize(zk, supportedSegmentSize, maxProofSize, maxVkSize, verificationKeyPath);
    }

    public static boolean setupAndCheckProofVkSize(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath,
            boolean zk,
            int supportedSegmentSize,
            int maxProofSize,
            int maxVkSize
    )
    {
        return setupAndCheckProofVkSize(
            psType, maxPks, provingKeyPath, verificationKeyPath, zk,
            supportedSegmentSize, maxProofSize, maxVkSize, true, true
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
            threshold, provingKeyPath, checkProvingKey, zk,
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
                threshold, provingKeyPath, checkProvingKey, zk,
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
            String provingKeyPath,
            boolean zk
    )
    {
        return nativeCreateProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                schnorrSignatureList.toArray(new SchnorrSignature[0]),
                schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, provingKeyPath, false, zk,
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
            byte[] proof,
            boolean checkProof,
            String verificationKeyPath,
            boolean checkVerificationKey
    )
    {
        return nativeVerifyProof(
            btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            constant, quality, proof, checkProof, true,
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
            byte[] proof,
            String verificationKeyPath
    )
    {
        return nativeVerifyProof(
                btList.toArray(new BackwardTransfer[0]), scId, epochNumber,
                endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
                constant, quality, proof, true, true,
                verificationKeyPath, false, true
        );
    }
}