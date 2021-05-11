package com.horizen.sigproofnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.provingsystemnative.ProvingSystem.ProvingSystemType;

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
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount
    );

    public static FieldElement createMsgToSign(
            BackwardTransfer[] bt,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount
    )
    {
        return nativeCreateMsgToSign(bt, epochNumber, endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount);
    }

    public static boolean setup(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath
    )
    {
        return nativeSetup(psType, maxPks, provingKeyPath, verificationKeyPath);
    }

    private static native boolean nativeSetup(
            ProvingSystemType psType,
            long maxPks,
            String provingKeyPath,
            String verificationKeyPath
    );

    private static native CreateProofResult nativeCreateProof(
            BackwardTransfer[] bt,
            int epochNumber,
            FieldElement endCumulativeScTxCommTreeRoot,
            long btrFee,
            long ftMinAmount,
            SchnorrSignature[] schnorrSignatures,
            SchnorrPublicKey[] schnorrPublicKeys,
            long threshold,
            String provingKeyPath,
            boolean checkProvingKey,
            boolean zk
    );

    public static CreateProofResult createProof(
            List<BackwardTransfer> btList,
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
    ) {
        return nativeCreateProof(
            btList.toArray(new BackwardTransfer[0]), epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            schnorrSignatureList.toArray(new SchnorrSignature[0]),
            schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
            threshold, provingKeyPath, checkProvingKey, zk
        );
    }

    private static native boolean nativeVerifyProof(
            BackwardTransfer[] btList,
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
    );

    public static boolean verifyProof(
            List<BackwardTransfer> btList,
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
    ){
        return nativeVerifyProof(
            btList.toArray(new BackwardTransfer[0]), epochNumber,
            endCumulativeScTxCommTreeRoot, btrFee, ftMinAmount,
            constant, quality, proof, checkProof, verificationKeyPath,
            checkVerificationKey
        );
    }
}