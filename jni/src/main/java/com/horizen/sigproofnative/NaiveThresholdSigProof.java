package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import com.horizen.provingsystemnative.ProvingSystem.ProvingSystemType;

import java.util.List;

public class NaiveThresholdSigProof {

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
            byte[] endEpochBlockHash,
            byte[] prevEndEpochBlockHash
    );

    public static FieldElement createMsgToSign(
            BackwardTransfer[] bt,
            byte[] endEpochBlockHash,
            byte[] prevEndEpochBlockHash
    )
    {
        return nativeCreateMsgToSign(bt, endEpochBlockHash, prevEndEpochBlockHash);
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
            ProvingSystemType psType,
            BackwardTransfer[] bt,
            byte[] endEpochBlockHash,
            byte[] prevEndEpochBlockHash,
            SchnorrSignature[] schnorrSignatures,
            SchnorrPublicKey[] schnorrPublicKeys,
            long threshold,
            String provingKeyPath,
            boolean checkProvingKey
    );

    public static CreateProofResult createProof(
            ProvingSystemType psType,
            List<BackwardTransfer> btList,
            byte[] endEpochBlockHash,
            byte[] prevEndEpochBlockHash,
            List<SchnorrSignature> schnorrSignatureList,
            List<SchnorrPublicKey> schnorrPublicKeyList,
            long threshold,
            String provingKeyPath,
            boolean checkProvingKey
    ) {
        return nativeCreateProof(psType, btList.toArray(new BackwardTransfer[0]), endEpochBlockHash, prevEndEpochBlockHash,
                schnorrSignatureList.toArray(new SchnorrSignature[0]), schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, provingKeyPath, checkProvingKey);
    }

    private static native boolean nativeVerifyProof(
            ProvingSystemType psType,
            BackwardTransfer[] btList,
            byte[] endEpochBlockHash,
            byte[] prevEndEpochBlockHash,
            FieldElement constant,
            long quality,
            byte[] proof,
            boolean checkProof,
            String verificationKeyPath,
            boolean checkVerificationKey);

    public static boolean verifyProof(
            ProvingSystemType psType,
            List<BackwardTransfer> btList,
            byte[] endEpochBlockHash,
            byte[] prevEndEpochBlockHash,
            FieldElement constant,
            long quality,
            byte[] proof,
            boolean checkProof,
            String verificationKeyPath,
            boolean checkVerificationKey
    ){
        return nativeVerifyProof(
                psType,
                btList.toArray(new BackwardTransfer[0]),
                endEpochBlockHash, prevEndEpochBlockHash,
                constant, quality, proof, checkProof, verificationKeyPath, checkVerificationKey);
    }
}