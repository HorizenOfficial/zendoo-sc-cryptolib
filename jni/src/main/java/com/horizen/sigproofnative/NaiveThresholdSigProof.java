package com.horizen.sigproofnative;

import com.horizen.schnorrnative.SchnorrKeyPair;

import java.util.List;

public class NaiveThresholdSigProof {

    private static native byte[] nativeCreateProof(BackwardTransfer[] bt,
                                                  byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                                  SchnorrKeyPair[] schnorrKeyPairs, long threshold,
                                                  String verificationKeyPath);

    public static byte[] createProof(List<BackwardTransfer> btList,
                                     byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                     List<SchnorrKeyPair> schnorrKeyList, long threshold,
                                     String verificationKeyPath) {
        return nativeCreateProof(btList.toArray(new BackwardTransfer[0]), endEpochBlockHash, prevEndEpochBlockHash,
                schnorrKeyList.toArray(new SchnorrKeyPair[0]), threshold, verificationKeyPath);
    }
}
