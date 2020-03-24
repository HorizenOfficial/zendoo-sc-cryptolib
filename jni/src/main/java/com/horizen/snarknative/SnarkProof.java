package com.horizen.snarknative;

import com.horizen.librustsidechains.Library;

public class SnarkProof {

    private byte[] proof;

    static {
        Library.load();
    }

    public SnarkProof(byte[] proofBytes) {
        this.proof = proofBytes;
    }

    private static native boolean nativeVerify(String keyPath, byte[] message, byte[] proof);

    public boolean verify(String keyPath, byte[] message) {
        return nativeVerify(keyPath, message, proof);
    }

}
