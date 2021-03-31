package com.horizen.commitmenttree;

import com.horizen.librustsidechains.Library;

public class ScExistenceProof implements AutoCloseable {
    private long existenceProofPointer;

    static {
        Library.load();
    }

    private ScExistenceProof(long existenceProofPointer) {
        if (existenceProofPointer == 0)
            throw new IllegalArgumentException("existenceProofPointer must be not null.");
        this.existenceProofPointer = existenceProofPointer;
    }

    private static native void nativeFreeScExistenceProof(long existenceProofPointer);

    // Free Rust memory
    public void freeScExistenceProof() {
        if (existenceProofPointer != 0) {
            nativeFreeScExistenceProof(this.existenceProofPointer);
            existenceProofPointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeScExistenceProof();
    }
}