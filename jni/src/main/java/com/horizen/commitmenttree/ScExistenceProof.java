package com.horizen.commitmenttree;

import com.horizen.librustsidechains.Library;

public class ScExistenceProof implements AutoCloseable {
    private long existanceProofPointer;

    static {
        Library.load();
    }

    private ScExistenceProof(long existanceProofPointer) {
        if (existanceProofPointer == 0)
            throw new IllegalArgumentException("existanceProofPointer must be not null.");
        this.existanceProofPointer = existanceProofPointer;
    }

    private static native void nativeFreeScExistanceProof(long existanceProofPointer);

    // Free Rust memory
    public void freeScExistanceProof() {
        if (existanceProofPointer != 0) {
            nativeFreeScExistanceProof(this.existanceProofPointer);
            existanceProofPointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeScExistanceProof();
    }
}