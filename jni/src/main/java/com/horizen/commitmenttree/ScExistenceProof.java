package com.horizen.commitmenttree;

public class ScExistanceProof implements AutoCloseable {
    private long existanceProofPointer;

    static {
        Library.load();
    }

    private ScExistanceProof(long existanceProofPointer) {
        if (existanceProofPointer == 0)
            throw new IllegalArgumentException("existanceProofPointer must be not null.");
        this.existanceProofPointer = existanceProofPointer;
    }

    @Override
    public void close() throws Exception {
        freeCommitmentTree();
    }

    private static native void nativeFreeScExistanceProof(long existanceProofPointer);

    // Free Rust memory from CommitmentTree
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