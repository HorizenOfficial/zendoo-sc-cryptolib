package com.horizen.commitmenttree;

public class ScAbsenceProof implements AutoCloseable {
    private long absenceProofPointer;

    static {
        Library.load();
    }

    private ScAbsenceProof(long absenceProofPointer) {
        if (absenceProofPointer == 0)
            throw new IllegalArgumentException("absenceProofPointer must be not null.");
        this.absenceProofPointer = absenceProofPointer;
    }

    @Override
    public void close() throws Exception {
        freeCommitmentTree();
    }

    private static native ScAbsenceProof nativeInit();

    public static ScAbsenceProof init() {
        return nativeInit();
    }

    private static native void nativeFreeScAbsenceProof(long absenceProofPointer);

    // Free Rust memory from CommitmentTree
    public void freeScAbsenceProof() {
        if (absenceProofPointer != 0) {
            nativeFreeScAbsenceProof(this.absenceProofPointer);
            absenceProofPointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeScAbsenceProof();
    }
}