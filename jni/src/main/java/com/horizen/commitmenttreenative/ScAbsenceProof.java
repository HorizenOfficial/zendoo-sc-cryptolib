package com.horizen.commitmenttreenative;

import com.horizen.librustsidechains.Library;

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

    private static native void nativeFreeScAbsenceProof(long absenceProofPointer);

    // Free Rust memory
    public void freeScAbsenceProof() {
        if (absenceProofPointer != 0) {
            nativeFreeScAbsenceProof(this.absenceProofPointer);
            absenceProofPointer = 0;
        }
    }

    private native byte[] nativeSerialize();


    public byte[] serialize() {
        if (absenceProofPointer == 0)
            throw new IllegalStateException("Absence proof was freed.");

        return nativeSerialize();
    }

    private static native ScAbsenceProof nativeDeserialize(byte[] absenceProofBytes);

    public static ScAbsenceProof deserialize(byte[] absenceProofBytes) {
        return nativeDeserialize(absenceProofBytes);
    }

    @Override
    public void close() {
        freeScAbsenceProof();
    }
}