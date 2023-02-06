package com.horizen.commitmenttreenative;

import java.util.Optional;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

/*
 * This class represent a path from the certificate to the root of side chain
 * tx commitments root. That is not a simple merkle path because we need use a
 * merkle path to find the root of the merkle tree of the cerificates, hash it 
 * with the sidechain id and two other roots (forward transfert and backward 
 * transfert); Finally use this hash to compute the final root.
 */
public class ScCommitmentCertPath implements AutoCloseable {

    private long scCommitmentCertPathPointer;

    static {
        Library.load();
    }

    private native Optional<FieldElement> nativeApply(FieldElement scId, FieldElement hash);

    private ScCommitmentCertPath(long scCommitCertPathPointer) {
        if (scCommitCertPathPointer == 0) {
            throw new IllegalArgumentException("scCommitmentPathPointer must be not null.");
        }
        this.scCommitmentCertPathPointer = scCommitCertPathPointer;
    }

    /*
     * Rebuild the root of a sidechain commitment tree `scId` for certificate
     * `hash`.
     */
    public Optional<FieldElement> apply(FieldElement scId, FieldElement hash) {
        return nativeApply(scId, hash);
    }

    private native boolean nativeVerify(FieldElement scTxCommitmentRoot, FieldElement scId, FieldElement hash);

    /*
     * Verify the Path for certificate `hash` given the `root` of a sidechain
     * commitment tree `scId`.
     */
    public boolean verify(FieldElement scTxCommitmentRoot, FieldElement scId, FieldElement hash) {
        check();
        return nativeVerify(scTxCommitmentRoot, scId, hash);
    }

    private native void nativeFreeScCommitmentCertPath(long scCommitCertPathPointer);

    // Take care: not thread safe. If the istance is not shared is not an issue.
    public void freeScCommitmentCertPath() {
        if (scCommitmentCertPathPointer != 0) {
            nativeFreeScCommitmentCertPath(this.scCommitmentCertPathPointer);
            scCommitmentCertPathPointer = 0;
        }
    }

    private native byte[] nativeSerialize();

    public byte[] serialize() {
        check();

        return nativeSerialize();
    }

    private static native ScCommitmentCertPath nativeDeserialize(byte[] scCommitmnetCertPathBytes,
            boolean semanticChecks);

    public static ScCommitmentCertPath deserialize(byte[] scCommitmnetCertPathBytes, boolean semanticChecks) {
        return nativeDeserialize(scCommitmnetCertPathBytes, semanticChecks);
    }

    public static ScCommitmentCertPath deserialize(byte[] scCommitmnetCertPathBytes) {
        return nativeDeserialize(scCommitmnetCertPathBytes, true);
    }

    @Override
    public void close() {
        freeScCommitmentCertPath();
    }

    private void check() {
        if (scCommitmentCertPathPointer == 0) {
            throw new IllegalStateException("Field element was freed.");
        }
    }
}
