package com.horizen.commitmenttree;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.sigproofnative.BackwardTransfer;

import java.util.List;
import java.util.Optional;

public class CommitmentTree implements AutoCloseable {

    private long commitmentTreePointer;

    static {
        Library.load();
    }

    private CommitmentTree(long commitmentTreePointer) {
        if (commitmentTreePointer == 0)
            throw new IllegalArgumentException("commitmentTreePointer must be not null.");
        this.commitmentTreePointer = commitmentTreePointer;
    }

    private static native CommitmentTree nativeInit(String dbPath);

    public static CommitmentTree init(String dbPath) {
        return nativeInit(dbPath);
    }

    private static native void nativeFreeCommitmentTree(long commitmentTreePointer);

    // Free Rust memory from CommitmentTree
    public void freeCommitmentTree() {
        if (commitmentTreePointer != 0) {
            nativeFreeCommitmentTree(this.commitmentTreePointer);
            commitmentTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeCommitmentTree();
    }

    private static native boolean nativeAddScCr(byte[] scId, long amount, byte[] pubKey, int withdrawalEpochLength,
                                                byte[] customData, byte[] constant, byte[] certVerificationKey,
                                                Optional<byte[]> btrVerificationKeyOpt,
                                                Optional<byte[]> cswVerificationKeyOpt,
                                                byte[] txHash, int outIdx);
    
    public boolean addScCr(byte[] scId, long amount, byte[] pubKey, int withdrawalEpochLength,
                           byte[] customData, byte[] constant, byte[] certVerificationKey,
                           Optional<byte[]> btrVerificationKeyOpt,
                           Optional<byte[]> cswVerificationKeyOpt,
                           byte[] txHash, int outIdx) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddScCr(scId, amount, pubKey, withdrawalEpochLength, customData, constant, certVerificationKey,
                btrVerificationKeyOpt, cswVerificationKeyOpt, txHash, outIdx);
    }
    
    private static native boolean nativeAddFwt(byte[] scId, long amount, byte[] pubKey, byte[] txHash, int outIdx);
    
    public boolean addFwt(byte[] scId, long amount, byte[] pubKey, byte[] txHash, int outIdx) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddFwt(scId, amount, pubKey, txHash, outIdx);
    }

    private static native boolean nativeAddBtr(byte[] scId, long scFee, byte[] pubKeyHash,
                                               byte[] scRequestData, byte[] txHash, int outIdx);
    
    public boolean addBtr(byte[] scId, long scFee, byte[] pubKeyHash, byte[] scRequestData, byte[] txHash, int outIdx) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddBtr(scId, scFee, pubKeyHash, scRequestData, txHash, outIdx);
    }
    
    private static native boolean nativeAddCert(byte[] scId, int epochNumber, long quality,
                                                byte[] certDataHash, BackwardTransfer[] btList,
                                                byte[] customFieldsMerkleRoot,
                                                byte[] endCumulativeScTxCommitmentTreeRoot);

    public boolean addCert(byte[] scId, int epochNumber, long quality, byte[] certDataHash, BackwardTransfer[] btList,
                           byte[] customFieldsMerkleRoot, byte[] endCumulativeScTxCommitmentTreeRoot) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddCert(scId, epochNumber, quality, certDataHash, btList,
                customFieldsMerkleRoot, endCumulativeScTxCommitmentTreeRoot);
    }

    public static native boolean nativeAddCertLeaf(byte[] scId, byte[] leaf);

    public boolean addCertLeaf(byte[] scId, byte[] leaf) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddCertLeaf(scId, leaf);
    }
    
    private static native boolean nativeAddCsw(byte[] scId, long amount, byte[] nullifier,
                                               byte[] pubKeyHash, byte[] activeCertDataHash);
    
    public boolean addCsw(byte[] scId, long amount, byte[] nullifier, byte[] pubKeyHash, byte[] activeCertDataHash) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddCsw(scId, amount, nullifier, pubKeyHash, activeCertDataHash);
    }


    private static native Optional<List<FieldElement>>  nativeGetCrtLeaves(byte[] scId);
    public Optional<List<FieldElement>> getCrtLeaves(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCrtLeaves(scId);
    }
    
    private static native Optional<FieldElement> nativeGetScCrCommitment(byte[] scId);
    
    public Optional<FieldElement> getScCrCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScCrCommitment(scId);
    }

    private static native Optional<FieldElement> nativeGetFwtCommitment(byte[] scId);
    
    public Optional<FieldElement> getFwtCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetFwtCommitment(scId);
    }

    private static native Optional<FieldElement> nativeBtrCommitment(byte[] scId);
    
    public Optional<FieldElement> getBtrCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeBtrCommitment(scId);
    }

    private static native Optional<FieldElement> nativeGetCertCommitment(byte[] scId);
    
    public Optional<FieldElement> getCertCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCertCommitment(scId);
    }

    private static native Optional<FieldElement> nativeGetCswCommitment(byte[] scId);
    
    public Optional<FieldElement> getCswCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCswCommitment(scId);
    }

    private static native Optional<FieldElement> nativeGetScCommitment(byte[] scId);
    
    public Optional<FieldElement> getScCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScCommitment(scId);
    }

    private static native Optional<FieldElement> nativeGetCommitment();
    
    public Optional<FieldElement> getCommitment() {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCommitment();
    }

    private static native Optional<ScExistanceProof> nativeGetScExistenceProof(byte[] scId);

    public Optional<ScExistanceProof> getScExistenceProof(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScExistenceProof(scId);
    }

    private static native bool nativeVerifyScCommitment(FieldElement scCommitment, ScExistanceProof existanceProof, FieldElement commitment);

    public static bool verifyScCommitment(FieldElement scCommitment, ScExistanceProof existanceProof, FieldElement commitment) {
        return nativeVerifyScCommitment(scCommitment, existanceProof, commitment);
    }

    private static native Optional<ScExistanceProof> nativeGetScAbsenceProof(byte[] scId);

    public Optional<ScAbsenceProof> getScAbsenceProof(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScAbsenceProof(scId);
    }

    private native bool nativeVerifyScAbsence(byte[] scid, ScExistanceProof existanceProof, FieldElement commitment);

    public bool verifyScAbsence(byte[] scid, ScExistanceProof existanceProof, FieldElement commitment) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeVerifyScAbsence(scCommitment, existanceProof, commitment);
    }
}
