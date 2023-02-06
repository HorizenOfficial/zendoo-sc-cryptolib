package com.horizen.commitmenttreenative;

import com.horizen.certnative.BackwardTransfer;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.merkletreenative.MerklePath;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class CommitmentTree implements AutoCloseable {

    private long commitmentTreePointer;

    static {
        Library.load();
    }

    private CommitmentTree(long commitmentTreePointer) {
        this.commitmentTreePointer = commitmentTreePointer;
    }

    private static native CommitmentTree nativeInit();

    public static CommitmentTree init() {
        return nativeInit();
    }

    private native void nativeFreeCommitmentTree(long commitmentTreePointer);

    // Free Rust memory from CommitmentTree
    public void freeCommitmentTree() {
        if (commitmentTreePointer != 0) {
            nativeFreeCommitmentTree(this.commitmentTreePointer);
            commitmentTreePointer = 0;
        }
    }

    @Override
    public void close() {
        freeCommitmentTree();
    }

    private native boolean nativeAddScCr(byte[] scId, long amount, byte[] pubKey, byte[] txHash, int outIdx,
                                         int withdrawalEpochLength, byte mcBtrRequestDataLength,
                                         CustomFieldElementsConfig[] customFieldElementsConfigs,
                                         CustomBitvectorElementsConfig[] customBitvectorElementsConfigs,
                                         long btrFee, long ftMinAmount, byte[] customCreationData,
                                         byte[] constantNullable, byte[] certVerificationKey, byte[] cswVerificationKeyNullable);
    
    public boolean addScCr(byte[] scId, long amount, byte[] pubKey, byte[] txHash, int outIdx, int withdrawalEpochLength,
                           byte mcBtrRequestDataLength, CustomFieldElementsConfig[] customFieldElementsConfigs,
                           CustomBitvectorElementsConfig[] customBitvectorElementsConfigs, long btrFee,
                           long ftMinAmount, byte[] customCreationData, Optional<byte[]> constantOpt,
                           byte[] certVerificationKey, Optional<byte[]> cswVerificationKeyOpt) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddScCr(scId, amount, pubKey, txHash, outIdx, withdrawalEpochLength,
                mcBtrRequestDataLength, customFieldElementsConfigs, customBitvectorElementsConfigs,
                btrFee, ftMinAmount, customCreationData, constantOpt.orElse(null), certVerificationKey,
                cswVerificationKeyOpt.orElse(null));
    }
    
    private native boolean nativeAddFwt(byte[] scId, long amount, byte[] pubKey, byte[] mcReturnAddress, byte[] txHash, int outIdx);
    
    public boolean addFwt(byte[] scId, long amount, byte[] pubKey, byte[] mcReturnAddress, byte[] txHash, int outIdx) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddFwt(scId, amount, pubKey, mcReturnAddress, txHash, outIdx);
    }

    private native boolean nativeAddBtr(byte[] scId, long scFee, byte[] mcDestinationAddress,
                                               byte[][] scRequestData, byte[] txHash, int outIdx);
    
    public boolean addBtr(byte[] scId, long scFee, byte[] mcDestinationAddress, byte[][] scRequestData, byte[] txHash, int outIdx) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddBtr(scId, scFee, mcDestinationAddress, scRequestData, txHash, outIdx);
    }
    
    private native boolean nativeAddCert(byte[] scId, int epochNumber, long quality,
                                         BackwardTransfer[] btList, byte[][] customFieldsNullable,
                                         byte[] endCumulativeScTxCommitmentTreeRoot, long btrFee, long ftMinAmount);

    public boolean addCert(byte[] scId, int epochNumber, long quality,
                           BackwardTransfer[] btList, Optional<byte[][]> customFieldsOpt,
                           byte[] endCumulativeScTxCommitmentTreeRoot, long btrFee, long ftMinAmount) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddCert(scId, epochNumber, quality, btList,
                customFieldsOpt.orElse(null), endCumulativeScTxCommitmentTreeRoot, btrFee, ftMinAmount);
    }

    public native boolean nativeAddCertLeaf(byte[] scId, byte[] leaf);

    public boolean addCertLeaf(byte[] scId, byte[] leaf) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddCertLeaf(scId, leaf);
    }
    
    private native boolean nativeAddCsw(byte[] scId, long amount, byte[] nullifier, byte[] mcPubKeyHash);
    
    public boolean addCsw(byte[] scId, long amount, byte[] nullifier, byte[] mcPubKeyHash) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeAddCsw(scId, amount, nullifier, mcPubKeyHash);
    }

    private native Optional<FieldElement[]>  nativeGetFwtLeaves(byte[] scId);

    public Optional<List<FieldElement>> getFwtLeaves(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetFwtLeaves(scId).map(array -> new ArrayList<FieldElement>(Arrays.asList(array)));
    }

    private native Optional<FieldElement[]>  nativeGetBtrLeaves(byte[] scId);

    public Optional<List<FieldElement>> getBtrLeaves(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetBtrLeaves(scId).map(array -> new ArrayList<FieldElement>(Arrays.asList(array)));
    }

    private native Optional<FieldElement[]>  nativeGetCrtLeaves(byte[] scId);

    public Optional<List<FieldElement>> getCrtLeaves(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCrtLeaves(scId).map(array -> new ArrayList<FieldElement>(Arrays.asList(array)));
    }
    
    private native Optional<FieldElement> nativeGetScCrCommitment(byte[] scId);
    
    public Optional<FieldElement> getScCrCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScCrCommitment(scId);
    }

    private native Optional<FieldElement> nativeGetFwtCommitment(byte[] scId);
    
    public Optional<FieldElement> getFwtCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetFwtCommitment(scId);
    }

    private native Optional<FieldElement> nativeBtrCommitment(byte[] scId);
    
    public Optional<FieldElement> getBtrCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeBtrCommitment(scId);
    }

    private native Optional<FieldElement> nativeGetCertCommitment(byte[] scId);
    
    public Optional<FieldElement> getCertCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCertCommitment(scId);
    }

    private native Optional<FieldElement> nativeGetCswCommitment(byte[] scId);
    
    public Optional<FieldElement> getCswCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCswCommitment(scId);
    }

    private native Optional<FieldElement> nativeGetScCommitment(byte[] scId);
    
    public Optional<FieldElement> getScCommitment(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScCommitment(scId);
    }

    private native Optional<FieldElement> nativeGetCommitment();
    
    public Optional<FieldElement> getCommitment() {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetCommitment();
    }

    private native Optional<ScExistenceProof> nativeGetScExistenceProof(byte[] scId);

    public Optional<ScExistenceProof> getScExistenceProof(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScExistenceProof(scId);
    }

    private static native boolean nativeVerifyScCommitment(FieldElement scCommitment, ScExistenceProof existenceProof, FieldElement commitment);

    public static boolean verifyScCommitment(FieldElement scCommitment, ScExistenceProof existenceProof, FieldElement commitment) {
        return nativeVerifyScCommitment(scCommitment, existenceProof, commitment);
    }

    private native Optional<ScAbsenceProof> nativeGetScAbsenceProof(byte[] scId);

    public Optional<ScAbsenceProof> getScAbsenceProof(byte[] scId) {
        if (commitmentTreePointer == 0)
            throw new IllegalStateException("CommitmentTree instance was freed.");
        return nativeGetScAbsenceProof(scId);
    }

    private static native boolean nativeVerifyScAbsence(byte[] scId, ScAbsenceProof absenceProof, FieldElement commitment);

    public static boolean verifyScAbsence(byte[] scId, ScAbsenceProof absenceProof, FieldElement commitment) {
        return nativeVerifyScAbsence(scId, absenceProof, commitment);
    }

    private native Optional<MerklePath> nativeGetScCommitmentMerklePath(byte[] scId);

    public Optional<MerklePath> getScCommitmentMerklePath(byte[] scId) {
        return nativeGetScCommitmentMerklePath(scId);
    }

    private native Optional<MerklePath> nativeGetFwtMerklePath(byte[] scId, int leafIndex);

    public Optional<MerklePath> getFwtMerklePath(byte[] scId, int leafIndex) {
        return nativeGetFwtMerklePath(scId, leafIndex);
    }

    private native Optional<MerklePath> nativeGetBtrMerklePath(byte[] scId, int leafIndex);

    public Optional<MerklePath> getBtrMerklePath(byte[] scId, int leafIndex) {
        return nativeGetBtrMerklePath(scId, leafIndex);
    }

    private native Optional<MerklePath> nativeGetCertMerklePath(byte[] scId, int leafIndex);

    public Optional<MerklePath> getCertMerklePath(byte[] scId, int leafIndex) {
        return nativeGetCertMerklePath(scId, leafIndex);
    }

    private native Optional<ScCommitmentCertPath> nativeGetScCommitmentCertPath(byte[] scId, byte[] certLeafHash);

    /**
     * Return the path from the certificate hash to the root of sidechain tx commitments root. That
     * is not a simple merkle path but provides all the info that we need to generate the root from 
     * the certificate.
     * 
     * @param scId              - The sidechain id
     * @param certLeafHash      - The certificate hash
     * @return                  - A ScCommitmentCertPath to build the sidechain tx commitments root
     *                              from the ceritificate hash leaf (if the certificate hash is a
     *                              leaf of the certificates tree).
     */
    public Optional<ScCommitmentCertPath> getScCommitmentCertPath(byte[] scId, byte[] certLeafHash) {
        return nativeGetScCommitmentCertPath(scId, certLeafHash);
    }
}
