package com.horizen.cswnative;

import java.util.List;

import com.horizen.fwtnative.ForwardTransferOutput;
import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.merkletreenative.MerklePath;

public class CswFtProverData implements AutoCloseable {
    private final ForwardTransferOutput output;
    private final byte[] ftInputSecretKey;
    private final FieldElement mcbScTxsComStart;
    private final MerklePath merklePathToScHash;
    private final MerklePath ftTreePath;
    private final FieldElement scCreationCommitment;
    private final FieldElement scbBtrTreeRoot;
    private final FieldElement wCertTreeRoot;
    private final List<FieldElement> scTxsComHashes;

    public CswFtProverData(ForwardTransferOutput output, byte[] ftInputSecretKey, FieldElement mcbScTxsComStart,
                           MerklePath merklePathToScHash, MerklePath ftTreePath, FieldElement scCreationCommitment,
                           FieldElement scbBtrTreeRoot, FieldElement wCertTreeRoot, List<FieldElement> scTxsComHashes) {
        this.output = output;

        if (ftInputSecretKey.length != Constants.SC_SK_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect ftInputSecretKey element length, %d expected, %d found",Constants.SC_SK_SIZE(), ftInputSecretKey.length)
            );
        this.ftInputSecretKey = ftInputSecretKey;

        this.mcbScTxsComStart = mcbScTxsComStart;

        if (merklePathToScHash.getLength() != Constants.SC_COMM_TREE_HEIGHT())
            throw new IllegalArgumentException(
                String.format("Incorrect merklePathToScHash element length, %d expected, %d found",Constants.SC_COMM_TREE_HEIGHT(), merklePathToScHash.getLength())
            );
        this.merklePathToScHash = merklePathToScHash;
        
        if (ftTreePath.getLength() != Constants.SC_COMM_TREE_FT_SUBTREE_HEIGHT())
            throw new IllegalArgumentException(
                String.format("Incorrect ftTreePath element length, %d expected, %d found",Constants.SC_COMM_TREE_FT_SUBTREE_HEIGHT(), ftTreePath.getLength())
            );
        this.ftTreePath = ftTreePath;

        this.scCreationCommitment = scCreationCommitment;
        this.scbBtrTreeRoot = scbBtrTreeRoot;
        this.wCertTreeRoot = wCertTreeRoot;
        this.scTxsComHashes = scTxsComHashes;
    }

    public ForwardTransferOutput getOutput() {
        return output;
    }

    public byte[] getFtInputSecretKey() {
        return ftInputSecretKey;
    }

    public FieldElement getMcbScTxsComStart() {
        return mcbScTxsComStart;
    }

    public MerklePath getMerklePathToScHash() {
        return merklePathToScHash;
    }

    public MerklePath getFtTreePath() {
        return ftTreePath;
    }

    public FieldElement getScCreationTxHash() {
        return scCreationCommitment;
    }

    public FieldElement getScbBtrTreeRoot() {
        return scbBtrTreeRoot;
    }

    public FieldElement getwCertTreeRoot() {
        return wCertTreeRoot;
    }

    public List<FieldElement> getScTxsComHashes() {
        return scTxsComHashes;
    }

    @Override
    public void close() throws Exception {
        this.mcbScTxsComStart.close();
        this.merklePathToScHash.close();
        this.ftTreePath.close();
        this.scCreationCommitment.close();
        this.scbBtrTreeRoot.close();
        this.wCertTreeRoot.close();
        for (FieldElement fe: scTxsComHashes)
            fe.close();
    }
}
