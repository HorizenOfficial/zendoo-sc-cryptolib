package com.horizen.cswnative;

import java.util.List;

import com.horizen.fwtnative.ForwardTransferOutput;
import com.horizen.librustsidechains.Constants;
import io.horizen.common.librustsidechains.FieldElement;
import io.horizen.common.merkletreenative.FieldBasedMerklePath;

public class CswFtProverData implements AutoCloseable {
    private final ForwardTransferOutput output;
    private final byte[] ftInputSecretKey;
    private final FieldElement mcbScTxsComStart;
    private final FieldBasedMerklePath merklePathToScHash;
    private final FieldBasedMerklePath ftTreePath;
    private final FieldElement scCreationCommitment;
    private final FieldElement scbBtrTreeRoot;
    private final FieldElement wCertTreeRoot;
    private final FieldElement[] scTxsComHashes;

    public CswFtProverData(ForwardTransferOutput output, byte[] ftInputSecretKey, FieldElement mcbScTxsComStart,
                           FieldBasedMerklePath merklePathToScHash, FieldBasedMerklePath ftTreePath, FieldElement scCreationCommitment,
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
        this.scTxsComHashes = scTxsComHashes.toArray(new FieldElement[0]);
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

    public FieldBasedMerklePath getMerklePathToScHash() {
        return merklePathToScHash;
    }

    public FieldBasedMerklePath getFtTreePath() {
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

    public FieldElement[] getScTxsComHashes() {
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
