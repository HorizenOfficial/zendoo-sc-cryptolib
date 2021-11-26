package com.horizen.certnative;

import java.util.List;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.poseidonnative.PoseidonHashable;

public class WithdrawalCertificate implements AutoCloseable, PoseidonHashable {
    private final int epochNumber;
    private final List<BackwardTransfer> btList;
    private final long quality;
    private final FieldElement mcbScTxsCom;
    private final long ftMinFee;
    private final long btrMinFee;
    private final FieldElement utxoMerkleRoot;

    static {
        Library.load();
    }

    public WithdrawalCertificate(int epochNumber, List<BackwardTransfer> btList, long quality, FieldElement mcbScTxsCom,
            long ftMinFee, long btrMinFee, FieldElement utxoMerkleRoot) {
        this.epochNumber = epochNumber;
        this.btList = btList;
        this.quality = quality;
        this.mcbScTxsCom = mcbScTxsCom;
        this.ftMinFee = ftMinFee;
        this.btrMinFee = btrMinFee;
        this.utxoMerkleRoot = utxoMerkleRoot;
    }

    public int getEpochNumber() {
        return epochNumber;
    }

    public List<BackwardTransfer> getBtList() {
        return btList;
    }

    public long getQuality() {
        return quality;
    }

    public FieldElement getMcbScTxsCom() {
        return mcbScTxsCom;
    }

    public long getFtMinFee() {
        return ftMinFee;
    }

    public long getBtrMinFee() {
        return btrMinFee;
    }

    public FieldElement getUtxoMerkleRoot() {
        return utxoMerkleRoot;
    }

    private native FieldElement nativeGetHash();

    @Override
    public FieldElement getHash() {
        return nativeGetHash();
    }

    @Override
    public void close() throws Exception {
        this.mcbScTxsCom.close();
        this.utxoMerkleRoot.close();
    }
}
