package com.horizen.certnative;

import java.util.List;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.poseidonnative.PoseidonHashable;

// TODO: Use this class also in NaiveThresholdSigProof and CommitmentTree (re use stuff also Rust side)
public class WithdrawalCertificate implements AutoCloseable, PoseidonHashable {
    private final FieldElement scId;
    private final int epochNumber;
    private final List<BackwardTransfer> btList;
    private final long quality;
    private final FieldElement mcbScTxsCom;
    private final long ftMinFee;
    private final long btrMinFee;
    private final List<FieldElement> customFields;

    static {
        Library.load();
    }

    public WithdrawalCertificate(FieldElement scId, int epochNumber, List<BackwardTransfer> btList, long quality, FieldElement mcbScTxsCom,
            long ftMinFee, long btrMinFee, List<FieldElement> customFields) {
        this.scId = scId;
        this.epochNumber = epochNumber;
        this.btList = btList;
        this.quality = quality;
        this.mcbScTxsCom = mcbScTxsCom;
        this.ftMinFee = ftMinFee;
        this.btrMinFee = btrMinFee;
        this.customFields = customFields;
    }

    public FieldElement getScId() {
        return scId;
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

    public List<FieldElement> getCustomFields() {
        return customFields;
    }

    private native FieldElement nativeGetHash();

    @Override
    public FieldElement getHash() {
        return nativeGetHash();
    }

    @Override
    public void close() throws Exception {
        this.scId.close();
        this.mcbScTxsCom.close();
        for (FieldElement fe: customFields)
            fe.close();
    }
}
