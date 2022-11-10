package com.horizen.certnative;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.poseidonnative.PoseidonHashable;

// TODO: Use this class also in NaiveThresholdSigProof and CommitmentTree (re use stuff also Rust side)
public class WithdrawalCertificate implements AutoCloseable, PoseidonHashable {
    private FieldElement scId;
    private int epochNumber;
    private BackwardTransfer[] btList;
    private long quality;
    private FieldElement mcbScTxsCom;
    private long ftMinAmount;
    private long btrMinFee;
    private FieldElement[] customFields;

    static {
        Library.load();
    }

    public WithdrawalCertificate(FieldElement scId, int epochNumber, List<BackwardTransfer> btList, FieldElement mcbScTxsCom,
            long ftMinAmount, long btrMinFee, List<FieldElement> customFields) {
        this.scId = scId;
        this.epochNumber = epochNumber;
        this.btList = btList.toArray(new BackwardTransfer[0]);
        this.quality = 0;
        this.mcbScTxsCom = mcbScTxsCom;
        this.ftMinAmount = ftMinAmount;
        this.btrMinFee = btrMinFee;
        this.customFields = customFields.toArray(new FieldElement[0]);
    }

    public WithdrawalCertificate(FieldElement scId, int epochNumber, List<BackwardTransfer> btList, long quality, FieldElement mcbScTxsCom,
            long ftMinAmount, long btrMinFee, List<FieldElement> customFields) {
        this.scId = scId;
        this.epochNumber = epochNumber;
        this.btList = btList.toArray(new BackwardTransfer[0]);
        this.quality = quality;
        this.mcbScTxsCom = mcbScTxsCom;
        this.ftMinAmount = ftMinAmount;
        this.btrMinFee = btrMinFee;
        this.customFields = customFields.toArray(new FieldElement[0]);
    }

    public FieldElement getScId() {
        return scId;
    }

    public int getEpochNumber() {
        return epochNumber;
    }

    public BackwardTransfer[] getBtList() {
        return btList;
    }

    public long getQuality() {
        return quality;
    }

    public FieldElement getMcbScTxsCom() {
        return mcbScTxsCom;
    }

    public long getFtMinAmount() {
        return ftMinAmount;
    }

    public long getBtrMinFee() {
        return btrMinFee;
    }

    public FieldElement[] getCustomFields() {
        return customFields;
    }

    public void setScId(FieldElement scId) {
        this.scId = scId;
    }

    public void setEpochNumber(int epochNumber) {
        this.epochNumber = epochNumber;
    }

    public void setBtList(BackwardTransfer[] btList) {
        this.btList = btList;
    }

    public void setQuality(long quality) {
        this.quality = quality;
    }

    public void setMcbScTxsCom(FieldElement mcbScTxsCom) {
        this.mcbScTxsCom = mcbScTxsCom;
    }

    public void setFtMinAmount(long ftMinAmount) {
        this.ftMinAmount = ftMinAmount;
    }

    public void setBtrMinFee(long btrMinFee) {
        this.btrMinFee = btrMinFee;
    }

    public void setCustomFields(FieldElement[] customFields) {
        this.customFields = customFields;
    }

    private native FieldElement nativeGetHash();

    @Override
    public FieldElement getHash() {
        return nativeGetHash();
    }

    public static WithdrawalCertificate getRandom(Random r, int numBt, int numCustomFields) {
        // Generate random BTs
        List<BackwardTransfer> btList = new ArrayList<>();
        if (numBt > 0) {            
            for(int i = 0; i < numBt; i++) {
                btList.add(BackwardTransfer.getRandom(r));
            }
        }

        // Generate random custom fields
        List<FieldElement> customFields = new ArrayList<>();
        if (numCustomFields > 0) {
            for(int i = 0; i < numCustomFields; i++)   
                customFields.add(FieldElement.createRandom(r));
        }

        // Generate and return random wCert
        return new WithdrawalCertificate(
            FieldElement.createRandom(r), r.nextInt(), btList, r.nextLong(),
            FieldElement.createRandom(r), r.nextLong(), r.nextLong(), customFields
        );
    }

    @Override
    public void close() throws Exception {
        this.scId.close();
        this.mcbScTxsCom.close();
        for (FieldElement fe: customFields)
            fe.close();
    }
}
