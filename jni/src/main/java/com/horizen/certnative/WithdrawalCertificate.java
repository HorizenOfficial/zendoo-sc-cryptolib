package com.horizen.certnative;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.poseidonnative.PoseidonHashable;

// TODO: Use this class also in NaiveThresholdSigProof and CommitmentTree (re use stuff also Rust side)
public class WithdrawalCertificate implements AutoCloseable, PoseidonHashable {
    private final FieldElement scId;
    private final int epochNumber;
    private final BackwardTransfer[] btList;
    private final long quality;
    private final FieldElement mcbScTxsCom;
    private final long ftMinAmount;
    private final long btrMinFee;
    private final FieldElement[] customFields;

    static {
        Library.load();
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
