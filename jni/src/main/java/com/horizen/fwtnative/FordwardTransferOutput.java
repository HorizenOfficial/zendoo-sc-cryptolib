package com.horizen.fwtnative;

import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.poseidonnative.PoseidonHashable;

public class FordwardTransferOutput implements PoseidonHashable {
    private final long amount;
    private final byte[] receiverPubKey; 
    private final byte[] paybackAddrDataHash;
    private final byte[] txHash;
    private final int outIdx;

    static {
        Library.load();
    }

    public FordwardTransferOutput(long amount, byte[] receiverPubKey, byte[] paybackAddrDataHash, byte[] txHash, int outIdx)
    {
        this.amount = amount;

        if (receiverPubKey.length != Constants.MC_PK_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect receiverPubKey element length, %d expected, %d found",Constants.MC_PK_HASH_SIZE(), receiverPubKey.length)
            );
        this.receiverPubKey = receiverPubKey;

        if (paybackAddrDataHash.length != Constants.SC_PK_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect paybackAddrDataHash element length, %d expected, %d found",Constants.SC_PK_HASH_SIZE(), paybackAddrDataHash.length)
            );
        this.paybackAddrDataHash = paybackAddrDataHash;

        
        if (txHash.length != Constants.SC_TX_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect txHash element length, %d expected, %d found",Constants.SC_TX_HASH_SIZE(), txHash.length)
            );
        this.txHash = txHash;

        this.outIdx = outIdx;
    }

    public long getAmount() {
        return amount;
    }

    public byte[] getReceiverPubKey() {
        return receiverPubKey;
    }

    public byte[] getPaybackAddrDataHash() {
        return paybackAddrDataHash;
    }

    public byte[] getTxHash() {
        return txHash;
    }

    public int getOutIdx() {
        return outIdx;
    }

    private native FieldElement nativeGetHash();

    @Override
    public FieldElement getHash() {
        return nativeGetHash();
    }

    public FieldElement getNullifier() {
        return this.getHash();
    }
}
