package com.horizen.fwtnative;

import java.util.Random;

import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.Library;
import io.horizen.common.librustsidechains.FieldElement;
import io.horizen.common.poseidonnative.PoseidonHashable;

public class ForwardTransferOutput implements PoseidonHashable {
    private long amount;
    private byte[] receiverPubKey; 
    private byte[] paybackAddrDataHash;
    private byte[] txHash;
    private int outIdx;

    static {
        Library.load();
    }

    public ForwardTransferOutput(long amount, byte[] receiverPubKey, byte[] paybackAddrDataHash, byte[] txHash, int outIdx)
    {
        this.amount = amount;

        if (receiverPubKey.length != Constants.SC_PK_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect receiverPubKey element length, %d expected, %d found", Constants.SC_PK_HASH_SIZE(), receiverPubKey.length)
            );
        this.receiverPubKey = receiverPubKey;

        if (paybackAddrDataHash.length != Constants.MC_PK_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect paybackAddrDataHash element length, %d expected, %d found", Constants.MC_PK_HASH_SIZE(), paybackAddrDataHash.length)
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

    public void setAmount(long amount) {
        this.amount = amount;
    }

    public void setReceiverPubKey(byte[] receiverPubKey) {
        this.receiverPubKey = receiverPubKey;
    }

    public void setPaybackAddrDataHash(byte[] paybackAddrDataHash) {
        this.paybackAddrDataHash = paybackAddrDataHash;
    }

    public void setTxHash(byte[] txHash) {
        this.txHash = txHash;
    }

    public void setOutIdx(int outIdx) {
        this.outIdx = outIdx;
    }

    public static ForwardTransferOutput getRandom(Random r) {
        byte[] receiverPubKey = new byte[Constants.SC_PK_HASH_SIZE()];
        r.nextBytes(receiverPubKey);

        byte[] paybackAddrDataHash = new byte[Constants.MC_PK_HASH_SIZE()];
        r.nextBytes(paybackAddrDataHash);

        byte[] txHash = new byte[Constants.SC_TX_HASH_SIZE()];
        r.nextBytes(txHash);

        return new ForwardTransferOutput(r.nextLong(), receiverPubKey, paybackAddrDataHash, txHash, r.nextInt());
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
