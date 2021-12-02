package com.horizen.scutxonative;

import java.util.Random;

import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.poseidonnative.PoseidonHashable;

public class ScUtxoOutput implements PoseidonHashable {
    private byte[] spendingPubKey;
    private long amount;
    private long nonce;
    private byte[] customHash;

    public ScUtxoOutput(byte[] spendingPubKey, long amount, long nonce, byte[] customHash) {
        if (spendingPubKey.length != Constants.SC_PK_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect spendingPubKey element length, %d expected, %d found",Constants.SC_PK_HASH_SIZE(), spendingPubKey.length)
            );
        this.spendingPubKey = spendingPubKey;

        this.amount = amount;
        this.nonce = nonce;

        if (customHash.length != Constants.SC_CUSTOM_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect customHash element length, %d expected, %d found",Constants.SC_CUSTOM_HASH_SIZE(), customHash.length)
            );
        this.customHash = customHash;
    }

    public byte[] getSpendingPubKey() {
        return spendingPubKey;
    }

    public long getAmount() {
        return amount;
    }

    public long getNonce() {
        return nonce;
    }

    public byte[] getCustomHash() {
        return customHash;
    }

    public void setSpendingPubKey(byte[] spendingPubKey) {
        this.spendingPubKey = spendingPubKey;
    }

    public void setAmount(long amount) {
        this.amount = amount;
    }

    public void setNonce(long nonce) {
        this.nonce = nonce;
    }

    public void setCustomHash(byte[] customHash) {
        this.customHash = customHash;
    }

    public static ScUtxoOutput getRandom(Random r) {

        byte[] spendingPubKey = new byte[Constants.SC_PK_HASH_SIZE()];
        r.nextBytes(spendingPubKey);

        byte[] customHash = new byte[Constants.SC_CUSTOM_HASH_SIZE()];
        r.nextBytes(customHash);

        return new ScUtxoOutput(spendingPubKey, r.nextLong(), r.nextLong(), customHash);
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
