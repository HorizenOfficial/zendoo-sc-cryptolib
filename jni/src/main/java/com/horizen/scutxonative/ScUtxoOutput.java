package com.horizen.scutxonative;

import java.util.Random;

import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.poseidonnative.PoseidonHashable;

public class ScUtxoOutput implements PoseidonHashable {
    private final byte[] spendingPubKey;
    private final long amount;
    private final long nonce;
    private final byte[] customHash;

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
