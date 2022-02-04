package com.horizen.certnative;

import com.horizen.librustsidechains.Library;

import java.util.Random;

import com.horizen.librustsidechains.Constants;

public class BackwardTransfer {

    private final byte[] publicKeyHash;
    private final long amount;

    static {
        Library.load();
    }

    public BackwardTransfer(byte[] publicKeyHash, long amount) {
        if (publicKeyHash.length != Constants.MC_PK_HASH_SIZE())
            throw new IllegalArgumentException(String.format("Incorrect publicKeyHash element length, %d expected, %d found",
            Constants.MC_PK_HASH_SIZE(), publicKeyHash.length));
        this.publicKeyHash = publicKeyHash;
        this.amount = amount;
    }

    public byte[] getPublicKeyHash() {
        return this.publicKeyHash;
    }

    public long getAmount() {
        return this.amount;
    }

    public static BackwardTransfer getRandom(Random r) {
        byte[] publicKeyHash = new byte[Constants.MC_PK_HASH_SIZE()];
        r.nextBytes(publicKeyHash);
        long amount = r.nextLong();

        return new BackwardTransfer(publicKeyHash, amount);
    }
}
