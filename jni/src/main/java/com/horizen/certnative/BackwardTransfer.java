package com.horizen.certnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.Constants;

public class BackwardTransfer {

    private final byte[] publicKeyHash;
    private final long amount;

    static {
        Library.load();
    }

    public BackwardTransfer(byte[] publicKeyHash, long amount) {
        if (publicKeyHash.length != Constants.get().MC_PK_HASH_SIZE)
            throw new IllegalArgumentException(String.format("Incorrect publicKeyHash element length, %d expected, %d found",
            Constants.get().MC_PK_HASH_SIZE, publicKeyHash.length));
        this.publicKeyHash = publicKeyHash;
        this.amount = amount;
    }

    public byte[] getPublicKeyHash() {
        return this.publicKeyHash;
    }

    public long getAmount() {
        return this.amount;
    }
}
