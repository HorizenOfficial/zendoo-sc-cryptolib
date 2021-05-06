package com.horizen.sigproofnative;

public class BackwardTransfer {

    private final byte[] publicKeyHash;
    private final long amount;

    public BackwardTransfer(byte[] publicKeyHash, long amount) {
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
