package com.horizen.sigproofnative;

public class BackwardTransfer {

    private byte[] publicKeyHash;
    private long amount;

    public BackwardTransfer(byte[] publicKeyHash, long amount) {
        this.publicKeyHash = publicKeyHash;
        this.amount = amount;
    }

    byte[] getPublicKeyHash() {return this.publicKeyHash;}

    long getAmount() {return this.amount;}
}
