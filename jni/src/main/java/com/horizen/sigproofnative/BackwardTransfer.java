package com.horizen.sigproofnative;

import com.horizen.librustsidechains.Library;

public class BackwardTransfer {

    public static final int MC_PK_HASH_SIZE;

    private byte[] publicKeyHash;
    private long amount;

    private static native int nativeGetMcPkHashSize();

    static {
        Library.load();
        MC_PK_HASH_SIZE = nativeGetMcPkHashSize();
    }

    public BackwardTransfer(byte[] publicKeyHash, long amount) {
        this.publicKeyHash = publicKeyHash;
        this.amount = amount;
    }

    byte[] getPublicKeyHash() {return this.publicKeyHash;}

    long getAmount() {return this.amount;}
}
