package com.horizen.provingsystemnative;

import com.horizen.librustsidechains.Library;

public class CreateProofResult {
    private byte[] proof;
    private long quality;

    static {
        Library.load();
    }

    public CreateProofResult(byte[] proof, long quality) {
        this.proof = proof;
        this.quality = quality;
    }

    public byte[] getProof() {
        return this.proof;
    }

    public long getQuality() {
        return this.quality;
    }
}