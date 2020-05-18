package com.horizen.sigproofnative;

public class CreateProofResult {
    private byte[] proof;
    private long quality;

    public CreateProofResult(long quality, byte[] proof) {
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