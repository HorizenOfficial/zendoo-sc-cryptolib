package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;


public class VRFKeyPair {
    private VRFSecretKey secretKey;
    private VRFPublicKey publicKey;

    static {
        Library.load();
    }

    VRFKeyPair(long secretKeyPointer, long publicKeyPointer) {
        this.secretKey = new VRFSecretKey(secretKeyPointer);
        this.publicKey = new VRFPublicKey(publicKeyPointer);
    }

    public VRFKeyPair(VRFSecretKey secretKey, VRFPublicKey publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public VRFKeyPair(VRFSecretKey secretKey) {
        this.secretKey = secretKey;
        this.publicKey = secretKey.getPublicKey();
    }

    private static native VRFKeyPair nativeGenerate();

    public static VRFKeyPair generate() {
        return nativeGenerate();
    }

    private static native VRFProof nativeProve(VRFSecretKey secretKey, VRFPublicKey publicKey, byte[] message);

    public VRFProof prove(byte[] message) {
        return nativeProve(this.secretKey, this.publicKey, message);
    }

    public VRFSecretKey getSecretKey() {
        return this.secretKey;
    }

    public VRFPublicKey getPublicKey() {
        return this.publicKey;
    }
}