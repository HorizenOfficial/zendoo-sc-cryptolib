package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;


public class VRFKeyPair implements AutoCloseable {
    private VRFSecretKey secretKey;
    private VRFPublicKey publicKey;

    static {
        Library.load();
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

    private static native VRFKeyPair nativeDeriveFromSeed(byte[] seed);

    /**
     * Generate a fresh VRF key-pair from a seed.
     * @param seed - The seed used to generate the key-pair. WARNING: It's caller responsibility
     *               to pass a seed of appropriate length. No checks are performed Rust-side.
     * @return the new VRF key-pair
    */
    public static VRFKeyPair generate(byte[] seed) {
        return nativeDeriveFromSeed(seed);
    }

    private native VRFProveResult nativeProve(FieldElement message);

    public VRFProveResult prove(FieldElement message) {
        return nativeProve(message);
    }

    public VRFSecretKey getSecretKey() {
        return this.secretKey;
    }

    public VRFPublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public void close() throws Exception {
        this.publicKey.close();
        this.secretKey.close();
    }
}