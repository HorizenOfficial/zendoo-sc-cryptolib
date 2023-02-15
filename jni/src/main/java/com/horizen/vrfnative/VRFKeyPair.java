package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;


public class VRFKeyPair implements AutoCloseable {
    private VRFSecretKey secretKey;
    private VRFPublicKey publicKey;
    private static final int MIN_SEED_LENGTH = 32;
    private static final int MAX_SEED_LENGTH = 64;

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

    public static VRFKeyPair generate(byte[] seed) throws Exception {
        if (seed.length < MIN_SEED_LENGTH || seed.length > MAX_SEED_LENGTH) {
            throw new Exception("invalid seed length '" + seed.length + "'. Must be between " + MIN_SEED_LENGTH + " and " + MAX_SEED_LENGTH);
        }
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