package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;

public class SchnorrKeyPair {
    private SchnorrSecretKey secretKey;
    private SchnorrPublicKey publicKey;

    static {
        Library.load();
    }

    public SchnorrKeyPair(SchnorrSecretKey secretKey, SchnorrPublicKey publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public SchnorrKeyPair(SchnorrSecretKey secretKey) {
        this.secretKey = secretKey;
        this.publicKey = secretKey.getPublicKey();
    }

    public SchnorrKeyPair(SchnorrPublicKey schnorrPublicKey) {
        this.publicKey = schnorrPublicKey;
        this.secretKey = null;
    }

    private static native SchnorrKeyPair nativeGenerate();

    public static SchnorrKeyPair generate() {
        return nativeGenerate();
    }

    private native SchnorrSignature nativeSignMessage(byte[] message);

    public SchnorrSignature signMessage(byte[] message) {
        return nativeSignMessage(message);
    }

    public SchnorrSecretKey getSecretKey() {
        return this.secretKey;
    }

    public SchnorrPublicKey getPublicKey() {
        return  this.publicKey;
    }
}
