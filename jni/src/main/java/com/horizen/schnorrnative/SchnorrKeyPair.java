package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;

public class SchnorrKeyPair {
    private SchnorrSecretKey secretKey;
    private SchnorrPublicKey publicKey;

    static {
        Library.load();
    }

    SchnorrKeyPair(long secretKeyPointer, long publicKeyPointer) {
        this.secretKey = new SchnorrSecretKey(secretKeyPointer);
        this.publicKey = new SchnorrPublicKey(publicKeyPointer);
    }

    public SchnorrKeyPair(SchnorrSecretKey secretKey, SchnorrPublicKey publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public SchnorrKeyPair(SchnorrSecretKey secretKey) {
        this.secretKey = secretKey;
        this.publicKey = secretKey.getPublicKey();
    }

    private static native SchnorrKeyPair nativeGenerate();

    public static SchnorrKeyPair generate() {
        return nativeGenerate();
    }

    private static native SchnorrSignature nativeSignMessage(SchnorrSecretKey secretKey, SchnorrPublicKey publicKey, byte[] message);

    public SchnorrSignature signMessage(byte[] message) {
        return nativeSignMessage(this.secretKey, this.publicKey, message);
    }

    public SchnorrSecretKey getSecretKey() {
        return this.secretKey;
    }

    public SchnorrPublicKey getPublicKey() {
        return  this.publicKey;
    }
}
