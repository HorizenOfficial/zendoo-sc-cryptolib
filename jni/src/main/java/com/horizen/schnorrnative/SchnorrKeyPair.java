package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class SchnorrKeyPair implements AutoCloseable {
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

    private static native SchnorrKeyPair nativeGenerate();

    public static SchnorrKeyPair generate() {
        return nativeGenerate();
    }

    private native SchnorrSignature nativeSignMessage(FieldElement message);

    public SchnorrSignature signMessage(FieldElement message) {
        return nativeSignMessage(message);
    }

    public SchnorrSecretKey getSecretKey() {
        return this.secretKey;
    }

    public SchnorrPublicKey getPublicKey() {
        return  this.publicKey;
    }

    @Override
    public void close() throws Exception {
        this.publicKey.close();
        this.secretKey.close();
    }
}
