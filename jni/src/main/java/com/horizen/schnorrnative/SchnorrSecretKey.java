package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;
import com.horizen.vrfnative.VRFPublicKey;

import java.util.Arrays;

public class SchnorrSecretKey
{

    public static final int SECRET_KEY_LENGTH = 96;

    private byte[] secretKey;
    private SchnorrPublicKey publicKey;

    static {
        Library.load();
    }

    public SchnorrSecretKey(SchnorrPublicKey publicKey, byte[] secretKeyBytes) {
        if (publicKey == null)
            throw new IllegalArgumentException("Public key must be not null.");
        if (secretKeyBytes.length != SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SECRET_KEY_LENGTH, secretKeyBytes.length));

        this.publicKey = publicKey;
        this.secretKey = secretKeyBytes;
    }

    public byte[] getSecretKey() {
        return Arrays.copyOf(secretKey, SECRET_KEY_LENGTH);
    }

    public SchnorrPublicKey getPublicKey() {
        return publicKey;
    }

    private static native byte[] nativeSignMessage (byte[] publicKey, byte[] secretKey, byte[] message); // jni call to Rust impl

    public byte[] signMessage(byte[] message) {
        return nativeSignMessage(this.publicKey.getPublicKey(), secretKey, message);
    }
}
