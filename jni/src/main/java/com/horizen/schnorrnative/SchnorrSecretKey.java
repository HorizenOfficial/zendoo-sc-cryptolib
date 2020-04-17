package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class SchnorrSecretKey
{
    public static final int SECRET_KEY_LENGTH = 96;

    private long secretKeyPointer;

    static {
        Library.load();
    }

    private SchnorrSecretKey(long secretKeyPointer) {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key pointer must be not null.");
        this.secretKeyPointer = secretKeyPointer;
    }

    public static native int nativeGetSecretKeySize();

    public static native SchnorrSecretKey nativeDeserializeSecretKey(byte[] secretKeyBytes);

    public static SchnorrSecretKey deserializeSecretKey(byte[] secretKeyBytes) {
        if (secretKeyBytes.length != SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SECRET_KEY_LENGTH, secretKeyBytes.length));

        return nativeDeserializeSecretKey(secretKeyBytes);
    }

    public native byte[] nativeSerializeSecretKey();

    public byte[] serializeSecretKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return nativeSerializeSecretKey();
    }

    public native void nativeFreeSecretKey();

    public void freeSecretKey() {
        if (secretKeyPointer != 0) {
            nativeFreeSecretKey();
            secretKeyPointer = 0;
        }
    }

    private native SchnorrPublicKey nativeGetPublicKey();

    public SchnorrPublicKey getPublicKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return nativeGetPublicKey();
    }
}
