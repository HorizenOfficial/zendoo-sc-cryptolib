package com.horizen.schnorrnative;

import com.horizen.librustsidechains.*;

import java.util.Arrays;

public class SchnorrSecretKey
{

    private long secretKeyPointer;

    static {
        Library.load();
    }

    private SchnorrSecretKey(long secretKeyPointer) {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key pointer must be not null.");
        this.secretKeyPointer = secretKeyPointer;
    }

    public static SchnorrSecretKey deserialize(byte[] secretKeyBytes) {
        if (secretKeyBytes.length != SecretKeyUtils.SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SecretKeyUtils.SECRET_KEY_LENGTH, secretKeyBytes.length));

        return new SchnorrSecretKey(SecretKeyUtils.nativeDeserializeSecretKey(secretKeyBytes));
    }

    public byte[] serializeSecretKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return SecretKeyUtils.nativeSerializeSecretKey(secretKeyPointer);
    }

    public void freeSecretKey() {
        if (secretKeyPointer != 0) {
            SecretKeyUtils.nativeFreeSecretKey(secretKeyPointer);
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
