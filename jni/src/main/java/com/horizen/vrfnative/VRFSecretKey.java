package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.SecretKeyUtils;

import java.util.Arrays;

public class VRFSecretKey
{

    private long secretKeyPointer;

    static {
        Library.load();
    }

    private VRFSecretKey(long secretKeyPointer) {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key pointer must be not null.");
        this.secretKeyPointer = secretKeyPointer;
    }

    public static VRFSecretKey deserialize(byte[] secretKeyBytes) {
        if (secretKeyBytes.length != SecretKeyUtils.SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SecretKeyUtils.SECRET_KEY_LENGTH, secretKeyBytes.length));

        return new VRFSecretKey(SecretKeyUtils.nativeDeserializeSecretKey(secretKeyBytes));
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

    private native VRFPublicKey nativeGetPublicKey();

    public VRFPublicKey getPublicKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return nativeGetPublicKey();
    }
}
