package com.horizen.vrf;

import java.util.Arrays;

public class VRFSecretKey
    extends VRFPublicKey
{

    public static final int SECRET_KEY_LENGTH = 96;

    private byte[] secretKey;

    public VRFSecretKey(byte[] publicKeyBytes, byte[] secretKeyBytes) {
        super(publicKeyBytes);
        if (secretKeyBytes.length != SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SECRET_KEY_LENGTH, secretKeyBytes.length));
        this.secretKey = secretKeyBytes;
    }

    static native boolean nativeVerify (String keyPath, byte[] message, byte[] proof); // jni call to Rust impl

    static native byte[] nativeProve (byte[] key, byte[] message); // jni call to Rust impl

    static native byte[] nativeVRFHash(byte[] key, byte[] message); // if need // jni call to Rust impl

}
