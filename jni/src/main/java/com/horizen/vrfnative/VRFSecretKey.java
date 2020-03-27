package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class VRFSecretKey
{

    public static final int SECRET_KEY_LENGTH = 96;

    static {
        Library.load();
    }

    public static native byte[] nativeProve (byte[] publicKey, byte[] secretKey, byte[] message); // jni call to Rust impl

    public static native byte[] nativeVRFHash(byte[] message, byte[] publicKey, byte[] proof); // if need // jni call to Rust impl
}
