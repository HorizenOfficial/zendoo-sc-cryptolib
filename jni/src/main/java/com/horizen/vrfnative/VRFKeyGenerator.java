package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFKeyGenerator {

    static {
        Library.load();
    }

    private static native boolean nativeGenerate (byte[] skResult, byte[] pkResult); // jni call to Rust impl

    public static VRFSecretKey generate() {
        byte[] secretKeyBytes = new byte[VRFSecretKey.SECRET_KEY_LENGTH];
        byte[] publicKeyBytes = new byte[VRFPublicKey.PUBLIC_KEY_LENGTH];
        if (nativeGenerate(secretKeyBytes, publicKeyBytes))
            return new VRFSecretKey(new VRFPublicKey(publicKeyBytes), secretKeyBytes);
        else
            throw new RuntimeException("Error during keys generation.");
    }
}
