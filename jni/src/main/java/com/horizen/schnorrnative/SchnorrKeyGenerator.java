package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;
import com.horizen.vrfnative.VRFPublicKey;
import com.horizen.vrfnative.VRFSecretKey;

public class SchnorrKeyGenerator {

    static {
        Library.load();
    }

    private static native boolean nativeGenerate (byte[] skResult, byte[] pkResult); // jni call to Rust impl

    public static SchnorrSecretKey generate() {
        byte[] secretKeyBytes = new byte[SchnorrSecretKey.SECRET_KEY_LENGTH];
        byte[] publicKeyBytes = new byte[SchnorrPublicKey.PUBLIC_KEY_LENGTH];
        if (nativeGenerate(secretKeyBytes, publicKeyBytes))
            return new SchnorrSecretKey(new SchnorrPublicKey(publicKeyBytes), secretKeyBytes);
        else
            throw new RuntimeException("Error during keys generation.");
    }
}
