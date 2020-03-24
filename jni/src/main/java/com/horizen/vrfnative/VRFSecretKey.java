package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class VRFSecretKey
{

    public static final int SECRET_KEY_LENGTH = 96;

    private byte[] secretKey;
    private VRFPublicKey publicKey;

    static {
        Library.load();
    }

    public VRFSecretKey(VRFPublicKey publicKey, byte[] secretKeyBytes) {
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

    public VRFPublicKey getPublicKey() {
        return publicKey;
    }

    private static native byte[] nativeProve (byte[] publicKey, byte[] secretKey, byte[] message); // jni call to Rust impl

    private static native byte[] nativeVRFHash(byte[] message, byte[] publicKey, byte[] proof); // if need // jni call to Rust impl

    public VRFProof prove(byte[] message) {
        byte[] proof = nativeProve(this.publicKey.getPublicKey(), secretKey, message);
        return new VRFProof(proof);
    }

    public byte[] vrfHash(byte[] message, VRFProof proof) {
        return nativeVRFHash(message, publicKey.getPublicKey(), proof.getProof());
    }
}
