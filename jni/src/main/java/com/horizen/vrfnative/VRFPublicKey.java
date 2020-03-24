package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class VRFPublicKey
{

  public static final int PUBLIC_KEY_LENGTH = 193;

  private byte[] publicKey;

  static {
    Library.load();
  }

  public VRFPublicKey(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PUBLIC_KEY_LENGTH, publicKeyBytes.length));
    this.publicKey = publicKeyBytes;
  }

  private static native boolean nativeVerify(byte[] key, byte[] message, byte[] proof); // jni call to Rust impl

  private static native boolean nativeVerifyKey(byte[] key); // jni call to Rust impl

  public boolean verify(byte[] message, VRFProof proof) {
    return nativeVerify(this.publicKey, message, proof.getProof());
  }

  public boolean verifyKey() {
    return nativeVerifyKey(this.publicKey);
  }

  public byte[] getPublicKey() {
    return Arrays.copyOf(publicKey, PUBLIC_KEY_LENGTH);
  }

}

