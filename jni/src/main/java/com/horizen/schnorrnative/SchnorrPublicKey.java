package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class SchnorrPublicKey
{

  public static final int PUBLIC_KEY_LENGTH = 193;

  private byte[] publicKey;

  static {
    Library.load();
  }

  public SchnorrPublicKey(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PUBLIC_KEY_LENGTH, publicKeyBytes.length));
    this.publicKey = publicKeyBytes;
  }

  private static native boolean nativeVerifySignature(byte[] key, byte[] message, byte[] proof); // jni call to Rust impl

  private static native boolean nativeVerifyKey(byte[] key); // jni call to Rust impl

  public boolean verifySignature(byte[] message, byte[] signature) {
    return nativeVerifySignature(this.publicKey, message, signature);
  }

  public boolean verifyKey() {
    return nativeVerifyKey(this.publicKey);
  }

  public byte[] getPublicKey() {
    return Arrays.copyOf(publicKey, PUBLIC_KEY_LENGTH);
  }

}

