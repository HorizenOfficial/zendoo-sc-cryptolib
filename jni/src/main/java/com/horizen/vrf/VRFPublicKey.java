package com.horizen.vrf;

public class VRFPublicKey
{

  public static final int PUBLIC_KEY_LENGTH = 96;

  private byte[] publicKey;

  public VRFPublicKey(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PUBLIC_KEY_LENGTH, publicKeyBytes.length));
    this.publicKey = publicKeyBytes;
  }

  // maybe also a method for verifying VRFPublicKey
  //def isValid: Boolean = ??? // jni call to Rust impl

}

