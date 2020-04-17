package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class VRFPublicKey
{

  public static final int PUBLIC_KEY_LENGTH = 193;

  private long publicKeyPointer;

  static {
    Library.load();
  }

  private VRFPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  public static native int nativeGetPublicKeySize();

  public static native VRFPublicKey nativeDeserializePublicKey(byte[] publicKeyBytes);

  public static VRFPublicKey deserialize(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PUBLIC_KEY_LENGTH, publicKeyBytes.length));

    return nativeDeserializePublicKey(publicKeyBytes);
  }

  public native byte[] nativeSerializePublicKey();

  public byte[] serializePublicKey() {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key was freed.");

    return nativeSerializePublicKey();
  }

  public native void nativeFreePublicKey();

  public void freePublicKey() {
    if (publicKeyPointer != 0) {
      nativeFreePublicKey();
      publicKeyPointer = 0;
    }
  }

  private native boolean nativeVerifyKey(); // jni call to Rust impl

  public boolean verifyKey() {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key was freed.");

    return nativeVerifyKey();
  }

  private native byte[] nativeProofToHash(VRFProof proof, FieldElement message);

  public byte[] proofToHash(VRFProof proof, FieldElement message) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key was freed.");

    return nativeProofToHash(proof, message);
  }
}

