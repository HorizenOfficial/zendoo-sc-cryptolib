package com.horizen.vrfnative;

import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class VRFPublicKey implements AutoCloseable
{
  private long publicKeyPointer;

  private static native int nativeGetPublicKeySize();

  static {
    Library.load();
  }

  private VRFPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  private static native VRFPublicKey nativeDeserializePublicKey(byte[] publicKeyBytes, boolean checkPublicKey, boolean compressed);

  public static VRFPublicKey deserialize(byte[] publicKeyBytes, boolean checkPublicKey, boolean compressed) {
    if (publicKeyBytes.length != Constants.VRF_PK_LENGTH())
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", Constants.VRF_PK_LENGTH(), publicKeyBytes.length));

    return nativeDeserializePublicKey(publicKeyBytes, checkPublicKey, compressed);
  }

  public static VRFPublicKey deserialize(byte[] publicKeyBytes, boolean checkPublicKey) {
    return deserialize(publicKeyBytes, checkPublicKey, true);
  }

  public static VRFPublicKey deserialize(byte[] publicKeyBytes) {
    return deserialize(publicKeyBytes, true, true);
  }

  private native byte[] nativeSerializePublicKey(boolean compressed);


  public byte[] serializePublicKey(boolean compressed) {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeSerializePublicKey(compressed);
  }

  public byte[] serializePublicKey() {
    return serializePublicKey(true);
  }

  private native void nativeFreePublicKey();

  public void freePublicKey() {
    if (publicKeyPointer != 0) {
      nativeFreePublicKey();
      publicKeyPointer = 0;
    }
  }

  private native boolean nativeVerifyKey(); // jni call to Rust impl

  public boolean verifyKey() {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeVerifyKey();
  }

  private native FieldElement nativeProofToHash(VRFProof proof, FieldElement message);

  public FieldElement proofToHash(VRFProof proof, FieldElement message) {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeProofToHash(proof, message);
  }

  @Override
  public void close() {
    freePublicKey();
  }
}

