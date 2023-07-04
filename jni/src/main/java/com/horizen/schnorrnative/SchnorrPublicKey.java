package com.horizen.schnorrnative;

import com.horizen.librustsidechains.*;

public class SchnorrPublicKey implements AutoCloseable
{
  private long publicKeyPointer;

  static {
    Library.load();
  }

  private SchnorrPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  private static native SchnorrPublicKey nativeDeserializePublicKey(byte[] publicKeyBytes, boolean checkPublicKey, boolean compressed);

  public static SchnorrPublicKey deserialize(byte[] publicKeyBytes, boolean checkPublicKey, boolean compressed) {
    if (publicKeyBytes.length != Constants.SCHNORR_PK_LENGTH())
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", Constants.SCHNORR_PK_LENGTH(), publicKeyBytes.length));

    return nativeDeserializePublicKey(publicKeyBytes, checkPublicKey, compressed);
  }

  public static SchnorrPublicKey deserialize(byte[] publicKeyBytes, boolean checkPublicKey) {
    return deserialize(publicKeyBytes, checkPublicKey, true);
  }

  public static SchnorrPublicKey deserialize(byte[] publicKeyBytes) {
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

  private native boolean nativeVerifySignature(SchnorrSignature signature, FieldElement message); // jni call to Rust impl

  private native FieldElement nativeGetHash();

  public FieldElement getHash() {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");
    return nativeGetHash();
  }

  private native boolean nativeVerifyKey(); // jni call to Rust impl

  public boolean verifySignature(SchnorrSignature signature, FieldElement message) {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeVerifySignature(signature, message);
  }

  public boolean verifyKey() {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeVerifyKey();
  }

  @Override
  public void close() {
    freePublicKey();
  }
}

