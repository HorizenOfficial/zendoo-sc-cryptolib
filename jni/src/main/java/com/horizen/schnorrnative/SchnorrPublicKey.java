package com.horizen.schnorrnative;

import com.horizen.librustsidechains.*;

import java.util.Arrays;

public class SchnorrPublicKey
{

  private long publicKeyPointer;

  static {
    Library.load();
  }

  SchnorrPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  public static SchnorrPublicKey deserialize(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PublicKeyUtils.PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PublicKeyUtils.PUBLIC_KEY_LENGTH, publicKeyBytes.length));

    return new SchnorrPublicKey(PublicKeyUtils.nativeDeserializePublicKey(publicKeyBytes));
  }

  public byte[] serializePublicKey() {
    return PublicKeyUtils.nativeSerializePublicKey(publicKeyPointer);
  }

  public void freePublicKey() {
    if (publicKeyPointer != 0) {
      PublicKeyUtils.nativeFreePublicKey(publicKeyPointer);
      publicKeyPointer = 0;
    }
  }

  long getPublicKeyPointer() {
    return this.publicKeyPointer;
  }

  private static native boolean nativeVerifySignature(SchnorrPublicKey publicKey, SchnorrSignature signature, byte[] message); // jni call to Rust impl

  private static native boolean nativeVerifyKey(SchnorrPublicKey key); // jni call to Rust impl

  //Don't yet completed.
  public boolean verifySignature(SchnorrSignature signature, byte[] message) {
    return nativeVerifySignature(this, signature, message);
  }

  public boolean verifyKey() {
    return nativeVerifyKey(this);
  }
}

