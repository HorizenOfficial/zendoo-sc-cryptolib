package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;

public class SchnorrSignature implements AutoCloseable
{

  public static int SIGNATURE_LENGTH = 192;

  private long signaturePointer;

  static {
    Library.load();
  }

  private SchnorrSignature(long signaturePointer) {
    if (signaturePointer == 0)
      throw new IllegalArgumentException("Signature pointer must be not null.");
    this.signaturePointer = signaturePointer;
  }

  public SchnorrSignature() {
    this.signaturePointer = 0;
  }

  private static native byte[] nativeSerializeSignature(long signaturePointer);

  private static native SchnorrSignature nativeDeserializeSignature(byte[] signatureBytes);

  private static native void nativefreeSignature(long signaturePointer);

  public static SchnorrSignature deserialize(byte[] signatureBytes) {
    if (signatureBytes.length != SIGNATURE_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect signature length, %d expected, %d found", SIGNATURE_LENGTH, signatureBytes.length));

    return nativeDeserializeSignature(signatureBytes);
  }

  public byte[] serializeSignature() {
    return nativeSerializeSignature(this.signaturePointer);
  }

  public void freeSignature() {
    if (signaturePointer != 0) {
      nativefreeSignature(this.signaturePointer);
      signaturePointer = 0;
    }
  }

  @Override
  public void close() throws Exception {
    freeSignature();
  }
}

