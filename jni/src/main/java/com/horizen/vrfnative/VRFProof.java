package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFProof implements AutoCloseable
{
  public static final int PROOF_LENGTH;

  private long proofPointer;

  private static native int nativeGetProofSize();

  static {
    Library.load();
    PROOF_LENGTH = nativeGetProofSize();
  }

  private VRFProof(long proofPointer) {
    if (proofPointer == 0)
      throw new IllegalArgumentException("Proof pointer must be not null.");
    this.proofPointer = proofPointer;
  }

  private native byte[] nativeSerializeProof(boolean compressed);

  private static native VRFProof nativeDeserializeProof(byte[] proofBytes, boolean checkVRFProof, boolean compressed);

  private static native void nativeFreeProof(long proofPointer);

  public static VRFProof deserialize(byte[] proofBytes, boolean checkVRFProof, boolean compressed) {
    if (proofBytes.length != PROOF_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect proof length, %d expected, %d found", PROOF_LENGTH, proofBytes.length));

    return nativeDeserializeProof(proofBytes, checkVRFProof, compressed);
  }

  public static VRFProof deserialize(byte[] proofBytes, boolean checkVRFProof) {
    return deserialize(proofBytes, checkVRFProof, true);
  }

  public static VRFProof deserialize(byte[] proofBytes) {
    return deserialize(proofBytes, true, true);
  }

  public byte[] serializeProof(boolean compressed) {
    if (proofPointer == 0)
      throw new IllegalStateException("Proof was freed.");

    return nativeSerializeProof(compressed);
  }

  public byte[] serializeProof() {
    return serializeProof(true);
  }

  private native boolean nativeIsValidVRFProof(); // jni call to Rust impl

  public boolean isValidVRFProof() {
    if (proofPointer == 0)
      throw new IllegalArgumentException("VRF Proof was freed.");

    return nativeIsValidVRFProof();
  }

  public void freeProof() {
    if (proofPointer != 0) {
      nativeFreeProof(this.proofPointer);
      proofPointer = 0;
    }
  }

  @Override
  public void close() throws Exception {
    freeProof();
  }
}

