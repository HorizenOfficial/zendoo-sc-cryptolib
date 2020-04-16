package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.PublicKeyUtils;

public class VRFPublicKey
{

  private long publicKeyPointer;

  static {
    Library.load();
  }

  VRFPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  public static VRFPublicKey deserialize(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PublicKeyUtils.PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PublicKeyUtils.PUBLIC_KEY_LENGTH, publicKeyBytes.length));

    return new VRFPublicKey(PublicKeyUtils.nativeDeserializePublicKey(publicKeyBytes));
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

  private static native boolean nativeVerifyKey(VRFPublicKey key); // jni call to Rust impl

  public boolean verifyKey() {
    return nativeVerifyKey(this);
  }

  private static native byte[] nativeProofToHash(VRFPublicKey publicKey, VRFProof proof, byte[] message);

  public byte[] proofToHash(VRFProof proof, byte[] message) {
    return nativeProofToHash(this, proof, message);
  }
}

