package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class VRFProof
{

  public static final int VRF_PROOF_SIZE = 385;
  public static final int VRF_HASH_SIZE = 96;

  private byte[] proof;

  static {
    Library.load();
  }

  public VRFProof(byte[] proofBytes) {
    if (proofBytes.length != VRF_PROOF_SIZE)
      throw new IllegalArgumentException(String.format("Incorrect proof length, %d expected, %d found", VRF_PROOF_SIZE, proofBytes.length));
    this.proof = proofBytes;
  }

  public byte[] getProof() {
    return Arrays.copyOf(proof, VRF_PROOF_SIZE);
  }

}

