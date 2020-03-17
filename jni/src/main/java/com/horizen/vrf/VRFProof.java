package com.horizen.vrf;

public class VRFProof
{
    native byte[] nativeProofToVRFHash (byte[] proof); // jni call to Rust impl
}