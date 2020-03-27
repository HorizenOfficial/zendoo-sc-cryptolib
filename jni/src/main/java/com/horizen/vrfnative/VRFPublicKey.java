package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class VRFPublicKey
{

  public static final int PUBLIC_KEY_LENGTH = 193;

  static {
    Library.load();
  }

  public static native boolean nativeVerify(byte[] key, byte[] message, byte[] proof); // jni call to Rust impl

  public static native boolean nativeVerifyKey(byte[] key); // jni call to Rust impl
}

