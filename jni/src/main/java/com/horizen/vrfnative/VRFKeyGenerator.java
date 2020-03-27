package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFKeyGenerator {

    static {
        Library.load();
    }

    public static native boolean nativeGenerate (byte[] skResult, byte[] pkResult); // jni call to Rust impl
}
