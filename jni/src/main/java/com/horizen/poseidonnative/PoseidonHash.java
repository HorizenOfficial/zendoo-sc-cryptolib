package com.horizen.poseidonnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class PoseidonHash {

    public static final int HASH_LENGTH = 96;

    static {
        Library.load();
    }

    public static native byte[] nativeComputeHash(byte[] input); // jni call to Rust impl

    public static native byte[] nativeComputeKeysHashCommitment(byte[] pks); // jni call to Rust impl
}
