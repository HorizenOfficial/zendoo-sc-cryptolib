package com.horizen.poseidonnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class PoseidonHash {

    public static final int HASH_LENGTH = 96;

    static {
        Library.load();
    }

    private static native FieldElement nativeComputeHash(FieldElement[] fieldElement); // jni call to Rust impl

    public static FieldElement computeHash(FieldElement[] fieldElement) {return nativeComputeHash(fieldElement);}
}
