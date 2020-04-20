package com.horizen.librustsidechains;

public class FieldElement {

    private long fieldElementPointer;

    static {
        Library.load();
    }

    private FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }

    private static native FieldElement nativeCreateFromLong(Long value);

    public static FieldElement createFromLong(Long value) {
        return nativeCreateFromLong(value);
    }
}
