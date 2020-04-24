package com.horizen.librustsidechains;

public class FieldElement {

    private long fieldElementPointer;

    static {
        Library.load();
    }

    private FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }

    private static native FieldElement nativeCreateFromLong(long value);

    public static FieldElement createFromLong(long value) {
        return nativeCreateFromLong(value);
    }

    private native boolean nativeEquals(FieldElement fe);

    @Override
    public boolean equals(Object o) {

        if (o == this) {
            return true;
        }

        if (!(o instanceof FieldElement)) {
            return false;
        }

        return nativeEquals((FieldElement) o);
    }
}
