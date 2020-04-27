package com.horizen.librustsidechains;

import java.lang.reflect.Field;
import java.util.Arrays;

public class FieldElement {

    public static final int FIELD_ELEMENT_SIZE = 96;

    private long fieldElementPointer;

    static {
        Library.load();
    }

    private FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }

    private static native int nativeGetFieldElementSize();

    public static int getFieldElementSize() {return  nativeGetFieldElementSize();}

    private native byte[] nativeSerializeFieldElement();

    public byte[] serializeFieldElement() {return nativeSerializeFieldElement();}

    private static native FieldElement nativeDeserializeFieldElement(byte[] fieldElementBytes);

    public static FieldElement deserializeFieldElement(byte[] fieldElementBytes) {
        if (fieldElementBytes == null)
            throw new IllegalArgumentException("Field element bytes must be not null.");

        if (fieldElementBytes.length > FIELD_ELEMENT_SIZE)
            throw new IllegalArgumentException("Field element bytes size must not exceed " + FIELD_ELEMENT_SIZE + " bytes.");

        return nativeDeserializeFieldElement(Arrays.copyOf(fieldElementBytes, FIELD_ELEMENT_SIZE));
    }

    private native void nativeFreeFieldElement();

    public void freeFieldElement() {nativeFreeFieldElement();}

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
