package com.horizen.librustsidechains;

public class FieldElement {

    public static int FIELD_ELEMENT_LENGTH = 96;

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

    private static native FieldElement nativeCreateRandom();

    public static FieldElement createRandom() { return nativeCreateRandom(); }

    private native byte[] nativeSerializeFieldElement();

    public byte[] serializeFieldElement() {
        if (fieldElementPointer == 0)
            throw new IllegalArgumentException("Field element was freed.");

        return nativeSerializeFieldElement();
    }

    private static native long nativeDeserializeFieldElement(byte[] fieldElementBytes);

    public static FieldElement deserialize(byte[] fieldElementBytes) {
        if (fieldElementBytes.length != FIELD_ELEMENT_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect field element length, %d expected, %d found",
                    FIELD_ELEMENT_LENGTH, fieldElementBytes.length));

        return new FieldElement(nativeDeserializeFieldElement(fieldElementBytes));
    }

    private static native void nativeFreeFieldElement(long fieldElementPointer);

    public void freeFieldElement() {
        if (fieldElementPointer != 0) {
            nativeFreeFieldElement(this.fieldElementPointer);
            fieldElementPointer = 0;
        }
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
