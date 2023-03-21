package com.horizen.librustsidechains;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class FieldElement implements AutoCloseable {

    private long fieldElementPointer;

    static {
        Library.load();
    }

    // Declared protected for testing purposes
    protected FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }

    private static native FieldElement nativeCreateFromLong(long value);

    /**
     * Convert an integer value to a field element
     * @param value - A positive integer value to be converted to a field element
     * @return The field element represented with the positive integer value provided as input
     */
    public static FieldElement createFromLong(long value) {
        return nativeCreateFromLong(value);
    }

    private static native FieldElement nativeCreateRandom(long seed);

    /*  NOTE: This function relies on a non-cryptographically safe RNG, therefore it
     *  must be used ONLY for testing purposes
     */
    public static FieldElement createRandom(long seed) { return nativeCreateRandom(seed); }

    public static FieldElement createRandom() {
        long seed = new Random().nextLong();
        return nativeCreateRandom(seed);
    }

    public static FieldElement createRandom(Random r) {
        long seed = r.nextLong();
        return nativeCreateRandom(seed);
    }

    // Declared protected for testing purposes
    protected native byte[] nativeSerializeFieldElement();


    public byte[] serializeFieldElement() {
        if (fieldElementPointer == 0)
            throw new IllegalStateException("Field element was freed.");

        return nativeSerializeFieldElement();
    }

    private static native FieldElement nativeDeserializeFieldElement(byte[] fieldElementBytes);

    /**
     * Deserialize a FieldElement from "fieldElementBytes"
     * @param fieldElementBytes bytes of the FieldElement to be deserialized
     * @return The deserialized FieldElement
     * @throws IllegalArgumentException If fieldElementBytes.len() &gt; FIELD_ELEMENT_LENGTH or if the bytes represent an invalid FieldElement
     */
    public static FieldElement deserialize(byte[] fieldElementBytes) throws IllegalArgumentException {
        if (fieldElementBytes.length > Constants.FIELD_ELEMENT_LENGTH())
            throw new IllegalArgumentException(String.format("Field element length exceeded: limit %d , %d found",
                Constants.FIELD_ELEMENT_LENGTH(), fieldElementBytes.length));

        return nativeDeserializeFieldElement(fieldElementBytes);
    }

    /**
     * Split this FieldElement into two FieldElements.
     * Split will happen at the specified index: one FieldElement will be read from
     * the original bytes [0..index) and the other ones from the original bytes [index..FIELD_ELEMENT_LENGTH)
     * @param index - a valid integer in the range (0, FIELD_ELEMENT_LENGTH)
     * @return a List made up of two FieldElements, read from the original one split at index
     * @throws IndexOutOfBoundsException in case of illegal index (i.e. index &lt;= 0 OR index &gt;= FIELD_ELEMENT_LENGTH)
     */
    public List<FieldElement> splitAt(int index) throws IndexOutOfBoundsException {
        
        // Check 0 < index < FIELD_ELEMENT_LENGTH
        if (index >= Constants.FIELD_ELEMENT_LENGTH() || index <= 0)
            throw new IndexOutOfBoundsException("Invalid split index");
        
        // Get FE bytes
        byte[] feBytes = serializeFieldElement();

        // Initialize bytes of the 2 new FieldElement
        byte[] newFeBytes1 = new byte[index];
        byte[] newFeBytes2 = new byte[Constants.FIELD_ELEMENT_LENGTH() - index];

        // Perform split
        System.arraycopy(feBytes, 0, newFeBytes1, 0, newFeBytes1.length);
        System.arraycopy(feBytes, index, newFeBytes2, 0, newFeBytes2.length);

        // Deserialize FieldElements
        return Arrays.asList(new FieldElement[]{ FieldElement.deserialize(newFeBytes1), FieldElement.deserialize(newFeBytes2) });
    }

    /**
     * The inverse of the splitAt() method: join fe1.bytes[0..index1) and fe2.bytes[0..index2) in a single byte array and deserialize
     * a FieldElement out of it.
     * @param fe1 - the first FieldElement to join
     * @param index1 - the number of bytes to consider from the first FieldElement
     * @param fe2 - the second FieldElement to join
     * @param index2 - the number of bytes to consider from the second FieldElement
     * @param checkZeroAfterIdx - if enabled, check that fe1.bytes[index1..] and fe2.bytes[index2..] are all 0s.
     * @return the FieldElement obtained from combining fe1.bytes[0..index1) with fe2.bytes[0..index2)
     * @throws IllegalArgumentException if the combine operation would produce a byte array bigger than FIELD_ELEMENT_LENGTH
     */
    public static FieldElement joinAt(FieldElement fe1, int index1, FieldElement fe2, int index2, boolean checkZeroAfterIdx) throws IllegalArgumentException {
        // Check that the resulting array dimension wouldn't be bigger than FIELD_ELEMENT_LENGTH
        if (index1 + index2 > Constants.FIELD_ELEMENT_LENGTH()) {
            throw new IllegalArgumentException("Invalid values for index1 + index2: the resulting array would overflow FIELD_ELEMENT_LENGTH");
        }

        // Initialize new byte array from which deserializing the new FieldElement
        byte[] newFeBytes = new byte[index1 + index2];

        // Get the bytes of fe1 and fe2
        byte[] fe1Bytes = fe1.serializeFieldElement();
        byte[] fe2Bytes = fe2.serializeFieldElement();

        if (checkZeroAfterIdx) {
            // Perform check on fe1 bytes
            for(int i = index1; i < fe1Bytes.length; i++) {
                if (fe1Bytes[i] != (byte)0)
                    throw new IllegalArgumentException("Zero check failed on bytes of fe1");
            }

            // Perform check on fe2 bytes
            for(int i = index2; i < fe2Bytes.length; i++) {
                if (fe2Bytes[i] != (byte)0)
                    throw new IllegalArgumentException("Zero check failed on bytes of fe2");
            }
        }

        // Perform the join
        System.arraycopy(fe1Bytes, 0, newFeBytes, 0, index1);
        System.arraycopy(fe2Bytes, 0, newFeBytes, index1, index2);

        // Deserialize and return the new FieldElement
        return FieldElement.deserialize(newFeBytes);
    }

    /**
     * The inverse of the splitAt() method: join fe1.bytes[0..index1) and fe2.bytes[0..index2) in a single byte array and deserialize
     * a FieldElement out of it.
     * @param fe1 - the first FieldElement to join
     * @param index1 - the number of bytes to consider from the first FieldElement
     * @param fe2 - the second FieldElement to join
     * @param index2 - the number of bytes to consider from the second FieldElement 
     * @return the FieldElement obtained from combining fe1.bytes[0..index1) with fe2.bytes[0..index2)
     * @throws IllegalArgumentException if the combine operation would produce a byte array bigger than FIELD_ELEMENT_LENGTH
     */
    public static FieldElement joinAt(FieldElement fe1, int index1, FieldElement fe2, int index2) throws IllegalArgumentException {
        return FieldElement.joinAt(fe1, index1, fe2, index2, false);
    }

    // Declared protected for testing purposes
    protected native void nativePrintFieldElementBytes();

    public void printFieldElementBytes() {
        if (fieldElementPointer == 0)
            throw new IllegalStateException("Field element was freed.");
        nativePrintFieldElementBytes();
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

    @Override
    public void close() {
        freeFieldElement();
    }
}
