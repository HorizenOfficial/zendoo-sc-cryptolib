package com.horizen.librustsidechains;

import org.junit.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

public class FieldElementTest {

    @Test
    public void testSerialization() {

        assertEquals("Field element size must be " + FieldElement.FIELD_ELEMENT_SIZE,
                FieldElement.FIELD_ELEMENT_SIZE,
                FieldElement.getFieldElementSize());

        Random r = new Random();

        byte[] bytes1 = new byte[FieldElement.FIELD_ELEMENT_SIZE - 32];
        r.nextBytes(bytes1);

        byte[] bytes2 = new byte[FieldElement.FIELD_ELEMENT_SIZE];
        r.nextBytes(bytes2);

        FieldElement fieldElement1 = FieldElement.deserializeFieldElement(bytes1);
        FieldElement fieldElement2 = FieldElement.deserializeFieldElement(bytes2);

        byte[] serialized1 = fieldElement1.serializeFieldElement();
        byte[] serialized2 = fieldElement2.serializeFieldElement();

        assertArrayEquals("Field element 1 bytes must be the same.", Arrays.copyOf(bytes1, FieldElement.FIELD_ELEMENT_SIZE), serialized1);
        assertArrayEquals("Field element 2 bytes must be the same.", Arrays.copyOf(bytes2, FieldElement.FIELD_ELEMENT_SIZE), serialized2);

        fieldElement1.freeFieldElement();
        fieldElement2.freeFieldElement();


    }
}
