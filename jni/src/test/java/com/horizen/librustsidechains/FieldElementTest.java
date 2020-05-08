package com.horizen.librustsidechains;

import org.junit.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

public class FieldElementTest {

    @Test
    public void testRandomSerializeDeserialize() {

        int samples = 100;

        for( int i = 0; i < samples; i++ ) {
            FieldElement fieldElement1 = FieldElement.createRandom();
            FieldElement fieldElement2 = FieldElement.createRandom();

            byte[] serialized1 = fieldElement1.serializeFieldElement();
            byte[] serialized2 = fieldElement2.serializeFieldElement();

            assertEquals("fieldElement1 size must be - " + FieldElement.FIELD_ELEMENT_LENGTH,
                    FieldElement.FIELD_ELEMENT_LENGTH,
                    serialized1.length);
            assertEquals("fieldElement2 size must be - " + FieldElement.FIELD_ELEMENT_LENGTH,
                    FieldElement.FIELD_ELEMENT_LENGTH,
                    serialized2.length);

            FieldElement fieldElementDeserialized1 = FieldElement.deserialize(serialized1);
            FieldElement fieldElementDeserialized2 = FieldElement.deserialize(serialized2);

            assertNotNull("fieldElement1 deserialization must not fail", fieldElementDeserialized1);
            assertNotNull("fieldElement2 deserialization must not fail", fieldElementDeserialized2);

            assertEquals("Field element 1 must be the same.", fieldElement1, fieldElementDeserialized1);
            assertEquals("Field element 2 must be the same.", fieldElement2, fieldElementDeserialized2);

            fieldElement1.freeFieldElement();
            fieldElement2.freeFieldElement();

            fieldElementDeserialized1.freeFieldElement();
            fieldElementDeserialized2.freeFieldElement();
        }
    }
}