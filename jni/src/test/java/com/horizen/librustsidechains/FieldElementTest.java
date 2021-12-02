package com.horizen.librustsidechains;

import org.junit.Test;

import static org.junit.Assert.*;

import java.util.List;

public class FieldElementTest {

    @Test
    public void testRandomSerializeDeserialize() throws Exception {

        int samples = 100;
        for( int i = 0; i < samples; i++ ) {
            try
            (
                FieldElement fieldElement1 = FieldElement.createRandom();
                FieldElement fieldElement2 = FieldElement.createRandom()
            )
            {
                byte[] serialized1 = fieldElement1.serializeFieldElement();
                byte[] serialized2 = fieldElement2.serializeFieldElement();

                assertEquals("fieldElement1 size must be - " + Constants.FIELD_ELEMENT_LENGTH(),
                Constants.FIELD_ELEMENT_LENGTH(),
                        serialized1.length);
                assertEquals("fieldElement2 size must be - " + Constants.FIELD_ELEMENT_LENGTH(),
                Constants.FIELD_ELEMENT_LENGTH(),
                        serialized2.length);
                try
                (
                    FieldElement fieldElementDeserialized1 = FieldElement.deserialize(serialized1);
                    FieldElement fieldElementDeserialized2 = FieldElement.deserialize(serialized2)
                )
                {
                    assertNotNull("fieldElement1 deserialization must not fail", fieldElementDeserialized1);
                    assertNotNull("fieldElement2 deserialization must not fail", fieldElementDeserialized2);

                    assertEquals("Field element 1 must be the same.", fieldElement1, fieldElementDeserialized1);
                    assertEquals("Field element 2 must be the same.", fieldElement2, fieldElementDeserialized2);
                }
            }
        }
    }

    @Test
    public void testSplitPositive() throws Exception {
        // Positive case
        for(int i = 1; i < Constants.FIELD_ELEMENT_LENGTH(); i++) {
            // Generate random FieldElement and split it into two FieldElements at index i
            FieldElement feToBeSplit = FieldElement.createRandom(); 
            List<FieldElement> splitFes = feToBeSplit.splitAt(i);

            // Assert that the resulting FieldElement are 2
            assertEquals(splitFes.size(), 2);

            // Rejoin the two FieldElements at the same index and check equality with the original one
            FieldElement restoredFe = FieldElement.joinAt(splitFes.get(0), i, splitFes.get(1), Constants.FIELD_ELEMENT_LENGTH() - i);
            assertEquals("Must be able to reconstruct the original FieldElement split ad index:" + i, feToBeSplit, restoredFe);

            // Free memory
            feToBeSplit.close();
            restoredFe.close();
            splitFes.get(0).close();
            splitFes.get(1).close();
        }
    }

    @Test
    public void testSplitNegative() throws Exception {
        // Split then rejoin at wrong index and assert we are not able to reconstruct the original FieldElement
        for(int i = 1; i < Constants.FIELD_ELEMENT_LENGTH() - 1; i++) {
            // Generate random FieldElement and split it into two FieldElements at index i
            FieldElement feToBeSplit = FieldElement.createRandom(); 
            List<FieldElement> splitFes = feToBeSplit.splitAt(i);

            // Assert that the resulting FieldElement are 2
            assertEquals(splitFes.size(), 2);

            // Rejoin the two FieldElements at an index shifted by one with respect to the original and
            // assert reconstruction of a different FieldElement
            FieldElement restoredFe = FieldElement.joinAt(splitFes.get(0), i + 1, splitFes.get(1), Constants.FIELD_ELEMENT_LENGTH() - i - 1);
            assertNotEquals("Mustn't be able to reconstruct the original FieldElement split ad index:" + i, feToBeSplit, restoredFe);

            // Free memory
            feToBeSplit.close();

            // Since we combine the two FieldElements incorrectly, might also happen that we generate an invalid (i.e. over the modulus) FieldElement
            if (restoredFe != null) {  
                restoredFe.close();
            }
            splitFes.get(0).close();
            splitFes.get(1).close();
        }
    }

    @Test
    public void testSplitExceptions() throws Exception {
        FieldElement fe = FieldElement.createRandom();

        // Try to split at 0
        try {
            fe.splitAt(0);
            assertTrue(false); // Mustn't be able to reach this point
        } catch (IndexOutOfBoundsException ex) {};

        // Try to split at FIELD_ELEMENT_LENGTH
        try {
            fe.splitAt(Constants.FIELD_ELEMENT_LENGTH());
            assertTrue(false); // Mustn't be able to reach this point
        } catch (IndexOutOfBoundsException ex) {};
    }
}