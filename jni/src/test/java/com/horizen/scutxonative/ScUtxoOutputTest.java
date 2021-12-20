package com.horizen.scutxonative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;

public class ScUtxoOutputTest {
    static long seed = 1234567890L;
    static String expectedScUtxoOutputNullifierHex =
        "dc10caecac96d6b32b7f8f46d4e4fdd5378611b01b1273fc7bebf8ac5e198804";

    @Test
    public void testScUtxoOutputNullifier() {

        // Generate random ForwardTransferOutput and get its nullifier
        Random r = new Random(seed);
        FieldElement nullifier = ScUtxoOutput.getRandom(r).getNullifier();
        byte[] nullifierBytes = nullifier.serializeFieldElement();

        // Check equality with expected one
        assertEquals(expectedScUtxoOutputNullifierHex, TestUtils.toHexString(nullifierBytes));

        // Free memory
        nullifier.close();
    }
}
