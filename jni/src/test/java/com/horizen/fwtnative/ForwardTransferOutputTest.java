package com.horizen.fwtnative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

public class ForwardTransferOutputTest {

    static long seed = 1234567890L;
    static String expectedFwtOutputNullifierHex = "09cca1c4317c32a5fa97f0bc699b3ed7b46b993fbbeea8bb0f6a008d60e38714";

    @Test
    public void testFwtOutputNullifier() {

        // Generate random ForwardTransferOutput and get its nullifier
        Random r = new Random(seed);
        FieldElement nullifier = ForwardTransferOutput.getRandom(r).getNullifier();
        byte[] nullifierBytes = nullifier.serializeFieldElement();

        // Check equality with expected one
        assertEquals(expectedFwtOutputNullifierHex, TestUtils.toHexString(nullifierBytes));

        // Free memory
        nullifier.close();
    }
}
