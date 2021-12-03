package com.horizen.scutxonative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;

public class ScUtxoOutputTest {
    static long seed = 1234567890L;
    static String expectedScUtxoOutputNullifierHex =
        "cfac14fbfea73c470ef029e1e4b2489f5351788753dd5545eb1f780dbb10330e";

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
