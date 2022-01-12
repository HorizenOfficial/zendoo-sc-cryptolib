package com.horizen.scutxonative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;

public class ScUtxoOutputTest {
    static long seed = 1234567890L;
    static String expectedScUtxoOutputNullifierHex =
        "9ef7685672544e69591a2b5f1b09e708c40582ac1378417acc821a3c8681870d";

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
