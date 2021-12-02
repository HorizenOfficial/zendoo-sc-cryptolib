package com.horizen.fwtnative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Utils;

import org.junit.Test;

public class ForwardTransferOutputTest {

    static long seed = 1234567890L;
    static String expectedFwtOutputNullifierHex = "09CCA1C4317C32A5FA97F0BC699B3ED7B46B993FBBEEA8BB0F6A008D60E38714";

    @Test
    public void testFwtOutputNullifier() {

        // Generate random ForwardTransferOutput and get its nullifier
        Random r = new Random(seed);
        FieldElement nullifier = ForwardTransferOutput.getRandom(r).getNullifier();
        byte[] nullifierBytes = nullifier.serializeFieldElement();

        // Check equality with expected one
        assertEquals(expectedFwtOutputNullifierHex, Utils.bytesToHex(nullifierBytes));

        // Free memory
        nullifier.close();
    }
}
