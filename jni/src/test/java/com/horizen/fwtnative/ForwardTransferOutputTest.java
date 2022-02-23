package com.horizen.fwtnative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.TestUtils;
import io.horizen.common.librustsidechains.FieldElement;
import org.junit.Test;

public class ForwardTransferOutputTest {

    static long seed = 1234567890L;
    static String expectedFwtOutputNullifierHex = "04198752f7382281ca6b90f7900fcae807ba56e6de2bd7e2e398a1eb8f9c7139";

    @Test
    public void testFwtOutputNullifier() throws Exception {

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
