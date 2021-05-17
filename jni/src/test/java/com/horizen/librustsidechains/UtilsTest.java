package com.horizen.librustsidechains;

import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.*;

public class UtilsTest {
    @Test
    public void calculateSidechainId() {
        long seed = 123L;
        byte[] txHash = new byte[32];
        new Random(seed).nextBytes(txHash);
        int index = 13;

        assertNotNull("Sidechain Id was not calculated.", Utils.calculateSidechainId(txHash, index));
    }
}
