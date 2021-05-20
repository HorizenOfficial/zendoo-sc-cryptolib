package com.horizen.librustsidechains;

import org.junit.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

public class UtilsTest {
    @Test
    public void calculateSidechainId() {
        long seed = 123L;
        Random r = new Random(seed);

        byte[] txHash1 = new byte[32];
        r.nextBytes(txHash1);

        byte[] txHash2 = new byte[32];
        r.nextBytes(txHash2);

        int index = 13;

        // Same index, but different tx hash
        byte[] scId1 = Utils.calculateSidechainId(txHash1, index);
        byte[] scId2 = Utils.calculateSidechainId(txHash2, index);
        assertFalse("Sidechain Ids expected to be different", Arrays.equals(scId1, scId2));

        // Same tx hash, but different index
        int anotherIndex = 20;
        byte[] scId3 = Utils.calculateSidechainId(txHash1, anotherIndex);
        assertFalse("Sidechain Ids expected to be different", Arrays.equals(scId1, scId3));
    }
}
