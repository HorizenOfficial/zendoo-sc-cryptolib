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

    @Test
    public void scIdRegTest() {
        byte[] txHash = new byte[32];
        Arrays.fill(txHash, (byte)0);

        int index = 0;

        byte[] scId = Utils.calculateSidechainId(txHash, index);

        StringBuilder sb = new StringBuilder(scId.length * 2);
        for(byte b: scId)
            sb.append(String.format("%02x", b));

        assertEquals(sb.toString(), "e5898923c5501dbecd48456555cf9225aa44bf3a4e84bc20ec069b4a4dcf972a");
    }

}
