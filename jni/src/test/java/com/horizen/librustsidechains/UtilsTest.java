package com.horizen.librustsidechains;

import com.horizen.TestUtils;
import org.junit.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

public class UtilsTest {
    @Test
    public void calculateSidechainId() throws Exception {
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
        assertNotEquals("Sidechain Ids expected to be different",
                TestUtils.toHexString(scId1), TestUtils.toHexString(scId2));

        // Same tx hash, but different index
        int anotherIndex = 20;
        byte[] scId3 = Utils.calculateSidechainId(txHash1, anotherIndex);
        assertNotEquals("Sidechain Ids expected to be different",
                TestUtils.toHexString(scId1), TestUtils.toHexString(scId3));
    }

    @Test
    public void calculateSidechainIdRegression() throws Exception {
        byte[] txHash = new byte[32];
        Arrays.fill(txHash, (byte)0);

        int index = 0;

        byte[] scId = Utils.calculateSidechainId(txHash, index);
        assertEquals("Calculate sc id regression failed.",
                "e5898923c5501dbecd48456555cf9225aa44bf3a4e84bc20ec069b4a4dcf972a",
                TestUtils.toHexString(scId));
    }

    @Test
    public void compressedBitvectorRegression() throws Exception {
        // Compressed with gzip
        String compressedBitvectorHex = "021f8b08000000000002ff017f0080ff44c7e21ba1c7c0a29de006cb8074e2ba39f15abfef2525a4cbb3f235734410bda21cdab6624de769ceec818ac6c2d3a01e382e357dce1f6e9a0ff281f0fedae0efe274351db37599af457984dcf8e3ae4479e0561341adfff4746fbe274d90f6f76b8a2552a6ebb98aee918c7ceac058f4c1ae0131249546ef5e22f4187a07da02ca5b7f000000";
        int decompressedSize = 128;

        // Test merkle root computation without size check
        byte[] merkleRoot = Utils.compressedBitvectorMerkleRoot(TestUtils.fromHexString(compressedBitvectorHex));

        assertEquals("Calculate compressed bitvector merkle root regression failed.",
                "8a7d5229f440d4700d8b0343de4e14400d1cb87428abf83bd67153bf58871721",
                TestUtils.toHexString(merkleRoot));

        // Test merkle root computation with size check
        boolean exceptionOccurred = false;
        try {
            Utils.compressedBitvectorMerkleRoot(TestUtils.fromHexString(compressedBitvectorHex), decompressedSize);
        } catch (Exception e) {
            exceptionOccurred = true;
            assertTrue("Different exception expected", e.getMessage().contains("Cannot compute merkle root with size check"));
        }
        assertTrue("Excecption expected.", exceptionOccurred);
    }
}
