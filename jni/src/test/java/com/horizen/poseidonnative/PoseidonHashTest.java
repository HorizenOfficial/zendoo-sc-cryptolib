package com.horizen.poseidonnative;

import org.junit.Test;

import static org.junit.Assert.*;


public class PoseidonHashTest {

    @Test
    public void testComputeHash() {

        byte[] input = new byte[PoseidonHash.HASH_LENGTH];

        byte[] hash = PoseidonHash.nativeComputeHash(input);

        assertNotNull("Hash must be computed", hash);
        assertEquals("Hash size must be " + PoseidonHash.HASH_LENGTH, PoseidonHash.HASH_LENGTH, hash.length);

    }
}
