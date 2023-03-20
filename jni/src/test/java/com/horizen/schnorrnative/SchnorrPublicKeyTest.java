package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import static org.junit.Assert.*;

public class SchnorrPublicKeyTest {

    @Test
    public void testGetHash() throws Exception {
        byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] expected = {-37, -55, 0, -12, 70, 91, 97, -85, 12, 76, -8, 66, -7, 90, -75, -15, -66, 91, -65, 111, 6, 104, 20, -20, -54, -61, 67, 78, 88, -54, 84, 30 };

        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate(seed))
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            SchnorrPublicKey pk = keyPair.getPublicKey();
            FieldElement hash = pk.getHash();
            byte[] hashBytes = hash.serializeFieldElement();
            assertArrayEquals(expected, hashBytes);
        };

        byte[] seed2 = { 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] expected2 = {-1,-46,-65,1,-39,82,-61,9,75,-58,-113,-112,121,105,-74,111,9,-35,-128,-4,7,-66,17,1,-92,-79,-127,-68,-4,-30,36,49};
        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate(seed2))
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            SchnorrPublicKey pk = keyPair.getPublicKey();
            FieldElement hash = pk.getHash();
            byte[] hashBytes = hash.serializeFieldElement();
            assertArrayEquals(expected2, hashBytes);
        };
    }
}
