package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import static org.junit.Assert.*;

public class SchnorrPublicKeyTest {

    @Test
    public void testGetHash() throws Exception {
        byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        byte[] expected = {94, 34, -122, -88, 122, -49, -113, 118, 109, 108, 45, -96, 85, -1, 110, -68, 52, -43, -92, 83, 34, 4, -48, 75, -21, -47, -89, 89, 69, -45, 3, 60};

        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate(seed))
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            SchnorrPublicKey pk = keyPair.getPublicKey();
            FieldElement hash = pk.getHash();
            byte[] hashBytes = hash.serializeFieldElement();
            if (expected[0] != hashBytes[0]) {
                throw new Exception(printByteArray(hashBytes));
            }
            assertArrayEquals(expected, hashBytes);
        };

        byte[] seed2 = { 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64 };
        byte[] expected2 = {-7, 41, -26, -125, -49, -37, -111, 121, 55, -60, 81, -108, -14, -94, 17, 120, -70, -12, 13, 52, -106, -5, -44, 51, -86, 39, -79, 44, -4, -79, 95, 21};
        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate(seed2))
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            SchnorrPublicKey pk = keyPair.getPublicKey();
            FieldElement hash = pk.getHash();
            byte[] hashBytes = hash.serializeFieldElement();
            if (expected2[0] != hashBytes[0]) {
                throw new Exception(printByteArray(hashBytes));
            }
            assertArrayEquals(expected2, hashBytes);
        };
    }

    private String printByteArray(byte[] array) {
        StringBuilder builder = new StringBuilder();
        String sep = "";
        for (byte b : array) {
            builder.append(sep);
            builder.append(b);
            sep = ", ";
        }
        return builder.toString();
    }

}
