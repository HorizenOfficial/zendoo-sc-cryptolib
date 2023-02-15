package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;

import static org.junit.Assert.*;

public class SchnorrKeyPairTest {

    @Test
    public void testGenerate() throws Exception {

        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate())
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
        }
    }

    @Test
    public void testDeriveFromSeed() throws Exception {
        byte[] badSeed = { 1, 2, 3, 4, 5, 6, 7, 8 };
        assertThrows(Exception.class, new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                SchnorrKeyPair keyPair = SchnorrKeyPair.generate(badSeed);
            }
        });
        byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        byte[] expectedPubKeyBytes = {42, -59, -79, -80, 59, -32, 64, -61, -94, 32, -7, 34, 69, 44, 48, -37, 73, 59, -114, 85, 90, 23, -103, 7, 78, -127, -75, -77, -25, -32, 65, 34, -128};
        byte[] expectedSecretKeyBytes = {72, 73, -55, -19, 127, 107, 27, -125, 45, 38, 48, 84, -13, -13, -82, 21, 1, 84, -47, 56, -63, 3, -50, 109, -126, -27, 12, 29, 38, 14, -124, 48};
        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate(seed))
        {
            assertNotNull("Key pair derive from seed was unsuccessful", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
            assertArrayEquals("Derive from seed didn't produce the expected public key", expectedPubKeyBytes, keyPair.getPublicKey().serializePublicKey());
            assertArrayEquals("Derive from seed didn't produce the expected secret key", expectedSecretKeyBytes, keyPair.getSecretKey().serializeSecretKey());
        }
    }

    @Test
    public void testSignVerify() throws Exception {

        byte[] skBytes = {
            -75, 35, 36, 5, -30, -110, 63, 101, -39, 39, 46, 84, 51, -93, -9, 15, 54, -66, -122, -27, -47, 79, 63, -127,
            120, -47, 119, 80, 119, 12, 54, 24
        };

        byte[] messageBytes = {
            -80, 103, 41, -19, 116, -82, 26, 29, 92, 7, 109, -44, -57, 100, -10, 86, 80, -17, 3, 46, 58, 53, -78, 118,
            59, -91, -84, -126, 52, 69, -51, 61
        };

        byte[] sigBytes = {
            84, -73, -118, 62, -124, -29, 52, 123, 9, -82, 32, 89, 17, 8, -2, 31, -103, -39, -77, -73, -3, 87, -100, 80,
            -11, 108, -86, 97, 119, -29, 101, 39, -73, 56, -43, 118, 107, 69, -91, 59, 51, 86, -88, -50, 127, 26, 114,
            39, -113, 94, -95, -50, -112, 98, 54, 68, -115, -120, -10, -119, 27, -121, -32, 20
        };

        try
        (
            SchnorrSecretKey sk = SchnorrSecretKey.deserialize(skBytes);
            SchnorrKeyPair keyPair = new SchnorrKeyPair(sk);
            FieldElement message = FieldElement.deserialize(messageBytes);
            SchnorrSignature sig = SchnorrSignature.deserialize(sigBytes)
        )
        {
            assertNotNull("sk deserialization must not fail", sk);
            assertNotNull("message deserialization must not fail", message);
            assertTrue("Signature must be verified", keyPair.getPublicKey().verifySignature(sig, message));
        }

    }

    @Test
    public void testRandomSignVerify() throws Exception {

        int samples = 100;

        for (int i = 0; i < samples; i++) {
            try
            (
                SchnorrKeyPair keyPair = SchnorrKeyPair.generate();
                FieldElement fieldElement = FieldElement.createRandom();
                FieldElement wrongFieldElement = FieldElement.createRandom()
            )
            {
                assertNotNull("Key pair generation was unsuccessful.", keyPair);
                assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

                try(SchnorrSignature signature = keyPair.signMessage(fieldElement))
                {
                    assertNotNull("Attempt to sign message failed.", signature);
                    assertTrue("Signature must be verified", keyPair.getPublicKey().verifySignature(signature, fieldElement));
                    assertFalse("Signature must not be verified", keyPair.getPublicKey().verifySignature(signature, wrongFieldElement));
                }
            }
        }
    }
}
