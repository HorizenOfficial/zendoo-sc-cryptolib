package com.horizen.schnorrnative;

import org.junit.Test;

import static org.junit.Assert.*;

public class SchnorrSecretKeyTest {


    @Test
    public void testRandomKey() {

        int samples = 100;

        for( int i = 0; i < samples; i++ ) {
            SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);

            byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
            byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

            assertEquals("Public key size must be - " + SchnorrPublicKey.PUBLIC_KEY_LENGTH,
                    SchnorrPublicKey.PUBLIC_KEY_LENGTH,
                    publicKeyBytes.length);
            assertEquals("Secret key size must be - " + SchnorrSecretKey.SECRET_KEY_LENGTH,
                    SchnorrSecretKey.SECRET_KEY_LENGTH,
                    secretKeyBytes.length);

            SchnorrPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();
            byte[] recreatedPublicKeyBytes = recreatedPublicKey.serializePublicKey();

            assertTrue("Recreated key must be valid.", recreatedPublicKey.verifyKey());
            assertArrayEquals("Recreated public key must be the same.", publicKeyBytes, recreatedPublicKeyBytes);

            SchnorrPublicKey deserializedPublicKey = SchnorrPublicKey.deserialize(publicKeyBytes, true);
            SchnorrSecretKey deserializedSecretKey = SchnorrSecretKey.deserialize(secretKeyBytes);

            assertNotNull("publicKey deserialization must not fail", deserializedPublicKey);
            assertNotNull("secretKey deserialization must not fail", deserializedSecretKey);

            keyPair.getPublicKey().freePublicKey();
            keyPair.getSecretKey().freeSecretKey();

            deserializedPublicKey.freePublicKey();
            deserializedSecretKey.freeSecretKey();

            recreatedPublicKey.freePublicKey();
        }
    }
}
