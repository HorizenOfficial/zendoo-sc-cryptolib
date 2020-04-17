package com.horizen.schnorrnative;

import org.junit.Test;

import static org.junit.Assert.*;

public class SchnorrSecretKeyTest {


    @Test
    public void testKey() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
        byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

        assertEquals("Public key size must me - " + SchnorrPublicKey.PUBLIC_KEY_LENGTH,
                SchnorrPublicKey.PUBLIC_KEY_LENGTH,
                publicKeyBytes.length);
        assertEquals("Secret key size must be - " + SchnorrSecretKey.SECRET_KEY_LENGTH,
                SchnorrSecretKey.SECRET_KEY_LENGTH,
                secretKeyBytes.length);

        SchnorrPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();

        assertTrue("Recreated key must be valid.", recreatedPublicKey.verifyKey());

        SchnorrPublicKey deserializedPublicKey = SchnorrPublicKey.deserializePublicKey(publicKeyBytes);
        SchnorrSecretKey deserializedSecretKey = SchnorrSecretKey.deserializeSecretKey(secretKeyBytes);

        assertTrue("Deserialized key must be valid.", deserializedPublicKey.verifyKey());

        keyPair.getPublicKey().freePublicKey();
        keyPair.getSecretKey().freeSecretKey();

        deserializedPublicKey.freePublicKey();
        deserializedSecretKey.freeSecretKey();
    }
}
