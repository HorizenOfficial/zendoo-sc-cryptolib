package com.horizen.vrfnative;

import org.junit.Test;

import static org.junit.Assert.*;

public class VRFSecretKeyTest {



    @Test
    public void testKey() {

        VRFKeyPair keyPair = VRFKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
        byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

        assertEquals("Public key size must me - " + VRFPublicKey.PUBLIC_KEY_LENGTH,
                VRFPublicKey.PUBLIC_KEY_LENGTH,
                publicKeyBytes.length);
        assertEquals("Secret key size must be - " + VRFSecretKey.SECRET_KEY_LENGTH,
                VRFSecretKey.SECRET_KEY_LENGTH,
                secretKeyBytes.length);

        VRFPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();

        assertTrue("Recreated key must be valid.", recreatedPublicKey.verifyKey());

        VRFPublicKey deserializedPublicKey = VRFPublicKey.deserializePublicKey(publicKeyBytes);
        VRFSecretKey deserializedSecretKey = VRFSecretKey.deserializeSecretKey(secretKeyBytes);

        assertTrue("Deserialized key must be valid.", deserializedPublicKey.verifyKey());

        keyPair.getPublicKey().freePublicKey();
        keyPair.getSecretKey().freeSecretKey();

        deserializedPublicKey.freePublicKey();
        deserializedSecretKey.freeSecretKey();
    }
}
