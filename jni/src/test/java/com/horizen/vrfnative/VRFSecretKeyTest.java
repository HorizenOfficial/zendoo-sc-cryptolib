package com.horizen.vrfnative;

import org.junit.Test;

import static org.junit.Assert.*;

public class VRFSecretKeyTest {



    @Test
    public void testRandomKey() {

        int samples = 100;

        for(int i = 0; i < samples; i++) {
            VRFKeyPair keyPair = VRFKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);

            byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
            byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

            assertEquals("Public key size must be - " + VRFPublicKey.PUBLIC_KEY_LENGTH,
                    VRFPublicKey.PUBLIC_KEY_LENGTH,
                    publicKeyBytes.length);
            assertEquals("Secret key size must be - " + VRFSecretKey.SECRET_KEY_LENGTH,
                    VRFSecretKey.SECRET_KEY_LENGTH,
                    secretKeyBytes.length);

            VRFPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();

            assertTrue("Recreated key must be valid.", recreatedPublicKey.verifyKey());

            VRFPublicKey deserializedPublicKey = VRFPublicKey.deserialize(publicKeyBytes);
            VRFSecretKey deserializedSecretKey = VRFSecretKey.deserialize(secretKeyBytes);

            assertNotNull("publicKey deserialization must not fail", deserializedPublicKey);
            assertNotNull("secretKey deserialization must not fail", deserializedSecretKey);

            assertTrue("Deserialized key must be valid.", deserializedPublicKey.verifyKey());

            keyPair.getPublicKey().freePublicKey();
            keyPair.getSecretKey().freeSecretKey();

            deserializedPublicKey.freePublicKey();
            deserializedSecretKey.freeSecretKey();
        }
    }
}
