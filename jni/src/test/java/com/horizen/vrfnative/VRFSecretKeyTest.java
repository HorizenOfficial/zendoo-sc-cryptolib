package com.horizen.vrfnative;

import org.junit.Test;

import static org.junit.Assert.*;

public class VRFSecretKeyTest {

    @Test
    public void testRandomKey() throws Exception {

        int samples = 100;

        for(int i = 0; i < samples; i++) {
            try(VRFKeyPair keyPair = VRFKeyPair.generate())
            {
                assertNotNull("Key pair generation was unsuccessful.", keyPair);

                byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
                byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

                assertEquals("Public key size must be - " + VRFPublicKey.PUBLIC_KEY_LENGTH,
                        VRFPublicKey.PUBLIC_KEY_LENGTH,
                        publicKeyBytes.length);
                assertEquals("Secret key size must be - " + VRFSecretKey.SECRET_KEY_LENGTH,
                        VRFSecretKey.SECRET_KEY_LENGTH,
                        secretKeyBytes.length);
                try
                (
                    VRFPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();
                    VRFPublicKey deserializedPublicKey = VRFPublicKey.deserialize(publicKeyBytes);
                    VRFSecretKey deserializedSecretKey = VRFSecretKey.deserialize(secretKeyBytes);
                )
                {
                    byte[] recreatedPublicKeyBytes = recreatedPublicKey.serializePublicKey();

                    assertTrue("Recreated key must be valid.", recreatedPublicKey.verifyKey());
                    assertArrayEquals("Recreated public key must be the same.", publicKeyBytes, recreatedPublicKeyBytes);

                    assertNotNull("publicKey deserialization must not fail", deserializedPublicKey);
                    assertNotNull("secretKey deserialization must not fail", deserializedSecretKey);

                    assertTrue("Deserialized key must be valid.", deserializedPublicKey.verifyKey());

                }
            }
        }
    }
}
