package com.horizen.vrfnative;

import com.horizen.librustsidechains.PublicKeyUtils;
import com.horizen.librustsidechains.SecretKeyUtils;

import org.junit.Test;

import static org.junit.Assert.*;

public class VRFSecretKeyTest {



    @Test
    public void testKey() {

        VRFKeyPair keyPair = VRFKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
        byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

        assertEquals("Public key size must me - " + PublicKeyUtils.PUBLIC_KEY_LENGTH,
                PublicKeyUtils.PUBLIC_KEY_LENGTH,
                publicKeyBytes.length);
        assertEquals("Secret key size must be - " + SecretKeyUtils.SECRET_KEY_LENGTH,
                SecretKeyUtils.SECRET_KEY_LENGTH,
                secretKeyBytes.length);

        VRFPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();

        assertTrue("Recreated key must be valid.", recreatedPublicKey.verifyKey());
    }
}
