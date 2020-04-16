package com.horizen.schnorrnative;

import com.horizen.librustsidechains.PublicKeyUtils;
import com.horizen.librustsidechains.SecretKeyUtils;
import org.junit.Test;

import static org.junit.Assert.*;

public class SchnorrSecretKeyTest {


    @Test
    public void testKey() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        byte[] publicKeyBytes = keyPair.getPublicKey().serializePublicKey();
        byte[] secretKeyBytes = keyPair.getSecretKey().serializeSecretKey();

        assertEquals("Public key size must me - " + PublicKeyUtils.PUBLIC_KEY_LENGTH,
                PublicKeyUtils.PUBLIC_KEY_LENGTH,
                publicKeyBytes.length);
        assertEquals("Secret key size must be - " + SecretKeyUtils.SECRET_KEY_LENGTH,
                SecretKeyUtils.SECRET_KEY_LENGTH,
                secretKeyBytes.length);

        SchnorrPublicKey recreatedPublicKey = keyPair.getSecretKey().getPublicKey();
    }
}
