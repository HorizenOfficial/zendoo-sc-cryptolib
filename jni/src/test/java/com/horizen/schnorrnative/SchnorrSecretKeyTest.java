package com.horizen.schnorrnative;

import com.horizen.vrfnative.VRFKeyGenerator;
import com.horizen.vrfnative.VRFSecretKey;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SchnorrSecretKeyTest {


    @Test
    public void testSignMessage() {

        SchnorrSecretKey key = SchnorrKeyGenerator.generate();

        assertTrue("Generated key must be valid.", key.getPublicKey().verifyKey());

        byte[] message = new byte[SchnorrSecretKey.SECRET_KEY_LENGTH];

        byte[] signature = key.signMessage(message);

        assertTrue("Proof must be valid.", key.getPublicKey().verifySignature(message, signature));

        signature[0] = 0;

        assertFalse("Proof must be invalid.", key.getPublicKey().verifySignature(message, signature));

    }
}
