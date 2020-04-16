package com.horizen.vrfnative;

import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrSignature;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class VRFKeyPairTest {


    @Test
    public void testGenerate() {

        VRFKeyPair keyPair = VRFKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
    }
}
