package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
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

    @Test
    public void testSign() {
        VRFKeyPair keyPair = VRFKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);
        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

        FieldElement fieldElement = FieldElement.createFromLong(123456789L);

        VRFProof proof = keyPair.prove(fieldElement);

        assertNotNull("Attempt to create proof failed.", proof);

    }
}
