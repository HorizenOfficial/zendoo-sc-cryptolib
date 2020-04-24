package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class SchnorrKeyPairTest {


    @Test
    public void testGenerate() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
    }

    @Test
    public void testSignVerify() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);
        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

        FieldElement fieldElement = FieldElement.createFromLong(123456789L);

        SchnorrSignature signature = keyPair.signMessage(fieldElement);

        assertNotNull("Attempt to sign message failed.", signature);

        assertTrue("Signature must be verified", keyPair.getPublicKey().verifySignature(signature, fieldElement));

        FieldElement wrongFieldElement = FieldElement.createFromLong(123456780L);

        assertFalse("Signature must not be verified", keyPair.getPublicKey().verifySignature(signature, wrongFieldElement));

    }

}
