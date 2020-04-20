package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

public class SchnorrKeyPairTest {


    @Test
    public void testGenerate() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
    }

    @Test
    public void testSign() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);
        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

        FieldElement fieldElement = FieldElement.createFromLong(123456789L);

        SchnorrSignature signature = keyPair.signMessage(fieldElement);

        assertNotNull("Attempt to sign message failed.", signature);
    }

}
