package com.horizen.schnorrnative;

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

    /*
    @Test
    public void testSign() {

        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);
        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

        byte[] message = new byte[96];

        SchnorrSignature signature = keyPair.signMessage(message);

        assertNotNull("Attempt to sign message failed.", signature);
    }
    */

}
