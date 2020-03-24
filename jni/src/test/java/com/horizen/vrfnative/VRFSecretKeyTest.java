package com.horizen.vrfnative;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;

public class VRFSecretKeyTest {


    @Test
    public void testProove() {

        VRFSecretKey key = VRFKeyGenerator.generate();

        assertTrue("Generated key must be valid.", key.getPublicKey().verifyKey());

        byte[] message = new byte[VRFSecretKey.SECRET_KEY_LENGTH];

        VRFProof proof = key.prove(message);

        assertTrue("Proof must be valid.", key.getPublicKey().verify(message, proof));
        assertEquals("Proof size must be " + VRFProof.VRF_PROOF_SIZE, VRFProof.VRF_PROOF_SIZE, proof.getProof().length);

        byte[] vrfHash = key.vrfHash(message, proof);

        assertEquals("VRF hash size must be " + VRFProof.VRF_PROOF_SIZE, VRFProof.VRF_PROOF_SIZE, vrfHash.length);
    }
}
