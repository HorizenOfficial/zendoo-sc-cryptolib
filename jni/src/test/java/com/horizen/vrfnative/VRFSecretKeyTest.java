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

        byte[] secretKeyBytes = new byte[VRFSecretKey.SECRET_KEY_LENGTH];
        byte[] publicKeyBytes = new byte[VRFPublicKey.PUBLIC_KEY_LENGTH];

        assertTrue("Key generation must be successful.", VRFKeyGenerator.nativeGenerate(secretKeyBytes, publicKeyBytes));
        assertTrue("Generated key must be valid.", VRFPublicKey.nativeVerifyKey(publicKeyBytes));

        byte[] message = new byte[VRFSecretKey.SECRET_KEY_LENGTH];

        byte[] proof = VRFSecretKey.nativeProve(publicKeyBytes, secretKeyBytes, message);

        assertTrue("Proof must be valid.", VRFPublicKey.nativeVerify(publicKeyBytes, message, proof));
        assertEquals("Proof size must be " + VRFProof.VRF_PROOF_SIZE, VRFProof.VRF_PROOF_SIZE, proof.length);

        byte[] vrfHash = VRFSecretKey.nativeVRFHash(message, publicKeyBytes, proof);

        assertEquals("VRF hash size must be " + VRFProof.VRF_PROOF_SIZE, VRFProof.VRF_PROOF_SIZE, vrfHash.length);
    }
}
