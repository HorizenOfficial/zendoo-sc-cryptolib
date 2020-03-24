package com.horizen.snarknative;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;

public class SnarkProofTest {


    @Test
    public void testVerify() {

        String keyPath;
        byte[] proof;
        byte[] message;


        try {
            ClassLoader classLoader = getClass().getClassLoader();
            keyPath = Paths.get(classLoader.getResource("vk").toURI()).toAbsolutePath().toString();
            proof = Files.readAllBytes(Paths.get(classLoader.getResource("good_proof").toURI()));
            message = Files.readAllBytes(Paths.get(classLoader.getResource("good_public_inputs").toURI()));
        }
        catch (Exception e) {
            assertEquals(e.toString(), true, false);
            return;
        }

        SnarkProof snarkProof = new SnarkProof(proof);

        assertTrue("Verification must be successful.", snarkProof.verify(keyPath, message));

        try {
            ClassLoader classLoader = getClass().getClassLoader();
            keyPath = Paths.get(classLoader.getResource("vk").toURI()).toAbsolutePath().toString();
            proof = Files.readAllBytes(Paths.get(classLoader.getResource("bad_proof").toURI()));
            message = Files.readAllBytes(Paths.get(classLoader.getResource("bad_public_inputs").toURI()));
        }
        catch (Exception e) {
            assertEquals(e.toString(), true, false);
            return;
        }

        SnarkProof badSnarkProof = new SnarkProof(proof);

        assertFalse("Verification must be unsuccessful.", badSnarkProof.verify(keyPath, message));
    }
}
