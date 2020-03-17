package com.horizen.vrf;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;

public class VRFSecretKeyTest {

    @BeforeClass
    public static void before() {
        System.loadLibrary("librustsidechains");
    }


    @Test
    public void testVerify() {

        String keyPath;
        byte[] proof;
        byte[] message;


        try {
            ClassLoader classLoader = getClass().getClassLoader();
            keyPath = Paths.get(classLoader.getResource("vk").toURI()).toAbsolutePath().toString() + "__";
            proof = Files.readAllBytes(Paths.get(classLoader.getResource("good_proof").toURI()));
            message = Files.readAllBytes(Paths.get(classLoader.getResource("good_public_inputs").toURI()));
        }
        catch (Exception e) {
            assertEquals(e.toString(), true, false);
            return;
        }

        assertTrue("Verification must be successful.", VRFSecretKey.nativeVerify(keyPath, message, proof));

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

        assertFalse("Verification must be unsuccessful.", VRFSecretKey.nativeVerify(keyPath, message, proof));
    }
}
