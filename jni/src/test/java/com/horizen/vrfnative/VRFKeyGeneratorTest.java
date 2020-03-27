package com.horizen.vrfnative;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;

public class VRFKeyGeneratorTest {


    @Test
    public void testGenerate() {

        byte[] secretKeyBytes = new byte[VRFSecretKey.SECRET_KEY_LENGTH];
        byte[] publicKeyBytes = new byte[VRFPublicKey.PUBLIC_KEY_LENGTH];

        assertTrue("Key generation must be successful.", VRFKeyGenerator.nativeGenerate(secretKeyBytes, publicKeyBytes));

        assertTrue("Generated key must be valid.", VRFPublicKey.nativeVerifyKey(publicKeyBytes));
    }
}
