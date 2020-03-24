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

        VRFSecretKey key = VRFKeyGenerator.generate();

        assertTrue("Generated key must be valid.", key.getPublicKey().verifyKey());
    }
}
