package com.horizen.schnorrnative;

import com.horizen.vrfnative.VRFKeyGenerator;
import com.horizen.vrfnative.VRFSecretKey;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

public class SchnorrKeyGeneratorTest {


    @Test
    public void testGenerate() {

        SchnorrSecretKey key = SchnorrKeyGenerator.generate();

        assertTrue("Generated key must be valid.", key.getPublicKey().verifyKey());
    }
}
