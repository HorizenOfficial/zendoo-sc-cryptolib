package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import static org.junit.Assert.*;

public class VRFKeyPairTest {

    @Test
    public void testGenerate() throws Exception {

        try(VRFKeyPair keyPair = VRFKeyPair.generate())
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);

            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
        }
    }

    @Test
    public void testDeriveFromSeed() throws Exception {
        byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] expectedPubKeyBytes = {-41, 6, 40, 40, 18, 36, 100, -72, -107, 103, 60, -47, 40, -5, -119, 103, 89, 31, 82, 66, -98, 103, -128, 57, -116, -108, 81, -33, -8, -101, -95, 14, 0};
        byte[] expectedSecretKeyBytes = {-104, -120, -125, 121, 24, -25, -109, -49, -98, 17, -91, 15, 27, 14, 16, -54, 123, 57, 79, -88, 0, -82, -17, 72, -74, -109, 77, 66, 7, 113, 104, 62};
        try(VRFKeyPair keyPair = VRFKeyPair.generate(seed))
        {
            assertNotNull("Key pair derive from seed was unsuccessful", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
            assertArrayEquals("Derive from seed didn't produce the expected public key", expectedPubKeyBytes, keyPair.getPublicKey().serializePublicKey());
            assertArrayEquals("Derive from seed didn't produce the expected secret key", expectedSecretKeyBytes, keyPair.getSecretKey().serializeSecretKey());
        }
        byte[] emptySeed = {};
        try(VRFKeyPair keyPair = VRFKeyPair.generate(seed))
        {
            assertNotNull("Key pair derive from empty seed was unsuccessful", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
        }
    }

    @Test
    public void testProveVerify() throws Exception {

        byte[] skBytes = {
                -13, 0, 45, -95, -7, -33, 91, -25, 64, -61, 30, -6, -123, -76, 32, -84, -59, 31, 73, -80, 74, -90, 123,
                -16, -2, -38, -46, 77, -61, 85, 87, 13
        };

        byte[] messageBytes = {
                -34, 96, -95, 35, 12, 73, 93, 31, -102, -64, 57, -41, -8, -117, -87, 108, 63, 111, 83, -21, -88, -56,
                55, -22, 23, 42, 78, 64, -97, -75, 91, 57
        };

        byte[] proofBytes = {
                -41, 88, 68, -53, 53, -86, 97, -102, -66, 21, -76, 10, 36, 3, -58, -106, 24, 121, 97, -70, 93, -28, 77,
                107, 73, 16, -12, -92, 49, -109, 29, 42, 0, -106, 94, -22, -57, -49, 31, 28, -92, 95, 69, 78, -11, -59,
                52, 54, -80, -35, -25, -39, 19, -116, 87, -90, 114, 43, 95, -48, -86, 18, 96, -92, 56, 101, 43, -33,
                -118, 6, 99, -75, -102, 87, 63, 67, 119, 78, 30, -58, 95, 52, -9, 106, -81, 101, -3, -25, 47, -108, 126,
                76, -81, -39, -96, 72, 44
        };

        byte[] vrfOutputBytes = {
                70, -65, -88, 45, 45, -83, 43, -81, 68, 68, -82, 109, 108, 19, 22, -78, 88, 39, -30, -30, -24, -14, 29,
                116, -96, -115, 95, 5, 22, -93, 32, 9
        };

        try
        (
            VRFSecretKey sk = VRFSecretKey.deserialize(skBytes);
            VRFKeyPair keyPair = new VRFKeyPair(sk);
            FieldElement message = FieldElement.deserialize(messageBytes);
            VRFProof proof = VRFProof.deserialize(proofBytes);
            FieldElement expectedVrfOutput = FieldElement.deserialize(vrfOutputBytes)
        )
        {
            assertNotNull("sk deserialization must not fail", sk);
            assertNotNull("message deserialization must not fail", message);
            assertNotNull("proof deserialization must not fail", proof);
            assertNotNull("expectedVrfOutput deserialization must not fail", sk);

            try(FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proof, message))
            {
                assertNotNull("VRF Proof verification and VRF Output computation has failed.", vrfOutput);

                // Check vrfOutput == expectedVrfOutput
                assertEquals("vrfOutput and expectedVrfOutput must be equal", vrfOutput, expectedVrfOutput);
            }
        }
    }

    @Test
    public void testRandomProveVerify() throws Exception {
        int samples = 100;

        for(int i = 0; i < samples; i++) {
            try
            (
                VRFKeyPair keyPair = VRFKeyPair.generate();
                FieldElement fieldElement = FieldElement.createRandom();
                FieldElement wrongFieldElement = FieldElement.createRandom()
            )
            {
                assertNotNull("Key pair generation was unsuccessful.", keyPair);
                assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

                try
                (
                    VRFProveResult proofVRFOutputPair = keyPair.prove(fieldElement);
                    FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), fieldElement)
                )
                {
                    assertNotNull("Attempt to create vrf proof and output failed.", proofVRFOutputPair);
                    assertNotNull("VRF Proof verification and VRF Output computation must not fail.", vrfOutput);
                    assertEquals("prove() and proof_to_hash() vrf outputs must be equal", proofVRFOutputPair.getVRFOutput(), vrfOutput);
                    assertNull("VRF Proof verification must fail", keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), wrongFieldElement));
                }
            }
        }
    }
}
