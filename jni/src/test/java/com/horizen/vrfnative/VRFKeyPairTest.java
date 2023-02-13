package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import static org.junit.Assert.*;

public class VRFKeyPairTest {

    @Test
    public void testGenerate() {

        try(VRFKeyPair keyPair = VRFKeyPair.generate())
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);

            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
        }
    }

    @Test
    public void testDeriveFromSeed() {
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
    public void testProveVerify() {

        byte[] skBytes = {
                -98, -107, -105, 70, 63, -92, -96, -24, 74, 29, 13, 80, 120, -45, 11, 125, 40, 52, 50, -92, -55, -35,
                81, -82, 2, 82, -16, -62, 44, 94, 54, 1
        };

        byte[] messageBytes = {
                -105, 7, 69, -103, -87, -108, 66, -72, -103, 77, -20, -74, -115, -59, 70, -96, 47, -11, 63, -117, -56,
                38, 36, 35, 79, 11, 86, 3, -76, 0, 18, 12
        };

        byte[] proofBytes = {
                63, -128, -38, 47, 121, -41, 43, 63, 93, -98, -91, -117, -118, -26, 2, -6, -108, 8, 39, 81, -108, -16,
                127, 97, -9, -61, 40, -63, -88, 17, -85, 48, 0, -14, -39, -66, 25, 98, 70, 37, -19, 56, 43, 125, 60,
                -82, 79, -96, 122, 16, -22, -9, -11, 14, 86, -103, -126, 41, -94, -128, -12, -10, -98, -113, 8, 2, 3,
                65, -22, 98, 119, 51, 26, -91, 70, 52, 116, 80, -120, 89, -104, -41, 71, 103, 32, 80, -97, 69, -13, -49,
                82, 55, 59, 42, 74, -107, 21
        };

        byte[] vrfOutputBytes = {
                13, -41, -81, 103, -94, 44, -103, 18, 3, 72, 58, 27, 16, -9, 4, 82, -99, 43, -83, -87, 2, -63, 115, -98,
                -16, 109, -113, -83, -1, -96, 25, 37
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
    public void testRandomProveVerify() {
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
