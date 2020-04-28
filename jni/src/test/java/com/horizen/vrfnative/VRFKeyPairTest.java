package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrSignature;
import org.junit.Test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class VRFKeyPairTest {


    @Test
    public void testGenerate() {

        VRFKeyPair keyPair = VRFKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);

        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

        //Free memory
        keyPair.getPublicKey().freePublicKey();
        keyPair.getSecretKey().freeSecretKey();
    }

    @Test
    public void testProveVerify() {

        // Deserialize sk and compute pk from it
        byte[] skBytes = {
            80, 44, -1, -119, 0, -104, -59, 27, -40, 20, -98, -86, -56, 109, -97, -8, -110, 73, -103, 39, 98, -50, -31,
            -60, 21, -74, 31, 43, -127, 37, 0, -13, 90, -68, 40, 89, 86, 63, -102, 8, -33, 74, -66, -36, -63, -98, 68,
            14, -66, 119, -27, 26, 81, 55, -127, -41, -4, -1, 22, 113, 77, -50, -44, -39, 97, 76, -97, -102, 85, -77,
            -106, -102, 105, 53, 77, -20, 114, 119, 118, 55, -96, -90, 60, 41, -72, 87, -48, -14, -98, 103, -71, 110,
            47, -26, 0, 0
        };
        VRFSecretKey sk = VRFSecretKey.deserializeSecretKey(skBytes);

        assertNotNull("sk deserialization must not fail", sk);

        VRFKeyPair keyPair = new VRFKeyPair(sk);

        // Deserialize message
        byte[] messageBytes = {
            99, -36, -16, -69, -122, 79, 69, -107, 13, -53, 103, -123, 15, 93, 94, 42, -99, 91, -116, 51, -86, 120, -51,
            83, -51, -44, -127, -65, -73, 109, 44, -92, 121, 54, 17, 61, -119, 58, 111, 11, -63, 36, 39, 31, 104, -45,
            20, 91, -63, 72, -59, -68, 67, 1, 55, 109, -9, -96, 125, -101, -62, 119, 41, -93, -89, -68, 17, -1, 85, 45,
            -71, 72, -48, -107, 18, -57, 91, -101, -105, -36, 31, 89, -113, -16, -61, 81, -96, 56, 112, 18, 115, -10,
            -114, 53, 0, 0
        };
        FieldElement message = FieldElement.deserialize(messageBytes);

        assertNotNull("message deserialization must not fail", sk);

        // Deserialize proof
        byte[] proofBytes = {
            -97, 57, -87, -104, 8, 59, -34, -19, -21, 123, 56, 26, 63, -43, 90, 11, -126, 50, -50, 109, -118, -70, -97,
            69, 86, 102, 94, 105, -32, 61, 64, -16, -61, -55, -90, 47, 68, 81, -110, 84, 62, 112, 6, 122, 85, 115, 111,
            83, -114, 43, 1, 72, 89, -25, -84, 113, -69, -112, -87, -106, -62, 40, -94, 65, 83, 91, 113, -65, 79, -62,
            60, -43, -75, 9, -35, 91, 116, -28, -15, -94, -58, -50, 110, 38, 41, 36, -91, 93, 16, -30, -58, 46, 54, 25,
            1, 0, -112, -123, 108, 13, 32, -8, 29, 106, 117, 71, 66, 0, 28, -16, 63, -44, 76, 122, 4, -106, -91, 69,
            -28, 102, -22, -40, -7, 61, -32, -14, 109, 15, 59, -35, -98, 108, 81, 9, 88, -58, -64, 43, 99, -117, 80,
            127, 51, 57, 53, -77, 71, 49, -49, 43, 116, -43, 112, -33, 20, -118, 66, -76, -110, 35, -60, -98, 75, -100,
            -122, 98, -19, 115, 87, -81, 32, -17, 85, -61, 89, 100, 23, -95, -86, 50, 121, -43, 14, -53, 99, -33, 22,
            117, 66, 53, 1, 0, 0, -90, -69, -26, -122, 34, 106, -56, 82, -67, 31, -68, 36, -128, -128, -91, -124, -124,
            47, -73, -91, -28, -16, -57, 120, -63, 111, 86, 76, 14, 31, -107, 86, 0, -102, 68, -111, 19, 2, -50, -118,
            -54, -28, 65, -11, 3, 99, -91, -111, 112, 56, 31, 42, 104, -108, 87, -118, 35, 82, -2, -26, -112, -46, -32,
            -23, -26, -92, 126, -98, -122, 112, 24, 74, 6, 73, 83, -108, 120, 104, -37, -73, -126, 58, 6, -86, 8, -60,
            125, 58, -40, -11, -88, -89, 118, -21, 0, 0, -99, 120, 59, -121, 13, -31, 39, -116, -11, 9, 43, 50, -82,
            117, -108, 71, 2, 48, -90, 47, -42, -4, -5, 74, 75, -36, 32, -16, -38, -14, -113, -64, 9, -116, -3, -43,
            -119, -11, 113, 77, -58, 84, -114, 20, 86, -57, -62, -120, 70, 101, -31, -93, -18, 52, 37, 96, 15, 6, 69,
            59, -123, -125, -102, -33, -113, -13, 58, 78, 56, 75, -54, 98, -43, -103, 32, 83, -72, -27, 76, 112, 13, 82,
            71, 32, -31, 110, 42, -11, -48, 47, -34, 107, -26, 109, 0, 0
        };
        VRFProof proof = VRFProof.deserialize(proofBytes);

        assertNotNull("proof deserialization must not fail", proof);

        // Deserialize VRF Output
        byte[] vrfOutputBytes = {
            -115, -106, -59, -105, 106, 104, -95, -83, 72, 24, 6, 73, 83, -32, -126, 8, -125, 56, -99, -46, -107, -121,
            -42, -4, -66, 37, 49, -48, -111, 65, 27, 34, 95, -17, -2, -101, 102, 58, -19, -61, 3, 30, 21, 37, -83, -23,
            -96, 91, -47, -101, -72, 8, 62, 7, 60, 52, 9, -112, 78, 98, -52, -120, 79, -55, -22, 67, -16, -18, 47, -39,
            57, 15, -55, 52, 118, -89, -67, 65, -70, 52, 72, 110, -58, 80, 84, -78, -27, -91, -23, -11, -128, -19, -63,
            44, 0, 0
        };
        FieldElement expectedVrfOutput = FieldElement.deserialize(vrfOutputBytes);

        assertNotNull("expectedVrfOutput deserialization must not fail", sk);

        // Verify proof and get vrf output
        FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proof, message);

        assertNotNull("VRF Proof verification and VRF Output computation has failed.", vrfOutput);

        // Check vrfOutput == expectedVrfOutput
        assertEquals("vrfOutput and expectedVrfOutput must be equal", vrfOutput, expectedVrfOutput);

        //Free memory
        keyPair.getPublicKey().freePublicKey();
        keyPair.getSecretKey().freeSecretKey();

        message.freeFieldElement();
        vrfOutput.freeFieldElement();
        expectedVrfOutput.freeFieldElement();

        proof.freeProof();
    }

    @Test
    public void testRandomProveVerify() {
        int samples = 100;

        for(int i = 0; i < samples; i++) {
            VRFKeyPair keyPair = VRFKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

            FieldElement fieldElement = FieldElement.createRandom();

            VRFProveResult proofVRFOutputPair = keyPair.prove(fieldElement);

            assertNotNull("Attempt to create vrf proof and output failed.", proofVRFOutputPair);

            FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), fieldElement);

            assertNotNull("VRF Proof verification and VRF Output computation must not fail.", vrfOutput);

            assertEquals("prove() and proof_to_hash() vrf outputs must be equal", proofVRFOutputPair.getVRFOutput(), vrfOutput);

            FieldElement wrongFieldElement = FieldElement.createRandom();

            assertNull("VRF Proof verification must fail", keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), wrongFieldElement));

            //Free memory
            keyPair.getPublicKey().freePublicKey();
            keyPair.getSecretKey().freeSecretKey();

            fieldElement.freeFieldElement();
            wrongFieldElement.freeFieldElement();

            vrfOutput.freeFieldElement();
            proofVRFOutputPair.getVRFOutput().freeFieldElement();

            proofVRFOutputPair.getVRFProof().freeProof();
        }
    }
}
