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
    }

    @Test
    public void testProveVerify() {
        VRFKeyPair keyPair = VRFKeyPair.generate();

        assertNotNull("Key pair generation was unsuccessful.", keyPair);
        assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

        FieldElement fieldElement = FieldElement.createFromLong(123456789L);

        VRFProveResult proofVRFOutputPair = keyPair.prove(fieldElement);

        assertNotNull("Attempt to create vrf proof and output failed.", proofVRFOutputPair);

        FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), fieldElement);

        assertNotNull("VRF Proof verification and VRF Output computation has failed.", vrfOutput);

        assertEquals("prove() and proof_to_hash() vrf outputs must be equal", proofVRFOutputPair.getVRFOutput(), vrfOutput);

        FieldElement wrongFieldElement = FieldElement.createFromLong(123456780L);

        assertNull("VRF Proof verification must fail", keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), wrongFieldElement));

    }
}
