package com.horizen.vrfnative;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VRFProofTest {

    @Test
    public void testSign() {
        VRFKeyPair keyPair = VRFKeyPair.generate();

        byte[] message = new byte[96];

        VRFProof proof = keyPair.prove(message);

        byte[] proofBytes = proof.serializeProof();

        assertEquals("Proof length expected to be - " + VRFProof.PROOF_LENGTH,
                VRFProof.PROOF_LENGTH,
                proofBytes.length);

        VRFProof proof2 = VRFProof.deserialize(proofBytes);

        proof.freeProof();
        proof2.freeProof();

    }
}
