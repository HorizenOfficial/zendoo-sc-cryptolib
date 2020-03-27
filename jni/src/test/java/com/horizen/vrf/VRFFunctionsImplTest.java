package com.horizen.vrf;

import com.horizen.vrfnative.VRFKeyGenerator;
import com.horizen.vrfnative.VRFProof;
import com.horizen.vrfnative.VRFPublicKey;
import com.horizen.vrfnative.VRFSecretKey;
import org.junit.Test;

import java.util.EnumMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VRFFunctionsImplTest {


    @Test
    public void testProove() {

        VrfFunctionsImpl functions = new VrfFunctionsImpl();

        EnumMap<VrfFunctions.KeyType, byte[]> keyMap = functions.generatePublicAndSecretKeys(new byte[0]);

        assertTrue("Key generation must be successful.", !keyMap.isEmpty());
        assertTrue("Generated key must be valid.", functions.publicKeyIsValid(keyMap.get(VrfFunctions.KeyType.PUBLIC)));
        assertEquals("Secret key must has size - " + VRFSecretKey.SECRET_KEY_LENGTH,
                VRFSecretKey.SECRET_KEY_LENGTH,
                keyMap.get(VrfFunctions.KeyType.SECRET).length);

        byte[] secretKeyBytes = keyMap.get(VrfFunctions.KeyType.SECRET);
        byte[] publicKeyBytes = keyMap.get(VrfFunctions.KeyType.PUBLIC);

        byte[] message = new byte[VRFSecretKey.SECRET_KEY_LENGTH];

        byte[] proof = functions.createVrfProofForMessage(secretKeyBytes, publicKeyBytes, message);

        assertTrue("Proof must be valid.", functions.verifyMessage(message, publicKeyBytes, proof));
        assertEquals("Proof size must be " + VRFProof.VRF_PROOF_SIZE, VRFProof.VRF_PROOF_SIZE, proof.length);

        byte[] vrfHash = functions.vrfProofToVrfHash(publicKeyBytes, message, proof);

        assertEquals("VRF hash size must be " + VRFProof.VRF_PROOF_SIZE, VRFProof.VRF_PROOF_SIZE, vrfHash.length);
    }
}
