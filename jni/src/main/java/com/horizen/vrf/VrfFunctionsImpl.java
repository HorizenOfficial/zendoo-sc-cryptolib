package com.horizen.vrf;

import com.horizen.vrfnative.VRFKeyGenerator;
import com.horizen.vrfnative.VRFPublicKey;
import com.horizen.vrfnative.VRFSecretKey;

import java.util.EnumMap;

public class VrfFunctionsImpl
    implements VrfFunctions
{
    @Override
    public EnumMap<KeyType, byte[]> generatePublicAndSecretKeys(byte[] seed) {
        byte[] secretKeyBytes = new byte[VRFSecretKey.SECRET_KEY_LENGTH];
        byte[] publicKeyBytes = new byte[VRFPublicKey.PUBLIC_KEY_LENGTH];
        if (VRFKeyGenerator.nativeGenerate(secretKeyBytes, publicKeyBytes)) {
            EnumMap<KeyType, byte[]> keyMap = new EnumMap<KeyType, byte[]>(VrfFunctions.KeyType.class);
            keyMap.put(KeyType.SECRET, secretKeyBytes);
            keyMap.put(KeyType.PUBLIC, publicKeyBytes);
            return keyMap;
        }
        else
            throw new RuntimeException("Error during keys generation.");
    }

    @Override
    public byte[] createVrfProofForMessage(byte[] secretKey, byte[] publicKey, byte[] message) {
        return VRFSecretKey.nativeProve(publicKey, secretKey, message);
    }

    @Override
    public boolean verifyMessage(byte[] message, byte[] publicKey, byte[] proofBytes) {
        return VRFPublicKey.nativeVerify(publicKey, message, proofBytes);
    }

    @Override
    public boolean publicKeyIsValid(byte[] publicKey) {
        return VRFPublicKey.nativeVerifyKey(publicKey);
    }

    @Override
    public byte[] vrfProofToVrfHash(byte[] publicKey, byte[] message, byte[] proof) {
        return VRFSecretKey.nativeVRFHash(message, publicKey, proof);
    }
}
