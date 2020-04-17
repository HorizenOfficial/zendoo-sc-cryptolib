package com.horizen.schnorrnative;

public class SchnorrSignatureTest {

    /*
    @Test
    public void testSign() {
        SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

        byte[] message = new byte[96];

        SchnorrSignature signature = keyPair.signMessage(message);

        byte[] signatureBytes = signature.serializeSignature();

        assertEquals("Signature length expected to be - " + SchnorrSignature.SIGNATURE_LENGTH,
                SchnorrSignature.SIGNATURE_LENGTH,
                signatureBytes.length);

        SchnorrSignature signature2 = SchnorrSignature.deserialize(signatureBytes);

        assertTrue("Signature must be valid.", keyPair.getPublicKey().verifySignature(signature, message));
        assertTrue("Signature must be valid.", keyPair.getPublicKey().verifySignature(signature2, message));

        signature.freeSignature();
        signature2.freeSignature();

    }
    */
}
