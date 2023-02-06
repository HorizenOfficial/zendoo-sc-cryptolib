package com.horizen.schnorrnative;

import java.util.List;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;

public class ValidatorKeysUpdatesList implements AutoCloseable {
    private SchnorrPublicKey[] signingKeys;
    private SchnorrPublicKey[] masterKeys;
    private SchnorrPublicKey[] updatedSigningKeys;
    private SchnorrPublicKey[] updatedMasterKeys;
    private SchnorrSignature[] updatedSigningKeysSkSignatures;
    private SchnorrSignature[] updatedSigningKeysMkSignatures;
    private SchnorrSignature[] updatedMasterKeysSkSignatures;
    private SchnorrSignature[] updatedMasterKeysMkSignatures;
    private long maxPks;

    static {
        Library.load();
    }

    private static native FieldElement nativeKeysRootHash(
        SchnorrPublicKey[] signingKeys,
        SchnorrPublicKey[] masterKeys,
        long maxPks
    ) throws Exception;

    /**
    * Create a set group for validators keys and signature updates.
    *
    * @param signingKeysList - The current signers' public keys.
    * @param masterKeysList - The current signers' master public keys.
    * @param updatedSigningKeysList - The list of updated signing keys.
    *                                 Should be equal to `signingKeysList` except where keys have changed.
    *                                 If no keys have changed, then this list should be
    *                                 equal to `signingKeysList`.
    * @param updatedMasterKeysList - The list of updated master signing keys.
    *                                Should be equal to `masterKeysList` except where keys have changed.
    *                                If no keys have changed, then this list should be
    *                                equal to `masterKeysList`.
    * @param updatedSigningKeysSkSignaturesList - signatures made with old signing keys for new signing keys,
    *                                             elements can be empty if there was no update
    * @param updatedSigningKeysMkSignaturesList - signatures made with old master keys for new signing keys,
    *                                             elements can be empty if there was no update
    * @param updatedMasterKeysSkSignaturesList - signatures made with old signing keys for new master keys,
    *                                            elements can be empty if there was no update
    * @param updatedMasterKeysMkSignaturesList - signatures made with old master keys for new master keys,
    *                                            elements can be empty if there was no update
    * @param maxPks - the maximum number of key validators
    */
    public ValidatorKeysUpdatesList(
        List<SchnorrPublicKey> signingKeysList,
        List<SchnorrPublicKey> masterKeysList,
        List<SchnorrPublicKey> updatedSigningKeysList,
        List<SchnorrPublicKey> updatedMasterKeysList,
        List<SchnorrSignature> updatedSigningKeysSkSignaturesList,
        List<SchnorrSignature> updatedSigningKeysMkSignaturesList,
        List<SchnorrSignature> updatedMasterKeysSkSignaturesList,
        List<SchnorrSignature> updatedMasterKeysMkSignaturesList,
        long maxPks
    ) {
        this.signingKeys = signingKeysList.toArray(new SchnorrPublicKey[0]);
        this.masterKeys = masterKeysList.toArray(new SchnorrPublicKey[0]);
        this.updatedSigningKeys = updatedSigningKeysList.toArray(new SchnorrPublicKey[0]);
        this.updatedMasterKeys = updatedMasterKeysList.toArray(new SchnorrPublicKey[0]);
        this.updatedSigningKeysSkSignatures = updatedSigningKeysSkSignaturesList.toArray(new SchnorrSignature[0]);
        this.updatedSigningKeysMkSignatures = updatedSigningKeysMkSignaturesList.toArray(new SchnorrSignature[0]);
        this.updatedMasterKeysSkSignatures = updatedMasterKeysSkSignaturesList.toArray(new SchnorrSignature[0]);
        this.updatedMasterKeysMkSignatures = updatedMasterKeysMkSignaturesList.toArray(new SchnorrSignature[0]);
        this.maxPks = maxPks;
    }

    public SchnorrPublicKey[] getSigningKeys() {
        return signingKeys;
    }

    public SchnorrPublicKey[] getMasterKeys() {
        return masterKeys;
    }

    /**
    * Utility: computes the validator keys merkle root given the set of signing keys
    * and master keys passed as input to the function.
    *
    * @param signingKeys - The signers' public keys.
    * @param masterKeys - The signers' master public keys.
    * @param maxPks - Maximum number of pks
    * @return the merkle root given the set of signing keys and master keys passed as input
    *         to the function
    * @throws Exception - if it was not possible to compute the root
    */
    public static FieldElement getInputKeysRootHash(
        SchnorrPublicKey[] signingKeys,
        SchnorrPublicKey[] masterKeys,
        long maxPks
    ) throws Exception {
        return nativeKeysRootHash(
            signingKeys, masterKeys, maxPks
        );
    }

    /**
    * Computes the current validator keys merkle root.
    *
    * @param maxPks - Maximum number of pks
    * @return the current validator keys merkle root.
    * @throws Exception - if it was not possible to compute the root
    */
    public FieldElement getKeysRootHash() throws Exception {
        return nativeKeysRootHash(
            signingKeys, masterKeys, maxPks
        );
    }

    public SchnorrPublicKey[] getUpdatedSigningKeys() {
        return updatedSigningKeys;
    }

    public SchnorrPublicKey[] getUpdatedMasterKeys() {
        return updatedMasterKeys;
    }

    /**
    * Computes the updated validator keys merkle root.
    *
    * @param maxPks - Maximum number of pks
    * @return the updated validator keys merkle root
    * @throws Exception - if it was not possible to compute the root
    */
    public FieldElement getUpdatedKeysRootHash() throws Exception {
        return nativeKeysRootHash(
            updatedSigningKeys, updatedMasterKeys, maxPks
        );
    }

    public SchnorrSignature[] getUpdatedSigningKeysSkSignatures() {
        return updatedSigningKeysSkSignatures;
    }

    public SchnorrSignature[] getUpdatedSigningKeysMkSignatures() {
        return updatedSigningKeysMkSignatures;
    }

    public SchnorrSignature[] getUpdatedMasterKeysSkSignatures() {
        return updatedMasterKeysSkSignatures;
    }

    public SchnorrSignature[] getUpdatedMasterKeysMkSignatures() {
        return updatedMasterKeysMkSignatures;
    }

    public void setUpdatedSigningKeysSkSignatures(SchnorrSignature[] updatedSigningKeysSkSignatures) {
        this.updatedSigningKeysSkSignatures = updatedSigningKeysSkSignatures;
    }

    public void setUpdatedSigningKeysMkSignatures(SchnorrSignature[] updatedSigningKeysMkSignatures) {
        this.updatedSigningKeysMkSignatures = updatedSigningKeysMkSignatures;
    }

    public void setUpdatedMasterKeysSkSignatures(SchnorrSignature[] updatedMasterKeysSkSignatures) {
        this.updatedMasterKeysSkSignatures = updatedMasterKeysSkSignatures;
    }

    public void setUpdatedMasterKeysMkSignatures(SchnorrSignature[] updatedMasterKeysMkSignatures) {
        this.updatedMasterKeysMkSignatures = updatedMasterKeysMkSignatures;
    }

    public void setSigningKeys(SchnorrPublicKey[] signingKeys) {
        this.signingKeys = signingKeys;
    }

    public void setMasterKeys(SchnorrPublicKey[] masterKeys) {
        this.masterKeys = masterKeys;
    }

    public void setUpdatedSigningKeys(SchnorrPublicKey[] updatedSigningKeys) {
        this.updatedSigningKeys = updatedSigningKeys;
    }

    public void setUpdatedMasterKeys(SchnorrPublicKey[] updatedMasterKeys) {
        this.updatedMasterKeys = updatedMasterKeys;
    }

    @Override
    public void close() throws Exception {
        for (SchnorrPublicKey pk : signingKeys)
            pk.close();
        for (SchnorrPublicKey pk : masterKeys)
            pk.close();
        for (SchnorrPublicKey pk : updatedSigningKeys)
            pk.close();
        for (SchnorrPublicKey pk : updatedMasterKeys)
            pk.close();
        for (SchnorrSignature sig : updatedSigningKeysSkSignatures)
            sig.close();
        for (SchnorrSignature sig : updatedSigningKeysMkSignatures)
            sig.close();
        for (SchnorrSignature sig : updatedMasterKeysSkSignatures)
            sig.close();
        for (SchnorrSignature sig : updatedMasterKeysMkSignatures)
            sig.close();
    }
}