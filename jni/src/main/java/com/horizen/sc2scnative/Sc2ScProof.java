package com.horizen.sc2scnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.provingsystemnative.ProvingSystem;

public class Sc2ScProof {
    private byte[] proof;

    static {
        Library.load();
    }

    /**
     * A wrap class for the Sidechain to sidechain proof. It's build from JNI part
     * from Sc2Sc.createProof().
     * 
     * @param proof
     */
    private Sc2ScProof(byte[] proof) {
        this.proof = proof;
    }

    public byte[] getProof() {
        return this.proof;
    }

    public Object getProofProvingSystemType() {
        return ProvingSystem.getProofProvingSystemType(proof);
    }

    private static native boolean nativeVerify(
            byte[] proof,
            FieldElement nextScTxCommitmentRoot,
            FieldElement currentScTxCommitmentRoot,
            FieldElement msgHash,
            String vKPath,
            boolean checkProof,
            boolean compressedProof,
            boolean checkVk,
            boolean compressedVk);

    /**
     * Verify a sidechain to sidechain redeemed message proof.
     * 
     * @param nextScTxCommitmentsRoot    - Next epoch sc tx root
     * @param currentScTxCommitmentsRoot - Current epoch sc tx root for
     * @param msgHash                    - Message hash
     * @param vkPath                     - Verification Key file path
     * @param checkProof                 - Do or not the proof sematic check
     * @param compressedProof            - Indicate if the proof is compressed or
     *                                   not
     * @param checkVk                    - Check or not check the verification key
     * @param compressedVk               - Indicate if the verification key is
     *                                   compressed or not
     * @return True if the the proof can be verified with the given public input and
     *         false otherwise.
     */
    public boolean verify(FieldElement nextScTxCommitmentsRoot, FieldElement currentScTxCommitmentsRoot,
            FieldElement msgHash, String vkPath,
            boolean checkProof, boolean compressedProof, boolean checkVk, boolean compressedVk) {
        return nativeVerify(this.proof, nextScTxCommitmentsRoot, currentScTxCommitmentsRoot, msgHash,
                vkPath, checkProof, compressedProof, checkVk, compressedVk);
    }

    /**
     * Verify a sidechain to sidechain redeemed message proof. In this case we
     * assume
     * that proof and the key are compressed and we check both.
     * 
     * @param nextScTxCommitmentsRoot    - Next epoch sc tx root
     * @param currentScTxCommitmentsRoot - Current epoch sc tx root for
     * @param msgHash                    - Message hash
     * @param vkPath                     - Verification Key file path
     * @return True if the the proof can be verified with the given public input and
     *         false otherwise.
     */
    public boolean verify(FieldElement nextScTxCommitmentsRoot, FieldElement currentScTxCommitmentsRoot,
            FieldElement msgHash, String vkPath) {
        return verify(nextScTxCommitmentsRoot, currentScTxCommitmentsRoot, msgHash,
                vkPath, true, true, true, true);
    }

    /**
     * Verify a sidechain to sidechain redeemed message proof. In this case we
     * assume
     * that proof and the key are compressed and we check both. This varian take
     * arrays
     * of bytes instead of FieldElement.
     * 
     * @param nextScTxCommitmentsRoot    - Next epoch sc tx root
     * @param currentScTxCommitmentsRoot - Current epoch sc tx root for
     * @param msgHash                    - Message hash
     * @param vkPath                     - Verification Key file path
     * @return True if the the proof can be verified with the given public input and
     *         false otherwise.
     */
    public boolean verify(byte[] nextScTxCommitmentsRootB, byte[] currentScTxCommitmentsRootB, byte[] msgHashB,
            String vkPath) {
        try (FieldElement nextScTxCommitmentsRoot = FieldElement.deserialize(nextScTxCommitmentsRootB);
                FieldElement currentScTxCommitmentsRoot = FieldElement.deserialize(currentScTxCommitmentsRootB);
                FieldElement msgHash = FieldElement.deserialize(msgHashB);) {
            return verify(nextScTxCommitmentsRoot, currentScTxCommitmentsRoot, msgHash, vkPath);
        }
    }
}
