package com.horizen.cswnative;

import java.util.Optional;

import com.horizen.certnative.WithdrawalCertificate;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.provingsystemnative.CreateProofResult;
import com.horizen.provingsystemnative.ProvingSystemType;

public class CswProof {
    private static native boolean nativeSetup(
        ProvingSystemType psType,
        int rangeSize,
        int mstTreeHeight,
        int ftTreeHeight,
        int scTxCommTreeHeight,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize,
        boolean compressPk,
        boolean compressVk
    );

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param mstTreeHeight - Height of the MST, i.e. the SC Utxo tree
     * @param ftTreeHeight - Height of the FT subtree of the Commitment Tree of a particular SC
     * @param scTxCommTreeHeight - Height of the subtree of the SCsCommitmentTree having as leaves the single ScTxsCommitments 
     * @param provingKeyPath - file path to which saving the proving key
     * @param verificationKeyPath - file path to which saving the verification key
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk
     * @param compressPk - if the proving key must be saved to provingKeyPath in compressed form
     * @param compressVk - if the verification key must be saved to verificationKeyPath in compressed form
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int mstTreeHeight,
        int ftTreeHeight,
        int scTxCommTreeHeight,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize,
        boolean compressPk,
        boolean compressVk
    )
    {
        return nativeSetup(
            psType, rangeSize, mstTreeHeight, ftTreeHeight, scTxCommTreeHeight,
            provingKeyPath, verificationKeyPath, zk, maxProofPlusVkSize, compressPk, compressVk
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param mstTreeHeight - Height of the MST, i.e. the SC Utxo tree
     * @param ftTreeHeight - Height of the FT subtree of the Commitment Tree of a particular SC
     * @param scTxCommTreeHeight - Height of the subtree of the SCsCommitmentTree having as leaves the single ScTxsCommitments 
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param zk - used to estimate the proof and vk size, tells if the proof will be created using zk or not
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int mstTreeHeight,
        int ftTreeHeight,
        int scTxCommTreeHeight,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize
    )
    {
        return nativeSetup(
            psType, rangeSize, mstTreeHeight, ftTreeHeight, scTxCommTreeHeight,
            provingKeyPath, verificationKeyPath, zk, maxProofPlusVkSize, true, true
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param mstTreeHeight - Height of the MST, i.e. the SC Utxo tree
     * @param ftTreeHeight - Height of the FT subtree of the Commitment Tree of a particular SC
     * @param scTxCommTreeHeight - Height of the subtree of the SCsCommitmentTree having as leaves the single ScTxsCommitments  
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk, estimated assuming not to use zk property
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise.
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int mstTreeHeight,
        int ftTreeHeight,
        int scTxCommTreeHeight,
        String provingKeyPath,
        String verificationKeyPath,
        int maxProofPlusVkSize
    )
    {
        return nativeSetup(
            psType, rangeSize, mstTreeHeight, ftTreeHeight, scTxCommTreeHeight,
            provingKeyPath, verificationKeyPath, false, maxProofPlusVkSize, true, true
        );
    }

    private static native CreateProofResult nativeCreateProof(
        CswSysData sysData,
        FieldElement scId,
        WithdrawalCertificate lastWcert,
        CswUtxoProverData utxoData,
        CswFtProverData ftData,
        String provingKeyPath,
        boolean checkProvingKey,
        boolean zk,
        boolean compressed_pk,
        boolean compress_proof
    );

    /**
     * Compute proof for given parameters
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. It's empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert must be present too.
     * @param ftData - data required to prove withdraw of a FT. It's empty if the prover wants to prove
     *                 withdraw of a SC utxo instead.
     * @param provingKeyPath - file path from which reading the proving key
     * @param checkProvingKey - enable semantic checks on the proving key (WARNING: very expensive)
     * @param zk - if proof must be created using zk property or not
     * @param compressed_pk - if the pk read from provingKeyPath is in compressed form or not
     * @param compress_proof - whether to return the proof bytes in compressed form or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes and the quality of the certificate (i.e. in this case, number of valid signatures),
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        String provingKeyPath,
        boolean checkProvingKey,
        boolean zk,
        boolean compressed_pk,
        boolean compress_proof
    )
    {
        if (utxoData.isPresent() && lastWcert.isEmpty())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo if the last WithdrawalCertificate is not specified !");

        if (utxoData.isPresent() && ftData.isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo and of a FT at the same time !");

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            provingKeyPath, checkProvingKey, zk, compressed_pk, compress_proof
        );
    }

    /**
     * Compute proof for given parameters
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. It's empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert must be present too.
     * @param ftData - data required to prove withdraw of a FT. It's empty if the prover wants to prove
     *                 withdraw of a SC utxo instead.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param checkProvingKey - enable semantic checks on the proving key (WARNING: very expensive)
     * @param zk - if proof must be created using zk property or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes (in compressed form),
     *         and the quality of the certificate (i.e. in this case, number of valid signatures)
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        String provingKeyPath,
        boolean checkProvingKey,
        boolean zk
    )
    {
        if (utxoData.isPresent() && lastWcert.isEmpty())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo if the last WithdrawalCertificate is not specified !");

        if (utxoData.isPresent() && ftData.isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo and of a FT at the same time !");

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            provingKeyPath, checkProvingKey, zk, true, true
        );
    }

    /**
     * Compute proof for given parameters
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. It's empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert must be present too.
     * @param ftData - data required to prove withdraw of a FT. It's empty if the prover wants to prove
     *                 withdraw of a SC utxo instead.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param zk - if proof must be created using zk property or not
     * @return a CreateProofResult instance, i.e. the computed proof bytes (in compressed form),
     *         and the quality of the certificate (i.e. in this case, number of valid signatures);
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        String provingKeyPath,
        boolean zk
    )
    {
        if (utxoData.isPresent() && lastWcert.isEmpty())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo if the last WithdrawalCertificate is not specified !");

        if (utxoData.isPresent() && ftData.isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo and of a FT at the same time !");

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            provingKeyPath, false, zk, true, true
        );
    }

    /**
     * Compute proof for given parameters. Zero knowledge will be used.
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. It's empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert must be present too.
     * @param ftData - data required to prove withdraw of a FT. It's empty if the prover wants to prove
     *                 withdraw of a SC utxo instead.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @return a CreateProofResult instance, i.e. the computed proof bytes (in compressed form),
     *         and the quality of the certificate (i.e. in this case, number of valid signatures);
     *         OR null pointer if some errors occured during proof creation.
     */
    public static CreateProofResult createProof(
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        String provingKeyPath
    )
    {
        if (utxoData.isPresent() && lastWcert.isEmpty())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo if the last WithdrawalCertificate is not specified !");

        if (utxoData.isPresent() && ftData.isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo and of a FT at the same time !");

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            provingKeyPath, false, true, true, true
        );
    }

    private static native boolean nativeVerifyProof(
        CswSysData sysData,
        byte[] proof,
        boolean checkProof,
        boolean compressedProof,
        String verificationKeyPath,
        boolean checkVerificationKey,
        boolean compressedVk
    );

    /**
     * Verify proof using the supplied parameters
     * @param sysData - certificate sys data.
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param checkProof - enable semantic checks on the proof
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @param checkVerificationKey - enable semantic checks on the verification key
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     */
    public static boolean verifyProof(
        CswSysData sysData,
        byte[] proof,
        boolean checkProof,
        String verificationKeyPath,
        boolean checkVerificationKey
    )
    {
        return nativeVerifyProof(
            sysData, proof, checkProof, true, verificationKeyPath, checkVerificationKey, true
        );
    }

    /**
     * Verify proof using the supplied parameters
     * @param sysData - certificate sys data.
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     */
    public static boolean verifyProof(
        CswSysData sysData,
        byte[] proof,
        String verificationKeyPath
    )
    {
        return nativeVerifyProof(
                sysData, proof, true, true, verificationKeyPath, false, true
        );
    }
}
