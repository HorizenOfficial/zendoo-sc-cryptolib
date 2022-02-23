package com.horizen.cswnative;

import java.util.Optional;

import com.horizen.certnative.WithdrawalCertificate;
import io.horizen.common.librustsidechains.FieldElement;
import io.horizen.common.librustsidechains.NativeParsingException;

import com.horizen.provingsystemnative.ProvingSystemException;
import com.horizen.provingsystemnative.ProvingSystemType;

public class CswProof {

    private static native boolean nativeSetup(
        ProvingSystemType psType,
        int rangeSize,
        int numCustomFields,
        boolean isConstantPresent,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize,
        boolean compressPk,
        boolean compressVk
    ) throws ProvingSystemException;

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param isConstantPresent - whether the circuit must support the presence of a constant
     * @param segmentSize - the segment size to be used to generate (pk, vk). Must be smaller equal than
     *                      the segment size passed to the ProvingSystem.generateDLogKeys() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path to which saving the proving key
     * @param verificationKeyPath - file path to which saving the verification key
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk
     * @param compressPk - if the proving key must be saved to provingKeyPath in compressed form
     * @param compressVk - if the verification key must be saved to verificationKeyPath in compressed form
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     * @throws ProvingSystemException - if it was not possible to generate (pk, vk) pair
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int numCustomFields,
        boolean isConstantPresent,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize,
        boolean compressPk,
        boolean compressVk
    ) throws ProvingSystemException
    {
        return nativeSetup(
            psType, rangeSize, numCustomFields, isConstantPresent, segmentSize,
            provingKeyPath, verificationKeyPath, zk, maxProofPlusVkSize, compressPk,
            compressVk
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param isConstantPresent - whether the circuit must support the presence of a constant
     * @param segmentSize - the segment size to be used to generate (pk, vk). Must be smaller equal than
     *                      the segment size passed to the ProvingSystem.generateDLogKeys() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param zk - used to estimate the proof and vk size, tells if the proof will be created using zk or not
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise
     * @throws ProvingSystemException - if it was not possible to generate (pk, vk) pair
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int numCustomFields,
        boolean isConstantPresent,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        boolean zk,
        int maxProofPlusVkSize
    ) throws ProvingSystemException
    {
        return nativeSetup(
            psType, rangeSize, numCustomFields, isConstantPresent, segmentSize,
            provingKeyPath, verificationKeyPath, zk, maxProofPlusVkSize, true, true
        );
    }

    /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param isConstantPresent - whether the circuit must support the presence of a constant
     * @param segmentSize - the segment size to be used to generate (pk, vk). Must be smaller equal than
     *                      the segment size passed to the ProvingSystem.generateDLogKeys() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk, estimated assuming not to use zk property
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise.
     * @throws ProvingSystemException - if it was not possible to generate (pk, vk) pair
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int numCustomFields,
        boolean isConstantPresent,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        String verificationKeyPath,
        int maxProofPlusVkSize
    ) throws ProvingSystemException
    {
        return nativeSetup(
            psType, rangeSize, numCustomFields, isConstantPresent, segmentSize,
            provingKeyPath, verificationKeyPath, false, maxProofPlusVkSize, true, true
        );
    }

        /**
     * Generate (provingKey, verificationKey) pair for this circuit.
     * @param psType - proving system to be used
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param isConstantPresent - whether the circuit must support the presence of a constant
     * @param provingKeyPath - file path to which saving the proving key. Proving key will be saved in compressed form.
     * @param verificationKeyPath - file path to which saving the verification key. Verification key will be saved in compressed form.
     * @param maxProofPlusVkSize - maximum allowed size for proof + vk, estimated assuming not to use zk property
     * @return true if (pk, vk) generation and saving to file was successfull, false otherwise.
     * @throws ProvingSystemException - if it was not possible to generate (pk, vk) pair
     */
    public static boolean setup(
        ProvingSystemType psType,
        int rangeSize,
        int numCustomFields,
        boolean isConstantPresent,
        String provingKeyPath,
        String verificationKeyPath,
        int maxProofPlusVkSize
    ) throws ProvingSystemException
    {
        return nativeSetup(
            psType, rangeSize, numCustomFields, isConstantPresent, Optional.empty(),
            provingKeyPath, verificationKeyPath, false, maxProofPlusVkSize, true, true
        );
    }

    private static native Optional<String> nativeDebugCircuit(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        WithdrawalCertificate lastWcert,
        CswUtxoProverData utxoData,
        CswFtProverData ftData
    ) throws NativeParsingException, ProvingSystemException;

    /**
     * Checks if possible to create a valid proof with the supplied data. Useful to understand
     * the reason for which proof creation fails (usually some inconsistency with input data).
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @return an Optional containing the name of the first failing constraint if the supplied data don't satisfy
     *         all the circuit's constraints, and nothing if all constraints are satisfied.
     * @throws IllegalArgumentException - if inputs are not consistent
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs while performing circuit debugging
     */
    public static Optional<String> debugCircuit(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData
    ) throws IllegalArgumentException, NativeParsingException, ProvingSystemException
    {
        checkProofDataConsistency(sysData, lastWcert, utxoData, ftData);

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeDebugCircuit(
            rangeSize, numCustomFields, sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null)
        );
    }

    private static native byte[] nativeCreateProof(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        WithdrawalCertificate lastWcert,
        CswUtxoProverData utxoData,
        CswFtProverData ftData,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        boolean checkProvingKey,
        boolean zk,
        boolean compressed_pk,
        boolean compress_proof
    ) throws NativeParsingException, ProvingSystemException;

    /**
     * Checks consistency, in terms of data that must or must not be present, of the inputs supplied to the
     * proof creation methods, as described below.
     * @param sysData - certificate sys data.
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @throws IllegalArgumentException - if inputs are not consistent
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof creation
     */
    private static void checkProofDataConsistency(
        CswSysData sysData,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData
    ) throws IllegalArgumentException
    {
        if (utxoData.isPresent() && !lastWcert.isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo if the last WithdrawalCertificate is not specified !");

        if (utxoData.isPresent() && !sysData.getScLastWcertHash().isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo if the last WithdrawalCertificate hash is not specified in sysData!");

        if (utxoData.isPresent() && ftData.isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a SC Utxo and of a FT at the same time !");

        if (ftData.isPresent() && !sysData.getMcbScTxsComEnd().isPresent())
            throw new IllegalArgumentException("Cannot prove withdraw of a FT if mcbScTxsComEnd is not specified in sysData !");
    }

    /**
     * Compute proof for given parameters
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key
     * @param checkProvingKey - enable semantic checks on the proving key (WARNING: very expensive)
     * @param zk - if proof must be created using zk property or not
     * @param compressed_pk - if the pk read from provingKeyPath is in compressed form or not
     * @param compress_proof - whether to return the proof bytes in compressed form or not
     * @return the proof bytes
     * @throws IllegalArgumentException if utxoData is present but lastWcert is empty, or if utxoData and ftData are both present
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof creation
     */
    public static byte[] createProof(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        boolean checkProvingKey,
        boolean zk,
        boolean compressed_pk,
        boolean compress_proof
    )  throws NativeParsingException, ProvingSystemException, IllegalArgumentException 
    {
        checkProofDataConsistency(sysData, lastWcert, utxoData, ftData);

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            rangeSize, numCustomFields, sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            segmentSize, provingKeyPath, checkProvingKey, zk, compressed_pk, compress_proof
        );
    }

    /**
     * Compute proof for given parameters
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param checkProvingKey - enable semantic checks on the proving key (WARNING: very expensive)
     * @param zk - if proof must be created using zk property or not
     * @return the proof bytes
     * @throws IllegalArgumentException if utxoData is present but lastWcert is empty, or if utxoData and ftData are both present
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof creation
     */
    public static byte[] createProof(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        boolean checkProvingKey,
        boolean zk
    )  throws NativeParsingException, ProvingSystemException, IllegalArgumentException 
    {
        checkProofDataConsistency(sysData, lastWcert, utxoData, ftData);

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            rangeSize, numCustomFields, sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            segmentSize, provingKeyPath, checkProvingKey, zk, true, true
        );
    }

    /**
     * Compute proof for given parameters
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param scId - the id of the corresponding sidechain
     * @param sysData - certificate sys data.
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @param zk - if proof must be created using zk property or not
     * @return the proof bytes
     * @throws IllegalArgumentException if utxoData is present but lastWcert is empty, or if utxoData and ftData are both present
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof creation
     */
    public static byte[] createProof(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        Optional<Integer> segmentSize,
        String provingKeyPath,
        boolean zk
    )  throws NativeParsingException, ProvingSystemException, IllegalArgumentException 
    {
        checkProofDataConsistency(sysData, lastWcert, utxoData, ftData);

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            rangeSize, numCustomFields, sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            segmentSize, provingKeyPath, false, zk, true, true
        );
    }

    /**
     * Compute proof for given parameters. Zero knowledge will be used.
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @param segmentSize - the segment size to be used to create the proof.
     *                      Must be equal to the one passed to the setup() method.
     *                      If not specified, it will default to the same size as the one passed to
     *                      ProvingSystem.generateDLogKeys() method.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @return the proof bytes
     * @throws IllegalArgumentException if utxoData is present but lastWcert is empty, or if utxoData and ftData are both present
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof creation
     */
    public static byte[] createProof(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        Optional<Integer> segmentSize,
        String provingKeyPath
    )  throws NativeParsingException, ProvingSystemException, IllegalArgumentException 
    {
        checkProofDataConsistency(sysData, lastWcert, utxoData, ftData);

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            rangeSize, numCustomFields, sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            segmentSize, provingKeyPath, false, true, true, true
        );
    }

        /**
     * Compute proof for given parameters. Zero knowledge will be used.
     * @param rangeSize - number of blocks between `mcbScTxsComStart` and `mcbScTxsComEnd`
     * @param numCustomFields - exact number of custom fields the circuit must support
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param lastWcert - the last confirmed wcert in the MC. Can be empty if SC has ceased before we have at least
     *                    certs for 2 epochs (in this case we can only withdraw FT)
     * @param utxoData - data required to prove withdraw of a SC utxo. Must be empty if the prover wants to prove
     *                   withdraw of a FT instead. If this field is present, then lastWCert and sysData.scLastWCertHash
     *                   must be present too.
     * @param ftData - data required to prove withdraw of a FT. Must be empty if the prover wants to prove
     *                 withdraw of a SC utxo instead. If present, then sysData.mcbScTxsComEnd must be present too.
     * @param provingKeyPath - file path from which reading the proving key, expected to be in compressed form
     * @return the proof bytes
     * @throws IllegalArgumentException if utxoData is present but lastWcert is empty, or if utxoData and ftData are both present
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof creation
     */
    public static byte[] createProof(
        int rangeSize,
        int numCustomFields,
        CswSysData sysData,
        FieldElement scId,
        Optional<WithdrawalCertificate> lastWcert,
        Optional<CswUtxoProverData> utxoData,
        Optional<CswFtProverData> ftData,
        String provingKeyPath
    )  throws NativeParsingException, ProvingSystemException, IllegalArgumentException 
    {
        checkProofDataConsistency(sysData, lastWcert, utxoData, ftData);

        // Note: to avoid too much unpacking boilerplate Rust side, we pass the empty Optional instances as null pointer instead.
        return nativeCreateProof(
            rangeSize, numCustomFields, sysData, scId, lastWcert.orElse(null), utxoData.orElse(null), ftData.orElse(null),
            Optional.empty(), provingKeyPath, false, true, true, true
        );
    }

    private static native boolean nativeVerifyProof(
        CswSysData sysData,
        FieldElement scId,
        byte[] proof,
        boolean checkProof,
        boolean compressedProof,
        String verificationKeyPath,
        boolean checkVerificationKey,
        boolean compressedVk
    ) throws NativeParsingException, ProvingSystemException;

    /**
     * Verify proof using the supplied parameters
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param checkProof - enable semantic checks on the proof
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @param checkVerificationKey - enable semantic checks on the verification key
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof verification
     */
    public static boolean verifyProof(
        CswSysData sysData,
        FieldElement scId,
        byte[] proof,
        boolean checkProof,
        String verificationKeyPath,
        boolean checkVerificationKey
    ) throws NativeParsingException, ProvingSystemException
    {
        return nativeVerifyProof(
            sysData, scId, proof, checkProof, true, verificationKeyPath, checkVerificationKey, true
        );
    }

    /**
     * Verify proof using the supplied parameters
     * @param sysData - certificate sys data.
     * @param scId - the id of the corresponding sidechain
     * @param proof - the bytes of the proof to be verified, expected to be in compressed form
     * @param verificationKeyPath - file path from which loading the verification key, expected to be in compressed form
     * @return true, if proof verification was successfull, false if proof verification failed or if some errors occured during verification
     * @throws NativeParsingException - if some error occurs during data parsing native side
     * @throws ProvingSystemException - if some error occurs during proof verification
     */
    public static boolean verifyProof(
        CswSysData sysData,
        FieldElement scId,
        byte[] proof,
        String verificationKeyPath
    ) throws NativeParsingException, ProvingSystemException
    {
        return nativeVerifyProof(
            sysData, scId, proof, true, true, verificationKeyPath, false, true
        );
    }
}
