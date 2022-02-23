package com.horizen.provingsystemnative;

import com.horizen.librustsidechains.Library;

import io.horizen.common.librustsidechains.DeserializationException;

public class ProvingSystem {

    static {
        Library.load();
    }

    private static native void nativeGenerateDLogKeys(
        ProvingSystemType psType,
        int maxSegmentSize
    ) throws ProvingSystemException;

    /**
     * Generates DLOG keys of specified size and stores them in memory
     * @param psType - the proving system for which generating the keys
     * @param segmentSize - the size of the keys
     * @throws ProvingSystemException if operation failed
     */
    public static void generateDLogKeys(
        ProvingSystemType psType,
        int segmentSize
    ) throws ProvingSystemException
    {
        nativeGenerateDLogKeys(psType, segmentSize);
    }

    private static native boolean nativeCheckProofVkSize(
        boolean zk,
        int supportedSegmentSize,
        int maxProofSize,
        int maxVkSize,
        String verificationKeyPath
    ) throws DeserializationException;

    /*
     * Given zk, supportedSegmentSize and vk, this function:
     * 1) Computes the size of the (compressed) proof that would be generated using this vk,
     *    and checks that is below maxProofSize;
     * 2) Checks that the size of the (compressed) vk is below maxVkSize.
     * NOTE: We expect the vk to be in compressed form. No checks on vk will be performed.
     */
    public static boolean checkProofVkSize(
        boolean zk,
        int supportedSegmentSize,
        int maxProofSize,
        int maxVkSize,
        String verificationKeyPath
    ) throws DeserializationException
    {
        return nativeCheckProofVkSize(zk, supportedSegmentSize, maxProofSize, maxVkSize, verificationKeyPath);
    }

    private static native int nativeGetProverKeyProvingSystemType(String provingKeyPath) throws DeserializationException;

    public static ProvingSystemType getProverKeyProvingSystemType(String provingKeyPath) throws DeserializationException {
        return ProvingSystemType.intToProvingSystemType(nativeGetProverKeyProvingSystemType(provingKeyPath));
    }

    private static native int nativeGetVerifierKeyProvingSystemType(String verifierKeyPath) throws DeserializationException;

    public static ProvingSystemType getVerifierKeyProvingSystemType(String verifierKeyPath) throws DeserializationException {
        return ProvingSystemType.intToProvingSystemType(nativeGetVerifierKeyProvingSystemType(verifierKeyPath));
    }

    private static native int nativeGetProofProvingSystemType(byte[] proof) throws DeserializationException;

    public static ProvingSystemType getProofProvingSystemType(byte[] proof) throws DeserializationException {
        return ProvingSystemType.intToProvingSystemType(nativeGetProofProvingSystemType(proof));
    }
}