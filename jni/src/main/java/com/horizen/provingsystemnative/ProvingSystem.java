package com.horizen.provingsystemnative;

import com.horizen.librustsidechains.Library;
import java.util.Optional;

public class ProvingSystem {

    static {
        Library.load();
    }

    private static native boolean nativeGenerateDLogKeys(
        ProvingSystemType psType,
        int maxSegmentSize,
        int supportedSegmentSize
    );

    /*
    * Generates DLOG keys of specified size and stores them in memory
    * Returns True if operation was successfull, False otherwise.
    * NOTE: SC is allowed to arbitrarly choose a segment size (via the parameter
    *       `supportedSegmentSize`), regardless of the size of the MC ones;
    *       However, we need to enforce SC keys being derived from MC keys,
    *       and this internally requires to specify also the segment size chosen
    *       by the MC (via the parameter maxSegmentSize).
    *       Also, if supportedSegmentSize > maxSegmentSize, this function will
    *       return False.
    * */
    public static boolean generateDLogKeys(
        ProvingSystemType psType,
        int maxSegmentSize,
        int supportedSegmentSize
    )
    {
        return nativeGenerateDLogKeys(psType, maxSegmentSize, supportedSegmentSize);
    }

    private static native boolean nativeCheckProofVkSize(
        boolean zk,
        int supportedSegmentSize,
        int maxProofSize,
        int maxVkSize,
        String verificationKeyPath
    );

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
    )
    {
        return nativeCheckProofVkSize(zk, supportedSegmentSize, maxProofSize, maxVkSize, verificationKeyPath);
    }

    private static native int nativeGetProverKeyProvingSystemType(String provingKeyPath);

    public static ProvingSystemType getProverKeyProvingSystemType(String provingKeyPath) {
        return ProvingSystemType.intToProvingSystemType(nativeGetProverKeyProvingSystemType(provingKeyPath));
    }

    private static native int nativeGetVerifierKeyProvingSystemType(String verifierKeyPath);

    public static ProvingSystemType getVerifierKeyProvingSystemType(String verifierKeyPath) {
        return ProvingSystemType.intToProvingSystemType(nativeGetVerifierKeyProvingSystemType(verifierKeyPath));
    }

    private static native int nativeGetProofProvingSystemType(byte[] proof);

    public static ProvingSystemType getProofProvingSystemType(byte[] proof) {
        return ProvingSystemType.intToProvingSystemType(nativeGetProofProvingSystemType(proof));
    }
}