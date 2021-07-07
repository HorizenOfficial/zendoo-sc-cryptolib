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
}