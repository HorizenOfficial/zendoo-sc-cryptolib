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
            int supportedSegmentSize,
            String g1KeyPath,
            String g2KeyPath
    );

    /*
    * Generates DLOG keys of specified size, stores them in memory
    * and saves them to files at g1KeyPath and g2KeyPath if not present.
    * If already present, simply loads the keys from them.
    * If COBOUNDARY_MARLIN ProvingSystemType is chosen, there is no need
    * to specify g2KeyPath; however, if DARLIN is chosen this function returns
    * an exception if g2KeyPath is not specified.
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
            int supportedSegmentSize,
            String g1KeyPath,
            Optional<String> g2KeyPath
    )
    {
        if (psType == ProvingSystemType.COBOUNDARY_MARLIN) {
            return nativeGenerateDLogKeys(psType, maxSegmentSize, supportedSegmentSize, g1KeyPath, "");
        } else {
            if (!g2KeyPath.isPresent()) {
                throw new IllegalArgumentException("If DARLIN ProvingSystemType is chosen, then g2KeyPath must be specified");
            }
            return nativeGenerateDLogKeys(psType, maxSegmentSize, supportedSegmentSize, g1KeyPath, g2KeyPath.get());
        }
    }
}