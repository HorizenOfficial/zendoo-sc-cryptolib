package com.horizen.provingsystemnative;

import com.horizen.librustsidechains.Library;
import java.util.Optional;

public class ProvingSystem {

    static {
        Library.load();
    }

    public enum ProvingSystemType {
        COBOUNDARY_MARLIN,
        DARLIN
    }

    private static native boolean nativeGenerateDLogKeys(
            ProvingSystemType psType,
            int segmentSize,
            String g1KeyPath,
            String g2KeyPath
    );

    /*
    * Generates DLOG keys of specified segmentSize, stores them in memory
    * and saves them to files at g1KeyPath and g2KeyPath if not present.
    * If already present, simply loads the keys from them.
    * If COBOUNDARY_MARLIN ProvingSystemType is chosen, there is no need
    * to specify g2KeyPath; however, if DARLIN is chosen this function returns
    * an exception if g2KeyPath is not specified.
    * Returns True if operation was successfull, False otherwise.
    * */
    public static boolean generateDLogKeys(
            ProvingSystemType psType,
            //TODO: We need a way to enforce segment size of the SC DLogKey(s) being less equal than the MC one(s)
            int segmentSize,
            String g1KeyPath,
            Optional<String> g2KeyPath
    )
    {
        if (psType == ProvingSystemType.COBOUNDARY_MARLIN) {
            return nativeGenerateDLogKeys(psType, segmentSize, g1KeyPath, "");
        } else {
            if (!g2KeyPath.isPresent()) {
                throw new IllegalArgumentException("If DARLIN ProvingSystemType is chosen, then g2KeyPath must be specified");
            }
            return nativeGenerateDLogKeys(psType, segmentSize, g1KeyPath, g2KeyPath.get());
        }
    }
}