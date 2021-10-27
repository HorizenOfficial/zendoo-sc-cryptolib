package com.horizen.provingsystemnative;

import com.horizen.librustsidechains.Library;

public enum ProvingSystemType {
    UNDEFINED,
    DARLIN,
    COBOUNDARY_MARLIN
    ;

    static {
        Library.load();
    }

    public static ProvingSystemType intToProvingSystemType(int val) {
        switch(val) {
            case 0:
                return ProvingSystemType.UNDEFINED;
            case 1:
                return ProvingSystemType.DARLIN;
            case 2:
                return ProvingSystemType.COBOUNDARY_MARLIN;
            default:
                throw new IllegalArgumentException("Unknown ProvingSystemType corresponding to input");
        }
    }
}