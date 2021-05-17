package com.horizen.librustsidechains;

public class Utils {
    static {
        Library.load();
    }

    private static native byte[] nativeCalculateSidechainId(byte[] transactionHash, int index);

    public static byte[] calculateSidechainId(byte[] transactionHash, int index){
        return nativeCalculateSidechainId(transactionHash, index);
    }
}
