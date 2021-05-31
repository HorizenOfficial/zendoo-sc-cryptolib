package com.horizen.librustsidechains;

public class Utils {
    static {
        Library.load();
    }

    private Utils() {}

    private static native byte[] nativeCalculateSidechainId(byte[] transactionHash, int index);

    public static byte[] calculateSidechainId(byte[] transactionHash, int index){
        return nativeCalculateSidechainId(transactionHash, index);
    }

    private static native byte[] nativeCompressedBitvectorMerkleRoot(byte[] compressedBitvector);

    public static byte[] compressedBitvectorMerkleRoot(byte[] compressedBitvector){
        return nativeCompressedBitvectorMerkleRoot(compressedBitvector);
    }
}
