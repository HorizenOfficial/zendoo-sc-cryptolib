package com.horizen.librustsidechains;

import io.horizen.common.librustsidechains.NativeOperationException;
import io.horizen.common.librustsidechains.NativeParsingException;

public class Utils {
    static {
        Library.load();
    }

    private Utils() {}

    private static native byte[] nativeCalculateSidechainId(byte[] transactionHash, int index) throws NativeParsingException, NativeOperationException;

    public static byte[] calculateSidechainId(byte[] transactionHash, int index) throws NativeParsingException, NativeOperationException {
        return nativeCalculateSidechainId(transactionHash, index);
    }

    private static native byte[] nativeCompressedBitvectorMerkleRoot(byte[] compressedBitvector) throws NativeOperationException;

    public static byte[] compressedBitvectorMerkleRoot(byte[] compressedBitvector) throws NativeOperationException{
        return nativeCompressedBitvectorMerkleRoot(compressedBitvector);
    }

    private static native byte[] nativeCompressedBitvectorMerkleRootWithSizeCheck(byte[] compressedBitvector, int expectedUncompressedSize) throws NativeOperationException;

    public static byte[] compressedBitvectorMerkleRoot(byte[] compressedBitvector, int expectedUncompressedSize) throws NativeOperationException {
        return nativeCompressedBitvectorMerkleRootWithSizeCheck(compressedBitvector, expectedUncompressedSize);
    }
}
