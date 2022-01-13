package com.horizen.commitmenttreenative;

public class CustomBitvectorElementsConfig {
    
    private final int bitVectorSizeBits;
    private final int maxCompressedByteSize;

    public CustomBitvectorElementsConfig(int bitVectorSizeBits, int maxCompressedByteSize) {
        this.bitVectorSizeBits = bitVectorSizeBits;
        this.maxCompressedByteSize = maxCompressedByteSize;
    }

    public int getBitVectorSizeBits() {
        return bitVectorSizeBits;
    }
    
    public int getMaxCompressedByteSize() {
        return maxCompressedByteSize;
    }
}
