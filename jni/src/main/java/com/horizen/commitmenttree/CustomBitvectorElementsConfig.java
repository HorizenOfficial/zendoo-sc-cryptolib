package com.horizen.commitmenttree;

public class CustomBitvectorElementsConfig {
    
    private final int bitVectorSizeBits;
    private final int maxCompressedSizeBytes;

    public CustomBitvectorElementsConfig(int bitVectorSizeBits, int maxCompressedSizeBytes) {
        this.bitVectorSizeBits = bitVectorSizeBits;
        this.maxCompressedSizeBytes = maxCompressedSizeBytes;
    }

    public int getBitVectorSizeBits() {
        return bitVectorSizeBits;
    }
    
    public int getMaxCompressedSizeBytes() {
        return maxCompressedSizeBytes;
    }
}
