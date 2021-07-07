package com.horizen.commitmenttree;

public class CustomFieldElementsConfig {
    
    private final byte nBits;
    
    public CustomFieldElementsConfig(byte nBits) {
        this.nBits = nBits;
    }
    
    public byte getBits() {
        return nBits;
    }
}
