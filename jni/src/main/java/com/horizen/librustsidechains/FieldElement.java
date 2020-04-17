package com.horizen.librustsidechains;

public class FieldElement {

    private long fieldElementPointer;

    static {
        Library.load();
    }

    private FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }
}
