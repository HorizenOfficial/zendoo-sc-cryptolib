package com.horizen.poseidonnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class UpdatablePoseidonHash implements AutoCloseable {

    public static final int HASH_LENGTH = 96;

    private long updatablePoseidonHashPointer;

    static {
        Library.load();
    }

    private UpdatablePoseidonHash(long updatablePoseidonHashPointer) {
        if (updatablePoseidonHashPointer == 0)
            throw new IllegalArgumentException("updatablePoseidonHashPointer must be not null.");
        this.updatablePoseidonHashPointer = updatablePoseidonHashPointer;
    }

    private static native UpdatablePoseidonHash nativeGetUpdatablePoseidonHash(FieldElement[] personalization);

    public static UpdatablePoseidonHash getInstance(){
        return nativeGetUpdatablePoseidonHash(new FieldElement[0]);
    }

    public static UpdatablePoseidonHash getInstance(FieldElement[] personalization)
    {
       return nativeGetUpdatablePoseidonHash(personalization);
    }

    private native void nativeUpdate(FieldElement input);

    public void update(FieldElement input) {
        if (updatablePoseidonHashPointer == 0)
            throw new IllegalArgumentException("UpdatablePoseidonHash instance was freed.");
        nativeUpdate(input);
    }

    private native FieldElement nativeFinalize();

    public FieldElement finalizeHash() {
        if (updatablePoseidonHashPointer == 0)
            throw new IllegalArgumentException("UpdatablePoseidonHash instance was freed.");
        return nativeFinalize();
    }

    private native void nativeFreeUpdatablePoseidonHash();

    public void freeUpdatablePoseidonHash(){
        if (updatablePoseidonHashPointer != 0) {
            nativeFreeUpdatablePoseidonHash();
            updatablePoseidonHashPointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeUpdatablePoseidonHash();
    }
}
