package com.horizen.merkletreenative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;

public class MerklePath implements AutoCloseable {

    private long merklePathPointer;

    static {
        Library.load();
    }

    private MerklePath(long merklePathPointer) {
        if (merklePathPointer == 0)
            throw new IllegalArgumentException("merklePathPointer must be not null.");
        this.merklePathPointer = merklePathPointer;
    }

    private native boolean nativeVerify(int merkleTreeHeight, FieldElement leaf, FieldElement root);

    public boolean verify(int merkleTreeHeight, FieldElement leaf, FieldElement root) {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeVerify(merkleTreeHeight, leaf, root);
    }

    private native void nativeFreeMerklePath(long merklePathPointer);

    public void freeMerklePath(){
        if (merklePathPointer != 0) {
            nativeFreeMerklePath(this.merklePathPointer);
            merklePathPointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeMerklePath();
    }
}
