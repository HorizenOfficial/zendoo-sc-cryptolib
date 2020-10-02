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

    private native boolean nativeVerifyWithoutLengthCheck(FieldElement leaf, FieldElement root);

    public boolean verify(FieldElement leaf, FieldElement root) {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeVerifyWithoutLengthCheck(leaf, root);
    }

    private native boolean nativeIsLeftmost();

    public boolean isLeftmost() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeIsLeftmost();
    }

    private native boolean nativeIsRightmost();

    public boolean isRightmost() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeIsRightmost();
    }

    private native long nativeLeafIndex();

    public long leafIndex() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeLeafIndex();
    }

    private native byte[] nativeSerialize();

    public byte[] serialize() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("Field element was freed.");

        return nativeSerialize();
    }

    private static native MerklePath nativeDeserialize(byte[] merklePathBytes);

    public static MerklePath deserialize(byte[] merklePathBytes) {
        return nativeDeserialize(merklePathBytes);
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
