package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class RandomAccessMerkleTree implements AutoCloseable {
    
    private long randomAccessMerkleTreePointer;

    static {
        Library.load();
    }

    private RandomAccessMerkleTree(long randomAccessMerkleTreePointer) {
        if (randomAccessMerkleTreePointer == 0)
            throw new IllegalArgumentException("randomAccessMerkleTreePointer must be not null.");
        this.randomAccessMerkleTreePointer = randomAccessMerkleTreePointer;
    }

    private static native RandomAccessMerkleTree nativeInit(int height);

    public static RandomAccessMerkleTree init(int height){
        return nativeInit(height);
    }

    private native void nativeAppend(FieldElement input);

    public void append(FieldElement input) {
        if (randomAccessMerkleTreePointer == 0)
            throw new IllegalArgumentException("RandomAccessMerkleTree instance was freed.");
        nativeAppend(input);
    }

    private native RandomAccessMerkleTree nativeFinalize();

    // Finalize the tree by computing the root and returns the finalized tree. It is possible
    // to continue updating the original tree.
    public RandomAccessMerkleTree finalizeTree() {
        if (randomAccessMerkleTreePointer == 0)
            throw new IllegalArgumentException("RandomAccessMerkleTree instance was freed.");
        return nativeFinalize();
    }

    private native void nativeFinalizeInPlace();

    // Finalize the tree by computing the root and updates the actual instance. It is not possible
    // to continue updating the tree, unless by restoring the original state (by calling reset()).
    public void finalizeTreeInPlace() {
        if (randomAccessMerkleTreePointer == 0)
            throw new IllegalArgumentException("RandomAccessMerkleTree instance was freed.");
        nativeFinalizeInPlace();
    }

    private native FieldElement nativeRoot();

    // Returns the root of the Merkle Tree. This function must be called on a finalized tree.
    // If not, the call will result in an exception.
    public FieldElement root() {
        if (randomAccessMerkleTreePointer == 0)
            throw new IllegalArgumentException("RandomAccessMerkleTree instance was freed.");
        return nativeRoot();
    }

    private native void nativeReset();

    public void reset() {
        if (randomAccessMerkleTreePointer == 0)
            throw new IllegalArgumentException("RandomAccessMerkleTree instance was freed.");
        nativeReset();
    }

    private native void nativeFreeRandomAccessMerkleTree(long randomAccessMerkleTreePointer);

    public void freeRandomAccessMerkleTree(){
        if (randomAccessMerkleTreePointer != 0) {
            nativeFreeRandomAccessMerkleTree(this.randomAccessMerkleTreePointer);
            randomAccessMerkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeRandomAccessMerkleTree();
    }
}
