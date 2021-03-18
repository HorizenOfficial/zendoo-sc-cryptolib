package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class InMemoryOptimizedMerkleTree implements AutoCloseable {
    
    private long inMemoryOptimizedMerkleTreePointer;

    static {
        Library.load();
    }

    private InMemoryOptimizedMerkleTree(long inMemoryOptimizedMerkleTreePointer) {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalArgumentException("inMemoryOptimizedMerkleTreePointer must be not null.");
        this.inMemoryOptimizedMerkleTreePointer = inMemoryOptimizedMerkleTreePointer;
    }

    private static native InMemoryOptimizedMerkleTree nativeInit(int height, long processingStep);

    // Creates a new InMemoryOptimizedMerkleTree given its `height` and `processingStep`.
    // `processingStep` is used to tune the memory usage of the tree.
    // In particular, `processing_step` defines the
    // number of leaves to store before triggering the computation of the root.
    // Decreasing `processing_step` leads to less memory consumption but
    // significantly worsen performances; conversely, increasing
    // `processing_step` increases the memory usage too but improves performances.
    // Meaningful values for `processing_step` are between 1 (i.e. update the root
    // at each leaf), leading to best memory efficiency but worst performances, and
    // the maximum number of leaves (or the mean number of leaves you plan to add),
    // leading to worse memory efficiency but best performances (root is computed
    // just once, but all the leaves must be kept in memory).
    public static InMemoryOptimizedMerkleTree init(int height, long processingStep){
        return nativeInit(height, processingStep);
    }

            private native void nativeAppend(FieldElement input);

    public void append(FieldElement input) {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalStateException("InMemoryOptimizedMerkleTree instance was freed.");
        nativeAppend(input);
    }

    private native InMemoryOptimizedMerkleTree nativeFinalize();

    // Finalize the tree by computing the root and returns the finalized tree. It is possible
    // to continue updating the original tree.
    public InMemoryOptimizedMerkleTree finalizeTree() {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalStateException("InMemoryOptimizedMerkleTree instance was freed.");
        return nativeFinalize();
    }

    private native void nativeFinalizeInPlace();

    // Finalize the tree by computing the root and updates the actual instance. It is not possible
    // to continue updating the tree, unless by restoring the original state (by calling reset()).
    public void finalizeTreeInPlace() {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalStateException("InMemoryOptimizedMerkleTree instance was freed.");
        nativeFinalizeInPlace();
    }

    private native FieldElement nativeRoot();

    // Returns the root of the Merkle Tree. This function must be called on a finalized tree.
    // If not, the call will result in an exception.
    public FieldElement root() {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalStateException("InMemoryOptimizedMerkleTree instance was freed.");
        return nativeRoot();
    }

    private native MerklePath nativeGetMerklePath(long leafIndex);

    public MerklePath getMerklePath(long leafIndex) {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalStateException("InMemoryOptimizedMerkleTree instance was freed.");
        return nativeGetMerklePath(leafIndex);
    }

    private native void nativeReset();

    // Restore the internal state of this instance to the initial one.
    public void reset() {
        if (inMemoryOptimizedMerkleTreePointer == 0)
            throw new IllegalStateException("InMemoryOptimizedMerkleTree instance was freed.");
        nativeReset();
    }

    private native void nativeFreeInMemoryOptimizedMerkleTree(long inMemoryOptimizedMerkleTreePointer);

    public void freeInMemoryOptimizedMerkleTree(){
        if (inMemoryOptimizedMerkleTreePointer != 0) {
            nativeFreeInMemoryOptimizedMerkleTree(this.inMemoryOptimizedMerkleTreePointer);
            inMemoryOptimizedMerkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeInMemoryOptimizedMerkleTree();
    }
}
