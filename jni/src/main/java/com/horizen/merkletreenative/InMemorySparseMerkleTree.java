package com.horizen.merkletreenative;

import java.util.Map;
import java.util.Set;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class InMemorySparseMerkleTree implements AutoCloseable {

    private long merkleTreePointer;

    static {
        Library.load();
    }

    private InMemorySparseMerkleTree(long merkleTreePointer) {
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        this.merkleTreePointer = merkleTreePointer;
    }

    private static native InMemorySparseMerkleTree nativeInit(int height);

    /**
     * Initialize an instance of InMemorySparseMerkleTree with specified height
     * @param height the height of the tree
     * @return an instance of InMemorySparseMerkleTree, allocated Rust side
     */
    public static InMemorySparseMerkleTree init(int height) {
        return nativeInit(height);
    }

    private native boolean nativeIsPositionEmpty(long position) throws Exception;

    /**
     * Check if specified position is empty
     * @param position the index of the leaf to check
     * @return True if no leaf is allocated at that position, False otherwise
     * @throws Exception If position &gt; 2^height - 1
     */
    public boolean isPositionEmpty(long position) throws Exception{
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemorySparseMerkleTree instance was freed.");
        return nativeIsPositionEmpty(position);
    }

    private native void nativeAddLeaves(Map<Long, FieldElement> leaves) throws Exception;

    /**
     * Add the specified leaves at the specified positions inside the tree.
     * No internal updates in the tree will be triggered by this operation.
     * @param leaves the leaves to be added to the tree and their corresponding index
     * @throws Exception if one of the indices is &gt; 2^height - 1
     */
    public void addLeaves(Map<Long, FieldElement> leaves) throws Exception{
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemorySparseMerkleTree instance was freed.");
        nativeAddLeaves(leaves);
    }

    // TODO: Currently we don't have good utilities to deal with a Set Rust-side.
    //       For the moment, let's pass an array, that will be converted back to
    //       a Set Rust side
    private native void nativeRemoveLeaves(Long[] positions) throws Exception;

    /**
     * Remove the specified leaves at the specified positions inside the tree.
     * No internal updates in the tree will be triggered by this operation.
     * @param positions a set of the indices of the leaves to be removed
     * @throws Exception if one of the indices is &gt; 2^height - 1 or if attempting
     * to remove a non-existing leaf.
     */
    public void removeLeaves(Set<Long> positions) throws Exception{
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemorySparseMerkleTree instance was freed.");
        nativeRemoveLeaves(positions.toArray(new Long[0]));
    }

    private native void nativeFinalizeInPlace() throws Exception;

    /**
     * Update the tree and the root with the leaves added/removed until this moment.
     * The tree is modified in place and set to a "finalized" state.
     * However, it is possibile to call this method as many times as possibile, with
     * new leaves insertion/removal between each call, bringing again the tree to 
     * a "non-finalized" state.
     * @throws Exception if it was not possible to update the tree correctly
     */
    public void finalizeInPlace() throws Exception {
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemorySparseMerkleTree instance was freed.");
        nativeFinalizeInPlace();
    }

    private native FieldElement nativeRoot() throws Exception;

    /**
     * Return the root of the tree, only if the tree is in "finalized" state.
     * @return The current root of the tree
     * @throws Exception if the tree was not in "finalized" state
     */
    public FieldElement root() throws Exception {
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemorySparseMerkleTree instance was freed.");
        return nativeRoot();
    }

    private native MerklePath nativeGetMerklePath(long leafPosition) throws Exception;

    /**
     * Return the MerklePath corresponding to the leaf at index leafPosition,
     * only if the tree is in "finalized" state
     * @param leafPosition the index of the leaf of which computing the Merkle Path
     * @return the Merkle Path of the leaf at index leafPosition
     * @throws Exception if the tree was not in "finalized" state
     */
    public MerklePath getMerklePath(long leafPosition) throws Exception {
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemorySparseMerkleTree instance was freed.");
        return nativeGetMerklePath(leafPosition);
    }


    private native void nativeFreeInMemorySparseMerkleTree();

    /**
     * Free memory Rust side
     */
    public void freeInMemorySparseMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFreeInMemorySparseMerkleTree();
            merkleTreePointer = 0;
        }
    }

    @Override
    public void close() {
        freeInMemorySparseMerkleTree();
    }
}