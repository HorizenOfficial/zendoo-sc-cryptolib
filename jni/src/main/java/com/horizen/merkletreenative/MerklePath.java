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

    /*
    * Verify the Merkle Path for `leaf` given the `root` of a Merkle Tree with height `merkleTreeHeight`.
    */
    public boolean verify(int merkleTreeHeight, FieldElement leaf, FieldElement root) {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeVerify(merkleTreeHeight, leaf, root);
    }

    private native boolean nativeVerifyWithoutLengthCheck(FieldElement leaf, FieldElement root);

    /*
    * Verify the Merkle Path for `leaf` given the `root` of a Merkle Tree. Doesn't check if the
    * length of the Merkle Path is consistent with the height of the corresponding Merkle Tree,
    * therefore it is advisable to use it when it's certain that `leaf` is actually a leaf.
    */
    public boolean verify(FieldElement leaf, FieldElement root) {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeVerifyWithoutLengthCheck(leaf, root);
    }

    private native FieldElement nativeApply(FieldElement leaf);

    /*
    * Compute the root of the MerkleTree associated to this path and to `leaf`
    */
    public FieldElement apply(FieldElement leaf) {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeApply(leaf);
    }

    private native boolean nativeIsLeftmost();

    /*
    * Returns true if this is a Merkle Path for the left most leaf of a Merkle Tree,
    * false, otherwise.
    */
    public boolean isLeftmost() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeIsLeftmost();
    }

    private native boolean nativeIsRightmost();

    /*
    * Returns true if this is a Merkle Path for the right most leaf of a Merkle Tree,
    * false, otherwise.
    */
    public boolean isRightmost() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeIsRightmost();
    }

    private native boolean nativeAreRightLeavesEmpty();

    /*
     * Returns true if this is a Merkle Path for a leaf whose right leaves are all empty.
     */
    public boolean areRightLeavesEmpty() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeAreRightLeavesEmpty();
    }

    private native long nativeLeafIndex();

    /*
    * Returns the index of the leaf, corresponding to this Merkle Path, in the
    * corresponding Merkle Tree.
    */
    public long leafIndex() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("MerklePath instance was freed.");
        return nativeLeafIndex();
    }

    private native byte[] nativeSerialize();

    /* Return NULL if serialization failed */
    public byte[] serialize() {
        if (merklePathPointer == 0)
            throw new IllegalStateException("Field element was freed.");

        return nativeSerialize();
    }

    private static native MerklePath nativeDeserialize(byte[] merklePathBytes, boolean semanticChecks);

    public static MerklePath deserialize(byte[] merklePathBytes, boolean semanticChecks) {
        return nativeDeserialize(merklePathBytes, semanticChecks);
    }

    public static MerklePath deserialize(byte[] merklePathBytes) {
        return nativeDeserialize(merklePathBytes, true);
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
