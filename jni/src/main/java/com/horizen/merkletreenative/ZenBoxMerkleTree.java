package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class ZenBoxMerkleTree implements AutoCloseable {

    // Loading the Rust library which contains all the underlying logic
    static {
        Library.load();
    }

    private long merkleTreePointer;

    private void checkPointer() throws IllegalStateException {
        if (merkleTreePointer == 0)
            throw new IllegalStateException("ZenBoxMerkleTree instance was freed");
    }

    // Constructor is intended to be called from inside of the Rust environment getting a raw pointer to ZenBoxSMT Rust-instance
    private ZenBoxMerkleTree(long merkleTreePointer) {
        this.merkleTreePointer = merkleTreePointer;
    }

    // Gates to the Rust-side API
    private static native ZenBoxMerkleTree nativeInit(int height, String dbPath);
    private static native void nativeFreeAndDestroy(long merkleTreePointer);
    private static native void nativeFree(long merkleTreePointer);
    private static native long nativeResetBitvector(long merkleTreePointer);
    private static native long nativeGetAbsolutePosition(FieldElement leaf, int height);

    private native long nativeGetPosition(FieldElement leaf);
    private native boolean nativeIsPositionEmpty(long position);
    private native boolean nativeIsBoxSpent(long position);
    private native void nativeAddBox(FieldElement leaf, long position);
    private native void nativeRemoveBox(long position);
    private native FieldElement nativeGetBox(long position);
    private native FieldElement nativeStateRoot();
    private native FieldElement nativeBitvectorRoot();
    private native MerklePath nativeGetStateMerklePath(long leafPosition);
    private native MerklePath nativeGetBitvectorMerklePath(long leafPosition);
    private native void nativeFlush();

    // Creates ZenBoxSMT Rust-instance, which though can be not created in case of underlying errors
    // The returned ZenBoxMerkleTree object should be checked with the 'isInitialized' method
    // Note: ZenBoxSMT Rust-instance may be not created due to errors such as incorrectly specified tree height or DB path, insufficient disk space and so on.
    //       In such a case constructor will be called with merkleTreePointer = null so ZenBoxMerkleTree will be empty.
    //       Thus ZenBoxMerkleTree should be checked with 'isInitialized' method before any usage
    public static ZenBoxMerkleTree init(int height, String dbPath) {
        return nativeInit(height, dbPath);
    }

    // Checks if ZenBoxMerkleTree is correctly initialized
    public boolean isInitialized(){
        return merkleTreePointer != 0;
    }

    // Free Rust memory from MerkleTree + delete persistent data
    public void freeAndDestroyMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFreeAndDestroy(this.merkleTreePointer);
            merkleTreePointer = 0;
        }
    }

    // Free Rust memory from MerkleTree
    public void freeMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFree(this.merkleTreePointer);
            merkleTreePointer = 0;
        }
    }

    // Resets Bitvector to its initial state where all bits are zero, while completely preserving the State Merkle Tree
    public void resetBitvector(){
        checkPointer();
        merkleTreePointer = nativeResetBitvector(merkleTreePointer);
    }

    // Returns the position to which insert the leaf given the leaf and the tree
    public long getPosition(FieldElement box) {
        checkPointer();
        return nativeGetPosition(box);
    }

    // Returns the position to which insert the leaf given the leaf and the height of the tree
    public static long getPosition(FieldElement box, int height) {
        return nativeGetAbsolutePosition(box, height);
    }

    // Checks whether a specified position contains a Box
    public boolean isPositionEmpty(long boxPosition){
        checkPointer();
        return nativeIsPositionEmpty(boxPosition);
    }

    // Checks whether a Box at a specified position is spent
    public boolean isBoxSpent(long boxPosition){
        checkPointer();
        return nativeIsBoxSpent(boxPosition);
    }

    // Places a Box into a specified position of the State Merkle Tree
    public void addBox(FieldElement box, long boxPosition){
        checkPointer();
        nativeAddBox(box, boxPosition);
    }

    // Removes a Box from a specified position of the State Merkle Tree
    // Also sets a bit correspondingly to the specified position in the Bitvector Merkle Tree
    public void removeBox(long boxPosition){
        checkPointer();
        nativeRemoveBox(boxPosition);
    }

    // Returns FieldElement which can be empty if a Box at a specified position doesn't exist
    // Should be checked with the FieldElement's 'nonEmpty' method
    public FieldElement getBox(long boxPosition){
        checkPointer();
        return nativeGetBox(boxPosition);
    }

    // Returns root of the State Merkle Tree
    public FieldElement getStateRoot() {
        checkPointer();
        return nativeStateRoot();
    }

    // Returns root of the Bitvector Merkle Tree
    public FieldElement getBitvectorRoot() {
        checkPointer();
        return nativeBitvectorRoot();
    }

    // Returns Merkle Path of a specified box inside of the State Merkle Tree
    public MerklePath getStateMerklePath(long boxPosition) {
        checkPointer();
        return nativeGetStateMerklePath(boxPosition);
    }

    // Returns Merkle Path of a leaf corresponding to a specified Box inside of the Bitvector Merkle Tree
    // Note: Each leaf of the Bitvector Merkle Tree (BMT) contains multiple bits corresponding to the Boxes with adjacent positions in the State Merkle Tree.
    //       Thus for different Boxes the containing BMT-leaf can be the same as well as a Merkle Path
    public MerklePath getBitvectorMerklePath(long boxPosition) {
        checkPointer();
        return nativeGetBitvectorMerklePath(boxPosition);
    }

    // Triggers saving ZenBoxMerkleTree to a disk
    public void flush() {
        checkPointer();
        nativeFlush();
    }

    @Override
    public void close() throws Exception {
        freeMerkleTree();
    }
}
