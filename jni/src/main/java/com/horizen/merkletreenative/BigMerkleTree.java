package com.horizen.merkletreenative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;

public class BigMerkleTree implements AutoCloseable {

    private long merkleTreePointer;

    static {
        Library.load();
    }

    private BigMerkleTree(long merkleTreePointer) {
        this.merkleTreePointer = merkleTreePointer;
    }

    private static native BigMerkleTree nativeInit(int height, String statePath, String dbPath, String cachePath);

    public static BigMerkleTree init(int height, String statePath, String dbPath, String cachePath) {
        return nativeInit(height, statePath, dbPath, cachePath);
    }

    private native long nativeGetPosition(FieldElement leaf);

    // Returns the position to which insert the leaf
    public long getPosition(FieldElement leaf) {
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        return nativeGetPosition(leaf);
    }

    private native boolean nativeIsPositionEmpty(long position);

    public boolean isPositionEmpty(long position){
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        return nativeIsPositionEmpty(position);
    }

    private native void nativeAddLeaf(FieldElement leaf, long position);

    public void addLeaf(FieldElement leaf, long position){
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        nativeAddLeaf(leaf, position);
    }

    private native void nativeRemoveLeaf(long position);

    public void removeLeaf(long position){
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
            nativeRemoveLeaf(position);
    }

    private native FieldElement nativeRoot();

    public FieldElement root() {
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        return nativeRoot();
    }

    private static native void nativeFreeMerkleTree(long merkleTreePointer);

    // Free Rust memory from MerkleTree
    public void freeMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFreeMerkleTree(this.merkleTreePointer);
            merkleTreePointer = 0;
        }
    }

    private static native void nativeFreeAndDestroyMerkleTree(long merkleTreePointer);

    // Free Rust memory from MerkleTree + delete persistent data
    public void freeAndDestroyMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFreeAndDestroyMerkleTree(this.merkleTreePointer);
            merkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        //freeMerkleTree();
    }
}
