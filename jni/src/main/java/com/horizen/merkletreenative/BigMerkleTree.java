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

    private static native BigMerkleTree nativeInit(int height, String dbPath, String cachePath);

    public static BigMerkleTree init(int height, String dbPath, String cachePath) {
        return nativeInit(height, dbPath, cachePath);
    }

    private native int nativeGetPosition(FieldElement leaf);

    // Returns the position to which insert the leaf
    public int getPosition(FieldElement leaf) {
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        return nativeGetPosition(leaf);
    }

    private native boolean nativeIsPositionEmpty(int position);

    public boolean isPositionEmpty(int position){
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        return nativeIsPositionEmpty(position);
    }

    private native void nativeAddLeaf(FieldElement leaf, int position);

    public void addLeaf(FieldElement leaf, int position){
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        nativeAddLeaf(leaf, position);
    }

    private native FieldElement nativeRoot();

    public FieldElement root() {
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        return nativeRoot();
    }

    private static native void nativeFreeMerkleTree(long merkleTreePointer);

    public void freeMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFreeMerkleTree(this.merkleTreePointer);
            merkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeMerkleTree();
    }
}
