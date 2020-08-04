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

    private static native BigMerkleTree nativeInit(String dbPath, String cachePath);

    public static BigMerkleTree init(String dbPath, String cachePath) {
        return nativeInit(dbPath, cachePath);
    }

    private native int nativeGetPosition(FieldElement leaf);

    // Returns the position to which insert the leaf in the tree if it's empty, otherwise -1
    public int getPosition(FieldElement leaf) {
        return nativeGetPosition(leaf);
    }

    private native boolean nativeAddLeaf(FieldElement leaf, int position);

    public boolean addLeaf(FieldElement leaf, int position){
        return nativeAddLeaf(leaf, position);
    }

    private native FieldElement nativeRoot();

    public FieldElement root() {
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
