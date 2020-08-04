package com.horizen.merkletreenative;

import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.FieldElement;

public class BigLazyMerkleTree implements AutoCloseable {

    private long lazyMerkleTreePointer;

    static {
        Library.load();
    }

    private BigLazyMerkleTree(long lazyMerkleTreePointer) {
        this.lazyMerkleTreePointer = lazyMerkleTreePointer;
    }

    private static native BigLazyMerkleTree nativeInit(String dbPath, String cachePath);

    public static BigLazyMerkleTree init(String dbPath, String cachePath) {
        return nativeInit(dbPath, cachePath);
    }

    private native FieldElement nativeAddLeaves(FieldElement[] leaves);

    // Add leaves to tree, compute and return the root
    public FieldElement addLeaves(FieldElement[] leaves){
        return nativeAddLeaves(leaves);
    }

    private native FieldElement nativeRoot();

    public FieldElement root() {
        return nativeRoot();
    }

    private static native void nativeFreeLazyMerkleTree(long lazyMerkleTreePointer);

    public void freeLazyMerkleTree() {
        if (lazyMerkleTreePointer != 0) {
            nativeFreeLazyMerkleTree(this.lazyMerkleTreePointer);
            lazyMerkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeLazyMerkleTree();
    }
}
