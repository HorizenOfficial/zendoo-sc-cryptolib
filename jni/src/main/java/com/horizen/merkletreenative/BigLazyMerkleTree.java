package com.horizen.merkletreenative;

import java.util.List;

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

    private static native BigLazyMerkleTree nativeInit(int height, String statePath, String dbPath, String cachePath);

    public static BigLazyMerkleTree init(int height, String statePath, String dbPath, String cachePath) {
        return nativeInit(height, statePath, dbPath, cachePath);
    }

    private static native BigLazyMerkleTree nativeLoad(String statePath, String dbPath, String cachePath);

    public static BigLazyMerkleTree load(String statePath, String dbPath, String cachePath) {
        return nativeInit(statePath, dbPath, cachePath);
    }

    private native FieldElement nativeAddLeaves(FieldElement[] leaves);

    // Add leaves to tree, compute and return the root
    public FieldElement addLeaves(List<FieldElement> leaves){
        if (lazyMerkleTreePointer == 0)
            throw new IllegalArgumentException("lazyMerkleTreePointer must be not null.");
        return nativeAddLeaves(leaves.toArray(new FieldElement[0]));
    }

    private native FieldElement nativeRoot();

    public FieldElement root() {
        if (lazyMerkleTreePointer == 0)
            throw new IllegalArgumentException("lazyMerkleTreePointer must be not null.");
        return nativeRoot();
    }

    private static native void nativeFreeLazyMerkleTree(long lazyMerkleTreePointer);

    // Free Rust memory from LazyMerkleTree
    public void freeLazyMerkleTree() {
        if (lazyMerkleTreePointer != 0) {
            nativeFreeLazyMerkleTree(this.lazyMerkleTreePointer);
            lazyMerkleTreePointer = 0;
        }
    }

    private static native void nativeFreeAndDestroyLazyMerkleTree(long lazyMerkleTreePointer);

    // Free Rust memory from LazyMerkleTree + delete persistent data
    public void freeAndDestroyLazyMerkleTree() {
        if (lazyMerkleTreePointer != 0) {
            nativeFreeAndDestroyLazyMerkleTree(this.lazyMerkleTreePointer);
            lazyMerkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeLazyMerkleTree();
    }
}
