import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class InMemoryLazySparseMerkleTree implements AutoCloseable {

    private long merkleTreePointer;

    static {
        Library.load();
    }

    private InMemoryLazySparseMerkleTree(long merkleTreePointer) {
        if (merkleTreePointer == 0)
            throw new IllegalArgumentException("merkleTreePointer must be not null.");
        this.merkleTreePointer = merkleTreePointer;
    }

    private static native InMemoryLazySparseMerkleTree nativeInit(int height);

    public static InMemoryLazySparseMerkleTree init(int height) {
        return nativeInit(height);
    }

    private native boolean nativeIsPositionEmpty(long position);

    public boolean isPositionEmpty(long position){
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemoryLazySparseMerkleTree instance was freed.");
        return nativeIsPositionEmpty(position);
    }

    private native FieldElement nativeAddLeaves(PositionLeaf[] leaves);

    // Add leaves to tree, compute and return the root
    public FieldElement addLeaves(PositionLeaf[] leaves){
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemoryLazySparseMerkleTree instance was freed.");
        return nativeAddLeaves(leaves);
    }

    private native void nativeRemoveLeaves(long[] positions);

    public void removeLeaves(long[] positions){
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemoryLazySparseMerkleTree instance was freed.");
        nativeRemoveLeaves(positions);
    }

    private native FieldElement nativeRoot();

    public FieldElement root() {
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemoryLazySparseMerkleTree instance was freed.");
        return nativeRoot();
    }

    private native MerklePath nativeGetMerklePath(long leafPosition);

    public MerklePath getMerklePath(long leafPosition) {
        if (merkleTreePointer == 0)
            throw new IllegalStateException("InMemoryLazySparseMerkleTree instance was freed.");
        return nativeGetMerklePath(leafPosition);
    }


    private static native void nativeFreeInMemoryLazySparseMerkleTree(long merkleTreePointer);

    // Free Rust memory from InMemoryLazySparseMerkleTree
    public void freeInMemoryLazySparseMerkleTree() {
        if (merkleTreePointer != 0) {
            nativeFreeInMemoryLazySparseMerkleTree(this.merkleTreePointer);
            merkleTreePointer = 0;
        }
    }

    @Override
    public void close() throws Exception {
        freeInMemoryLazySparseMerkleTree();
    }
}