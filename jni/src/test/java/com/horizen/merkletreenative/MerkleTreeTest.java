package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import java.util.List;
import java.util.ArrayList;

import static org.junit.Assert.*;

public class MerkleTreeTest {

    static long[] positions = { 458L, 478L, 161L, 0L, 291L, 666L, 313L, 532L };
    static int height = 10;
    static int numLeaves = 8;
    List<FieldElement> leaves;

    static byte[] expectedRootBytes = {
        111, -105, 99, -40, -16, -11, 28, -97, 49, -96, 37, -33, 14, 107, 81, 26,
        -108, -75, 18, -77, -34, 5, 126, 10, -6, -33, -47, 126, 64, 24, -41, 42
    };
    FieldElement expectedRoot;

    private List<FieldElement> buildLeaves(long initialSeed){
        List<FieldElement> leaves = new ArrayList<>();

        for (int i = 0; i < numLeaves; i++) {
            FieldElement leaf = FieldElement.createRandom(initialSeed);
            leaves.add(leaf);
            initialSeed += 1;
        }

        return leaves;
    }

    @Before
    public void initTestParams() {
        leaves = buildLeaves(1234567890L);
        expectedRoot = FieldElement.deserialize(expectedRootBytes);
    }

    @Test
    public void testMerkleTrees() throws Exception {

        //Get InMemorySparseMerkleTree
        InMemorySparseMerkleTree smtLazy = InMemorySparseMerkleTree.init(height);

        //Add leaves to InMemorySparseMerkleTree
        List<PositionLeaf> positionLeaves = new ArrayList<>();
        for(int i = 0; i < numLeaves; i++) {
            assertTrue("Position must be empty", smtLazy.isPositionEmpty(positions[i]));
            positionLeaves.add(new PositionLeaf(positions[i], leaves.get(i)));
        }
        smtLazy.addLeaves(positionLeaves);

        //Remove leaves from InMemorySparseMerkleTree
        long[] leavesToRemove = { 458L, 532L };
        smtLazy.removeLeaves(leavesToRemove);

        //Compute root and assert equality with the expected one
        smtLazy.finalizeInPlace();
        FieldElement smtLazyRoot = smtLazy.root();
        assertEquals("InMemorySparseMerkleTree root is not as expected", smtLazyRoot, expectedRoot);

        //Free memory
        smtLazy.freeInMemorySparseMerkleTree();
        smtLazyRoot.freeFieldElement();

        //Get InMemoryOptimizedMerkleTree
        InMemoryOptimizedMerkleTree mht = InMemoryOptimizedMerkleTree.init(height, numLeaves);
        assertNotNull("Merkle Tree initialization must succeed", mht);

        // Must place the leaves at the same positions of the previous trees
        List<FieldElement> mhtLeaves = new ArrayList<>();
        //Initialize all leaves to zero
        FieldElement zero = FieldElement.createFromLong(0L);
        for(int j = 0; j < 1024; j++)
            mhtLeaves.add(zero);
        //Substitute at positions the correct leaves
        for (int j = 1; j < numLeaves - 1; j++) {
            // Warning: Conversion from long to int is not to be used for production.
            mhtLeaves.set((int)positions[j], leaves.get(j));
        }

        //Append all the leaves to mht
        for (FieldElement leaf: mhtLeaves)
            assertTrue("Leaf append must be successfull", mht.append(leaf));

        //Finalize the tree
        assertTrue("Merkle Tree finalization must succeed", mht.finalizeTreeInPlace());

        //Compute root and assert equality with the expected one
        FieldElement mhtRoot = mht.root();
        assertNotNull("Root must not be NULL", mhtRoot);
        assertEquals("InMemoryOptimizedMerkleTree root is not as expected", mhtRoot, expectedRoot);

        //It is the same with finalizeTree()
        InMemoryOptimizedMerkleTree mhtCopy = mht.finalizeTree();
        assertNotNull("Merkle Tree finalization must succeed", mhtCopy);

        FieldElement mhtRootCopy = mhtCopy.root();
        assertNotNull("Root must not be NULL", mhtRootCopy);
        assertEquals("InMemoryOptimizedMerkleTree copy root is not as expected", mhtRootCopy, expectedRoot);

        //Free memory
        zero.freeFieldElement();
        mht.freeInMemoryOptimizedMerkleTree();
        mhtCopy.freeInMemoryOptimizedMerkleTree();
        mhtRoot.freeFieldElement();
        mhtRootCopy.freeFieldElement();
    }

    @Test
    public void testMerklePaths() throws Exception {
        List<FieldElement> testLeaves = new ArrayList<>();
        List<PositionLeaf> testPositionLeaves = new ArrayList<>();
        InMemoryOptimizedMerkleTree mht = InMemoryOptimizedMerkleTree.init(6, numLeaves);
        InMemorySparseMerkleTree smt = InMemorySparseMerkleTree.init(6);
        assertNotNull("Merkle Tree initialization must succeed", mht);
        assertNotNull("Sparse Merkle Tree initialization must succeed", smt);

        int numLeaves = 64;

        // Append leaves to mht
        for (int i = 0; i < numLeaves/2; i ++) {
            FieldElement leaf = FieldElement.createRandom(i);
            testLeaves.add(leaf);
            testPositionLeaves.add(new PositionLeaf((long)i, leaf));
            assertTrue("Leaf append must be successfull", mht.append(leaf));
        }
        for (int i = numLeaves/2; i < numLeaves; i ++) {
            FieldElement leaf = FieldElement.createFromLong(0L);
            testLeaves.add(leaf);
        }

        // Append leaves to SMT too
        smt.addLeaves(testPositionLeaves);
        smt.finalizeInPlace();
        FieldElement smtRoot = smt.root();

        //Finalize the tree and get the root
        assertTrue("Merkle Tree finalization must succeed", mht.finalizeTreeInPlace());
        FieldElement mhtRoot = mht.root();
        assertNotNull("Root must not be NULL", mhtRoot);
        assertEquals("Sparse and Append Merkle Tree roots must be the same", smtRoot, mhtRoot);

        for (int i = 0; i < numLeaves; i ++) {

            // Get/Verify Merkle Path
            MerklePath path = mht.getMerklePath((long)i);
            MerklePath smtPath = smt.getMerklePath((long)i);

            assertNotNull("Path must not be NULL", path);
            assertNotNull("Path must not be NULL", smtPath);

            assertEquals("Sparse and Append Merkle Tree paths must be the same", path, smtPath);

            assertTrue("Merkle Path must be verified", path.verify(testLeaves.get(i), mhtRoot));

            // Serialization/Deserialization test
            byte[] merklePathBytes = path.serialize();
            MerklePath pathDeserialized = MerklePath.deserialize(merklePathBytes);
            assertTrue("Deserialized Merkle Path must be verified", pathDeserialized.verify(testLeaves.get(i), mhtRoot));

            if (i == 0) { // leftmost check
                assertTrue("Path must be the leftmost", path.isLeftmost());
            }
            else if (i == (numLeaves / 2) - 1) { // areRightLeavesEmpty check
                assertTrue("Right leaves must be all empty", path.areRightLeavesEmpty());
            }
            else if (i == numLeaves - 1) { //rightmost check
                assertTrue("Path must be the rightmost", path.isRightmost());
            }
            else { // Other cases check
                assertFalse("Path must not be the leftmost", path.isLeftmost());
                assertFalse("Path must not be the rightmost", path.isRightmost());

                if (i < (numLeaves / 2) - 1) {
                    assertFalse("Right leaves must not be all empty", path.areRightLeavesEmpty());
                }
            }

            assertEquals("Leaf index computed from path must be correct", i, path.leafIndex());

            // apply() test
            FieldElement rootComputed = path.apply(testLeaves.get(i));
            assertEquals("Root computed out of Merkle Path must be the same", rootComputed, mhtRoot);
            rootComputed.freeFieldElement();

            // Free paths
            path.freeMerklePath();
            pathDeserialized.freeMerklePath();
        }

        // Free memory
        mht.freeInMemoryOptimizedMerkleTree();
        mhtRoot.freeFieldElement();
        for (FieldElement leaf: testLeaves)
            leaf.freeFieldElement();
    }

    @Test
    public void testAreRightLeavesEmpty() {
        InMemoryOptimizedMerkleTree mht = InMemoryOptimizedMerkleTree.init(6, numLeaves);
        assertNotNull("Merkle Tree initialization must succeed", mht);

        int numLeaves = 64;

        // Generate random leaves
        for (int i = 0; i < numLeaves; i ++) {
            FieldElement leaf = FieldElement.createRandom(i);
            assertTrue("Leaf append must be successfull", mht.append(leaf));

            InMemoryOptimizedMerkleTree mhtCopy = mht.finalizeTree();
            assertNotNull("Merkle Tree finalization must succeed", mhtCopy);

            MerklePath path = mhtCopy.getMerklePath((long)i);
            assertNotNull("Path must not be NULL", path);
            assertTrue(path.areRightLeavesEmpty());

            leaf.freeFieldElement();
            path.freeMerklePath();
            mhtCopy.freeInMemoryOptimizedMerkleTree();
        }
    }

    @After
    public void freeTestParams(){
        for (FieldElement leaf: leaves)
            leaf.freeFieldElement();
        expectedRoot.freeFieldElement();
    }
}
