package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import java.util.List;
import java.util.ArrayList;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.Assert.*;

public class MerkleTreeTest {

    static long[] positions = { 458L, 478L, 161L, 0L, 291L, 666L, 313L, 532L };
    static int height = 10;
    static int numLeaves = 8;
    List<FieldElement> leaves;

    static byte[] expectedRootBytes = {
            98, 17, 48, -16, 78, -116, -101, -33, -30, -122, -126, -83, -120, 106, -53, 30, -96, -119, 102, -25, 33, -27, -114, -13, -4, -33, 54, 49, -20, 53, 42, 83, 75, 17, -19, -95, -10, 22, -116, -35, 83, -91, -3, -1, 109, 27, -90, 120, 109, 59, 53, -115, -115, 71, -53, -80, 51, -118, 119, 49, -28, -3, -49, 27, -113, -120, 55, 114, -83, 98, -7, 109, 41, 46, -68, -40, -12, 75, -37, -121, 71, -98, 124, -87, -105, -45, 5, -88, 47, -55, -51, -49, -127, 77, 0, 0,
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
    public void testMerkleTrees() {

        //Get BigMerkleTree
        BigMerkleTree smt = BigMerkleTree.init(height, "./state_big", "./db_big", "./cache_big");
        int i = 0;
        for (FieldElement leaf: leaves) {
            long position = smt.getPosition(leaf);
            assertEquals("Computed position for leaf " + i + " is not the expected one", positions[i], position);
            assertTrue("Position must be empty", smt.isPositionEmpty(position));
            smt.addLeaf(leaf, position);
            i++;
        }

        smt.removeLeaf(positions[0]);
        smt.removeLeaf(positions[numLeaves - 1]);

        //Compute root and assert equality with the expected one
        FieldElement smtRoot = smt.root();
        assertEquals("BigMerkleTree root is not as expected", smtRoot, expectedRoot);

        //Free memory
        smt.freeAndDestroyMerkleTree();
        smtRoot.freeFieldElement();

        //Get BigLazyMerkleTree
        BigLazyMerkleTree smtLazy = BigLazyMerkleTree.init(height, "./state_big_lazy", "./db_big_lazy", "./cache_big_lazy");

        //Add leaves to BigLazyMerkleTree
        smtLazy.addLeaves(leaves);

        //Remove leaves from BigLazyMerkleTree
        long[] leavesToRemove = { 458L, 532L };
        smtLazy.removeLeaves(leavesToRemove);

        //Compute root and assert equality with the expected one
        FieldElement smtLazyRoot = smtLazy.root();
        assertEquals("BigLazyMerkleTree root is not as expected", smtLazyRoot, expectedRoot);

        //Free memory
        smtLazy.freeAndDestroyLazyMerkleTree();
        smtLazyRoot.freeFieldElement();

        //Get InMemoryOptimizedMerkleTree
        InMemoryOptimizedMerkleTree mht = InMemoryOptimizedMerkleTree.init(height, numLeaves);

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
            mht.append(leaf);

        //Finalize the tree
        mht.finalizeTreeInPlace();

        //Compute root and assert equality with the expected one
        FieldElement mhtRoot = mht.root();
        assertEquals("InMemoryOptimizedMerkleTree root is not as expected", mhtRoot, expectedRoot);

        //It is the same with finalizeTree()
        InMemoryOptimizedMerkleTree mhtCopy = mht.finalizeTree();
        FieldElement mhtRootCopy = mhtCopy.root();
        assertEquals("InMemoryOptimizedMerkleTree copy root is not as expected", mhtRootCopy, expectedRoot);

        //Free memory
        zero.freeFieldElement();
        mht.freeInMemoryOptimizedMerkleTree();
        mhtCopy.freeInMemoryOptimizedMerkleTree();
        mhtRoot.freeFieldElement();
        mhtRootCopy.freeFieldElement();
    }

    @Test
    public void testMerklePaths() {
        List<FieldElement> testLeaves = new ArrayList<>();
        InMemoryOptimizedMerkleTree mht = InMemoryOptimizedMerkleTree.init(6, numLeaves);
        int numLeaves = 64;

        // Append leaves to the tree
        for (int i = 0; i < numLeaves; i ++) {
            FieldElement leaf = FieldElement.createRandom(i);
            testLeaves.add(leaf);
            mht.append(leaf);
        }

        //Finalize the tree and get the root
        mht.finalizeTreeInPlace();
        FieldElement mhtRoot = mht.root();

        for (int i = 0; i < numLeaves; i ++) {

            // Get/Verify Merkle Path
            MerklePath path = mht.getMerklePath((long)i);
            assertTrue("Merkle Path must be verified", path.verify(testLeaves.get(i), mhtRoot));

            // Serialization/Deserialization test
            byte[] merklePathBytes = path.serialize();
            MerklePath pathDeserialized = MerklePath.deserialize(merklePathBytes);
            assertTrue("Deserialized Merkle Path must be verified", pathDeserialized.verify(testLeaves.get(i), mhtRoot));

            // isLeftmost() / isRightmost() / leafIndex() test
            if (i == 0) { assertTrue("Path must be the leftmost", path.isLeftmost()); }
            else if (i == numLeaves - 1) { assertTrue("Path must be the rightmost", path.isRightmost()); }
            else {
                assertFalse("Path must not be the leftmost", path.isLeftmost());
                assertFalse("Path must not be the rightmost", path.isRightmost());
            }

            assertEquals("Leaf index computed from path must be correct", i, path.leafIndex());

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
    public void testBigMerkleTreePersistency() {

        //Create a BigMerkleTree
        BigMerkleTree smt = BigMerkleTree.init(height, "./state_big_persistency", "./db_big_persistency", "./cache_big_persistency");
        for(int i = 0; i < leaves.size(); i++){
            smt.addLeaf(leaves.get(i), positions[i]);
        }

        //Free BigMerkleTree but don't delete its state
        smt.freeMerkleTree();

        // Check data have been saved
        File f = new File("./state_big_persistency");
        assertTrue("State has not been saved", f.exists());

        f = new File("./db_big_persistency");
        assertTrue("DB has not been saved", f.exists());

        f = new File("./cache_big_persistency");
        assertTrue("Cache has not been saved", f.exists());

        //Restore Merkle Tree
        smt = BigMerkleTree.init(height, "./state_big_persistency", "./db_big_persistency", "./cache_big_persistency");

        //Remove some leaves
        smt.removeLeaf(positions[0]);
        smt.removeLeaf(positions[numLeaves - 1]);

        // Compute root and assert equality with the expected one (if state was deleted or altered in some
        // way, the assertion below won't pass)
        FieldElement smtRoot = smt.root();
        assertEquals("BigMerkleTree root is not as expected", smtRoot, expectedRoot);

        //Free memory
        smt.freeAndDestroyMerkleTree();
        smtRoot.freeFieldElement();

        // Check data have been destroyed
        f = new File("./state_big_persistency");
        assertTrue("State has not been destroyed", !f.exists());

        f = new File("./db_big_persistency");
        assertTrue("DB has not been destroyed", !f.exists());

        f = new File("./cache_big_persistency");
        assertTrue("Cache has not been destroyed", !f.exists());
    }

    @Test
    public void testBigLazyMerkleTreePersistency() {

        //Create a BigLazyMerkleTree
        BigLazyMerkleTree lazySmt = BigLazyMerkleTree.init(height, "./state_big_lazy_persistency", "./db_big_lazy_persistency", "./cache_big_lazy_persistency");

        // Add some leaves
        lazySmt.addLeaves(leaves);

        //Free BigLazyMerkleTreeMerkleTree but don't delete its state
        lazySmt.freeLazyMerkleTree();

        // Check data have been saved
        File f = new File("./state_big_lazy_persistency");
        assertTrue("State has not been saved", f.exists());

        f = new File("./db_big_lazy_persistency");
        assertTrue("DB has not been saved", f.exists());

        f = new File("./cache_big_lazy_persistency");
        assertTrue("Cache has not been saved", f.exists());

        //Restore Merkle Tree
        lazySmt = BigLazyMerkleTree.init(height, "./state_big_lazy_persistency", "./db_big_lazy_persistency", "./cache_big_lazy_persistency");

        //Remove some leaves
        long[] toRemove = { positions[0], positions[numLeaves - 1] };
        lazySmt.removeLeaves(toRemove);

        // Compute root and assert equality with the expected one (if state was deleted or altered in some
        // way, the assertion below won't pass)
        FieldElement lazySmtRoot = lazySmt.root();
        assertEquals("BigMerkleTree root is not as expected", lazySmtRoot, expectedRoot);

        //Free memory
        lazySmt.freeAndDestroyLazyMerkleTree();
        lazySmtRoot.freeFieldElement();

        // Check data have been destroyed
        f = new File("./state_big_lazy_persistency");
        assertTrue("State has not been destroyed", !f.exists());

        f = new File("./db_big_lazy_persistency");
        assertTrue("DB has not been destroyed", !f.exists());

        f = new File("./cache_big_lazy_persistency");
        assertTrue("Cache has not been destroyed", !f.exists());
    }

    @After
    public void freeTestParams(){
        for (FieldElement leaf: leaves)
            leaf.freeFieldElement();
        expectedRoot.freeFieldElement();
    }
}
