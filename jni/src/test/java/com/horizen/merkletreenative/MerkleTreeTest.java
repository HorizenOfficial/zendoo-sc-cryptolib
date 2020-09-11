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

    static long[] positions = { 256L, 46L, 373L, 261L, 360L, 462L, 409L, 245L };
    static int height = 9;
    static int numLeaves = 8;
    List<FieldElement> leaves;

    static byte[] expectedRootBytes = {
        118, -113, -72, 105, 101, -50, 88, 52, -117, -107, -71, -27, -41, -44, 72, -90, 28, -51, 78, 16, -118, -20, 7, -33, -122, 118, 54, -2, -17, 26, 97, 122, -19, -111, 76, 10, 98, -60, -85, 22, -114, -93, -22, 104, -39, -11, 91, 101, -97, 64, -23, 55, -84, -49, 61, 22, -34, -77, 89, 16, -50, -120, 9, -34, -32, 38, -98, 25, -68, -73, -8, 69, 97, 114, -102, -5, 103, -93, 85, -34, -46, 40, -103, 63, 102, 2, -55, -3, -9, -14, -53, 4, -116, -82, 1, 0
    };
    FieldElement expectedRoot;

    private List<FieldElement> buildLeavesFromHardcodedValues(){
        List<FieldElement> leaves = new ArrayList<>();
        byte[] leaf = new byte[FieldElement.FIELD_ELEMENT_LENGTH];
        int numLeaves = 8;
        int readBytes;

        try {
            ClassLoader classLoader = getClass().getClassLoader();
            File file = new File(classLoader.getResource("testLeaves").getFile());
            file.createNewFile();
            FileInputStream in = new FileInputStream(file);

            int i = 1;

            while ((readBytes = in.read(leaf)) != -1) {
                FieldElement leafDeserialized = FieldElement.deserialize(leaf);
                assertNotNull("Leaf " + i + " deserialization must be successfull", leafDeserialized);
                leaves.add(leafDeserialized);
                i++;
            }
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        assertEquals("Must read " + numLeaves + " leaves", numLeaves, leaves.size());

        return leaves;
    }

    @Before
    public void initTestParams() {
        leaves = buildLeavesFromHardcodedValues();
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

        // Verify Merkle paths for each leaf
        FieldElement tempSmtRoot = smt.root();
        for (FieldElement leaf: leaves) {
            MerklePath path = smt.getMerklePath(smt.getPosition(leaf));
            assertTrue("Merkle Path must be verified", path.verify(height, leaf, tempSmtRoot));
            path.freeMerklePath();
        }
        tempSmtRoot.freeFieldElement();

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

        // Verify Merkle paths for each leaf
        FieldElement tempLazySmtRoot = smtLazy.root();
        for (FieldElement leaf: leaves) {
            MerklePath path = smtLazy.getMerklePath(smtLazy.getPosition(leaf));
            assertTrue("Merkle Path must be verified", path.verify(height, leaf, tempLazySmtRoot));
            path.freeMerklePath();
        }
        tempLazySmtRoot.freeFieldElement();

        long[] leavesToRemove = { 256L, 245L };
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
        for(int j = 0; j < 512; j++)
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

        // Verify Merkle paths for each leaf
        FieldElement mhtRoot = mht.root();
        for (int j = 1; j < numLeaves - 1; j++) {
            MerklePath path = mht.getMerklePath((int)positions[j]);
            assertTrue("Merkle Path must be verified", path.verify(height, leaves.get(j), mhtRoot));
            path.freeMerklePath();
        }

        //Compute root and assert equality with the expected one
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
