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

    static long[] positions = { 0L, 46L, 117L, 5L, 104L, 206L, 153L, 245L };
    static int height = 10;
    static int numLeaves = 8;
    List<FieldElement> leaves;

    static byte[] expectedRootBytes = {
            32, -55, -54, 82, 75, -100, 57, 43, 120, 95, 38, -62, 88, -69, 64, -5, 110, -79, -26, 36, 72, 11, 88, -125,
            115, 18, -1, -13, -122, 6, 108, 23, -78, -1, -75, -115, 96, -55, 109, 74, 126, -44, -47, 67, 86, 4, -66, 19,
            -46, -39, 47, -85, -124, -122, -47, -104, -90, 75, -54, -64, -101, -126, -18, -34, 44, 60, 123, 88, 102,
            -15, 83, 58, -42, -120, -122, 63, 40, -25, -56, -15, 18, 120, 84, -28, -69, -81, 33, 56, -52, -108, -116,
            -100, 107, -8, 0, 0
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
            assertEquals("Computed position for leaf " + i + "is not the expected one", positions[i], position);
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
        long[] leavesToRemove = { 0L, 245L };
        smtLazy.removeLeaves(leavesToRemove);

        //Compute root and assert equality with the expected one
        FieldElement smtLazyRoot = smtLazy.root();
        assertEquals("BigLazyMerkleTree root is not as expected", smtLazyRoot, expectedRoot);

        //Free memory
        smtLazy.freeAndDestroyLazyMerkleTree();
        smtLazyRoot.freeFieldElement();

        //Get RandomAccessMerkleTree
        RandomAccessMerkleTree ramt = RandomAccessMerkleTree.init(height);

        // Must place the leaves at the same positions of the previous trees
        List<FieldElement> ramtLeaves = new ArrayList<>();
        //Initialize all leaves to zero
        FieldElement zero = FieldElement.createFromLong(0L);
        for(int j = 0; j < 512; j++)
            ramtLeaves.add(zero);
        //Substitute at positions the correct leaves
        for (int j = 1; j < numLeaves - 1; j++) {
            // Warning: Conversion from long to int is not to be used for production.
            ramtLeaves.set((int)positions[j], leaves.get(j));
        }

        //Append all the leaves to ramt
        for (FieldElement leaf: ramtLeaves)
            ramt.append(leaf);

        //Finalize the tree
        ramt.finalizeTreeInPlace();

        //Compute root and assert equality with the expected one
        FieldElement ramtRoot = ramt.root();
        assertEquals("RandomAccessMerkleTree root is not as expected", ramtRoot, expectedRoot);

        //It is the same with finalizeTree()
        RandomAccessMerkleTree ramtCopy = ramt.finalizeTree();
        FieldElement ramtRootCopy = ramtCopy.root();
        assertEquals("RandomAccessMerkleTree copy root is not as expected", ramtRootCopy, expectedRoot);

        //Free memory
        zero.freeFieldElement();
        ramt.freeRandomAccessMerkleTree();
        ramtCopy.freeRandomAccessMerkleTree();
        ramtRoot.freeFieldElement();
        ramtRootCopy.freeFieldElement();
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
