package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

public class MerkleTreeTest {

    static long[] positions = { 458L, 478L, 161L, 0L, 291L, 666L, 313L, 532L };
    static int height = 10;
    static int numLeaves = 8;
    List<FieldElement> leaves;

    static byte[] expectedRootBytes = {
            98, 17, 48, -16, 78, -116, -101, -33, -30, -122, -126, -83, -120, 106, -53, 30, -96, -119, 102, -25, 33, -27, -114, -13, -4, -33, 54, 49, -20, 53, 42, 83, 75, 17, -19, -95, -10, 22, -116, -35, 83, -91, -3, -1, 109, 27, -90, 120, 109, 59, 53, -115, -115, 71, -53, -80, 51, -118, 119, 49, -28, -3, -49, 27, -113, -120, 55, 114, -83, 98, -7, 109, 41, 46, -68, -40, -12, 75, -37, -121, 71, -98, 124, -87, -105, -45, 5, -88, 47, -55, -51, -49, -127, 77, 0, 0,
    };

    static byte[] expectedBvtRootBytes = {
            72, 103, 29, 25, 32, -65, 26, -43, -12, 4, 110, -110, -98, 60, 120, -116, -79, -52, 65, 31, 11, -23, 81, 90, 98, 81, -120, 46, 2, -13, -37, -34, 58, -52, 1, 121, 80, -108, 17, -75, 9, -68, 102, 80, -109, -25, -64, -25, -45, -98, 118, -12, 74, -117, -47, -31, -67, -2, 111, 108, 67, -80, -123, 67, 127, 58, 59, 31, -88, -119, -103, 27, -81, 15, -3, 54, -115, -94, -72, 6, 14, 105, 64, -16, 32, 78, -61, 47, 6, -127, -62, -18, -111, 4, 0, 0,
    };

    FieldElement expectedRoot;
    FieldElement expectedBvtRoot;

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
        expectedBvtRoot = FieldElement.deserialize(expectedBvtRootBytes);
    }

    @Test
    public void testZenBoxMerkleTree(){

        ZenBoxMerkleTree zmt4 = ZenBoxMerkleTree.init(4, "./db_zbt");
        assertFalse("ZenBoxMerkleTree can't be initialized with height of 4", zmt4.isInitialized());

        ZenBoxMerkleTree zmt = ZenBoxMerkleTree.init(height, "./db_zbt");
        assertTrue("ZenBoxMerkleTree should be initialized for test running", zmt.isInitialized());

        MerklePath bvt_path0 = zmt.getBitvectorMerklePath(positions[0]);
        FieldElement emptyBvtRoot = zmt.getBitvectorRoot();

        // Check that initially boxes are empty
        for (long pos : positions) {
            assertFalse("Position " + pos + " shouldn't contain any box", zmt.getBox(pos).nonEmpty());
        }

        // Set the boxes according to their positions
        for (int i = 0; i < positions.length; i++) {
            FieldElement leaf = leaves.get(i);
            long position = zmt.getPosition(leaf);

            assertEquals("Computed position for leaf " + i + " is not the expected one", positions[i], position);
            assertEquals("Positions must be the same", position, ZenBoxMerkleTree.getPosition(leaf, height));
            assertTrue("Position must be empty", zmt.isPositionEmpty(position));

            zmt.addBox(leaf, position);
        }

        // Check that boxes are the same as have been set according to their positions
        for(int i = 0; i < positions.length; i++){
            FieldElement box = zmt.getBox(positions[i]);
            assertTrue("Box at position " + positions[i] + " should be non-empty", box.nonEmpty());
            assertEquals("Box at position " + positions[i] + " is not the expected one", box, leaves.get(i));
            box.freeFieldElement();
        }

        assertFalse("Boxes should be marked as unspent", zmt.isBoxSpent(positions[0]) && zmt.isBoxSpent(positions[numLeaves - 1]));

        MerklePath state_path0 = zmt.getStateMerklePath(positions[0]);

        zmt.removeBox(positions[0]);

        MerklePath state_path0_1 = zmt.getStateMerklePath(positions[0]);
        assertTrue("Path in State should be the same", Arrays.equals(state_path0_1.serialize(), state_path0.serialize()));
        state_path0_1.freeMerklePath();

        zmt.removeBox(positions[numLeaves - 1]);

        MerklePath state_path0_2 = zmt.getStateMerklePath(positions[0]);
        assertFalse("Path in State should change", Arrays.equals(state_path0_2.serialize(), state_path0.serialize()));
        state_path0_2.freeMerklePath();
        state_path0.freeMerklePath();

        assertTrue("Boxes should be marked as spent", zmt.isBoxSpent(positions[0]) && zmt.isBoxSpent(positions[numLeaves - 1]));

        //Compute roots and assert equality with the expected ones
        FieldElement stateRoot = zmt.getStateRoot();
        assertEquals("State root is not as expected", stateRoot, expectedRoot);
        FieldElement bvtRoot = zmt.getBitvectorRoot();
        assertEquals("Bitvector root is not as expected", bvtRoot, expectedBvtRoot);

        MerklePath bvt_path0_1 = zmt.getBitvectorMerklePath(positions[0]);
        // All boxes from the test settings are less than BVT leaf CAPACITY = 752, so all of them fit into the same BVT leaf, thus BVT path for the leaf at position 0 remains unchanged
        assertArrayEquals("Path in Bitvector should be the same", bvt_path0_1.serialize(), bvt_path0.serialize());
        bvt_path0_1.freeMerklePath();

        zmt.resetBitvector();

        // Check that BVT is reset
        FieldElement resetBvtRoot = zmt.getBitvectorRoot();
        assertEquals("Bitvector should be empty", resetBvtRoot, emptyBvtRoot);
        assertNotEquals("Bitvector should be empty", resetBvtRoot, bvtRoot);

        // Check that State hasn't changed
        FieldElement stateRootAfterBvtReset = zmt.getStateRoot();
        assertEquals("State root should remain unchanged", stateRootAfterBvtReset, stateRoot);

        //Free memory
        stateRootAfterBvtReset.freeFieldElement();
        resetBvtRoot.freeFieldElement();
        emptyBvtRoot.freeFieldElement();
        bvtRoot.freeFieldElement();
        stateRoot.freeFieldElement();
        bvt_path0.freeMerklePath();
        zmt.freeAndDestroyMerkleTree();
    }

    @Test
    public void testMerkleTrees() {

        //Get BigMerkleTree
        BigMerkleTree smt = BigMerkleTree.init(height, "./db_big");
        int i = 0;
        for (FieldElement leaf: leaves) {
            long position = smt.getPosition(leaf);
            assertEquals("Computed position for leaf " + i + " is not the expected one", positions[i], position);
            assertEquals("Positions must be the same", position, BigMerkleTree.getPosition(leaf, height));
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
        BigLazyMerkleTree smtLazy = BigLazyMerkleTree.init(height, "./db_big_lazy");

        //Check leaves position also for BigLazyMerkleTree
        i = 0;
        for (FieldElement leaf: leaves) {
            long position = smtLazy.getPosition(leaf);
            assertEquals("Computed position for leaf " + i + " is not the expected one", positions[i], position);
            assertEquals("Positions must be the same", position, BigLazyMerkleTree.getPosition(leaf, height));
            assertTrue("Position must be empty", smtLazy.isPositionEmpty(position));
            i++;
        }

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
        for (int i = 0; i < numLeaves/2; i ++) {
            FieldElement leaf = FieldElement.createRandom(i);
            testLeaves.add(leaf);
            mht.append(leaf);
        }
        for (int i = numLeaves/2; i < numLeaves; i ++) {
            FieldElement leaf = FieldElement.createFromLong(0L);
            testLeaves.add(leaf);
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

            if (i == 0) { // leftmost check
                assertTrue("Path must be the leftmost", path.isLeftmost());
            }
            else if (i == (numLeaves / 2) - 1) { // non-empty rightmost check
                assertTrue("Path must be the non-empty rightmost", path.isNonEmptyRightmost());
            }
            else if (i == numLeaves - 1) { //rightmost check
                assertTrue("Path must be the rightmost", path.isRightmost());
            }
            else { // Other cases check
                assertFalse("Path must not be the leftmost", path.isLeftmost());
                assertFalse("Path must not be the rightmost", path.isRightmost());

                if (i < (numLeaves / 2) - 1) {
                    assertFalse("Path must not be the non-empty rightmost", path.isNonEmptyRightmost());
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
    public void testNonEmptyRightmost() {
        InMemoryOptimizedMerkleTree mht = InMemoryOptimizedMerkleTree.init(6, numLeaves);
        int numLeaves = 64;

        // Generate random leaves
        for (int i = 0; i < numLeaves; i ++) {
            FieldElement leaf = FieldElement.createRandom(i);
            mht.append(leaf);

            InMemoryOptimizedMerkleTree mhtCopy = mht.finalizeTree();
            MerklePath path = mhtCopy.getMerklePath((long)i);
            assertTrue(path.isNonEmptyRightmost());

            leaf.freeFieldElement();
            path.freeMerklePath();
            mhtCopy.freeInMemoryOptimizedMerkleTree();
        }
    }

    @Test
    public void testBigMerkleTreePersistency() {

        //Create a BigMerkleTree
        BigMerkleTree smt = BigMerkleTree.init(height, "./db_big_persistency");
        for(int i = 0; i < leaves.size(); i++){
            smt.addLeaf(leaves.get(i), positions[i]);
        }

        //Free BigMerkleTree but don't delete its state
        smt.freeMerkleTree();

        // Check data have been saved

        File f = new File("./db_big_persistency");
        assertTrue("DB has not been saved", f.exists());

        //Restore Merkle Tree
        smt = BigMerkleTree.init(height, "./db_big_persistency");

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

        f = new File("./db_big_persistency");
        assertTrue("DB has not been destroyed", !f.exists());
    }

    @Test
    public void testBigLazyMerkleTreePersistency() {

        //Create a BigLazyMerkleTree
        BigLazyMerkleTree lazySmt = BigLazyMerkleTree.init(height, "./db_big_lazy_persistency");

        // Add some leaves
        lazySmt.addLeaves(leaves);

        //Free BigLazyMerkleTreeMerkleTree but don't delete its state
        lazySmt.freeLazyMerkleTree();

        // Check data have been saved

        File f = new File("./db_big_lazy_persistency");
        assertTrue("DB has not been saved", f.exists());

        //Restore Merkle Tree
        lazySmt = BigLazyMerkleTree.init(height, "./db_big_lazy_persistency");

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
        f = new File("./db_big_lazy_persistency");
        assertTrue("DB has not been destroyed", !f.exists());
    }

    @After
    public void freeTestParams(){
        for (FieldElement leaf: leaves)
            leaf.freeFieldElement();
        expectedRoot.freeFieldElement();
    }
}
