package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import java.util.List;
import java.util.ArrayList;

import static org.junit.Assert.*;

//TODO: Move serialized leaves to file and simplify the parsing of all the leaves in the test
public class MerkleTreeTest {

    private List<FieldElement> buildLeavesFromHardcodedValues(){
        List<FieldElement> leaves = new ArrayList<>();

        // Deserialize leaf 1 and add it to leaves
        byte[] serializedLeaf1 = {
            -40, 112, 96, -79, 44, 105, -115, -9, -19, -21, 47, 93, -123, 62, -23, -41, 85, 90, -119, 123, -61, 20, -75,
            -44, -57, -69, -82, 114, 83, 62, 108, -107, -99, 70, 28, 80, 98, 6, 104, -29, 13, 60, 50, 82, -11, -58, 49,
            -54, -15, -11, 30, 42, -123, -21, -26, -101, 32, -114, -100, 30, -27, 43, 3, 67, 5, -112, -42, -40, -122,
            -58, 111, -87, 59, -67, -38, 48, -34, -24, -101, 46, 91, 45, -41, 79, 29, -58, -121, 56, 4, -45, 27, -118,
            54, 1, 0, 0
        };

        FieldElement leaf = FieldElement.deserialize(serializedLeaf1);
        assertNotNull("Leaf 1 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 2 and add it to leaves
        byte[] serializedLeaf2 = {
            105, -36, -115, -40, 84, 31, -34, 101, -96, 11, -122, -51, 26, 0, -26, 18, -124, 111, -104, -80, 101, 93, 17
            , -49, 52, -98, 95, -46, 127, 21, -3, -127, 22, -43, -74, -14, -84, 81, -88, 113, 107, 81, 56, 3, -38, -91,
            -94, 122, -21, 75, 118, -121, 36, -122, 49, 73, 3, 5, 97, -54, 106, 56, -81, 126, -90, -29, 27, -41, -112,
            58, 55, 116, -119, 51, -41, 9, -17, -114, -19, 74, 62, 100, 84, 34, -85, 61, 62, -97, 105, 70, -119, -62,
            -26, -24, 0, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf2);
        assertNotNull("Leaf 2 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 3 and add it to leaves
        byte[] serializedLeaf3 = {
            119, -12, 88, 60, 47, 26, 89, 114, 77, 76, -4, 70, 13, -55, 101, 1, -89, -55, 53, -86, -50, -33, 18, -122,
            -25, 51, -128, 62, -118, 64, 51, -118, 83, -67, -115, 95, 31, 12, 85, 69, -93, 40, -86, -118, 32, 50, 89,
            46, 7, -20, 20, -100, 66, -102, 27, -125, -11, -40, 115, 51, 102, 17, -17, 32, 78, 36, -96, 0, 77, 48, 57,
            -123, -28, 102, 98, 47, 59, -62, -109, 31, 42, 72, 99, -65, -93, 64, -83, -101, 99, -10, 56, -26, 11, 93,
            1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf3);
        assertNotNull("Leaf 3 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 4 and add it to leaves
        byte[] serializedLeaf4 = {
            -12, 91, -86, -76, -71, 43, -75, 45, -75, 104, -12, -107, -8, -107, 109, -54, 42, -71, -61, 39, 27, -5, 35,
            -31, 35, -93, 101, 29, -118, 125, 76, 95, 7, -43, -68, -6, 33, 53, -61, -75, -55, 70, -56, -31, -23, -113,
            70, -28, 99, 65, 18, -98, -53, -70, 122, -66, -39, -83, -83, -113, -94, -58, 113, -8, 96, 12, -104, 81, 71,
            -34, 19, -49, -108, -54, 78, 69, 98, 120, 21, -79, 72, -119, 125, 109, 125, -38, -61, 22, -45, 72, 79, 92,
            47, 65, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf4);
        assertNotNull("Leaf 4 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 5 and add it to leaves
        byte[] serializedLeaf5 = {
            -109, 113, -76, 101, 15, -54, 49, 85, -111, -56, -80, 121, -79, -23, 107, 8, -82, 13, 110, 80, -109, 64,
            -21, -77, 4, 45, -60, -71, 55, -107, 59, -73, 124, 112, 38, 75, -31, -52, -24, -55, -78, 118, 70, -24, -105,
            11, -115, -23, 117, 84, -4, -112, -90, -10, 71, -66, -124, 83, -51, 19, 98, 27, 31, 8, -5, -62, 23, -78,
            -53, 99, 78, 66, -111, -54, -56, 15, 58, -7, -91, 36, -18, 32, -97, -34, -8, -84, 67, -46, -16, -126, -37,
            127, 15, 45, 0, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf5);
        assertNotNull("Leaf 5 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 6 and add it to leaves
        byte[] serializedLeaf6 = {
            90, 90, -105, 84, -71, 56, -124, -94, -90, 121, -101, -49, 98, 34, 50, 12, 51, 127, 1, -109, 99, 62, -127,
            89, -56, -42, 36, -78, -32, -80, 61, 125, -50, -72, 41, -52, 14, -3, -20, 24, -120, -127, 36, -99, -119, 54,
            107, 76, 13, 121, -85, 67, 84, 57, -17, 115, -48, -90, -118, 26, -64, 46, 127, 21, -95, 124, -28, 11, -55,
            16, 91, 11, -37, 107, 6, -64, 3, -123, 67, -14, 120, -57, -73, 95, -63, 112, -60, 100, -34, 123, 102, -73,
            6, -25, 0, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf6);
        assertNotNull("Leaf 6 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 7 and add it to leaves
        byte[] serializedLeaf7 = {
            -77, -60, 105, -118, -3, 17, -20, 2, 11, -45, 30, -78, -62, 65, -51, 5, 58, 91, -90, 124, -16, 71, -55, 83,
            -77, -73, 38, 6, 90, -10, -3, -46, 47, 34, 77, 65, -64, -50, 74, 87, 0, 18, -59, -74, -71, 86, -73, -68,
            -29, 106, 90, 17, -90, 94, -90, -122, -70, 3, 118, -92, 13, -87, -61, 117, 73, -123, 105, -55, 49, 124, 1,
            80, -103, -68, -12, 81, -43, 67, -22, 74, 35, -54, -78, -112, 108, -74, -113, -24, 100, -16, 122, -118, -71,
            51, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf7);
        assertNotNull("Leaf 7 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 8 and add it to leaves
        byte[] serializedLeaf8 = {
            25, 101, 126, 59, -111, 86, -109, 80, 124, 68, -41, 10, 26, 120, -58, -89, 97, 44, -80, 104, -84, 33, -60,
            27, 59, 27, 24, 27, 62, -113, -106, 26, -45, 20, 30, 56, -113, -108, 9, 89, -109, -112, -28, 26, 32, 115,
            -47, -54, -62, -49, -98, 118, -79, 110, 23, 99, 59, -9, 124, -63, -31, 24, -23, 43, -42, -118, 111, 84, -31,
            123, 107, 33, -114, -23, 86, -38, 9, 23, -106, -8, 52, 120, -66, 24, -6, 79, -113, -92, 72, 49, -113, -27,
            116, 94, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf8);
        assertNotNull("Leaf 8 deserialization must be successfull", leaf);
        leaves.add(leaf);

        return leaves;
    }

    @Test
    public void testMerkleTrees() {

        // Initialize test params
        long[] positions = { 0L, 46L, 117L, 5L, 104L, 206L, 153L, 245L };
        int height = 10;
        int numLeaves = 8;
        List<FieldElement> leaves = buildLeavesFromHardcodedValues();

        byte[] expectedRootBytes = {
            32, -55, -54, 82, 75, -100, 57, 43, 120, 95, 38, -62, 88, -69, 64, -5, 110, -79, -26, 36, 72, 11, 88, -125,
            115, 18, -1, -13, -122, 6, 108, 23, -78, -1, -75, -115, 96, -55, 109, 74, 126, -44, -47, 67, 86, 4, -66, 19,
            -46, -39, 47, -85, -124, -122, -47, -104, -90, 75, -54, -64, -101, -126, -18, -34, 44, 60, 123, 88, 102,
            -15, 83, 58, -42, -120, -122, 63, 40, -25, -56, -15, 18, 120, 84, -28, -69, -81, 33, 56, -52, -108, -116,
            -100, 107, -8, 0, 0
        };
        FieldElement expectedRoot = FieldElement.deserialize(expectedRootBytes);

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

        //Free remaining memory
        for (FieldElement leaf: leaves)
            leaf.freeFieldElement();
        expectedRoot.freeFieldElement();
    }
}
