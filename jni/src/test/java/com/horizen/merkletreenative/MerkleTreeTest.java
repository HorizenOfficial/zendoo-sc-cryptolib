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
            80, -78, -37, -99, -9, -60, -65, 37, 93, 50, 15, 74, 35, -92, -74, -3, 38, 23, -13, 0, -28, 65, -82, -43,
            -108, 5, -78, -108, -34, 76, -61, -58, 62, -41, 33, -114, -102, -70, -28, -14, -21, 51, -54, 110, 81, 21,
            34, -25, -71, -115, -50, 11, 125, 53, -84, 122, 8, -99, -75, -60, -84, 108, 95, -45, 43, 32, 19, -108, -85,
            -83, 70, 57, -71, 104, -128, 42, 80, -110, -65, 5, 31, 71, -64, 25, -65, 0, -18, -95, -62, 48, 48, -123,
            -22, -12, 0, 0
        };

        FieldElement leaf = FieldElement.deserialize(serializedLeaf1);
        assertNotNull("Leaf 1 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 2 and add it to leaves
        byte[] serializedLeaf2 = {
            108, -8, 13, -117, -104, 61, 47, 96, -38, -61, 117, 97, 119, -65, 63, 24, 98, -7, 68, 101, 96, 85, 31, -106,
            115, 106, 127, 76, -111, -28, -16, 120, 40, 36, 105, 68, 17, -97, -71, 47, -92, 27, 113, 42, -59, 18, 84, 61,
            -2, -82, -114, -57, 1, 127, -26, 104, 43, 102, 70, -55, 36, 12, 32, 127, -30, -66, 44, 107, 79, -64, 46, 27,
            107, 76, -113, -21, 70, -72, 76, 42, 98, 75, 57, -20, -7, -16, 18, 82, -16, 15, 12, 90, -81, 121, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf2);
        assertNotNull("Leaf 2 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 3 and add it to leaves
        byte[] serializedLeaf3 = {
            -93, 99, 38, -44, 72, -10, 104, 7, -58, -3, 73, -79, -111, -103, -81, -42, -118, 73, 116, -59, -15, -12,
            -105, 86, 32, -98, 98, -94, 14, -26, 72, -98, -85, 7, -122, -76, -13, -110, -99, -68, 52, -1, 122, 35, -72,
            45, 24, -17, 85, -42, -94, 45, -93, -107, 94, -17, -62, -58, -31, 91, 80, -110, -121, 94, 68, -36, -94, 66,
            -63, -97, 52, -79, 91, 104, 100, -31, 31, 126, -72, -31, 32, -83, -80, 79, 40, 32, -95, 52, -27, 28, -101,
            -38, -116, 87, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf3);
        assertNotNull("Leaf 3 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 4 and add it to leaves
        byte[] serializedLeaf4 = {
            -121, 49, -85, -79, 60, 68, 17, 4, 80, -26, -120, 111, -117, -9, 52, 126, -27, 104, 74, -66, -52, -4, 110,
            -73, 25, 67, 39, 107, 61, 89, -117, 21, -62, -45, -13, 91, 115, -24, 68, 24, -11, -70, 38, -17, 91, 59, 86,
            -45, 69, -34, 69, -57, -18, 22, -120, 79, -74, -66, -77, 50, 98, 120, -12, -35, 10, -96, -76, 127, 49, -10,
            -58, 114, -54, 31, 123, 19, 42, 43, -122, 16, -67, 114, 48, 81, -8, 115, -59, -101, 104, 1, 98, 79, -64,
            -109, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf4);
        assertNotNull("Leaf 4 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 5 and add it to leaves
        byte[] serializedLeaf5 = {
            75, 27, 69, -16, 32, 47, -19, 81, -31, 70, 67, 127, -93, -64, 79, -128, -64, -31, 25, -39, 103, 59, 91,
            -122, -76, 108, -54, -5, 38, -67, -9, -15, -91, 95, 68, -88, -6, 105, -91, 24, 41, -21, 109, 24, -57, -84,
            29, 6, -122, 84, 10, -76, 37, 34, -27, 89, 0, 27, -21, -83, -116, 87, 48, 7, 76, 126, -24, -107, -98, 103,
            80, -128, -49, -97, 25, -83, -72, 117, 65, -3, 113, -17, -122, -22, 39, -19, 22, -28, 9, 51, 117, -84, 15,
            -71, 0, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf5);
        assertNotNull("Leaf 5 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 6 and add it to leaves
        byte[] serializedLeaf6 = {
            -42, 9, -76, -105, -79, 127, 69, 100, 43, -105, 33, 41, -59, -35, -67, 91, 69, 120, -11, 116, 74, -91, -4,
            -84, 28, -40, 101, -24, -122, 27, 62, -11, -105, 67, -78, 125, -99, 37, 81, 26, -7, -99, -75, -89, -114, 54,
            50, -64, 120, -20, -121, 32, 45, -74, -92, -127, -92, -50, 21, -69, -33, 117, -12, 109, 88, -40, -104, 3,
            87, -70, 33, 97, 51, -41, -97, 33, -50, -109, 70, -91, -20, 85, 83, -35, -89, 102, -67, 92, -34, -3, 77,
            -80, -117, -26, 0, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf6);
        assertNotNull("Leaf 6 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 7 and add it to leaves
        byte[] serializedLeaf7 = {
            34, -3, 109, -23, 81, 70, -19, 39, 53, 16, -82, 47, -90, 45, 0, -83, 41, -19, -110, -77, -122, 96, 2, -54,
            -120, 20, 58, 90, 41, -121, 75, 74, 62, -89, 6, 41, -97, -124, -1, 37, -119, -128, 6, -4, -106, -102, -102,
            -74, -41, 45, -74, -26, 51, -10, -31, -66, 60, -124, -29, -99, -125, -26, -85, -77, -49, 105, -7, 28, 27,
            127, 114, 15, 65, 117, 84, -45, -74, 11, 12, 97, -71, 19, -19, -75, -110, -34, -14, 32, 38, 122, 25, 86, 81,
            83, 0, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf7);
        assertNotNull("Leaf 7 deserialization must be successfull", leaf);
        leaves.add(leaf);

        // Deserialize leaf 8 and add it to leaves
        byte[] serializedLeaf8 = {
            -25, -14, -77, -75, -34, 29, -11, -77, 118, 54, 108, -100, 6, 122, -86, -41, 86, 79, 0, 40, -84, 112, -60,
            -120, 90, -18, 47, -68, -29, 16, 104, -26, 12, -83, 36, -112, -100, 88, -51, -39, -64, 83, 103, -72, 21,
            -86, 67, -77, 76, 37, 53, 120, 90, -46, 18, 40, 14, -80, -11, 113, 64, 83, -95, -123, -55, -70, 64, 114,
            -29, 25, -126, -59, 38, 116, -57, 79, 24, -46, -101, -118, 3, 18, 64, 55, -111, -63, 100, 63, -10, 80, 126,
            -31, -75, -96, 1, 0
        };

        leaf = FieldElement.deserialize(serializedLeaf8);
        assertNotNull("Leaf 8 deserialization must be successfull", leaf);
        leaves.add(leaf);

        return leaves;
    }

    @Test
    public void testMerkleTrees() {

        // Initialize test params
        int[] positions = { 94, 61, 213, 147, 58, 206, 148, 11 };
        int height = 10;
        int numLeaves = 8;
        List<FieldElement> leaves = buildLeavesFromHardcodedValues();

        byte[] expectedRootBytes = {
            71, -19, -81, 114, 18, 33, -49, 98, 15, 114, 40, -62, 47, 44, -63, -125, 14, -45, -27, 36, -40, 31, -67,
            -112, 81, 51, -8, 15, 118, 30, 112, -53, 93, 69, 25, -31, -56, 111, 117, -68, 38, 87, 106, -74, 112, 110,
            -90, -52, 31, -87, 83, -104, -5, 34, -64, -54, -124, 66, -72, -3, 38, -43, 0, -8, -23, -114, -64, 93, -90,
            -125, -99, -2, -53, -127, 26, -46, 111, 7, 112, 122, -7, -115, 38, -76, -121, -3, 74, 58, 2, 105, -98, 120,
            5, 127, 0, 0
        };
        FieldElement expectedRoot = FieldElement.deserialize(expectedRootBytes);

        //Get BigMerkleTree
        BigMerkleTree smt = BigMerkleTree.init(height, "./state_big", "./db_big", "./cache_big");
        int i = 0;
        for (FieldElement leaf: leaves) {
            int position = smt.getPosition(leaf);
            assertEquals("Computed position for leaf " + i + "is not the expected one", positions[i], position);
            assertTrue("Position must be empty", smt.isPositionEmpty(position));
            smt.addLeaf(leaf, position);
            i++;
        }

        //Compute root and assert equality with the expected one
        FieldElement smtRoot = smt.root();
        assertEquals("BigMerkleTree root is not as expected", smtRoot, expectedRoot);

        //Free memory
        //smt.freeMerkleTree();
        smtRoot.freeFieldElement();

        //Get BigLazyMerkleTree
        BigLazyMerkleTree smtLazy = BigLazyMerkleTree.init(height, "./state_big_lazy", "./db_big_lazy", "./cache_big_lazy");

        //Add leaves to BigLazyMerkleTree
        smtLazy.addLeaves(leaves);

        //Compute root and assert equality with the expected one
        FieldElement smtLazyRoot = smtLazy.root();
        assertEquals("BigLazyMerkleTree root is not as expected", smtLazyRoot, expectedRoot);

        //Free memory
        //smtLazy.freeLazyMerkleTree();
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
        for (int j = 0; j < numLeaves; j++) {
            ramtLeaves.set(positions[j], leaves.get(j));
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
        //ramt.freeRandomAccessMerkleTree();
        //ramtCopy.freeRandomAccessMerkleTree();
        ramtRoot.freeFieldElement();
        ramtRootCopy.freeFieldElement();

        //Free remaining memory
        for (FieldElement leaf: leaves)
            leaf.freeFieldElement();
        expectedRoot.freeFieldElement();
    }
}
