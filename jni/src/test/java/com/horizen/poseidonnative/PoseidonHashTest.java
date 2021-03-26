//package com.horizen.poseidonnative;
//
//import com.horizen.librustsidechains.FieldElement;
//import org.junit.Test;
//
//import static org.junit.Assert.*;
//
//
//public class PoseidonHashTest {
//
//    @Test
//    public void testComputeHash() throws Exception {
//
//        // Deserialize lhs
//        byte[] lhsBytes = {
//            112, 8, -18, 91, -117, -117, 32, 30, -33, 83, 61, -65, -22, 62, 23, -14, -26, -74, 61, 35, -27, -58,
//            -93, 118, -10, -114, 75, -35, 16, -123, -20, -66, -64, 13, -15, 25, -70, -99, -89, -116, -28, -52, 76,
//            -1, -84, -17, 71, 102, 44, 6, 10, -3, 98, 49, -95, -6, -38, 56, -105, -79, -94, 103, 59, 0, 123, -113,
//            -125, -34, -1, 60, -10, -72, -113, 97, -59, 11, -78, 62, -91, -68, -103, -17, -109, -2, -26, 13, -25,
//            -61, 20, -30, 38, -41, 77, -113, 1, 0
//        };
//
//        // Deserialize rhs
//        byte[] rhsBytes = {
//            7, -73, 119, -82, -89, -18, 23, -75, -27, 79, -54, 91, 74, -108, -93, 122, 24, 72, 76, 46, 69, -21, -101,
//            6, -106, -84, -127, 73, -104, -44, 77, 18, -10, 91, -58, 86, 69, 57, 20, 111, 49, -47, -79, -95, 87, 80, 93,
//            -104, -69, 75, -38, -60, -29, 60, 122, 38, 10, -95, -92, 59, -95, -48, -85, 35, 80, -63, 119, 46, -95, 109,
//            -55, 117, -16, -123, 67, 42, 87, 17, 88, 48, -1, -40, 116, -44, 68, 84, 10, -95, 106, -124, 118, -62, -119,
//            -97, 0, 0
//        };
//
//        try
//        (
//            FieldElement lhs = FieldElement.deserialize(lhsBytes);
//            FieldElement rhs = FieldElement.deserialize(rhsBytes)
//        )
//        {
//            assertNotNull("lhs deserialization must not fail", lhs);
//            assertNotNull("rhs deserialization must not fail", rhs);
//
//            // Compute hash = PoseidonHash(lhs, rhs)
//            FieldElement[] hashInput = {lhs, rhs};
//
//            // Deserialize expected hash
//            byte[] hashBytes = {
//                -34, -60, 127, 82, 42, -83, -66, 18, -8, -31, -71, -5, 68, 54, -70, 40, 13, -127, -91, 112, 10, 88, 43,
//                6, 117, -46, 85, -15, 121, 38, -44, 73, -34, -33, -113, 74, -104, -61, -105, 44, -119, 94, 10, 64, 117,
//                21, 7, 65, -62, -52, 98, -35, 80, 110, -38, -121, -49, -120, 71, 48, 8, -25, -8, -52, -5, -78, 32, -4,
//                -19, 38, 31, 1, 78, 56, 91, -88, -70, -31, 95, 48, -65, -56, -88, -4, -66, -94, -85, -95, 47, 25,
//                80, 112, -48, 65, 0, 0
//            };
//
//            try
//            (
//                FieldElement expectedHash = FieldElement.deserialize(hashBytes);
//                PoseidonHash digest = PoseidonHash.getInstance()
//            )
//            {
//                assertNotNull("expectedHash deserialization must not fail", expectedHash);
//
//                digest.update(lhs);
//                FieldElement temp = digest.finalizeHash(); // Calls to finalize keeps the state
//                temp.freeFieldElement();
//                digest.update(rhs);
//
//                try
//                (
//                    FieldElement hash = digest.finalizeHash();
//                    FieldElement hashTemp = digest.finalizeHash() //.finalizeHash() is idempotent
//                )
//                {
//                    assertEquals("hash must be equal to expected hash", hash, expectedHash);
//                    assertEquals(".finalizeHash() is not idempotent", hash, hashTemp);
//                }
//            }
//        }
//    }
//}
