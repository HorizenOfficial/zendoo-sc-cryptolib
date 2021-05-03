package com.horizen.poseidonnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import static org.junit.Assert.*;


public class PoseidonHashTest {

    //@Test
    public void testComputeHashConstantLength() throws Exception {

        // Deserialize lhs
        byte[] lhsBytes = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x3f
        };

        // Deserialize rhs
        byte[] rhsBytes = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x3f
        };

        try
        (
            FieldElement lhs = FieldElement.deserialize(lhsBytes);
            FieldElement rhs = FieldElement.deserialize(rhsBytes)
        )
        {
            assertNotNull("lhs deserialization must not fail", lhs);
            assertNotNull("rhs deserialization must not fail", rhs);

            // Compute hash = PoseidonHash(lhs, rhs)
            FieldElement[] hashInput = {lhs, rhs};

            // Deserialize expected hash
            byte[] hashBytes = {
                    (byte) 0x42, (byte) 0xff, (byte) 0xd4, (byte) 0x94, (byte) 0x7f, (byte) 0x76, (byte) 0xf7, (byte) 0xc1,
                    (byte) 0xba, (byte) 0x0a, (byte) 0xcf, (byte) 0x73, (byte) 0xf3, (byte) 0x0a, (byte) 0xa3, (byte) 0x7b,
                    (byte) 0x5a, (byte) 0xe8, (byte) 0xeb, (byte) 0xde, (byte) 0x5d, (byte) 0x61, (byte) 0xc3, (byte) 0x19,
                    (byte) 0x70, (byte) 0xc2, (byte) 0xf6, (byte) 0x45, (byte) 0x7b, (byte) 0x83, (byte) 0x2a, (byte) 0x39
            };

            try
            (
                FieldElement expectedHash = FieldElement.deserialize(hashBytes);
                PoseidonHash digest = PoseidonHash.getInstanceConstantLength(2)
            )
            {
                assertNotNull("expectedHash deserialization must not fail", expectedHash);

                digest.update(lhs);
                digest.update(rhs);

                try
                (
                    FieldElement hash = digest.finalizeHash();
                    FieldElement hashTemp = digest.finalizeHash() //.finalizeHash() keeps the state
                )
                {
                    assertEquals("hash must be equal to expected hash", hash, expectedHash);
                    assertEquals(".finalizeHash() is not idempotent", hash, hashTemp);
                }
            }
        }
    }
}
