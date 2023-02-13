package com.horizen.poseidonnative;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;

import java.util.List;
import java.util.Random;
import java.util.ArrayList;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class PoseidonHashTest {

    static long seed = 4123352525293977497L;
    static String expectedHashForReset =
        "e9908b5f42f8670e64fcde81517449304c7aa3a9aada4bc590329283405c8202";
    static List<FieldElement> hashInput = new ArrayList<>();

    @BeforeClass
    public static void initHashInput() {
        for(long i = 0L; i < 100L; i++) {
            hashInput.add(FieldElement.createFromLong(i));
        }
    }

    @Test
    public void testReset() {

        Random r = new Random(seed);
        FieldElement expectedHash = FieldElement.deserialize(TestUtils.fromHexString(expectedHashForReset));
        PoseidonHash h = PoseidonHash.getInstanceConstantLength(2);

        // Generate random FieldElement
        FieldElement input1 = FieldElement.createRandom(r);
        FieldElement input2 = FieldElement.createRandom(r);

        for (int i = 0; i < 100; i++) {
            // Update acc
            h.update(input1);
            h.update(input2);
            FieldElement hash = h.finalizeHash();
            h.reset();

            assertEquals("hash must be equal to expected hash", hash, expectedHash);
            hash.close();
        }
        h.close();
    }

    @Test
    public void testComputeHashConstantLength() {

        // Deserialize expected hash
        byte[] hashBytes = {
            38, 19, 70, -18, 85, -23, -77, -117, -4, 47, -70, 13, -17, -87, -23, 48,
            88, -107, -63, -74, -68, 46, -7, -49, 118, 16, 68, 121, 107, 8, 70, 22
        };

        try
        (
            FieldElement expectedHash = FieldElement.deserialize(hashBytes);
            PoseidonHash digest = PoseidonHash.getInstanceConstantLength(hashInput.size())
        )
        {
            assertNotNull("expectedHash deserialization must not fail", expectedHash);
            for (int i = 0; i < hashInput.size() - 1; i++)
                digest.update(hashInput.get(i));

            assertNull("Finalizing with smaller input size than specified must be forbidden", digest.finalizeHash());

            // Update with last input
            digest.update(hashInput.get(hashInput.size() - 1));

            try
            (
                FieldElement hash = digest.finalizeHash();
                FieldElement hashTemp = digest.finalizeHash() //.finalizeHash() keeps the state
            )
            {
                assertNotNull("Finalizing with correct number of inputs must be ok", hash);
                assertEquals("hash must be equal to expected hash", hash, expectedHash);
                assertEquals(".finalizeHash() is not idempotent", hash, hashTemp);
            }

            digest.update(hashInput.get(hashInput.size() - 1));
            assertNull("Finalizing with bigger input size than specified must be forbidden", digest.finalizeHash());
        }
    }

    @Test
    public void testComputeHashVariableLength() {

        // Deserialize expected hash
        byte[] hashBytes = {
            91, 86, -48, -123, 17, 40, 89, -89, 79, 41, 68, 84, -120, -118, 19, 116,
            -111, -121, 111, 99, -122, 79, 67, 19, -111, -57, 18, 48, -8, 80, 60, 13
        };

        try
        (
            FieldElement expectedHash = FieldElement.deserialize(hashBytes);
            PoseidonHash digest = PoseidonHash.getInstanceVariableLength(false)
        )
        {
            assertNotNull("expectedHash deserialization must not fail", expectedHash);
            for (int i = 0; i < hashInput.size() - 1; i++)
                digest.update(hashInput.get(i));

            try
            (
                FieldElement hash = digest.finalizeHash();
                FieldElement hashTemp = digest.finalizeHash() //.finalizeHash() keeps the state
            )
            {
                assertNotNull("Finalizing with correct number of inputs must be ok", hash);
                assertEquals(".finalizeHash() is not idempotent", hash, hashTemp);
            }
        }
    }

    @Test
    public void testComputeHashVariableLengthModRate() throws Exception {

        // Deserialize expected hash
        byte[] hashBytes = {
            38, 19, 70, -18, 85, -23, -77, -117, -4, 47, -70, 13, -17, -87, -23, 48,
            88, -107, -63, -74, -68, 46, -7, -49, 118, 16, 68, 121, 107, 8, 70, 22
        };

        try
        (
            FieldElement expectedHash = FieldElement.deserialize(hashBytes);
            PoseidonHash digest = PoseidonHash.getInstanceVariableLength(true)
        )
        {
            assertNotNull("expectedHash deserialization must not fail", expectedHash);
            for (int i = 0; i < hashInput.size() - 1; i++)
                digest.update(hashInput.get(i));

            assertNull("Finalizing with input size non mod rate must be forbidden", digest.finalizeHash());

            // Update with last input
            digest.update(hashInput.get(hashInput.size() - 1));

            try
            (
                FieldElement hash = digest.finalizeHash();
                FieldElement hashTemp = digest.finalizeHash() //.finalizeHash() keeps the state
            )
            {
                assertNotNull("Finalizing with correct number of inputs must be ok", hash);
                assertEquals("hash must be equal to expected hash", hash, expectedHash);
                assertEquals(".finalizeHash() is not idempotent", hash, hashTemp);
            }
        }
    }

    @AfterClass
    public static void freeHashInput() {
        for (FieldElement fe: hashInput)
            fe.freeFieldElement();
        hashInput.clear();
    }
}
