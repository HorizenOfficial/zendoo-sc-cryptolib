package com.horizen.poseidonnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import static org.junit.Assert.*;


public class PoseidonHashTest {

    @Test
    public void testComputeHash() {

        FieldElement fieldElement = FieldElement.createFromLong(123456789L);

        FieldElement[] fieldElementArray = {fieldElement};

        FieldElement hash = PoseidonHash.computeHash(fieldElementArray);

        assertNotNull("Hash must be computed", hash);

    }
}
