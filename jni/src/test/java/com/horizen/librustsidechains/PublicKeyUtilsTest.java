package com.horizen.librustsidechains;

import org.junit.Test;

import static org.junit.Assert.*;

public class PublicKeyUtilsTest {

    @Test
    public void testNativeGetPublicKeySize() {
        assertEquals("Public key size must be " + PublicKeyUtils.PUBLIC_KEY_LENGTH,
                PublicKeyUtils.PUBLIC_KEY_LENGTH,
                PublicKeyUtils.nativeGetPublicKeySize());
    }
}
