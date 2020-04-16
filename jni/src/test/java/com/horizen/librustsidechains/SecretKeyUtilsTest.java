package com.horizen.librustsidechains;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SecretKeyUtilsTest {

    @Test
    public void testNativeGetSecretKeySize() {
        assertEquals("Secret key size must be " + SecretKeyUtils.SECRET_KEY_LENGTH,
                SecretKeyUtils.SECRET_KEY_LENGTH,
                SecretKeyUtils.nativeGetSecretKeySize());
    }

}
