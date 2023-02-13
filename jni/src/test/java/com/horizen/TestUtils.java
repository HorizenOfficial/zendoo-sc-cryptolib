package com.horizen;

import com.google.common.io.BaseEncoding;

import static org.junit.Assert.*;

public class TestUtils {
    public static final int DLOG_KEYS_SIZE = 1 << 18;
    public static final int CERT_SEGMENT_SIZE = 1 << 15;
    public static final int CSW_SEGMENT_SIZE = 1 << 18;

    private TestUtils() {
    }

    public static byte[] fromHexString(String hex) {
        return BaseEncoding.base16().lowerCase().decode(hex.toLowerCase());
    }

    // Get hex string representation of byte array
    public static String toHexString(byte[] bytes) {
        return BaseEncoding.base16().lowerCase().encode(bytes);
    }

    public static void assertArrayEquals(String message, byte[] expected, byte[] actual) {
        boolean result = expected.length == actual.length;

        for (int i = 0; i < expected.length && result; i++) {
            result &= expected[i] == actual[i];
        }
        assertTrue(message, result);
    }

}
