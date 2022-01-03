package com.horizen;

import com.google.common.io.BaseEncoding;

public class TestUtils {
    public static final int DLOG_KEYS_SIZE = 1 << 18;
    public static final int CERT_SEGMENT_SIZE = 1 << 15;
    public static final int CSW_SEGMENT_SIZE = 1 << 18;

    private TestUtils() {}

    public static byte[] fromHexString(String hex) {
        return BaseEncoding.base16().lowerCase().decode(hex.toLowerCase());
    }

    // Get hex string representation of byte array
    public static String toHexString(byte[] bytes) {
        return BaseEncoding.base16().lowerCase().encode(bytes);
    }
}
