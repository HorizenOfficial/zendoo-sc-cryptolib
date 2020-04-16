package com.horizen.librustsidechains;

public class SecretKeyUtils {

    public static final int SECRET_KEY_LENGTH = 96;

    static {
        Library.load();
    }

    public static native int nativeGetSecretKeySize();
    public static native byte[] nativeSerializeSecretKey(long secretKeyPointer);
    public static native long nativeDeserializeSecretKey(byte[] secretKeyBytes);
    public static native void nativeFreeSecretKey(long secretKeyPointer);
}
