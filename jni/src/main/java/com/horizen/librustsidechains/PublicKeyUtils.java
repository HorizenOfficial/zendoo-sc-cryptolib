package com.horizen.librustsidechains;

public class PublicKeyUtils {

    public static final int PUBLIC_KEY_LENGTH = 193;

    static {
        Library.load();
    }

    public static native int nativeGetPublicKeySize();
    public static native byte[] nativeSerializePublicKey(long publicKeyPointer);
    public static native long nativeDeserializePublicKey(byte[] publicKeyBytes);
    public static native void nativeFreePublicKey(long publicKeyPointer);

}
