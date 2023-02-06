package com.horizen.librustsidechains;

/**
 * Holds constant values used Rust side and statically initialized by it
 */
public final class Constants {

    private static int MC_PK_HASH_SIZE;
    private static int SC_PK_HASH_SIZE;
    private static int SC_SK_SIZE;
    private static int SC_TX_HASH_SIZE;
    private static int SC_CUSTOM_HASH_SIZE;

    private static int SC_MST_HEIGHT;
    private static int SC_COMM_TREE_FT_SUBTREE_HEIGHT;
    private static int SC_COMM_TREE_HEIGHT;

    private static int FIELD_ELEMENT_LENGTH;
    private static int SCHNORR_PK_LENGTH;
    private static int SCHNORR_SK_LENGTH;
    private static int SCHNORR_SIGNATURE_LENGTH;
    private static int VRF_PK_LENGTH;
    private static int VRF_SK_LENGTH;
    private static int VRF_PROOF_LENGTH;
    private static int MSG_ROOT_HASH_CUSTOM_FIELDS_POS;
    private static int MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS;
    private static int MIN_CUSTOM_FIELDS;
    private static int MSG_MT_HEIGHT;

    private static native void nativeInitializeAllConstants();

    static {
        Library.load();
        nativeInitializeAllConstants();
    }

    public static int MC_PK_HASH_SIZE() {
        return MC_PK_HASH_SIZE;
    }

    public static int SC_PK_HASH_SIZE() {
        return SC_PK_HASH_SIZE;
    }

    public static int SC_SK_SIZE() {
        return SC_SK_SIZE;
    }

    public static int SC_TX_HASH_SIZE() {
        return SC_TX_HASH_SIZE;
    }

    public static int SC_CUSTOM_HASH_SIZE() {
        return SC_CUSTOM_HASH_SIZE;
    }

    public static int SC_MST_HEIGHT() {
        return SC_MST_HEIGHT;
    }

    public static int SC_COMM_TREE_FT_SUBTREE_HEIGHT() {
        return SC_COMM_TREE_FT_SUBTREE_HEIGHT;
    }

    public static int SC_COMM_TREE_HEIGHT() {
        return SC_COMM_TREE_HEIGHT;
    }

    public static int FIELD_ELEMENT_LENGTH() {
        return FIELD_ELEMENT_LENGTH;
    }

    public static int SCHNORR_PK_LENGTH() {
        return SCHNORR_PK_LENGTH;
    }

    public static int SCHNORR_SK_LENGTH() {
        return SCHNORR_SK_LENGTH;
    }

    public static int SCHNORR_SIGNATURE_LENGTH() {
        return SCHNORR_SIGNATURE_LENGTH;
    }

    public static int VRF_PK_LENGTH() {
        return VRF_PK_LENGTH;
    }

    public static int VRF_SK_LENGTH() {
        return VRF_SK_LENGTH;
    }

    public static int VRF_PROOF_LENGTH() {
        return VRF_PROOF_LENGTH;
    }

    public static int MSG_ROOT_HASH_CUSTOM_FIELDS_POS() {
        return MSG_ROOT_HASH_CUSTOM_FIELDS_POS;
    }

    public static int MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS() {
        return MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS;
    }

    public static int MIN_CUSTOM_FIELDS() {
        return MIN_CUSTOM_FIELDS;
    }

    public static int MSG_MT_HEIGHT() {
        return MSG_MT_HEIGHT;
    }
}
