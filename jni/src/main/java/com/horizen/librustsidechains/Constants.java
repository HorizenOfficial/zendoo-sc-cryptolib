package com.horizen.librustsidechains;

public final class Constants {
    public final class InnerConstants {
        public int MC_PK_HASH_SIZE;
        public int SC_PK_HASH_SIZE;
        public int SC_SK_SIZE;
        public int SC_TX_HASH_SIZE;
        public int SC_CUSTOM_HASH_SIZE;
    
        public int SC_MST_HEIGHT;
        public int SC_COMM_TREE_FT_SUBTREE_HEIGHT;
        public int SC_COMM_TREE_HEIGHT;
    
        public int FIELD_ELEMENT_LENGTH;
        public int SCHNORR_PK_LENGTH;
        public int SCHNORR_SK_LENGTH;
        public int SCHNORR_SIGNATURE_LENGTH;
        public int VRF_PK_LENGTH;
        public int VRF_SK_LENGTH;
        public int VRF_PROOF_LENGTH;
    }

    private static final InnerConstants constantsAssignment;

    public static InnerConstants get() {
        return constantsAssignment;
    }

    private static native InnerConstants nativeInitializeAllConstants();

    static {
        Library.load();
        constantsAssignment = nativeInitializeAllConstants();
    }
}
