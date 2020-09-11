package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class VRFProveResult implements AutoCloseable {
    private VRFProof vrfProof;
    private FieldElement vrfOutput;

    static {
        Library.load();
    }

    public VRFProveResult(VRFProof vrfProof, FieldElement vrfOutput) {
        this.vrfProof = vrfProof;
        this.vrfOutput = vrfOutput;
    }

    public VRFProof getVRFProof() {
        return this.vrfProof;
    }

    public FieldElement getVRFOutput() {
        return this.vrfOutput;
    }

    @Override
    public void close() throws Exception {
        this.vrfProof.close();
        this.vrfOutput.close();
    }
}