package com.horizen.poseidonnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class PoseidonHash implements AutoCloseable {

    private long poseidonHashPointer;

    static {
        Library.load();
    }

    private PoseidonHash(long poseidonHashPointer) {
        if (poseidonHashPointer == 0)
            throw new IllegalArgumentException("poseidonHashPointer must be not null.");
        this.poseidonHashPointer = poseidonHashPointer;
    }

    private static native PoseidonHash nativeGetConstantLengthPoseidonHash(int inputSize, FieldElement[] personalization);

    private static native PoseidonHash nativeGetVariableLengthPoseidonHash(boolean modRate, FieldElement[] personalization);

    /*
    * Default that returns a variable input length, non modRate, new PoseidonHash instance.
    */
    public static PoseidonHash getInstance(){
        return nativeGetVariableLengthPoseidonHash(false, new FieldElement[0]);
    }

    public static PoseidonHash getInstance(FieldElement[] personalization)
    {
       return nativeGetVariableLengthPoseidonHash(false, personalization);
    }

    /*
     * Return a constant input length new PoseidonHash instance, given the size of the input.
     * If calling finalizeHash() after having updated this instance with more or less than
     * inputSize elements, an exception will be raised Rust-side.
     */
    public static PoseidonHash getInstanceConstantLength(int inputSize){
        return nativeGetConstantLengthPoseidonHash(inputSize, new FieldElement[0]);
    }

    public static PoseidonHash getInstanceConstantLength(int inputSize, FieldElement[] personalization)
    {
        return nativeGetConstantLengthPoseidonHash(inputSize, personalization);
    }

    /*
     * Return a variable input length new PoseidonHash instance, with the possibility to
     * specify (for performances) if the input will be modulus the rate of the hash or not.
     * If calling finalizeHash() after having updated this instance with a number of elements
     * not multiple of the rate, and modRate is True, an exception will be raised Rust-side.
     */
    public static PoseidonHash getInstanceVariableLength(boolean modRate){
        return nativeGetVariableLengthPoseidonHash(modRate, new FieldElement[0]);
    }

    public static PoseidonHash getInstanceVariableLength(boolean modRate, FieldElement[] personalization)
    {
        return nativeGetVariableLengthPoseidonHash(modRate, personalization);
    }

    private native void nativeUpdate(FieldElement input);

    /*
     * Update this isntance with the specified input.
     */
    public void update(FieldElement input) {
        if (poseidonHashPointer == 0)
            throw new IllegalStateException("PoseidonHash instance was freed.");
        nativeUpdate(input);
    }

    private native FieldElement nativeFinalize();

    /*
    * Compute and return the digest.
    * An exception will occur in the following cases:
    * - This instance was constructed by calling getInstanceConstantLength(inputSize, ...)
    *   but the number of times update() has been called is not equal to the value of inputSize;
    * - This instance was constructed by calling getInstanceVariableLength(True, ...)
    *   but the number of times update() has been called is not multiple of the hash rate.
    */
    public FieldElement finalizeHash() {
        if (poseidonHashPointer == 0)
            throw new IllegalStateException("PoseidonHash instance was freed.");
        return nativeFinalize();
    }

    private native void nativeReset(FieldElement[] personalization);

    /*
    * Reinitialize this instance to its starting state.
    */
    public void reset(FieldElement[] personalization) {
        if (poseidonHashPointer == 0)
            throw new IllegalStateException("PoseidonHash instance was freed.");
        nativeReset(personalization);
    }

    public void reset() {
        if (poseidonHashPointer == 0)
            throw new IllegalStateException("PoseidonHash instance was freed.");
        nativeReset(new FieldElement[0]);
    }

    /**
     * @deprecated
     * Kept for backward compatibility if needed. Use init -&gt; update -&gt; finalize
     * procedure instead.
     */
    @Deprecated
    public static FieldElement computePoseidonHash(FieldElement[] inputs){
        PoseidonHash digest = PoseidonHash.getInstanceConstantLength(inputs.length);
        for (FieldElement fe: inputs)
            digest.update(fe);
        FieldElement hashOutput = digest.finalizeHash();

        digest.freePoseidonHash();
        return hashOutput;
    }

    private native void nativeFreePoseidonHash();

    public void freePoseidonHash(){
        if (poseidonHashPointer != 0) {
            nativeFreePoseidonHash();
            poseidonHashPointer = 0;
        }
    }

    @Override
    public void close() {
        freePoseidonHash();
    }
}
