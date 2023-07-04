package com.horizen.cswnative;

import com.horizen.librustsidechains.Constants;
import com.horizen.merkletreenative.MerklePath;
import com.horizen.scutxonative.ScUtxoOutput;

public class CswUtxoProverData implements AutoCloseable {
    private final ScUtxoOutput output;
    private final byte[] utxoInputSecretKey;
	private final MerklePath mstPathToOutput;

    public CswUtxoProverData(ScUtxoOutput output, byte[] utxoInputSecretKey, MerklePath mstPathToOutput) {
        this.output = output;

        if (utxoInputSecretKey.length != Constants.SC_SK_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect utxoInputSecretKey element length, %d expected, %d found",Constants.SC_SK_SIZE(), utxoInputSecretKey.length)
            );
        this.utxoInputSecretKey = utxoInputSecretKey;

        if (mstPathToOutput.getLength() != Constants.SC_MST_HEIGHT())
            throw new IllegalArgumentException(
                String.format("Incorrect mstPathToOutput length, %d expected, %d found",Constants.SC_MST_HEIGHT(), mstPathToOutput.getLength())
            );
        this.mstPathToOutput = mstPathToOutput;
    }

    public ScUtxoOutput getOutput() {
        return output;
    }

    public byte[] getutxoInputSecretKey() {
        return utxoInputSecretKey;
    }

    public MerklePath getMstPathToOutput() {
        return mstPathToOutput;
    }

    @Override
    public void close() {
        this.mstPathToOutput.close();
    }
}
