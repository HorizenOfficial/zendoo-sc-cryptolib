package com.horizen.cswnative;

import java.util.Optional;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;
import com.horizen.librustsidechains.Constants;

public class CswSysData implements AutoCloseable {
    private final FieldElement constant;
    private final FieldElement scLastWcertHash;
    private final Optional<FieldElement> mcbScTxsComEnd;
    private final long amount;
    private final FieldElement nullifier;
    private final byte[] receiver;

    static {
        Library.load();
    }

    public CswSysData(FieldElement constant, FieldElement scLastWcertHash, Optional<FieldElement> mcbScTxsComEnd,
            long amount, FieldElement nullifier, byte[] receiver)
    {
        if (receiver.length != Constants.MC_PK_HASH_SIZE())
            throw new IllegalArgumentException(
                String.format("Incorrect receiver element length, %d expected, %d found",Constants.MC_PK_HASH_SIZE(), receiver.length)
            );
        this.constant = constant;
        this.scLastWcertHash = scLastWcertHash;
        this.mcbScTxsComEnd = mcbScTxsComEnd;
        this.amount = amount;
        this.nullifier = nullifier;
        this.receiver = receiver;
    }

    public FieldElement getConstant() {
        return constant;
    }

    public FieldElement getScLastWcertHash() {
        return scLastWcertHash;
    }

    public Optional<FieldElement> getMcbScTxsComEnd() {
        return mcbScTxsComEnd;
    }

    public long getAmount() {
        return amount;
    }

    public FieldElement getNullifier() {
        return nullifier;
    }

    public byte[] getReceiver() {
        return receiver;
    }

    @Override
    public void close() throws Exception {
        this.constant.close();
        this.scLastWcertHash.close();
        if (this.mcbScTxsComEnd.isPresent())
            this.mcbScTxsComEnd.get().close();
        this.nullifier.close();
        
    }
}
