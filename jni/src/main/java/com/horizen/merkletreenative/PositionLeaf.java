package com.horizen.merkletreenative;

import com.horizen.librustsidechains.FieldElement;

public class PositionLeaf implements AutoCloseable {
    private long position;
    private FieldElement data;

    public PositionLeaf(long position, FieldElement data) {
        this.position = position;
        this.data = data;
    }

    public long getPosition() {
        return position;
    }

    public FieldElement getData() {
        return data;
    }

    @Override
    public void close() throws Exception {
        this.data.close();
    }
}
