package com.horizen.commitmenttreenative;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.junit.Test;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.merkletreenative.InMemoryAppendOnlyMerkleTree;
import com.horizen.merkletreenative.MerklePath;

public class ScCommitmentCertPathTest {
    private ScCommitmentCertPath addCertAndReturnPath(CommitmentTree commTree, FieldElement scId,
            FieldElement certLeaf) {
        byte[] scIdBytes = scId.serializeFieldElement();
        byte[] certBytes = certLeaf.serializeFieldElement();
        commTree.addCertLeaf(scIdBytes, certBytes);

        return commTree.getScCommitmentCertPath(scIdBytes, certBytes).get();
    }

    @Test
    public void validPath() {
        try (
                CommitmentTree ct = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf = FieldElement.createRandom();
                ScCommitmentCertPath path = addCertAndReturnPath(ct, scId, certLeaf);
                FieldElement root = ct.getCommitment().get();) {
            assertTrue(path.verify(root, scId, certLeaf));
        }
    }

    @Test
    public void verifyShouldFailIfInvalidRoot() {
        try (
                CommitmentTree ct = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf = FieldElement.createRandom();
                ScCommitmentCertPath path = addCertAndReturnPath(ct, scId, certLeaf);
                FieldElement fakeRoot = FieldElement.createRandom();) {
            assertFalse(path.verify(fakeRoot, scId, certLeaf));
        }
    }

    @Test
    public void verifyShouldFailIfInvalidScId() {
        try (
                CommitmentTree ct = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf = FieldElement.createRandom();
                ScCommitmentCertPath path = addCertAndReturnPath(ct, scId, certLeaf);
                FieldElement root = ct.getCommitment().get();
                FieldElement fakeScId = FieldElement.createRandom();) {
            assertFalse(path.verify(root, fakeScId, certLeaf));
        }
    }

    @Test
    public void verifyShouldFailIfInvalidCertHash() {
        try (
                CommitmentTree ct = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf = FieldElement.createRandom();
                ScCommitmentCertPath path = addCertAndReturnPath(ct, scId, certLeaf);
                FieldElement root = ct.getCommitment().get();
                FieldElement fakeCertHash = FieldElement.createRandom();) {
            assertFalse(path.verify(root, fakeCertHash, certLeaf));
        }
    }

    @Test
    public void generateScTxCommitmentRoot() {
        try (
                CommitmentTree ct = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf = FieldElement.createRandom();
                ScCommitmentCertPath path = addCertAndReturnPath(ct, scId, certLeaf);
                FieldElement root = ct.getCommitment().get();) {
            assertEquals(root, path.apply(scId, certLeaf).get());
        }
    }

    @Test
    public void shouldSerializeDeserialize() {
        try (
                CommitmentTree ct = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf = FieldElement.createRandom();
                ScCommitmentCertPath path = addCertAndReturnPath(ct, scId, certLeaf);
                FieldElement root = ct.getCommitment().get();) {
            /// Sanity Check
            assertTrue(path.verify(root, scId, certLeaf));

            byte[] serialized = path.serialize();

            try (ScCommitmentCertPath deserialized = ScCommitmentCertPath.deserialize(serialized, true)) {
                assertTrue(deserialized.verify(root, scId, certLeaf));
            }

            serialized[0] = (byte) (serialized[0] + 1);

            try (ScCommitmentCertPath deserialized = ScCommitmentCertPath.deserialize(serialized, true)) {
                assertFalse(deserialized.verify(root, scId, certLeaf));
            }
        }
    }

    @Test
    public void completeTest() {
        try (
                CommitmentTree commTree = CommitmentTree.init();
                FieldElement scId = FieldElement.createRandom();
                FieldElement certLeaf0 = FieldElement.createRandom();
                FieldElement certLeaf1 = FieldElement.createRandom();
                FieldElement certLeaf2 = FieldElement.createRandom();) {
            byte[] scIdBytes = scId.serializeFieldElement();
            FieldElement[] certs = { certLeaf0, certLeaf1, certLeaf2 };
            ArrayList<byte[]> certsHashBytes = Arrays.stream(certs)
                    .map(FieldElement::serializeFieldElement)
                    .collect(Collectors.toCollection(ArrayList::new));

            for (byte[] h : certsHashBytes) {
                commTree.addCertLeaf(scIdBytes, h);
            }

            try (FieldElement scTxCommitmentRoot = commTree.getCommitment().get()) {
                ArrayList<ScCommitmentCertPath> paths = certsHashBytes.stream().map(
                        h -> commTree.getScCommitmentCertPath(scIdBytes, h).get())
                        .collect(Collectors.toCollection(ArrayList::new));

                assertFalse(
                        commTree.getScCommitmentCertPath(scIdBytes, FieldElement.createRandom().serializeFieldElement())
                                .isPresent());

                for (int i = 0; i < certs.length; i++) {
                    assertTrue(paths.get(i).verify(scTxCommitmentRoot, scId, certs[i]));
                }
                assertFalse(paths.get(0).verify(scTxCommitmentRoot, scId, FieldElement.createRandom()));
                for (int i = 0; i < certs.length; i++) {
                    assertFalse(paths.get(i).verify(FieldElement.createRandom(), scId, certs[i]));
                }
                for (int i = 0; i < certs.length; i++) {
                    assertFalse(paths.get(i).verify(scTxCommitmentRoot, FieldElement.createRandom(), certs[i]));
                }
                for (int i = 0; i < certs.length; i++) {
                    try (FieldElement root = paths.get(i).apply(scId, certs[i]).get()) {
                        assertEquals(scTxCommitmentRoot, root);
                    }
                }
                for (ScCommitmentCertPath path : paths) {
                    path.freeScCommitmentCertPath();
                }
            }
        }
    }

    @Test
    public void updatePath() {
        try (
                CommitmentTree commTreeReal = CommitmentTree.init();
                FieldElement scId1 = FieldElement.createFromLong(10);
                FieldElement scId2 = FieldElement.createFromLong(20);
                FieldElement certLeaf11 = FieldElement.createRandom();
                FieldElement certLeaf12 = FieldElement.createRandom();
                FieldElement certLeaf21 = FieldElement.createRandom();) {

            byte[] scId1Bytes = scId1.serializeFieldElement();
            byte[] scId2Bytes = scId2.serializeFieldElement();
            FieldElement[] certs1 = { certLeaf11, certLeaf12 };
            FieldElement[] certs2 = { certLeaf21 };
            ArrayList<byte[]> certs1HashBytes = Arrays.stream(certs1)
                    .map(FieldElement::serializeFieldElement)
                    .collect(Collectors.toCollection(ArrayList::new));

            ArrayList<byte[]> certs2HashBytes = Arrays.stream(certs2)
                    .map(FieldElement::serializeFieldElement)
                    .collect(Collectors.toCollection(ArrayList::new));

            for (byte[] h : certs1HashBytes) {
                commTreeReal.addCertLeaf(scId1Bytes, h);
            }
            for (byte[] h : certs2HashBytes) {
                commTreeReal.addCertLeaf(scId2Bytes, h);
            }

            try (
                    FieldElement expectedScTxCommitmentRoot = commTreeReal.getCommitment().get();
                    MerklePath correctScPath = commTreeReal.getScCommitmentMerklePath(scId1Bytes).get();
                    CommitmentTree commTreePartial = CommitmentTree.init();) {
                for (byte[] h : certs1HashBytes) {
                    commTreePartial.addCertLeaf(scId1Bytes, h);
                }

                try (
                        ScCommitmentCertPath pathCert1 = commTreePartial
                                .getScCommitmentCertPath(scId1Bytes, certs1HashBytes.get(0)).get();
                        ScCommitmentCertPath pathCert2 = commTreePartial
                                .getScCommitmentCertPath(scId1Bytes, certs1HashBytes.get(1)).get();) {
                    assertFalse(pathCert1.verify(expectedScTxCommitmentRoot, scId1, certLeaf11));
                    assertFalse(pathCert2.verify(expectedScTxCommitmentRoot, scId1, certLeaf12));

                    pathCert1.updateScCommitmentPath(correctScPath);
                    pathCert2.updateScCommitmentPath(correctScPath);

                    assertTrue(pathCert1.verify(expectedScTxCommitmentRoot, scId1, certLeaf11));
                    assertTrue(pathCert2.verify(expectedScTxCommitmentRoot, scId1, certLeaf12));
                }
            }
        }
    }

    @Test
    public void updatePathShouldThrowExceptionIfWrongLength() {
        try (
                CommitmentTree commTree = CommitmentTree.init();
                FieldElement scId = FieldElement.createFromLong(10);
                FieldElement certLeaf = FieldElement.createRandom();
                ) {

            byte[] scIdBytes = scId.serializeFieldElement();
            byte[] certLeafBytes = scId.serializeFieldElement();

            commTree.addCertLeaf(scIdBytes, certLeafBytes);

            try (
                ScCommitmentCertPath pathCert = commTree
                                .getScCommitmentCertPath(scIdBytes, certLeafBytes).get();
                InMemoryAppendOnlyMerkleTree mt = InMemoryAppendOnlyMerkleTree.init(5, 1 << 5);
                FieldElement leaf = FieldElement.createRandom();
             ) {
                mt.append(leaf);
                mt.finalizeTreeInPlace();
                try (MerklePath invalidPath = mt.getMerklePath(0)) {
                    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
                        pathCert.updateScCommitmentPath(invalidPath);
                    });
                    assertTrue("'" + ex.getMessage() + "\' Not contains 'invalid path length'", ex.getMessage().toLowerCase().contains("invalid path length"));
                }
            }
        }
    }
}
