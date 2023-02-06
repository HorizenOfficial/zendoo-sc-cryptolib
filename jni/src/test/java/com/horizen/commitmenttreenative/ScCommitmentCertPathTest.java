package com.horizen.commitmenttreenative;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.junit.Test;

import com.horizen.librustsidechains.FieldElement;

public class ScCommitmentCertPathTest {
    private ScCommitmentCertPath getCertPath(CommitmentTree commTree, FieldElement scId, FieldElement certLeaf) {
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
                ScCommitmentCertPath path = getCertPath(ct, scId, certLeaf);
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
                ScCommitmentCertPath path = getCertPath(ct, scId, certLeaf);
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
                ScCommitmentCertPath path = getCertPath(ct, scId, certLeaf);
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
                ScCommitmentCertPath path = getCertPath(ct, scId, certLeaf);
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
                ScCommitmentCertPath path = getCertPath(ct, scId, certLeaf);
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
                ScCommitmentCertPath path = getCertPath(ct, scId, certLeaf);
                FieldElement root = ct.getCommitment().get();) {
            /// Sanity Check
            assertTrue(path.verify(root, scId, certLeaf));

            byte[] serilized = path.serialize();

            try (ScCommitmentCertPath deserialized = ScCommitmentCertPath.deserialize(serilized, true)) {
                assertTrue(deserialized.verify(root, scId, certLeaf));
            }

            serilized[0] = (byte) (serilized[0] + 1);

            try (ScCommitmentCertPath deserialized = ScCommitmentCertPath.deserialize(serilized, true)) {
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
}
