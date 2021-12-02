package com.horizen.cswnative;

import com.horizen.certnative.WithdrawalCertificate;
import com.horizen.fwtnative.ForwardTransferOutput;
import com.horizen.librustsidechains.Constants;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.merkletreenative.InMemoryAppendOnlyMerkleTree;
import com.horizen.merkletreenative.MerklePath;
import com.horizen.poseidonnative.PoseidonHash;
import com.horizen.scutxonative.ScUtxoOutput;
import com.horizen.provingsystemnative.ProvingSystem;
import com.horizen.provingsystemnative.ProvingSystemType;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class CswProofTest {
    static long seed = 1234567890L;
    
    static int rangeSize = 100;
    static int maxProofPlusVkSize = 9 * 1024;
    static boolean zk = true;

    static int numBt = 10;
    static ScUtxoOutput scUtxoOutput;
    static ForwardTransferOutput ftOutput;
    static WithdrawalCertificate wCert;

    static byte[] testScSecretKey;
    static byte[] testScPublicKey;
    
    static String snarkPkPath = "./test_csw_snark_pk";
    static String snarkVkPath = "./test_csw_snark_vk";
    static int maxSegmentSize = 1 << 20;
    static int supportedSegmentSize = 1 << 18;
    static ProvingSystemType psType = ProvingSystemType.COBOUNDARY_MARLIN;
    
    @BeforeClass
    public static void initKeys() {
        // Generate keys
        assertTrue(ProvingSystem.generateDLogKeys(psType, maxSegmentSize, supportedSegmentSize));
        assertTrue(CswProof.setup(psType, rangeSize, 2, snarkPkPath, snarkVkPath, zk, maxProofPlusVkSize));
        assertFalse(CswProof.setup(psType, rangeSize, 0, snarkPkPath, snarkVkPath, zk, 1));
        assertEquals(
            psType,
            ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPath)
        );
        assertEquals(
            ProvingSystem.getProverKeyProvingSystemType(snarkPkPath),
            ProvingSystem.getVerifierKeyProvingSystemType(snarkVkPath)
        );

        // Generate random (but consistent) data
        Random r = new Random(seed);

        wCert = WithdrawalCertificate.getRandom(r, numBt, 0);

        scUtxoOutput = ScUtxoOutput.getRandom(r);
        scUtxoOutput.setSpendingPubKey(testScPublicKey);

        ftOutput = ForwardTransferOutput.getRandom(r);
        ftOutput.setReceiverPubKey(testScPublicKey);
    }

    @Test
    public void testCreateVerifyScUtxoRandomProof() throws Exception {

        // Compute scUtxo nullifier
        FieldElement nullifier = scUtxoOutput.getNullifier();

        // Put ScUtxo in MerkleTree just to generate valid root
        // and path that will be used to update the data
        InMemoryAppendOnlyMerkleTree mht = InMemoryAppendOnlyMerkleTree.init(Constants.SC_MST_HEIGHT(), 1);
        mht.append(nullifier);
        mht.finalizeTreeInPlace();
        
        FieldElement mstRoot = mht.root();
        MerklePath mstPathToOutput = mht.getMerklePath(0);
        mht.close(); // Free tree as we don't need it anymore

        // Split the mstRoot into 2 FieldElements to be declared as custom fields and put them inside wCert
        List<FieldElement> customFields = mstRoot.splitAt(Constants.FIELD_ELEMENT_LENGTH()/2);
        wCert.setCustomFields(customFields.toArray(new FieldElement[0]));

        // Generate CswUtxoProverData
        CswUtxoProverData utxoData = new CswUtxoProverData(
            scUtxoOutput,
            testScSecretKey,
            mstPathToOutput
        );

        // Compute wCert hash
        FieldElement scLastWcertHash = wCert.getHash();

        // Generate random receiver
        Random r = new Random(seed);
        byte[] receiver = new byte[Constants.MC_PK_HASH_SIZE()];
        r.nextBytes(receiver);

        // Generate random constant
        FieldElement constant = FieldElement.createRandom(r);

        // Generate CswSysData
        CswSysData sysData = new CswSysData(
            Optional.of(constant),
            Optional.of(scLastWcertHash),
            Optional.empty(),
            scUtxoOutput.getAmount(),
            nullifier,
            receiver
        );

        // Create proof
        byte[] proof = CswProof.createProof(
            rangeSize, 2, sysData, wCert.getScId(),
            Optional.of(wCert), Optional.of(utxoData), Optional.empty(), snarkPkPath
        );
    }

    @Test
    public void testCreateVerifyFwtRandomProof() throws Exception {
        // Generate random receiver
        Random r = new Random(seed);
        byte[] receiver = new byte[Constants.MC_PK_HASH_SIZE()];
        r.nextBytes(receiver);

        // Generate random constant
        FieldElement constant = FieldElement.createRandom(r);

        // Compute ftOutput nullifier
        FieldElement nullifier = ftOutput.getNullifier();

        // Put ftOutput in MerkleTree just to generate valid root and path
        InMemoryAppendOnlyMerkleTree mht = InMemoryAppendOnlyMerkleTree.init(Constants.SC_COMM_TREE_FT_SUBTREE_HEIGHT(), 1);
        mht.append(nullifier);
        mht.finalizeTreeInPlace();
        
        FieldElement ftTreeRoot = mht.root();
        MerklePath ftTreePath = mht.getMerklePath(0);
        mht.close(); // Free tree as we don't need it anymore

        // Sample random data and compute scHash
        FieldElement scCreationCommitment = FieldElement.createRandom(r);
        FieldElement scbBtrTreeRoot = FieldElement.createRandom(r);
        FieldElement wCertTreeRoot = FieldElement.createRandom(r);
        PoseidonHash h = PoseidonHash.getInstanceConstantLength(5);
        h.update(ftTreeRoot);
        h.update(scbBtrTreeRoot);
        h.update(wCertTreeRoot);
        h.update(scCreationCommitment);
        h.update(wCert.getScId());
        FieldElement scHash = h.finalizeHash();
        h.close(); // We don't need PoseidonHash instance anymroe

        // Put scHash in MerkleTree just to generate valid root and path
        InMemoryAppendOnlyMerkleTree mhtNew = InMemoryAppendOnlyMerkleTree.init(Constants.SC_COMM_TREE_HEIGHT(), 1);
        mhtNew.append(scHash);
        mhtNew.finalizeTreeInPlace();
        
        FieldElement scTxsComTreeRoot = mht.root();
        MerklePath merklePathToScHash = mht.getMerklePath(0);
        mht.close(); // Free tree as we don't need it anymore

        // Now generate scTxsComHashes list, putting scTxsComTreeRoot in one of them
        // and contextually compute mcbScTxsComEnd
        FieldElement mcbScTxsComStart = FieldElement.createRandom(r);
        int scTxsComTreeRootPosition = r.nextInt(rangeSize);

        FieldElement acc = mcbScTxsComStart;
        PoseidonHash h1 = PoseidonHash.getInstanceConstantLength(2);

        List<FieldElement> scTxsComHashes = new ArrayList<>();
        for (int i = 0; i < rangeSize; i++) {
            // Generate random FieldElement
            FieldElement scTxsComHash = (i == scTxsComTreeRootPosition) ? scTxsComTreeRoot: FieldElement.createRandom(r);

            // Add it to the list
            scTxsComHashes.add(scTxsComHash);

            // Update acc
            h1.update(acc);
            h1.update(scTxsComHash);
            acc = h1.finalizeHash();
            h1.reset();
        }
        FieldElement mcbScTxsComEnd = acc;

        // Generate FtCswProverData
        CswFtProverData ftData = new CswFtProverData(
            ftOutput,
            testScSecretKey,
            mcbScTxsComStart,
            merklePathToScHash,
            ftTreePath,
            scCreationCommitment,
            scbBtrTreeRoot,
            wCertTreeRoot,
            scTxsComHashes
        );

        // Generate CswSysData
        CswSysData sysData = new CswSysData(
            Optional.of(constant),
            Optional.empty(),
            Optional.of(mcbScTxsComEnd),
            ftOutput.getAmount(),
            nullifier,
            receiver
        );

        // Create proof
        byte[] proof = CswProof.createProof(
            rangeSize, 2, sysData, wCert.getScId(), Optional.empty(),
            Optional.empty(), Optional.of(ftData), snarkPkPath
        );
    }

    // private void testCreateVerifyRandomProof(String snarkPkPath, String snarkVkPath) throws Exception {
    //     Random r = new Random();

    //     scId = FieldElement.createRandom();
    //     endCumulativeScTxCommTreeRoot = FieldElement.createRandom();

    //     backwardTransferCout = r.nextInt(backwardTransferCout + 1);
    //     // Create dummy Backward Transfers
    //     for(int i = 0; i < backwardTransferCout; i++)
    //         btList.add(BackwardTransfer.getRandom(r));

    //     // Compute keys and signatures
    //     List<SchnorrKeyPair> keyPairList = new ArrayList<>();

    //     for (int i = 0; i<keyCount; i++) {
    //         SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

    //         assertNotNull("Key pair generation was unsuccessful.", keyPair);
    //         assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

    //         keyPairList.add(keyPair);
    //         publicKeyList.add(keyPair.getPublicKey());
    //     }

    //     // Generate random custom fields if requested
    //     if (numCustomFields > 0) {
    //         for (int i = 0; i < numCustomFields; i++)
    //             customFields.add(FieldElement.createRandom());
    //     }

    //     for (int i = 0; i<keyCount; i++) {
    //         if (i < threshold) {
    //             FieldElement msgToSign = NaiveThresholdSigProof.createMsgToSign(
    //                 btList.toArray(new BackwardTransfer[0]),
    //                 scId,
    //                 epochNumber,
    //                 endCumulativeScTxCommTreeRoot,
    //                 btrFee,
    //                 ftMinAmount,
    //                 customFields
    //             );
    //             signatureList.add(keyPairList.get(i).signMessage(msgToSign));
    //         } else {
    //             signatureList.add(new SchnorrSignature());
    //         }
    //     }

    //     //Free memory from the secret keys
    //     for (SchnorrKeyPair kp: keyPairList)
    //         kp.getSecretKey().freeSecretKey();

    //     // Create and verify proof

    //     // Positive test
    //     CreateProofResult proofResult = NaiveThresholdSigProof.createProof(
    //         btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
    //         btrFee, ftMinAmount, signatureList, publicKeyList, threshold,
    //         customFields, snarkPkPath, false, zk
    //     );

    //     assertNotNull("Proof creation must be successful", proofResult);

    //     byte[] proof = proofResult.getProof();
    //     assertEquals(psType, ProvingSystem.getProofProvingSystemType(proof));

    //     long quality = proofResult.getQuality();

    //     FieldElement constant = NaiveThresholdSigProof.getConstant(publicKeyList, threshold);
    //     assertNotNull("Constant creation must be successful", constant);

    //     boolean isProofVerified = NaiveThresholdSigProof.verifyProof(
    //         btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
    //         btrFee, ftMinAmount, constant, quality, customFields, proof, true, snarkVkPath, true
    //     );

    //     assertTrue("Proof must be verified", isProofVerified);

    //     // Negative test
    //     quality = threshold - 1;
    //     isProofVerified = NaiveThresholdSigProof.verifyProof(
    //         btList, scId, epochNumber, endCumulativeScTxCommTreeRoot,
    //         btrFee, ftMinAmount, constant, quality, customFields, proof, true, snarkVkPath, true
    //     );

    //     assertFalse("Proof must not be verified", isProofVerified);
    // }

    // @After
    // public void freeData() {
    //     for (SchnorrPublicKey pk: publicKeyList)
    //         pk.freePublicKey();
    //     publicKeyList.clear();

    //     for (SchnorrSignature sig: signatureList)
    //         sig.freeSignature();
    //     signatureList.clear();

    //     for (FieldElement fe: customFields)
    //         fe.freeFieldElement();
    //     customFields.clear();

    //     scId.freeFieldElement();
    //     endCumulativeScTxCommTreeRoot.freeFieldElement();
    // }

    // @AfterClass
    // public static void deleteKeys(){
    //     // Delete proving keys and verification keys
    //     new File(snarkPkPathNoCustomFields).delete();
    //     new File(snarkVkPathNoCustomFields).delete();
    //     new File(snarkPkPathCustomFields).delete();
    //     new File(snarkVkPathCustomFields).delete();
    // }
}