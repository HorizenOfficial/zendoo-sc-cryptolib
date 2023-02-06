package com.horizen.sc2scnative;

import java.util.Optional;

import com.horizen.certnative.WithdrawalCertificate;
import com.horizen.commitmenttreenative.ScCommitmentCertPath;
import com.horizen.librustsidechains.FieldElement;
import com.horizen.merkletreenative.MerklePath;
import com.horizen.provingsystemnative.ProvingSystemType;

public class Sc2Sc {

        private static native boolean nativeSetup(
                        ProvingSystemType psType,
                        int numCustomFields,
                        Optional<Integer> segmentSize,
                        String provingKeyPath,
                        String verificationKeyPath,
                        boolean zk,
                        int maxProofPlusVkSize,
                        boolean compressPk,
                        boolean compressVk) throws Exception;

        /**
         * Generate (provingKey, verificationKey) pair for this circuit.
         * 
         * @param psType
         *                            - proving system to be used
         * @param numCustomFields
         *                            - exact number of custom fields the circuit must
         *                            support
         * @param segmentSize         - the segment size to be used to generate (pk,
         *                            vk). Must be smaller equal than
         *                            the segment size passed to the
         *                            ProvingSystem.generateDLogKeys() method.
         *                            If not specified, it will default to the same size
         *                            as the one passed to
         *                            ProvingSystem.generateDLogKeys() method.
         * @param provingKeyPath      - file path to which saving the proving key
         * @param verificationKeyPath - file path to which saving the verification key
         * @param zk                  - used to estimate the proof and vk size, tells if
         *                            the proof will be created using zk or not
         * @param maxProofPlusVkSize  - maximum allowed size for proof + vk
         * @param compressPk          - if the proving key must be saved to
         *                            provingKeyPath in compressed form
         * @param compressVk          - if the verification key must be saved to
         *                            verificationKeyPath in compressed form
         * @return true if (pk, vk) generation and saving to file was successfull
         * @throws Exception if (pk, vk) generation or saving to file fails
         */
        public static boolean setup(
                        ProvingSystemType psType,
                        int numCustomFields,
                        Optional<Integer> segmentSize,
                        String provingKeyPath,
                        String verificationKeyPath,
                        boolean zk,
                        int maxProofPlusVkSize,
                        boolean compressPk,
                        boolean compressVk) throws Exception {
                return nativeSetup(
                                psType, numCustomFields, segmentSize, provingKeyPath,
                                verificationKeyPath, zk, maxProofPlusVkSize, compressPk, compressVk);

        }

        /**
         * Generate a compressed (provingKey, verificationKey) pair for this circuit.
         * 
         * @param psType
         *                            - proving system to be used
         * @param numCustomFields
         *                            - exact number of custom fields the circuit must
         *                            support
         * @param segmentSize         - the segment size to be used to generate (pk,
         *                            vk). Must be smaller equal than
         *                            the segment size passed to the
         *                            ProvingSystem.generateDLogKeys() method.
         *                            If not specified, it will default to the same size
         *                            as the one passed to
         *                            ProvingSystem.generateDLogKeys() method.
         * @param provingKeyPath      - file path to which saving the proving key
         * @param verificationKeyPath - file path to which saving the verification key
         * @param zk                  - used to estimate the proof and vk size, tells if
         *                            the proof will be created using zk or not
         * @param maxProofPlusVkSize  - maximum allowed size for proof + vk
         * @return true if (pk, vk) generation and saving to file was successfull
         * @throws Exception if (pk, vk) generation or saving to file fails
         */
        public static boolean setup(
                        ProvingSystemType psType,
                        int numCustomFields,
                        Optional<Integer> segmentSize,
                        String provingKeyPath,
                        String verificationKeyPath,
                        boolean zk,
                        int maxProofPlusVkSize) throws Exception {
                return setup(psType, numCustomFields, segmentSize, provingKeyPath,
                                verificationKeyPath, zk, maxProofPlusVkSize, true, true);

        }

        private static native Sc2ScProof nativeCreateProof(
                        FieldElement nextScTxCommitmentsRoot,
                        FieldElement currentScTxCommitmentsRoot,
                        FieldElement msgHash,
                        WithdrawalCertificate nextWithdrawalCertificate,
                        WithdrawalCertificate currWithdrawalCertificate,
                        ScCommitmentCertPath nextPath,
                        ScCommitmentCertPath currentPath,
                        MerklePath msgPath,
                        Optional<Integer> segmentSize,
                        String pkPath,
                        boolean checkProvingKey,
                        boolean zk,
                        boolean compressedPk,
                        boolean compressProof);

        /**
         * Create a proof for Side to Sidechain redeemed message
         * 
         * @param nextScTxCommitmentsRoot    - Next epoch sc tx root (public)
         * @param currentScTxCommitmentsRoot - Current epoch sc tx root for (public)
         * @param msgHash                    - Message hash (public)
         * @param nextWithdrawalCertificate  - Next epoch Withdrowal Certificate
         *                                   (witness)
         * @param currWithdrawalCertificate  - Current epoch Withdrowal Certificate
         *                                   (witness)
         * @param nextPath                   - Next epoch certificate path (witness)
         * @param currentPath                - Current epoch certificate path (witness)
         * @param msgPath                    - Merkle tree message path (witness)
         * @param segmentSize                - The segment size: SHOULD BE THE SAME USED
         *                                   TO GENERATE THE PROVING KEY FILE
         * @param pkPath                     - Proving Key file path
         * @param checkProvingKey            - Check or not the proving key
         * @param zk                         - Use zero knowledge or not
         * @param compressedPk               - Indicate if the proving key is compressed
         *                                   or not
         * @param compressProof              - The proof will be compressed or not
         * @return A Sidechain to sidechain proof.
         */
        public static Sc2ScProof createProof(
                        FieldElement nextScTxCommitmentsRoot,
                        FieldElement currentScTxCommitmentsRoot,
                        FieldElement msgHash,
                        WithdrawalCertificate nextWithdrawalCertificate,
                        WithdrawalCertificate currWithdrawalCertificate,
                        ScCommitmentCertPath nextPath, ScCommitmentCertPath currentPath, MerklePath msgPath,
                        Optional<Integer> segmentSize,
                        String pkPath,
                        boolean checkProvingKey,
                        boolean zk,
                        boolean compressedPk,
                        boolean compressProof) {
                return nativeCreateProof(
                                nextScTxCommitmentsRoot,
                                currentScTxCommitmentsRoot,
                                msgHash,
                                nextWithdrawalCertificate,
                                currWithdrawalCertificate,
                                nextPath,
                                currentPath,
                                msgPath,
                                segmentSize,
                                pkPath,
                                checkProvingKey,
                                zk,
                                compressedPk,
                                compressProof);
        }

        /**
         * Create a proof for Side to Sidechain redeemed message. In this case it will
         * check the proving key and assume that proving key and proof are compressed.
         * 
         * @param nextScTxCommitmentsRoot    - Next epoch sc tx root (public)
         * @param currentScTxCommitmentsRoot - Current epoch sc tx root for (public)
         * @param msgHash                    - Message hash (public)
         * @param nextWithdrawalCertificate  - Next epoch Withdrowal Certificate
         *                                   (witness)
         * @param currWithdrawalCertificate  - Current epoch Withdrowal Certificate
         *                                   (witness)
         * @param nextPath                   - Next epoch certificate path (witness)
         * @param currentPath                - Current epoch certificate path (witness)
         * @param msgPath                    - Merkle tree message path (witness)
         * @param segmentSize                - The segment size: SHOULD BE THE SAME USED
         *                                   TO GENERATE THE PROVING KEY FILE
         * @param pkPath                     - Proving Key file path
         * @param zk                         - Use zero knowledge or not
         * @return A Sidechain to sidechain proof.
         */
        public static Sc2ScProof createProof(
                        FieldElement nextScTxCommitmentsRoot,
                        FieldElement currentScTxCommitmentsRoot,
                        FieldElement msgHash,
                        WithdrawalCertificate nextWithdrawalCertificate,
                        WithdrawalCertificate currWithdrawalCertificate,
                        ScCommitmentCertPath nextPath, ScCommitmentCertPath currentPath, MerklePath msgPath,
                        Optional<Integer> segmentSize,
                        String pkPath,
                        boolean zk) {
                return createProof(
                                nextScTxCommitmentsRoot,
                                currentScTxCommitmentsRoot,
                                msgHash,
                                nextWithdrawalCertificate,
                                currWithdrawalCertificate,
                                nextPath,
                                currentPath,
                                msgPath,
                                segmentSize,
                                pkPath,
                                true,
                                zk,
                                true,
                                true);
        }

        /**
         * Create a proof for Side to Sidechain redeemed message. In this case it will
         * check the proving key and assume that proving key and proof are compressed.
         * This varian take arrays of bytes instead of FieldElement.
         * 
         * @param nextScTxCommitmentsRoot    - Next epoch sc tx root (public)
         * @param currentScTxCommitmentsRoot - Current epoch sc tx root for (public)
         * @param msgHash                    - Message hash (public)
         * @param nextWithdrawalCertificate  - Next epoch Withdrowal Certificate
         *                                   (witness)
         * @param currWithdrawalCertificate  - Current epoch Withdrowal Certificate
         *                                   (witness)
         * @param nextPath                   - Next epoch certificate path (witness)
         * @param currentPath                - Current epoch certificate path (witness)
         * @param msgPath                    - Merkle tree message path (witness)
         * @param segmentSize                - The segment size: SHOULD BE THE SAME USED
         *                                   TO GENERATE THE PROVING KEY FILE
         * @param pkPath                     - Proving Key file path
         * @param zk                         - Use zero knowledge or not
         * @return A Sidechain to sidechain proof.
         */
        public static Sc2ScProof createProof(byte[] nextScTxCommitmentsRootB, byte[] currentScTxCommitmentsRootB,
                        byte[] msgHashB,
                        WithdrawalCertificate nextWithdrawalCertificate,
                        WithdrawalCertificate currWithdrawalCertificate,
                        ScCommitmentCertPath nextPath, ScCommitmentCertPath currentPath, MerklePath msgPath,
                        String pkPath,
                        Optional<Integer> segmentSize,
                        boolean zk) {
                // I know that multiple JNI call generate lot of overhead but I choose to do it
                // because:
                // - I prefer to call a native method that is type safe
                // - I would provide to the end user also a method that not use FieldElement
                // type and use almost as possible java type and not wraps of native ones.
                try (FieldElement nextScTxCommitmentsRoot = FieldElement.deserialize(nextScTxCommitmentsRootB);
                                FieldElement currentScTxCommitmentsRoot = FieldElement
                                                .deserialize(currentScTxCommitmentsRootB);
                                FieldElement msgHash = FieldElement.deserialize(msgHashB);) {
                        return createProof(
                                        nextScTxCommitmentsRoot,
                                        currentScTxCommitmentsRoot,
                                        msgHash,
                                        nextWithdrawalCertificate,
                                        currWithdrawalCertificate,
                                        nextPath,
                                        currentPath,
                                        msgPath,
                                        segmentSize,
                                        pkPath,
                                        zk);
                }
        }
}
