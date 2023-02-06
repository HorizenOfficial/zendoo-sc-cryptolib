use std::{borrow::Borrow, convert::TryInto};

use algebra::{
    CanonicalDeserialize, CanonicalSerialize, Error, Field, Read, SemanticallyValid,
    SerializationError, Write,
};
use cctp_primitives::{
    commitment_tree::{sidechain_tree_alive::CERT_MT_HEIGHT, CommitmentTree, CMT_MT_HEIGHT},
    proving_system::verifier::UserInputs,
    type_mapping::FieldElement,
    utils::commitment_tree::hash_vec,
};
use primitives::FieldBasedMerkleTreePath;
use r1cs_core::ConstraintSynthesizer;
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedMerkleTreePathGadget, FieldHasherGadget};
use r1cs_std::{
    fields::fp::FpGadget,
    prelude::{AllocGadget, EqGadget, FieldGadget},
    FromBitsGadget,
};

use crate::{
    common::{
        constraints::WithdrawalCertificateDataGadget, WithdrawalCertificateData,
        MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS, MIN_CUSTOM_FIELDS,
        MSG_ROOT_HASH_CUSTOM_FIELDS_POS,
    },
    FieldElementGadget, FieldHashGadget, GingerMHTBinaryGadget, GingerMHTBinaryPath,
};

/// The height of the Messages Merkle Tree in the current epoch
/// TODO: move it in cctp-lib
pub const MSG_MT_HEIGHT: usize = 16;

#[derive(Clone)]
pub struct Sc2Sc {
    // Public Inputs
    public_input: Sc2ScUserInput,

    // Witnesses
    /// Certificate of epoch N+1
    next_cert: WithdrawalCertificateData,
    /// Certificate of epoch N
    curr_cert: WithdrawalCertificateData,
    /// Path of `next_cert` in the next sc_tx_commitment tree
    next_cert_path: ScCommitmentCertPath,
    /// Path of `curr_cert` in the current sc_tx_commitment tree
    curr_cert_path: ScCommitmentCertPath,
    /// Merkle path of the message to be redeemed inside
    /// SC2SC_message_tree_root that you can fine in `curr_cert`.
    /// This value is in the custom fields position 1.
    msg_path: GingerMHTBinaryPath,
}

impl Sc2Sc {
    /// Create a new circuit data to build the circuit
    pub fn new(
        next_sc_tx_commitments_root: FieldElement,
        curr_sc_tx_commitments_root: FieldElement,
        msg_hash: FieldElement,
        next_cert: WithdrawalCertificateData,
        curr_cert: WithdrawalCertificateData,
        next_cert_path: ScCommitmentCertPath,
        curr_cert_path: ScCommitmentCertPath,
        msg_path: GingerMHTBinaryPath,
    ) -> Self {
        assert_eq!(
            next_cert.custom_fields.len(),
            curr_cert.custom_fields.len(),
            "Certificates should contains the same custom fields"
        );
        assert!(next_cert.custom_fields.len() >= MIN_CUSTOM_FIELDS, "We need at least {} custom fields: see 
            https://github.com/HorizenOfficial/ZenIPs/blob/57fe28cb13202550ed29512f913de2508877dc0b/zenip-42205.md#zenip-42205
            for more details", MIN_CUSTOM_FIELDS);

        Self {
            public_input: Sc2ScUserInput::new(
                next_sc_tx_commitments_root,
                curr_sc_tx_commitments_root,
                msg_hash,
            ),
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        }
    }

    /// Return a default instance that can be used for setup
    pub fn get_instance_for_setup(num_custom_fields: u32) -> Self {
        Self::new(
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            WithdrawalCertificateData::get_default(num_custom_fields),
            WithdrawalCertificateData::get_default(num_custom_fields),
            ScCommitmentCertPath::default(),
            ScCommitmentCertPath::default(),
            GingerMHTBinaryPath::new(vec![(FieldElement::default(), false); MSG_MT_HEIGHT]),
        )
    }

    pub fn public_input(&self) -> &Sc2ScUserInput {
        &self.public_input
    }

    fn enforce_contiguos_epochs<CS>(
        &self,
        cs: &mut CS,
        curr_cert_g: &WithdrawalCertificateDataGadget,
        next_cert_g: &WithdrawalCertificateDataGadget,
    ) -> Result<(), r1cs_core::SynthesisError>
    where
        CS: r1cs_core::ConstraintSystemAbstract<FieldElement>,
    {
        let next_epoch_id_g = {
            let bits = next_cert_g.epoch_id_g.clone().into_bits_be();
            FieldElementGadget::from_bits(cs.ns(|| "next_epoch_id_g"), bits.as_slice())
        }?;
        let curr_epoch_id_g = {
            let bits = curr_cert_g.epoch_id_g.clone().into_bits_be();
            FieldElementGadget::from_bits(cs.ns(|| "curr_epoch_id_g"), bits.as_slice())
        }?;
        curr_epoch_id_g
            .add_constant(cs.ns(|| "curr_epoch_id + 1"), &Field::one())?
            .enforce_equal(
                cs.ns(|| "require(curr_cert.epoch + 1 == next_cert.epoch)"),
                &next_epoch_id_g,
            )?;
        Ok(())
    }
}

impl ConstraintSynthesizer<FieldElement> for Sc2Sc {
    fn generate_constraints<CS: r1cs_core::ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), r1cs_core::SynthesisError> {
        // Expose public inputs
        let next_sc_tx_commitments_root_g =
            FieldElementGadget::alloc_input(cs.ns(|| "Alloc next sc tx commitment root"), || {
                Ok(self.public_input.next_sc_tx_commitments_root)
            })?;
        let curr_sc_tx_commitments_root_g = FieldElementGadget::alloc_input(
            cs.ns(|| "Alloc current sc tx commitment root"),
            || Ok(self.public_input.curr_sc_tx_commitments_root),
        )?;
        let msg_hash_g = FieldElementGadget::alloc_input(cs.ns(|| "Alloc msg_hash"), || {
            Ok(self.public_input.msg_hash)
        })?;

        // Alloc Withdraw certificate gadgets
        let curr_cert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc current wcert data"), || {
                Ok(self.curr_cert.clone())
            })?;
        let next_cert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc next wcert data"), || {
                Ok(self.next_cert.clone())
            })?;

        // Enforce certificates hashes
        let curr_cert_hash_g =
            curr_cert_g.enforce_hash(cs.ns(|| "enforce current certificate hash"), None)?;
        let next_cert_hash_g =
            next_cert_g.enforce_hash(cs.ns(|| "enforce next certificate hash"), None)?;

        // Enforce next certificate top quality hash == current certificate hash
        next_cert_g.custom_fields_g[MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS].enforce_equal(
            cs.ns(|| "require(next_cert.previous_top_quality_hash == H(curr_cert_hash)"),
            &curr_cert_hash_g,
        )?;

        // Enforce current certificate epoch id + 1 == next certificate epoch id
        self.enforce_contiguos_epochs(cs, &curr_cert_g, &next_cert_g)?;

        // Enforce paths for current certificate, next certificate and message hash
        ScCommitmentCertPathGadget::alloc(
            cs.ns(|| "Alloc current epoch sc_tx_commitment_root recostruction gadget"),
            || Ok(&self.curr_cert_path),
        )?
        .check_membership(
            cs.ns(|| "Check current epoch sc_tx_commitment_root"),
            &curr_sc_tx_commitments_root_g,
            &curr_cert_hash_g,
            &curr_cert_g.ledger_id_g,
        )?;

        ScCommitmentCertPathGadget::alloc(
            cs.ns(|| "Alloc next epoch sc_tx_commitment_root recostruction gadget"),
            || Ok(&self.next_cert_path),
        )?
        .check_membership(
            cs.ns(|| "Check next epoch sc_tx_commitment_root"),
            &next_sc_tx_commitments_root_g,
            &next_cert_hash_g,
            &next_cert_g.ledger_id_g,
        )?;

        GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc messages tree path"), || {
            Ok(self.msg_path.clone())
        })?
        .check_membership(
            cs.ns(|| {
                "Verify merkle root of (msg_hash, msg_path) == curr_cert.SC2SC_message_tree_root"
            }),
            &curr_cert_g.custom_fields_g[MSG_ROOT_HASH_CUSTOM_FIELDS_POS],
            &msg_hash_g,
        )?;

        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
pub struct Sc2ScUserInput {
    // Public Inputs
    /// Side Chain Tx Commitment  Root of epoch N+1
    next_sc_tx_commitments_root: FieldElement,
    /// Side Chain Tx Commitment  Root of epoch N
    curr_sc_tx_commitments_root: FieldElement,
    /// Hash of the message to be redeemed
    msg_hash: FieldElement,
}

impl Sc2ScUserInput {
    pub fn new(
        next_sc_tx_commitments_root: FieldElement,
        curr_sc_tx_commitments_root: FieldElement,
        msg_hash: FieldElement,
    ) -> Self {
        Self {
            next_sc_tx_commitments_root,
            curr_sc_tx_commitments_root,
            msg_hash,
        }
    }
}

impl UserInputs for Sc2ScUserInput {
    fn get_circuit_inputs(
        &self,
    ) -> Result<Vec<FieldElement>, cctp_primitives::proving_system::error::ProvingSystemError> {
        Ok(vec![
            self.next_sc_tx_commitments_root,
            self.curr_sc_tx_commitments_root,
            self.msg_hash,
        ])
    }
}

/// Represent the data that we need to rebuild the sc_tx_commitment root
/// from the withdrawal certificate. We need
/// - `cert_path` to recover the withdrawal certificate root from certificate hash
/// - `fwt_root`, `bwt_root`, `ssc` (start sidechain) to build sc_commitment with
/// withdrawal certificate root and passed sidechain id
/// - sc_commitment_path to rebuild the sidechain tx commitment root
///
/// The method `enforce_sc_tx_commitment_root` take the certificate hash and
/// sidechain id gadgets to enforce all the path.
// TODO: Maybe is better to move it in zendoo-cctp-cryptolib
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScCommitmentCertPath {
    fwt_root: FieldElement,
    bwt_root: FieldElement,
    ssc: FieldElement,
    cert_path: GingerMHTBinaryPath,
    sc_commitment_path: GingerMHTBinaryPath,
}

impl Default for ScCommitmentCertPath {
    fn default() -> Self {
        Self {
            fwt_root: FieldElement::zero(),
            bwt_root: FieldElement::zero(),
            ssc: FieldElement::zero(),
            cert_path: GingerMHTBinaryPath::new(vec![Default::default(); CERT_MT_HEIGHT]),
            sc_commitment_path: GingerMHTBinaryPath::new(vec![Default::default(); CMT_MT_HEIGHT]),
        }
    }
}

impl ScCommitmentCertPath {
    /// Create a new path
    pub fn new(
        fwt_root: FieldElement,
        bwt_root: FieldElement,
        ssc: FieldElement,
        cert_path: GingerMHTBinaryPath,
        sc_commitment_path: GingerMHTBinaryPath,
    ) -> Self {
        Self {
            fwt_root,
            bwt_root,
            ssc,
            cert_path,
            sc_commitment_path,
        }
    }

    pub fn compute_root(
        &self,
        sc_id: &FieldElement,
        cert_hash: &FieldElement,
    ) -> Result<FieldElement, Error> {
        let cert_root = self.cert_path.compute_root(&cert_hash);
        let commitment = hash_vec(vec![
            self.fwt_root.clone(),
            self.bwt_root.clone(),
            cert_root.clone(),
            self.ssc,
            sc_id.clone(),
        ])?;
        Ok(self.sc_commitment_path.compute_root(&commitment))
    }

    pub fn valid(
        &self,
        sc_tx_commitment_root: &FieldElement,
        sc_id: &FieldElement,
        cert_hash: &FieldElement,
    ) -> bool {
        self.compute_root(sc_id, cert_hash)
            .map(|r| &r == sc_tx_commitment_root)
            .unwrap_or(false)
    }

    /// Add implementation to simplify the extraction from a commitment
    pub fn from_commitment_cert_index(
        cmt: &mut CommitmentTree,
        sc_id: FieldElement,
        cert_index: usize,
    ) -> Result<Self, Error> {
        Ok(Self::new(
            cmt.get_fwt_commitment(&sc_id)
                .ok_or(format!("Cannot retrive the forward transfer root"))?,
            cmt.get_bwtr_commitment(&sc_id)
                .ok_or(format!("Cannot retrive the backward transfer root"))?,
            cmt.get_scc(&sc_id)
                .ok_or(format!("Cannot retrive the sidechain creation"))?,
            cmt.get_cert_merkle_path(&sc_id, cert_index)
                .ok_or(format!("Cannot retrive the certificate merkle path"))?
                .try_into()?,
            cmt.get_sc_commitment_merkle_path(&sc_id)
                .ok_or(format!("Cannot retrive the commitment merkle path"))?
                .try_into()?,
        )
        .into())
    }
}

impl SemanticallyValid for ScCommitmentCertPath {
    fn is_valid(&self) -> bool {
        self.cert_path.get_length() == CERT_MT_HEIGHT
            && self.sc_commitment_path.get_length() == CMT_MT_HEIGHT
    }
}

struct ScCommitmentCertPathGadget {
    fwt_root: FieldElementGadget,
    bwt_root: FieldElementGadget,
    ssc: FieldElementGadget,
    cert_path: GingerMHTBinaryGadget,
    sc_commitment_path: GingerMHTBinaryGadget,
}

impl ScCommitmentCertPathGadget {
    /// Recostruct and verify the root of sc tx commitment tree. Need follow gadgets:
    /// -`sc_tx_commitment_root` the final sc tx commitment root
    /// -`cert_hash` the certificate hash leaf gadget in the withdrawal certificates merkle tree
    /// -`sc_id` the sidechain id gadget that we can take from the withdrawal certificate gadget
    fn check_membership<CS: r1cs_core::ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        sc_tx_commitment_root: &FpGadget<FieldElement>,
        cert_hash: &FpGadget<FieldElement>,
        sc_id: &FpGadget<FieldElement>,
    ) -> Result<(), r1cs_core::SynthesisError> {
        // Rebuild the certificate root from hash leaf and merkle path.
        let cert_root_g = self.cert_path.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(cert_hash, cert_path)"),
            &cert_hash,
        )?;
        let sc_tx_commitment_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "Enforce H(fwt_mr, bwt_mr, cert_mr, scc, sc_id)"),
            &[
                self.fwt_root.clone(),
                self.bwt_root.clone(),
                cert_root_g,
                self.ssc.clone(),
                sc_id.clone(),
            ],
        )?;
        self.sc_commitment_path.check_membership(
            cs.ns(|| {
                "Verify merkle root of (sc_tx_commitment, sc_tx_commitments_path) == sc_tx_commitments_root"
            }),
            sc_tx_commitment_root,
            &sc_tx_commitment_g,
        )
    }
}

impl AllocGadget<ScCommitmentCertPath, FieldElement> for ScCommitmentCertPathGadget {
    fn alloc<F, T, CS: r1cs_core::ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, r1cs_core::SynthesisError>
    where
        F: FnOnce() -> Result<T, r1cs_core::SynthesisError>,
        T: Borrow<ScCommitmentCertPath>,
    {
        let path = f()?;
        let path = path.borrow();
        Ok(Self {
            fwt_root: FieldElementGadget::alloc(cs.ns(|| "alloc fwt root gadget"), || {
                Ok(path.fwt_root)
            })?,
            bwt_root: FieldElementGadget::alloc(cs.ns(|| "alloc bwt root gadget"), || {
                Ok(path.bwt_root)
            })?,
            ssc: FieldElementGadget::alloc(cs.ns(|| "alloc start sc gadget"), || Ok(path.ssc))?,
            cert_path: GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc cert tree path"), || {
                Ok(path.cert_path.clone())
            })?,
            sc_commitment_path: GingerMHTBinaryGadget::alloc(
                cs.ns(|| "alloc sc_tx_commitments tree path"),
                || Ok(path.sc_commitment_path.clone()),
            )?,
        })
    }

    fn alloc_input<F, T, CS: r1cs_core::ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, r1cs_core::SynthesisError>
    where
        F: FnOnce() -> Result<T, r1cs_core::SynthesisError>,
        T: Borrow<ScCommitmentCertPath>,
    {
        let path = f()?;
        let path = path.borrow();
        Ok(Self {
            fwt_root: FieldElementGadget::alloc_input(cs.ns(|| "alloc fwt root gadget"), || {
                Ok(path.fwt_root)
            })?,
            bwt_root: FieldElementGadget::alloc_input(cs.ns(|| "alloc bwt root gadget"), || {
                Ok(path.bwt_root)
            })?,
            ssc: FieldElementGadget::alloc_input(cs.ns(|| "alloc start sc gadget"), || {
                Ok(path.ssc)
            })?,
            cert_path: GingerMHTBinaryGadget::alloc_input(
                cs.ns(|| "alloc cert tree path"),
                || Ok(path.cert_path.clone()),
            )?,
            sc_commitment_path: GingerMHTBinaryGadget::alloc_input(
                cs.ns(|| "alloc sc_tx_commitments tree path"),
                || Ok(path.sc_commitment_path.clone()),
            )?,
        })
    }
}

#[cfg(test)]
mod tests;
