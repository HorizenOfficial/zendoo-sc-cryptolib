use algebra::Field;
use cctp_primitives::{
    commitment_tree::{sidechain_tree_alive::CERT_MT_HEIGHT, CMT_MT_HEIGHT},
    type_mapping::FieldElement,
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
    common::{constraints::WithdrawalCertificateDataGadget, WithdrawalCertificateData},
    FieldElementGadget, FieldHashGadget, GingerMHTBinaryGadget, GingerMHTBinaryPath,
};

/// The height of the Messages Merkle Tree in the current epoch
pub const MSG_MT_HEIGHT: usize = 12;
pub const MIN_CUSTOM_FIELDS: usize = 3;
pub const MSG_ROOT_HASH_CUSTOM_FIELDS_POS: usize = 1;
pub const MAX_QUALITY_CERT_HASH_CUSTOM_FIELDS_POS: usize = 2;

#[derive(Clone)]
pub struct Sc2Sc {
    // Public Inputs
    /// Side Chain Tx Commitment  Root of epoch N+1
    next_sc_tx_commitments_root: FieldElement,
    /// Side Chain Tx Commitment  Root of epoch N
    curr_sc_tx_commitments_root: FieldElement,
    /// Hash of the message to be redeemed
    msg_hash: FieldElement,

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
        assert!(next_cert.custom_fields.len() >= 3, "We need at least 3 custom fields: see 
            https://github.com/HorizenOfficial/ZenIPs/blob/57fe28cb13202550ed29512f913de2508877dc0b/zenip-42205.md#zenip-42205
            for more detteils");

        Self {
            next_sc_tx_commitments_root,
            curr_sc_tx_commitments_root,
            msg_hash,
            next_cert,
            curr_cert,
            next_cert_path,
            curr_cert_path,
            msg_path,
        }
    }

    /// Return a default instance that can be used for setup
    pub fn get_instance_for_setup(num_custom_fields: u32) -> Self {
        Self {
            next_sc_tx_commitments_root: FieldElement::zero(),
            curr_sc_tx_commitments_root: FieldElement::zero(),
            msg_hash: FieldElement::zero(),
            next_cert: WithdrawalCertificateData::get_default(num_custom_fields),
            curr_cert: WithdrawalCertificateData::get_default(num_custom_fields),
            next_cert_path: ScCommitmentCertPath::default(),
            curr_cert_path: ScCommitmentCertPath::default(),
            msg_path: GingerMHTBinaryPath::new(vec![
                (FieldElement::default(), false);
                MSG_MT_HEIGHT
            ]),
        }
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

    fn enforce_message_path<CS>(
        self,
        cs: &mut CS,
        msg_hash_g: &FieldElementGadget,
        msg_root_g: &FieldElementGadget,
    ) -> Result<(), r1cs_core::SynthesisError>
    where
        CS: r1cs_core::ConstraintSystemAbstract<FieldElement>,
    {
        GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc messages tree path"), || {
            Ok(self.msg_path.clone())
        })?
        .enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(msg_hash, msg_path)"),
            msg_hash_g,
        )?
        .enforce_equal(
            cs.ns(|| {
                "Verify merkle root of (msg_hash, msg_path) == curr_cert.SC2SC_message_tree_root"
            }),
            msg_root_g,
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
                Ok(self.next_sc_tx_commitments_root)
            })?;
        let curr_sc_tx_commitments_root_g = FieldElementGadget::alloc_input(
            cs.ns(|| "Alloc current sc tx commitment root"),
            || Ok(self.curr_sc_tx_commitments_root),
        )?;
        let msg_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "Alloc msg_hash"), || Ok(self.msg_hash))?;

        // Alloc Withdraw certificate gadgets
        let next_cert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc next wcert data"), || {
                Ok(self.next_cert.clone())
            })?;
        let curr_cert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc current wcert data"), || {
                Ok(self.curr_cert.clone())
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

        // Enforce merkle paths for current certificate, next certificate and message hash
        self.curr_cert_path.enforce_sc_tx_commitment_root(cs.ns(|| "Current epoch sc_tx_commitment_root recostruction") , 
            curr_cert_hash_g, curr_cert_g.ledger_id_g)?
            .enforce_equal(
                cs.ns(|| "Verify merkle root of (curr_sc_tx_commitment, curr_sc_tx_commitments_path) == curr_sc_tx_commitments_root"),
                &curr_sc_tx_commitments_root_g,
            )?;

        self.next_cert_path.enforce_sc_tx_commitment_root(cs.ns(|| "Next epoch sc_tx_commitment_root recostruction") , 
            next_cert_hash_g, next_cert_g.ledger_id_g)?
            .enforce_equal(
                cs.ns(|| "Verify merkle root of (next_sc_tx_commitment, next_sc_tx_commitments_path) == next_sc_tx_commitments_root"),
                &next_sc_tx_commitments_root_g,
            )?;

        self.enforce_message_path(
            cs,
            &msg_hash_g,
            &curr_cert_g.custom_fields_g[MSG_ROOT_HASH_CUSTOM_FIELDS_POS],
        )?;

        Ok(())
    }
}

/// Represent the data that we need to rebuild the sc_tx_commitment root
/// from the widthdrawal certificate. We need
/// - `cert_path` to recover the widthdrawal certificate root from certificate hash
/// - `fwt_root`, `bwt_root`, `ssc` (start sidechain) to build sc_commitment with
/// widthdrawal certificate root and passed sidechain id
/// - sc_commitment_path to rebuild the sidechain tx commitment root
///
/// The method `enforce_sc_tx_commitment_root` take the certificate hash and
/// sidechain id gadgets to enforce all the path.
#[derive(Clone)]
pub struct ScCommitmentCertPath {
    cert_root: FieldElement,
    fwt_root: FieldElement,
    bwt_root: FieldElement,
    ssc: FieldElement,
    cert_path: GingerMHTBinaryPath,
    sc_commitment_path: GingerMHTBinaryPath,
}

impl Default for ScCommitmentCertPath {
    fn default() -> Self {
        Self {
            cert_root: FieldElement::zero(),
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
        cert_root: FieldElement,
        fwt_root: FieldElement,
        bwt_root: FieldElement,
        ssc: FieldElement,
        cert_path: GingerMHTBinaryPath,
        sc_commitment_path: GingerMHTBinaryPath,
    ) -> Self {
        Self {
            cert_root,
            fwt_root,
            bwt_root,
            ssc,
            cert_path,
            sc_commitment_path,
        }
    }

    /// Recostruct the root of sc tx commitment tree and return a gadget for the enforced
    /// root. Need the certificate hash leaf gadget in the widthdrawal certificates merkle tree
    /// and the sidechain id gadget that we can take from the widthdrawal certificate gadget.
    fn enforce_sc_tx_commitment_root<CS: r1cs_core::ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        cert_hash_g: FpGadget<FieldElement>,
        sc_id_g: FpGadget<FieldElement>,
    ) -> Result<FpGadget<FieldElement>, r1cs_core::SynthesisError> {
        let cert_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc wcert root gadget"), || Ok(self.cert_root))?;
        let fwt_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc fwt root gadget"), || Ok(self.fwt_root))?;
        let bwt_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc bwt root gadget"), || Ok(self.bwt_root))?;
        let ssc_g = FieldElementGadget::alloc(cs.ns(|| "alloc start sc gadget"), || Ok(self.ssc))?;
        GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc cert tree path"), || {
            Ok(self.cert_path.clone())
        })?
        .enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(cert_hash, cert_path)"),
            &cert_hash_g,
        )?
        .enforce_equal(
            cs.ns(|| "Verify merkle root of (cert_hash, cert_path) == cert_root"),
            &cert_root_g,
        )?;

        let sc_tx_commitment_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "Enforce H(fwt_mr, bwt_mr, cert_mr, scc, sc_id)"),
            &[fwt_root_g, bwt_root_g, cert_root_g, ssc_g, sc_id_g],
        )?;
        GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc sc_tx_commitments tree path"), || {
            Ok(self.sc_commitment_path.clone())
        })?
        .enforce_root_from_leaf(
            cs.ns(|| {
                "reconstruct_merkle_root_hash(sc_tx_commitments_root, sc_tx_commitments_path)"
            }),
            &sc_tx_commitment_g,
        )
    }
}

#[cfg(test)]
mod tests;
