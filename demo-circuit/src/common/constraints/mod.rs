use cctp_primitives::type_mapping::{FieldElement, FieldHash};
use r1cs_core::{ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldHasherGadget};
use r1cs_std::prelude::*;
use r1cs_std::uint64::UInt64;
use std::borrow::Borrow;
use std::fmt::{Debug, Formatter};

use crate::{FieldElementGadget, FieldHashGadget};

use super::WithdrawalCertificateData;

#[derive(Clone)]
/// The gadget for a withdrawal certificate of a sidechain
pub struct WithdrawalCertificateDataGadget {
    pub ledger_id_g: FieldElementGadget,
    pub epoch_id_g: UInt32,
    /// Merkle root hash of all BTs from the certificate
    pub bt_list_root_g: FieldElementGadget,
    pub quality_g: UInt64,
    /// Reference to the state of the mainchain-to-sidechain transaction history.
    /// Declares to which extent the sidechain processed forward transactions.
    pub mcb_sc_txs_com_g: FieldElementGadget,
    pub ft_min_amount_g: UInt64,
    pub btr_min_fee_g: UInt64,
    /// Carries the reference to the sidechain state. (Currently the reference is
    /// split over two field elements)
    pub custom_fields_g: Vec<FieldElementGadget>,
}

impl AllocGadget<WithdrawalCertificateData, FieldElement> for WithdrawalCertificateDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<WithdrawalCertificateData>,
    {
        let (
            ledger_id,
            epoch_id,
            bt_root,
            quality,
            mcb_sc_txs_com,
            ft_min_amount,
            btr_min_fee,
            custom_fields,
        ) = match f() {
            Ok(certificate_data) => {
                let certificate_data = certificate_data.borrow().clone();
                (
                    Ok(certificate_data.ledger_id),
                    Ok(certificate_data.epoch_id),
                    Ok(certificate_data.bt_root),
                    Ok(certificate_data.quality),
                    Ok(certificate_data.mcb_sc_txs_com),
                    Ok(certificate_data.ft_min_amount),
                    Ok(certificate_data.btr_min_fee),
                    Ok(certificate_data.custom_fields),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let ledger_id_g = FieldElementGadget::alloc(cs.ns(|| "alloc ledger id"), || ledger_id)?;

        let epoch_id_g = UInt32::alloc(cs.ns(|| "alloc epoch id"), epoch_id.ok())?;

        //Compute bt_list merkle_root

        let bt_list_root_g = FieldElementGadget::alloc(cs.ns(|| "alloc bt list hash"), || bt_root)?;

        let quality_g = UInt64::alloc(cs.ns(|| "alloc quality"), quality.ok())?;

        let mcb_sc_txs_com_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc mcb sc txs com"), || mcb_sc_txs_com)?;

        let ft_min_amount_g = UInt64::alloc(cs.ns(|| "alloc ft min fee"), ft_min_amount.ok())?;

        let btr_min_fee_g = UInt64::alloc(cs.ns(|| "alloc btr min fee"), btr_min_fee.ok())?;

        let custom_fields_value = custom_fields?;
        let mut custom_fields_g = Vec::with_capacity(custom_fields_value.len());

        for (i, custom_field) in custom_fields_value.iter().enumerate() {
            let custom_field_g =
                FieldElementGadget::alloc(cs.ns(|| format!("alloc custom field {}", i)), || {
                    Ok(*custom_field)
                })?;

            custom_fields_g.push(custom_field_g);
        }

        let new_instance = Self {
            ledger_id_g,
            epoch_id_g,
            bt_list_root_g,
            quality_g,
            mcb_sc_txs_com_g,
            ft_min_amount_g,
            btr_min_fee_g,
            custom_fields_g,
        };

        Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<WithdrawalCertificateData>,
    {
        unimplemented!()
    }
}

impl FieldHasherGadget<FieldHash, FieldElement, FieldHashGadget>
    for WithdrawalCertificateDataGadget
{
    fn enforce_hash<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        _personalization: Option<&[FieldElementGadget]>,
    ) -> Result<FieldElementGadget, SynthesisError> {
        let last_wcert_epoch_id_fe_g = {
            let bits = self.epoch_id_g.clone().into_bits_be();
            FieldElementGadget::from_bits(cs.ns(|| "last_wcert_epoch_id_fe_g"), bits.as_slice())
        }?;

        let last_wcert_quality_fe_g = {
            let mut bits = self.quality_g.to_bits_le();
            bits.reverse();

            FieldElementGadget::from_bits(cs.ns(|| "last_wcert_quality_fe_g"), bits.as_slice())
        }?;

        let mut last_wcert_btr_fee_bits_g = self.btr_min_fee_g.to_bits_le();
        last_wcert_btr_fee_bits_g.reverse();

        let mut last_wcert_ft_fee_bits_g = self.ft_min_amount_g.to_bits_le();
        last_wcert_ft_fee_bits_g.reverse();

        let mut last_wcert_fee_bits_g = last_wcert_btr_fee_bits_g;
        last_wcert_fee_bits_g.append(&mut last_wcert_ft_fee_bits_g);

        let last_wcert_fee_fe_g =
            FieldElementGadget::from_bits(cs.ns(|| "last_wcert_fee_fe_g"), &last_wcert_fee_bits_g)?;

        let temp_last_wcert_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(last_wcert without custom fields)"),
            &[
                self.ledger_id_g.clone(),
                last_wcert_epoch_id_fe_g,
                self.bt_list_root_g.clone(),
                last_wcert_quality_fe_g,
                self.mcb_sc_txs_com_g.clone(),
                last_wcert_fee_fe_g,
            ],
        )?;

        // Alloc custom_fields and enforce their hash, if they are present
        let last_wcert_custom_fields_hash_g = if !self.custom_fields_g.is_empty() {
            let custom_fields_hash_g = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H(custom_fields)"),
                self.custom_fields_g.as_slice(),
            )?;
            Some(custom_fields_hash_g)
        } else {
            None
        };

        let preimage = if last_wcert_custom_fields_hash_g.is_some() {
            vec![
                last_wcert_custom_fields_hash_g.unwrap(),
                temp_last_wcert_hash_g,
            ]
        } else {
            vec![temp_last_wcert_hash_g]
        };

        FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H([custom_fields], cert_data_hash)"),
            preimage.as_slice(),
        )
    }
}

#[derive(Clone)]
/// The gadget for a checking a message was signed
pub struct MessageSigningDataGadget {
    pub ledger_id_g: FieldElementGadget,
    pub epoch_id_g: UInt32,
    /// Merkle root hash of all BTs from the certificate
    pub bt_list_root_g: FieldElementGadget,
    /// Reference to the state of the mainchain-to-sidechain transaction history.
    /// Declares to which extent the sidechain processed forward transactions.
    pub mcb_sc_txs_com_g: FieldElementGadget,
    pub ft_min_amount_g: UInt64,
    pub btr_min_fee_g: UInt64,
    /// Carries the reference to the sidechain state. (Currently the reference is
    /// split over two field elements)
    pub custom_fields_g: Vec<FieldElementGadget>,
}

impl Debug for MessageSigningDataGadget {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MessageSigningDataGadget {{ ledger_id: {:?}, epoch_id: {:?}, bt_list_root: {:?}, mcb_sc_txs_com: {:?}, ft_min_amount: {:?}, btr_min_fee: {:?}, custom_fields: {:?} }}",
            self.ledger_id_g.value.map(|v| v.to_string()),
            self.epoch_id_g.value,
            self.bt_list_root_g.value.map(|v| v.to_string()),
            self.mcb_sc_txs_com_g.value.map(|v| v.to_string()),
            self.ft_min_amount_g.get_value(),
            self.btr_min_fee_g.get_value(),
            self.custom_fields_g.iter().map(|v| v.value.map(|v| v.to_string())).collect::<Vec<Option<String>>>()
        )
    }
}

impl From<&WithdrawalCertificateDataGadget> for MessageSigningDataGadget {
    fn from(wcert: &WithdrawalCertificateDataGadget) -> Self {
        Self {
            ledger_id_g: wcert.ledger_id_g.clone(),
            epoch_id_g: wcert.epoch_id_g.clone(),
            bt_list_root_g: wcert.bt_list_root_g.clone(),
            mcb_sc_txs_com_g: wcert.mcb_sc_txs_com_g.clone(),
            ft_min_amount_g: wcert.ft_min_amount_g.clone(),
            btr_min_fee_g: wcert.btr_min_fee_g.clone(),
            custom_fields_g: wcert.custom_fields_g.clone(),
        }
    }
}

impl FieldHasherGadget<FieldHash, FieldElement, FieldHashGadget> for MessageSigningDataGadget {
    fn enforce_hash<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        _personalization: Option<&[FieldElementGadget]>,
    ) -> Result<FieldElementGadget, SynthesisError> {
        let wcert_epoch_id_fe_g = {
            let bits = self.epoch_id_g.clone().into_bits_be();
            FieldElementGadget::from_bits(cs.ns(|| "last_wcert_epoch_id_fe_g"), bits.as_slice())
        }?;

        let mut bits = self.btr_min_fee_g.to_bits_le();
        bits.reverse();

        let mut ft_fee_bits_g = self.ft_min_amount_g.to_bits_le();
        ft_fee_bits_g.reverse();

        bits.append(&mut ft_fee_bits_g);

        let wcert_fee_fe_g =
            FieldElementGadget::from_bits(cs.ns(|| "pack(btr_fee, ft_min_amount)"), &bits)?;

        let mut inputs = vec![
            self.ledger_id_g.clone(),
            wcert_epoch_id_fe_g,
            self.bt_list_root_g.clone(),
            self.mcb_sc_txs_com_g.clone(),
            wcert_fee_fe_g,
        ];
        let custom_fields_hash = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(custom fields)"),
            self.custom_fields_g.as_slice(),
        )?;
        inputs.push(custom_fields_hash);

        FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(wcert fields)"),
            inputs.as_slice(),
        )
    }
}
