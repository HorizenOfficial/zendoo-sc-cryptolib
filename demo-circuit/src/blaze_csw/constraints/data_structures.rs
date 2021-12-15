use std::{borrow::Borrow, convert::TryInto};

use algebra::Field;
use cctp_primitives::type_mapping::{FieldElement, FieldHash, FIELD_CAPACITY, FIELD_SIZE};
use primitives::bytes_to_bits;
use r1cs_core::{ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedMerkleTreePathGadget, FieldHasherGadget};
use r1cs_std::{
    boolean::Boolean,
    fields::FieldGadget,
    prelude::{AllocGadget, ConstantGadget, EqGadget},
    select::CondSelectGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    uint32::UInt32,
    uint64::UInt64,
    FromBitsGadget, ToBitsGadget,
};

use crate::{
    constants::constants::BoxType, CswFtOutputData, CswFtProverData, CswProverData, CswSysData,
    CswUtxoInputData, CswUtxoOutputData, CswUtxoProverData, FieldElementGadget, FieldHashGadget,
    GingerMHTBinaryGadget, WithdrawalCertificateData, MC_RETURN_ADDRESS_BYTES,
    PHANTOM_FIELD_ELEMENT, PHANTOM_SECRET_KEY_BITS, SIMULATED_FIELD_BYTE_SIZE,
    SIMULATED_SCALAR_FIELD_MODULUS_BITS,
};

#[derive(Clone, PartialEq, Eq)]
pub struct WithdrawalCertificateDataGadget {
    pub ledger_id_g: FieldElementGadget,
    pub epoch_id_g: UInt32,
    pub bt_list_root_g: FieldElementGadget,
    pub quality_g: UInt64,
    pub mcb_sc_txs_com_g: FieldElementGadget,
    pub ft_min_amount_g: UInt64,
    pub btr_min_fee_g: UInt64,
    pub custom_fields_g: Vec<FieldElementGadget>,
}

impl WithdrawalCertificateDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        num_custom_fields: u32,
    ) -> Result<Boolean, SynthesisError> {
        let phantom_wcert_g = WithdrawalCertificateDataGadget::from_value(
            cs.ns(|| "alloc phantom_wcert_g"),
            &WithdrawalCertificateData::get_phantom(num_custom_fields),
        );

        self.is_eq(cs.ns(|| "is wcert phantom"), &phantom_wcert_g)
    }
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

impl ConstantGadget<WithdrawalCertificateData, FieldElement> for WithdrawalCertificateDataGadget {
    fn from_value<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        value: &WithdrawalCertificateData,
    ) -> Self {
        let ledger_id_g =
            FieldElementGadget::from_value(cs.ns(|| "alloc constant ledger_id"), &value.ledger_id);
        let epoch_id_g = UInt32::constant(value.epoch_id);
        let bt_list_root_g =
            FieldElementGadget::from_value(cs.ns(|| "alloc constant bt_list_root"), &value.bt_root);
        let quality_g = UInt64::constant(value.quality);
        let mcb_sc_txs_com_g = FieldElementGadget::from_value(
            cs.ns(|| "alloc constant mcb_sc_txs_com"),
            &value.mcb_sc_txs_com,
        );
        let ft_min_amount_g = UInt64::constant(value.ft_min_amount);
        let btr_min_fee_g = UInt64::constant(value.btr_min_fee);
        let mut custom_fields_g = Vec::with_capacity(value.custom_fields.len());

        for (i, custom_field) in value.custom_fields.iter().enumerate() {
            let custom_field_g = FieldElementGadget::from_value(
                cs.ns(|| format!("alloc constant custom field {}", i)),
                &custom_field,
            );
            custom_fields_g.push(custom_field_g);
        }

        Self {
            ledger_id_g,
            epoch_id_g,
            bt_list_root_g,
            quality_g,
            mcb_sc_txs_com_g,
            ft_min_amount_g,
            btr_min_fee_g,
            custom_fields_g,
        }
    }

    fn get_constant(&self) -> WithdrawalCertificateData {
        WithdrawalCertificateData {
            ledger_id: self.ledger_id_g.value.unwrap(),
            epoch_id: self.epoch_id_g.value.unwrap(),
            bt_root: self.bt_list_root_g.value.unwrap(),
            quality: self.quality_g.get_value().unwrap(),
            mcb_sc_txs_com: self.mcb_sc_txs_com_g.value.unwrap(),
            ft_min_amount: self.ft_min_amount_g.get_value().unwrap(),
            btr_min_fee: self.btr_min_fee_g.get_value().unwrap(),
            custom_fields: self
                .custom_fields_g
                .iter()
                .map(|custom_field_g| custom_field_g.value.unwrap())
                .collect(),
        }
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
        let last_wcert_custom_fields_hash_g = if self.custom_fields_g.len() > 0 {
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

impl EqGadget<FieldElement> for WithdrawalCertificateDataGadget {
    fn is_eq<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        other: &Self,
    ) -> Result<Boolean, SynthesisError> {
        let b1 = self
            .ledger_id_g
            .is_eq(cs.ns(|| "is eq ledger_id"), &other.ledger_id_g)?;
        let b2 = self
            .epoch_id_g
            .is_eq(cs.ns(|| "is eq epoch_id"), &other.epoch_id_g)?;
        let b3 = self
            .bt_list_root_g
            .is_eq(cs.ns(|| "is eq bt_list_root"), &other.bt_list_root_g)?;
        let b4 = self
            .quality_g
            .is_eq(cs.ns(|| "is eq quality"), &other.quality_g)?;
        let b5 = self
            .mcb_sc_txs_com_g
            .is_eq(cs.ns(|| "is eq mcb_sc_txs_com"), &other.mcb_sc_txs_com_g)?;
        let b6 = self
            .ft_min_amount_g
            .is_eq(cs.ns(|| "is eq ft_min_amount"), &other.ft_min_amount_g)?;
        let b7 = self
            .btr_min_fee_g
            .is_eq(cs.ns(|| "is eq btr_min_fee"), &other.btr_min_fee_g)?;
        let mut b8 = Boolean::Constant(true);
        if !self.custom_fields_g.is_empty() {
            b8 = self
                .custom_fields_g
                .is_eq(cs.ns(|| "is eq custom_fields"), &other.custom_fields_g)?;
        }

        Boolean::kary_and(
            cs.ns(|| "is_eq CswUtxoOutputDataGadget"),
            &[b1, b2, b3, b4, b5, b6, b7, b8],
        )
    }
}

#[derive(PartialEq, Eq)]
pub struct CswUtxoOutputDataGadget {
    pub spending_pub_key_g: [Boolean; SIMULATED_FIELD_BYTE_SIZE * 8], // Assumed to be big endian. TODO: Check this
    pub amount_g: UInt64,
    pub nonce_g: UInt64,
    pub custom_hash_g: [Boolean; FIELD_SIZE * 8], // Assumed to be big endian. TODO: Check this
}

impl CswUtxoOutputDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Boolean, SynthesisError> {
        // TODO: properly create and store the phantom gadget
        let phantom_utxo_output_g = CswUtxoOutputDataGadget::from_value(
            cs.ns(|| "alloc constant UTXO input phantom gadget"),
            &CswUtxoOutputData::default(),
        );

        self.is_eq(cs.ns(|| "is UTXO output phantom"), &phantom_utxo_output_g)
    }
}

impl AllocGadget<CswUtxoOutputData, FieldElement> for CswUtxoOutputDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoOutputData>,
    {
        let (spending_pub_key, amount, nonce, custom_hash) = match f() {
            Ok(csw_utxo_output_data) => {
                let csw_utxo_output_data = csw_utxo_output_data.borrow().clone();
                (
                    Ok(csw_utxo_output_data.spending_pub_key),
                    Ok(csw_utxo_output_data.amount),
                    Ok(csw_utxo_output_data.nonce),
                    Ok(csw_utxo_output_data.custom_hash),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let spending_pub_key_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc spending pub key"), || spending_pub_key)?
                .try_into()
                .map_err(|_| {
                    SynthesisError::Other(format!(
                        "invalid size for spending_pub_key, expected {} bits",
                        SIMULATED_FIELD_BYTE_SIZE * 8
                    ))
                })?;

        let amount_g = UInt64::alloc(cs.ns(|| "alloc amount"), amount.ok())?;

        let nonce_g = UInt64::alloc(cs.ns(|| "alloc nonce"), nonce.ok())?;

        let custom_hash_g = Vec::<Boolean>::alloc(cs.ns(|| "alloc custom hash"), || custom_hash)?
            .try_into()
            .map_err(|_| {
                SynthesisError::Other(format!(
                    "invalid size for custom_hash, expected {} bits",
                    FIELD_SIZE * 8
                ))
            })?;

        let new_instance = Self {
            spending_pub_key_g,
            amount_g,
            nonce_g,
            custom_hash_g,
        };

        Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoOutputData>,
    {
        unimplemented!()
    }
}

impl ConstantGadget<CswUtxoOutputData, FieldElement> for CswUtxoOutputDataGadget {
    fn from_value<CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        value: &CswUtxoOutputData,
    ) -> Self {
        let spending_pub_key_g = value
            .spending_pub_key
            .iter()
            .map(|&bit| Boolean::Constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let amount_g = UInt64::constant(value.amount);

        let nonce_g = UInt64::constant(value.nonce);

        let custom_hash_g = value
            .custom_hash
            .iter()
            .map(|&bit| Boolean::Constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self {
            spending_pub_key_g,
            amount_g,
            nonce_g,
            custom_hash_g,
        }
    }

    fn get_constant(&self) -> CswUtxoOutputData {
        CswUtxoOutputData {
            spending_pub_key: self
                .spending_pub_key_g
                .iter()
                .map(|bit| bit.get_value().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            amount: self.amount_g.get_value().unwrap(),
            nonce: self.nonce_g.get_value().unwrap(),
            custom_hash: self
                .custom_hash_g
                .iter()
                .map(|bit| bit.get_value().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
}

impl EqGadget<FieldElement> for CswUtxoOutputDataGadget {
    fn is_eq<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        other: &Self,
    ) -> Result<Boolean, SynthesisError> {
        let b1 = self.spending_pub_key_g.is_eq(
            cs.ns(|| "is eq spending_pub_key_g"),
            &other.spending_pub_key_g,
        )?;
        let b2 = self
            .amount_g
            .is_eq(cs.ns(|| "is eq amount_g"), &other.amount_g)?;
        let b3 = self
            .nonce_g
            .is_eq(cs.ns(|| "is eq nonce_g"), &other.nonce_g)?;
        let b4 = self
            .custom_hash_g
            .is_eq(cs.ns(|| "is eq custom_hash_g"), &other.custom_hash_g)?;

        Boolean::kary_and(cs.ns(|| "is_eq CswUtxoOutputDataGadget"), &[b1, b2, b3, b4])
    }
}

impl ToConstraintFieldGadget<FieldElement> for CswUtxoOutputDataGadget {
    type FieldGadget = FieldElementGadget;

    fn to_field_gadget_elements<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<FieldElementGadget>, SynthesisError> {
        let mut bits = self
            .spending_pub_key_g
            .to_bits(cs.ns(|| "spending_pub_key_g to bits"))
            .unwrap();

        let mut amount_big_endian_g = self.amount_g.to_bits_le();
        amount_big_endian_g.reverse();
        bits.extend_from_slice(&amount_big_endian_g);

        let mut nonce_big_endian_g = self.nonce_g.to_bits_le();
        nonce_big_endian_g.reverse();
        bits.extend_from_slice(&nonce_big_endian_g);

        bits.extend_from_slice(&self.custom_hash_g);

        let elements = bits
            .chunks(FIELD_CAPACITY)
            .enumerate()
            .map(|(index, chunk)| {
                FieldElementGadget::from_bits(cs.ns(|| format!("from bits {}", index)), chunk)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(elements)
    }
}

#[derive(PartialEq, Eq)]
pub struct CswUtxoInputDataGadget {
    pub output_g: CswUtxoOutputDataGadget,
    pub secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS], // Assumed to be big endian. TODO: Check this
}

impl CswUtxoInputDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Boolean, SynthesisError> {
        let phantom_secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS] =
            PHANTOM_SECRET_KEY_BITS
                .iter()
                .map(|&bit| Boolean::constant(bit))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

        let b1 = self.output_g.is_phantom(cs.ns(|| "is output_g phantom"))?;
        let b2 = self
            .secret_key_g
            .is_eq(cs.ns(|| "is secret_key_g phantom"), &phantom_secret_key_g)?;

        Boolean::and(cs.ns(|| "is_phantom CswUtxoInputDataGadget"), &b1, &b2)
    }
}

impl AllocGadget<CswUtxoInputData, FieldElement> for CswUtxoInputDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoInputData>,
    {
        let (output, secret_key) = match f() {
            Ok(csw_utxo_input_data) => {
                let csw_utxo_input_data = csw_utxo_input_data.borrow().clone();
                (
                    Ok(csw_utxo_input_data.output),
                    Ok(csw_utxo_input_data.secret_key),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let output_g = CswUtxoOutputDataGadget::alloc(cs.ns(|| "alloc output"), || output)?;

        let secret_key_g = Vec::<Boolean>::alloc(cs.ns(|| "alloc secret key"), || secret_key)?
            .try_into()
            .map_err(|_| {
                SynthesisError::Other(format!(
                    "invalid size for secret_key, expected {} bits",
                    SIMULATED_SCALAR_FIELD_MODULUS_BITS
                ))
            })?;

        Ok(Self {
            output_g,
            secret_key_g,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoInputData>,
    {
        unimplemented!()
    }
}

impl ConstantGadget<CswUtxoInputData, FieldElement> for CswUtxoInputDataGadget {
    fn from_value<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        value: &CswUtxoInputData,
    ) -> Self {
        let output_g = CswUtxoOutputDataGadget::from_value(cs.ns(|| "alloc output"), &value.output);

        let secret_key_g = value
            .secret_key
            .iter()
            .map(|&bit| Boolean::constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self {
            output_g,
            secret_key_g,
        }
    }

    fn get_constant(&self) -> CswUtxoInputData {
        CswUtxoInputData {
            output: self.output_g.get_constant(),
            secret_key: self
                .secret_key_g
                .iter()
                .map(|byte| byte.get_value().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
}

impl EqGadget<FieldElement> for CswUtxoInputDataGadget {
    fn is_eq<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        other: &Self,
    ) -> Result<Boolean, SynthesisError> {
        let b1 = self
            .output_g
            .is_eq(cs.ns(|| "is eq output_g"), &other.output_g)?;
        let b2 = self
            .secret_key_g
            .is_eq(cs.ns(|| "is eq secret_key_g"), &other.secret_key_g)?;

        Boolean::and(cs.ns(|| "is_eq CswUtxoInputDataGadget"), &b1, &b2)
    }
}

pub struct CswUtxoProverDataGadget {
    pub input_g: CswUtxoInputDataGadget, // unspent output we are trying to withdraw
    pub mst_path_to_output_g: GingerMHTBinaryGadget, // path to output in the MST of the known state
}

impl CswUtxoProverDataGadget {
    /// Enforce that:
    /// 1) H(self.input_g.output_g) belongs to merkle tree with root 'scb_new_mst_root_g';
    /// 2) H(self.input_g.output_g) == 'nullifier_g'
    /// 3) self.input_g.output_g.amount_g == 'amount_g'
    pub(crate) fn conditionally_enforce_utxo_withdrawal<
        CS: ConstraintSystemAbstract<FieldElement>,
    >(
        &self,
        mut cs: CS,
        scb_new_mst_root_g: &FieldElementGadget,
        nullifier_g: &FieldElementGadget,
        amount_g: &FieldElementGadget,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> {
        // Enfore UTXO output hash computation
        let box_type_coin_g = FieldElementGadget::from(
            cs.ns(|| "alloc BoxType.Coin constant"),
            &FieldElement::from(BoxType::CoinBox as u8),
        );

        let mut output_hash_elements_g = self
            .input_g
            .output_g
            .to_field_gadget_elements(cs.ns(|| "alloc output hash elements"))?;

        debug_assert_eq!(output_hash_elements_g.len(), 3);
        output_hash_elements_g.push(box_type_coin_g);

        let output_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(input.output)"),
            &output_hash_elements_g,
        )?;

        // 1 Check output presence in the known state
        // mst_root = reconstruct_merkle_root_hash(outputHash, mst_path_to_output)
        let mst_root_g = self.mst_path_to_output_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(outputHash, mst_path_to_output)"),
            &output_hash_g,
        )?;

        // require(last_wcert.proof_data.scb_new_mst_root == mst_root)
        mst_root_g.conditional_enforce_equal(
            cs.ns(|| "last_wcert.proof_data.scb_new_mst_root == mst_root"),
            scb_new_mst_root_g,
            should_enforce,
        )?;

        // 2 Enforce nullifier
        output_hash_g.conditional_enforce_equal(
            cs.ns(|| "require(nullifier == outputHash)"),
            nullifier_g,
            should_enforce,
        )?;

        // 3. Enforce amount
        let mut utxo_amount_big_endian_bits_g = self.input_g.output_g.amount_g.to_bits_le();
        utxo_amount_big_endian_bits_g.reverse();

        let utxo_input_amount_g = FieldElementGadget::from_bits(
            cs.ns(|| "read utxo input amount"),
            &utxo_amount_big_endian_bits_g,
        )?;

        utxo_input_amount_g.conditional_enforce_equal(
            cs.ns(|| "input.amount == sys_data.amount"),
            amount_g,
            should_enforce,
        )?;

        Ok(())
    }
}

impl AllocGadget<CswUtxoProverData, FieldElement> for CswUtxoProverDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoProverData>,
    {
        let (input, mst_path_to_output) = match f() {
            Ok(csw_utxo_prover_data) => {
                let csw_utxo_prover_data = csw_utxo_prover_data.borrow().clone();
                (
                    Ok(csw_utxo_prover_data.input),
                    Ok(csw_utxo_prover_data.mst_path_to_output),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let input_g = CswUtxoInputDataGadget::alloc(cs.ns(|| "alloc input"), || input)?;

        let mst_path_to_output_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc mst path to output"), || {
                mst_path_to_output
            })?;

        Ok(Self {
            input_g,
            mst_path_to_output_g,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswUtxoProverData>,
    {
        unimplemented!()
    }
}

#[derive(PartialEq, Eq)]
pub struct CswFtOutputDataGadget {
    pub amount_g: UInt64,
    pub receiver_pub_key_g: [Boolean; SIMULATED_FIELD_BYTE_SIZE * 8],
    pub payback_addr_data_hash_g: [Boolean; MC_RETURN_ADDRESS_BYTES * 8],
    pub tx_hash_g: [Boolean; FIELD_SIZE * 8],
    pub out_idx_g: UInt32,
}

impl CswFtOutputDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Boolean, SynthesisError> {
        let phantom_ft_input_g = CswFtOutputDataGadget::from_value(
            cs.ns(|| "alloc constant FT input phantom gadget"),
            &CswFtOutputData::default(),
        );

        self.is_eq(cs.ns(|| "is FT output phantom"), &phantom_ft_input_g)
    }
}

impl AllocGadget<CswFtOutputData, FieldElement> for CswFtOutputDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtOutputData>,
    {
        let (amount, receiver_pub_key, payback_addr_data_hash, tx_hash, out_idx) = match f() {
            Ok(csw_ft_input_data) => {
                let csw_ft_input_data = csw_ft_input_data.borrow().clone();
                (
                    Ok(csw_ft_input_data.amount),
                    Ok(csw_ft_input_data.receiver_pub_key),
                    Ok(csw_ft_input_data.payback_addr_data_hash),
                    Ok(csw_ft_input_data.tx_hash),
                    Ok(csw_ft_input_data.out_idx),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let amount_g = UInt64::alloc(cs.ns(|| "alloc amount"), amount.ok())?;

        let receiver_pub_key_g = Vec::<Boolean>::alloc(cs.ns(|| "alloc receiver pub key"), || {
            Ok(bytes_to_bits(&receiver_pub_key?))
        })?
        .try_into()
        .map_err(|_| {
            SynthesisError::Other(format!(
                "invalid size for public key, expected {} bits",
                SIMULATED_FIELD_BYTE_SIZE * 8
            ))
        })?;

        let payback_addr_data_hash_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc payback addr data hash"), || {
                Ok(bytes_to_bits(&payback_addr_data_hash?))
            })?
            .try_into()
            .map_err(|_| {
                SynthesisError::Other(format!(
                    "invalid size for payback_addr_data_hash, expected {} bits",
                    MC_RETURN_ADDRESS_BYTES * 8
                ))
            })?;

        let tx_hash_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc tx hash"), || Ok(bytes_to_bits(&tx_hash?)))?
                .try_into()
                .map_err(|_| {
                    SynthesisError::Other(format!(
                        "invalid size for tx hash, expected {} bits",
                        FIELD_SIZE * 8
                    ))
                })?;

        let out_idx_g = UInt32::alloc(cs.ns(|| "alloc out idx"), out_idx.ok())?;

        let new_instance = Self {
            amount_g,
            receiver_pub_key_g,
            payback_addr_data_hash_g,
            tx_hash_g,
            out_idx_g,
        };

        Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtOutputData>,
    {
        unimplemented!()
    }
}

impl ConstantGadget<CswFtOutputData, FieldElement> for CswFtOutputDataGadget {
    fn from_value<CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        value: &CswFtOutputData,
    ) -> Self {
        let amount_g = UInt64::constant(value.amount);
        let receiver_pub_key_g = bytes_to_bits(&value.receiver_pub_key)
            .iter()
            .map(|&bit| Boolean::constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let payback_addr_data_hash_g = bytes_to_bits(&value.payback_addr_data_hash)
            .iter()
            .map(|&bit| Boolean::constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let tx_hash_g = bytes_to_bits(&value.tx_hash)
            .iter()
            .map(|&bit| Boolean::constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let out_idx_g = UInt32::constant(value.out_idx);

        Self {
            amount_g,
            receiver_pub_key_g,
            payback_addr_data_hash_g,
            tx_hash_g,
            out_idx_g,
        }
    }

    fn get_constant(&self) -> CswFtOutputData {
        unimplemented!();
    }
}

impl EqGadget<FieldElement> for CswFtOutputDataGadget {
    fn is_eq<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
        other: &Self,
    ) -> Result<Boolean, SynthesisError> {
        let b1 = self
            .amount_g
            .is_eq(cs.ns(|| "is eq amount_g"), &other.amount_g)?;
        let b2 = self.receiver_pub_key_g.is_eq(
            cs.ns(|| "is eq receiver_pub_key_g"),
            &other.receiver_pub_key_g,
        )?;
        let b3 = self.payback_addr_data_hash_g.is_eq(
            cs.ns(|| "is eq payback_addr_data_hash_g"),
            &other.payback_addr_data_hash_g,
        )?;
        let b4 = self
            .tx_hash_g
            .is_eq(cs.ns(|| "is eq tx_hash_g"), &other.tx_hash_g)?;
        let b5 = self
            .out_idx_g
            .is_eq(cs.ns(|| "is eq out_idx_g"), &other.out_idx_g)?;

        Boolean::kary_and(
            cs.ns(|| "is_eq CswUtxoInputDataGadget"),
            &[b1, b2, b3, b4, b5],
        )
    }
}

impl ToConstraintFieldGadget<FieldElement> for CswFtOutputDataGadget {
    type FieldGadget = FieldElementGadget;

    fn to_field_gadget_elements<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<FieldElementGadget>, SynthesisError> {
        let mut bits = self.amount_g.to_bits_le();
        bits.reverse();

        let mut receiver_pub_key_bits = self.receiver_pub_key_g.clone();
        receiver_pub_key_bits.reverse();

        bits.extend_from_slice(&receiver_pub_key_bits);

        let mut payback_addr_data_hash_bits = self.payback_addr_data_hash_g.clone();
        payback_addr_data_hash_bits.reverse();

        bits.extend_from_slice(&payback_addr_data_hash_bits);

        let mut tx_hash_bits = self.tx_hash_g.clone();
        tx_hash_bits.reverse();

        bits.extend_from_slice(&tx_hash_bits);

        let mut out_idx_big_endian_g = self.out_idx_g.to_bits_le();
        out_idx_big_endian_g.reverse();

        bits.extend_from_slice(&out_idx_big_endian_g);

        let elements = bits
            .chunks(FIELD_CAPACITY)
            .enumerate()
            .map(|(index, chunk)| {
                FieldElementGadget::from_bits(cs.ns(|| format!("FT from bits {}", index)), chunk)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        Ok(elements)
    }
}

pub struct CswFtProverDataGadget {
    pub ft_output_g: CswFtOutputDataGadget,
    pub ft_input_secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS], // Assumed to be big endian. TODO: Check this
    pub mcb_sc_txs_com_start_g: FieldElementGadget,
    pub merkle_path_to_sc_hash_g: GingerMHTBinaryGadget,
    pub ft_tree_path_g: GingerMHTBinaryGadget,
    pub sc_creation_commitment_g: FieldElementGadget,
    pub scb_btr_tree_root_g: FieldElementGadget,
    pub wcert_tree_root_g: FieldElementGadget,
    pub sc_txs_com_hashes_g: Vec<FieldElementGadget>,
}

impl CswFtProverDataGadget {
    /// Enforce that:
    /// 1) H(self.ft_output_g) belongs to one of the sc_txs_com_hashes between self.mcb_sc_txs_com_start_g and 'mcb_sc_txs_com_end_g'
    /// 2) H(self.ft_output_g) == 'nullifier_g'
    /// 3) self.ft_output_g.amount_g == 'amount_g'
    pub(crate) fn conditionally_enforce_ft_withdrawal<
        CS: ConstraintSystemAbstract<FieldElement>,
    >(
        &self,
        mut cs: CS,
        sidechain_id_g: &FieldElementGadget,
        range_size: u32,
        mcb_sc_txs_com_end_g: &FieldElementGadget,
        nullifier_g: &FieldElementGadget,
        amount_g: &FieldElementGadget,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> {
        // Enforce FT output hash
        let ft_output_hash_elements = self
            .ft_output_g
            .to_field_gadget_elements(cs.ns(|| "alloc ft_output_hash input elements"))?;

        let ft_output_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(ft_input)"),
            &ft_output_hash_elements,
        )?;

        // 1) H(self.ft_output_g) belongs to one of the sc_txs_com_hashes between self.mcb_sc_txs_com_start_g and 'mcb_sc_txs_com_end_g'

        // Reconstruct the sc tx commitment tree root to which this ft output hash should belong

        // val scb_ft_tree_root = reconstruct_merkle_root_hash(ft_output_hash, ft_tree_path)
        let scb_ft_tree_root_g = self.ft_tree_path_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(ft_output_hash, ft_tree_path)"),
            &ft_output_hash_g,
        )?;

        // val txs_hash = H(scb_ft_tree_root | scb_btr_tree_root | wcert_tree_root)     // Q: what about sc_creation_tx that may be included in txs_hash? Should we add NULL instead?
        let sc_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(scb_ft_tree_root | scb_btr_tree_root | wcert_tree_root | ledgerId)"),
            &[
                scb_ft_tree_root_g.clone(),
                self.scb_btr_tree_root_g.clone(),
                self.wcert_tree_root_g.clone(),
                sidechain_id_g.clone(),
            ],
        )?;

        // val sc_txs_com_tree_root = reconstruct_merkle_root_hash(sc_hash, merkle_path_to_scHash)
        let sc_txs_com_tree_root_g = self.merkle_path_to_sc_hash_g.enforce_root_from_leaf(
            cs.ns(|| "reconstruct_merkle_root_hash(sc_hash, merkle_path_to_scHash)"),
            &sc_hash_g,
        )?;

        // Check that sc_txs_com_tree_root is one of those between self.mcb_sc_txs_com_start_g and 'mcb_sc_txs_com_end_g'

        // var sc_txs_com_cumulative = mcb_sc_txs_com_start
        let mut sc_txs_com_cumulative_g = self.mcb_sc_txs_com_start_g.clone();

        // var cnt = 0
        let mut counter_g = FieldElementGadget::from_value(
            cs.ns(|| "alloc initial counter"),
            &FieldElement::from(0u8),
        );

        // Alloc phantom field element
        let phantom_g = FieldElementGadget::from_value(cs.ns(|| "Break"), &PHANTOM_FIELD_ELEMENT);

        for i in 0..range_size as usize {
            // if (sc_txs_com_tree_root == sc_txs_com_hashes[i]) { cnt++ }
            let should_increase_counter = sc_txs_com_tree_root_g.is_eq(
                cs.ns(|| format!("sc_txs_com_tree_root == sc_txs_com_hashes[{}]", i)),
                &self.sc_txs_com_hashes_g[i],
            )?;

            // cnt++
            counter_g = counter_g.conditionally_add_constant(
                cs.ns(|| format!("cnt++ [{}]", i)),
                &should_increase_counter,
                FieldElement::one(),
            )?;

            // sc_txs_com_cumulative = H(sc_txs_com_cumulative, sc_txs_com_hashes[i])
            let temp_sc_txs_com_cumulative = FieldHashGadget::enforce_hash_constant_length(
                cs.ns(|| format!("H(sc_txs_com_cumulative, sc_txs_com_hashes[{}])", i)),
                &[
                    sc_txs_com_cumulative_g.clone(),
                    self.sc_txs_com_hashes_g[i].clone(),
                ],
            )?;

            // Ignore NULL hashes
            let should_ignore_hash = self.sc_txs_com_hashes_g[i].is_eq(
                cs.ns(|| format!("sc_txs_com_hashes[{}] == PHANTOM", i)),
                &phantom_g,
            )?;

            sc_txs_com_cumulative_g = FieldElementGadget::conditionally_select(
                cs.ns(|| format!("Conditionally select hash at iteration {}", i)),
                &should_ignore_hash,
                &sc_txs_com_cumulative_g,
                &temp_sc_txs_com_cumulative,
            )?;
        }

        // require(cnt == 1)   // We must have exactly one match
        let constant_one_g =
            FieldElementGadget::from_value(cs.ns(|| "alloc constant 1"), &FieldElement::from(1u8));
        counter_g.conditional_enforce_equal(
            cs.ns(|| "require(cnt == 1)"),
            &constant_one_g,
            &should_enforce,
        )?;

        // require(mcb_sc_txs_com_end = sc_txs_com_cumulative)
        mcb_sc_txs_com_end_g.conditional_enforce_equal(
            cs.ns(|| "mcb_sc_txs_com_end = sc_txs_com_cumulative"),
            &sc_txs_com_cumulative_g,
            &should_enforce,
        )?;

        // 2 Enforce nullifier
        ft_output_hash_g.conditional_enforce_equal(
            cs.ns(|| "require(nullifier == outputHash)"),
            nullifier_g,
            should_enforce,
        )?;

        // 3. Enforce amount
        let mut ft_amount_big_endian_bits_g = self.ft_output_g.amount_g.to_bits_le();
        ft_amount_big_endian_bits_g.reverse();

        let ft_input_amount_g = FieldElementGadget::from_bits(
            cs.ns(|| "read ft input amount"),
            &ft_amount_big_endian_bits_g,
        )?;

        ft_input_amount_g.conditional_enforce_equal(
            cs.ns(|| "input.amount == sys_data.amount"),
            amount_g,
            should_enforce,
        )?;

        Ok(())
    }
}

impl AllocGadget<CswFtProverData, FieldElement> for CswFtProverDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtProverData>,
    {
        let (
            ft_output,
            ft_input_secret_key,
            mcb_sc_txs_com_start,
            merkle_path_to_sc_hash,
            ft_tree_path,
            sc_creation_commitment,
            scb_btr_tree_root,
            wcert_tree_root,
            sc_txs_com_hashes,
        ) = match f() {
            Ok(csw_ft_prover_data) => {
                let csw_ft_prover_data = csw_ft_prover_data.borrow().clone();
                (
                    Ok(csw_ft_prover_data.ft_output),
                    Ok(csw_ft_prover_data.ft_input_secret_key),
                    Ok(csw_ft_prover_data.mcb_sc_txs_com_start),
                    Ok(csw_ft_prover_data.merkle_path_to_sc_hash),
                    Ok(csw_ft_prover_data.ft_tree_path),
                    Ok(csw_ft_prover_data.sc_creation_commitment),
                    Ok(csw_ft_prover_data.scb_btr_tree_root),
                    Ok(csw_ft_prover_data.wcert_tree_root),
                    Ok(csw_ft_prover_data.sc_txs_com_hashes),
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
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let ft_output_g = CswFtOutputDataGadget::alloc(cs.ns(|| "alloc ft input"), || ft_output)?;

        let ft_input_secret_key_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc ft input secret key"), || {
                ft_input_secret_key
            })?
            .try_into()
            .map_err(|_| {
                SynthesisError::Other(format!(
                    "invalid size for secret_key, expected {} bits",
                    SIMULATED_SCALAR_FIELD_MODULUS_BITS
                ))
            })?;

        let mcb_sc_txs_com_start_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc mcb sc txs com start"), || {
                mcb_sc_txs_com_start
            })?;

        let merkle_path_to_sc_hash_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc merkle path to sc hash"), || {
                merkle_path_to_sc_hash
            })?;

        let ft_tree_path_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc ft tree path"), || ft_tree_path)?;

        let sc_creation_commitment_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc sc creation commitment"), || {
                sc_creation_commitment
            })?;

        let scb_btr_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc scb btr tree root"), || scb_btr_tree_root)?;

        let wcert_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc wcert tree root"), || wcert_tree_root)?;

        let sc_txs_com_hashes_g =
            Vec::<FieldElementGadget>::alloc(cs.ns(|| "alloc custom fields"), || {
                sc_txs_com_hashes
            })?;

        Ok(Self {
            ft_output_g,
            ft_input_secret_key_g,
            mcb_sc_txs_com_start_g,
            merkle_path_to_sc_hash_g,
            ft_tree_path_g,
            sc_creation_commitment_g,
            scb_btr_tree_root_g,
            wcert_tree_root_g,
            sc_txs_com_hashes_g,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtProverData>,
    {
        todo!()
    }
}

pub struct CswSysDataGadget {
    pub mcb_sc_txs_com_end_g: FieldElementGadget,
    pub sc_last_wcert_hash_g: FieldElementGadget,
    pub amount_g: FieldElementGadget,
    pub nullifier_g: FieldElementGadget,
    pub receiver_g: [Boolean; MC_RETURN_ADDRESS_BYTES * 8],
}

impl AllocGadget<CswSysData, FieldElement> for CswSysDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswSysData>,
    {
        let (mcb_sc_txs_com_end, sc_last_wcert_hash, amount, nullifier, receiver) = match f() {
            Ok(csw_sys_data) => {
                let csw_sys_data = csw_sys_data.borrow().clone();
                (
                    Ok(csw_sys_data.mcb_sc_txs_com_end),
                    Ok(csw_sys_data.sc_last_wcert_hash),
                    Ok(csw_sys_data.amount),
                    Ok(csw_sys_data.nullifier),
                    Ok(csw_sys_data.receiver),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let mcb_sc_txs_com_end_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc mcb sc txs com end"), || mcb_sc_txs_com_end)?;

        let sc_last_wcert_hash_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc sc last wcert hash"), || sc_last_wcert_hash)?;

        let amount_g = FieldElementGadget::alloc(cs.ns(|| "alloc amount"), || {
            Ok(FieldElement::from(amount?))
        })?;

        let nullifier_g = FieldElementGadget::alloc(cs.ns(|| "alloc nullifier"), || nullifier)?;

        let receiver_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc receiver"), || Ok(bytes_to_bits(&receiver?)))?
                .try_into()
                .map_err(|_| {
                    SynthesisError::Other(format!(
                        "invalid size for payback_addr_data_hash, expected {} bits",
                        MC_RETURN_ADDRESS_BYTES * 8
                    ))
                })?;

        Ok(Self {
            mcb_sc_txs_com_end_g,
            sc_last_wcert_hash_g,
            amount_g,
            nullifier_g,
            receiver_g,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswSysData>,
    {
        todo!()
    }
}

pub struct CswProverDataGadget {
    pub sys_data_g: CswSysDataGadget,
    pub last_wcert_g: WithdrawalCertificateDataGadget, // the last confirmed wcert in the MC
    pub utxo_data_g: CswUtxoProverDataGadget,
    pub ft_data_g: CswFtProverDataGadget,
}

impl AllocGadget<CswProverData, FieldElement> for CswProverDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswProverData>,
    {
        let (sys_data, last_wcert, utxo_data, ft_data) = match f() {
            Ok(csw_prover_data) => {
                let csw_prover_data = csw_prover_data.borrow().clone();
                (
                    Ok(csw_prover_data.sys_data),
                    Ok(csw_prover_data.last_wcert),
                    Ok(csw_prover_data.utxo_data),
                    Ok(csw_prover_data.ft_data),
                )
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let sys_data_g = CswSysDataGadget::alloc(cs.ns(|| "alloc csw sys data"), || sys_data)?;
        let last_wcert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc wcert data"), || last_wcert)?;
        let utxo_data_g = CswUtxoProverDataGadget::alloc(cs.ns(|| "alloc ft data"), || utxo_data)?;
        let ft_data_g =
            CswFtProverDataGadget::alloc(cs.ns(|| "alloc csw ft prover data"), || ft_data)?;

        Ok(Self {
            sys_data_g,
            last_wcert_g,
            utxo_data_g,
            ft_data_g,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        _cs: CS,
        _f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswProverData>,
    {
        unimplemented!();
    }
}
