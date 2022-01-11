use std::{borrow::Borrow, convert::TryInto};

use algebra::{AffineCurve, Field, MontgomeryModelParameters, SquareRootField, TEModelParameters};
use cctp_primitives::type_mapping::{FieldElement, FieldHash, FIELD_CAPACITY, FIELD_SIZE};
use primitives::bytes_to_bits;
use r1cs_core::{ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedMerkleTreePathGadget, FieldHasherGadget};
use r1cs_std::{
    boolean::Boolean,
    fields::{nonnative::nonnative_field_gadget::NonNativeFieldGadget, FieldGadget},
    groups::GroupGadget,
    prelude::{AllocGadget, ConstantGadget, EqGadget, UInt8},
    select::CondSelectGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    uint32::UInt32,
    uint64::UInt64,
    Assignment, FromBitsGadget,
};

use crate::{
    constants::constants::BoxType, CswFtOutputData, CswFtProverData, CswProverData, CswSysData,
    CswUtxoInputData, CswUtxoOutputData, CswUtxoProverData, ECPointSimulationGadget,
    FieldElementGadget, FieldHashGadget, GingerMHTBinaryGadget, SimulatedCurveParameters,
    SimulatedFieldElement, SimulatedSWGroup, WithdrawalCertificateData, MC_RETURN_ADDRESS_BYTES,
    SC_CUSTOM_HASH_LENGTH, SC_PUBLIC_KEY_LENGTH, SC_TX_HASH_LENGTH, SIMULATED_FIELD_BYTE_SIZE,
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

        self.ledger_id_g
            .is_eq(cs.ns(|| "is wcert phantom"), &phantom_wcert_g.ledger_id_g)
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
    pub spending_pub_key_g: [Boolean; SC_PUBLIC_KEY_LENGTH * 8],
    pub amount_g: UInt64,
    pub nonce_g: UInt64,
    pub custom_hash_g: [Boolean; SC_TX_HASH_LENGTH * 8],
}

impl CswUtxoOutputDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Boolean, SynthesisError> {
        let phantom_utxo_output_g = CswUtxoOutputDataGadget::from_value(
            cs.ns(|| "alloc constant UTXO input phantom gadget"),
            &CswUtxoOutputData::get_phantom(),
        );

        self.spending_pub_key_g.is_eq(
            cs.ns(|| "is UTXO output phantom"),
            &phantom_utxo_output_g.spending_pub_key_g,
        )
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

        let spending_pub_key_g = Vec::<Boolean>::alloc(cs.ns(|| "alloc spending pub key"), || {
            Ok(bytes_to_bits(&spending_pub_key?))
        })?
        .try_into()
        .map_err(|_| {
            SynthesisError::Other(format!(
                "invalid size for spending_pub_key, expected {} bits",
                SIMULATED_FIELD_BYTE_SIZE * 8
            ))
        })?;

        let amount_g = UInt64::alloc(cs.ns(|| "alloc amount"), amount.ok())?;

        let nonce_g = UInt64::alloc(cs.ns(|| "alloc nonce"), nonce.ok())?;

        let custom_hash_g = Vec::<Boolean>::alloc(cs.ns(|| "alloc custom hash"), || {
            Ok(bytes_to_bits(&custom_hash?))
        })?
        .try_into()
        .map_err(|_| {
            SynthesisError::Other(format!(
                "invalid size for custom_hash, expected {} bits",
                SC_CUSTOM_HASH_LENGTH * 8
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
        let spending_pub_key_g = bytes_to_bits(&value.spending_pub_key)
            .into_iter()
            .map(Boolean::Constant)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let amount_g = UInt64::constant(value.amount);

        let nonce_g = UInt64::constant(value.nonce);

        let custom_hash_g = bytes_to_bits(&value.custom_hash)
            .into_iter()
            .map(Boolean::Constant)
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
        unimplemented!()
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
        let mut bits = self.spending_pub_key_g.to_vec();
        bits.reverse();

        let mut amount_big_endian_g = self.amount_g.to_bits_le();
        amount_big_endian_g.reverse();
        bits.extend_from_slice(&amount_big_endian_g);

        let mut nonce_big_endian_g = self.nonce_g.to_bits_le();
        nonce_big_endian_g.reverse();
        bits.extend_from_slice(&nonce_big_endian_g);

        let mut custom_hash_bits_g = self.custom_hash_g;
        custom_hash_bits_g.reverse();

        bits.extend_from_slice(&custom_hash_bits_g);

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
    pub secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
}

impl CswUtxoInputDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Boolean, SynthesisError> {
        self.output_g.is_phantom(cs.ns(|| "is output_g phantom"))
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
    pub receiver_pub_key_g: [UInt8; SC_PUBLIC_KEY_LENGTH],
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
            &CswFtOutputData::get_phantom(),
        );

        self.payback_addr_data_hash_g.is_eq(
            cs.ns(|| "is FT output phantom"),
            &phantom_ft_input_g.payback_addr_data_hash_g,
        )
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

        let receiver_pub_key_g =
            Vec::<UInt8>::alloc(cs.ns(|| "alloc receiver pub key"), || receiver_pub_key)?
                .try_into()
                .map_err(|_| {
                    SynthesisError::Other(format!(
                        "invalid size for public key, expected {} bytes",
                        SC_PUBLIC_KEY_LENGTH
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
        let receiver_pub_key_g = value
            .receiver_pub_key
            .iter()
            .map(|&byte| UInt8::constant(byte))
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

        let mut receiver_pub_key_bits = self
            .receiver_pub_key_g
            .iter()
            .rev() // Reverse the bytes due to a MC <-> SC endianness incompatibility
            .flat_map(|byte| byte.into_bits_le())
            .collect::<Vec<Boolean>>();
        receiver_pub_key_bits.reverse();

        bits.extend_from_slice(&receiver_pub_key_bits);

        let mut payback_addr_data_hash_bits = self.payback_addr_data_hash_g;
        payback_addr_data_hash_bits.reverse();

        bits.extend_from_slice(&payback_addr_data_hash_bits);

        let mut tx_hash_bits = self.tx_hash_g;
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
    pub ft_input_secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
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
                scb_ft_tree_root_g,
                self.scb_btr_tree_root_g.clone(),
                self.wcert_tree_root_g.clone(),
                self.sc_creation_commitment_g.clone(),
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
        let phantom_g = FieldElementGadget::from_value(cs.ns(|| "Break"), &FieldElement::default());

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
        unimplemented!()
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
        unimplemented!()
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

// TODO: Define it as [Boolean; SC_PUBLIC_KEY_LENGTH * 8] and replace in all other data structures
pub struct ScPublicKeyGadget {}

impl ScPublicKeyGadget {
    /// Enforce reconstruction of the x coordinate from the y and the sign, and return the whole TE point.
    /// x^2 = (y^2 - 1)/(d * y^2 - a)
    fn get_te_pk_x_from_x_sign_and_y<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        pk_x_sign_bit_g: Boolean,
        pk_y_coordinate_g: &NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
    ) -> Result<NonNativeFieldGadget<SimulatedFieldElement, FieldElement>, SynthesisError> {
        // Reconstruct the x coordinate from the y and the sign, and return the whole TE point.
        // x^2 = (y^2 - 1)/(d * y^2 - a)
        let pk_x_coordinate_g = NonNativeFieldGadget::<SimulatedFieldElement, FieldElement>::alloc(
            cs.ns(|| "alloc pk_x"),
            || {
                let te_pk_y = pk_y_coordinate_g.get_value().get()?;
                let numerator = te_pk_y.square() - SimulatedFieldElement::one();
                let denominator = (te_pk_y.square() * SimulatedCurveParameters::COEFF_D)
                    - <SimulatedCurveParameters as TEModelParameters>::COEFF_A;
                let x2 = denominator
                    .inverse()
                    .map(|denom| denom * numerator)
                    .ok_or_else(|| {
                        SynthesisError::Other("Must be able to compute denominator".to_string())
                    })?;

                let x = x2.sqrt().ok_or_else(|| {
                    SynthesisError::Other("x^2 square root must exist in the field".to_string())
                })?;
                let negx = -x;
                let x = if x.is_odd() ^ pk_x_sign_bit_g.get_value().get()? {
                    negx
                } else {
                    x
                };
                Ok(x)
            },
        )?;
        let pk_x_squared = pk_x_coordinate_g.square(cs.ns(|| "pk_x^2"))?;
        let pk_y_squared = pk_y_coordinate_g.square(cs.ns(|| "pk_y ^ 2"))?;
        let pk_y_squared_minus_one =
            pk_y_squared.sub_constant(cs.ns(|| "pk_y ^ 2 - 1"), &SimulatedFieldElement::one())?;
        let d_times_pk_y_squared_minus_a = pk_y_squared
            .mul_by_constant(cs.ns(|| "d * pk_y^2"), &SimulatedCurveParameters::COEFF_D)?
            .sub_constant(
                cs.ns(|| "d * pk_y^2 - a"),
                &<SimulatedCurveParameters as TEModelParameters>::COEFF_A,
            )?;

        // Check pk_x
        pk_x_squared.mul_equals(
            cs.ns(|| "Check te_pk_x"),
            &d_times_pk_y_squared_minus_a,
            &pk_y_squared_minus_one,
        )?;

        // Check sign of pk_x
        pk_x_coordinate_g
            .is_odd(cs.ns(|| "is te_pk_x odd"))?
            .enforce_equal(cs.ns(|| "check te_pk_x sign"), &pk_x_sign_bit_g)?;

        Ok(pk_x_coordinate_g)
    }


    fn convert_te_to_sw_point<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        te_pk_x_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
        te_pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
    ) -> Result<ECPointSimulationGadget, SynthesisError> {
        let y_ed_minus_one = te_pk_y_coordinate_g
            .add_constant(cs.ns(|| "y_ed - 1"), &-SimulatedFieldElement::one())?;

        let one_plus_y_ed = te_pk_y_coordinate_g
            .add_constant(cs.ns(|| "1 + y_ed"), &SimulatedFieldElement::one())?;

        // TODO: These can be precomputed
        let b_inv = <SimulatedCurveParameters as MontgomeryModelParameters>::COEFF_B
            .inverse()
            .expect("B inverse must exist");

        let a_over_three =
        <SimulatedCurveParameters as MontgomeryModelParameters>::COEFF_A
            * (SimulatedFieldElement::from(3u8)
                .inverse()
                .expect("Must be able to compute 3.inverse() in SimulatedField"));

        // Alloc x coordinate in SW representation
        let sw_pk_x_coordinate_g =
            NonNativeFieldGadget::<SimulatedFieldElement, FieldElement>::alloc(
                cs.ns(|| "alloc x coord in SW"),
                || {
                    let one_plus_te_y_coord = one_plus_y_ed.get_value().get()?;
                    let one_minus_te_y_coord = -y_ed_minus_one.get_value().get()?;

                    let one_plus_te_y_coord_over_one_minus_te_y_coord = one_plus_te_y_coord
                        * one_minus_te_y_coord.inverse().ok_or_else(|| {
                            SynthesisError::Other(
                                "Should be able to compute inverse of (1 - y_te)".to_string(),
                            )
                        })?;

                    Ok((one_plus_te_y_coord_over_one_minus_te_y_coord + a_over_three) * b_inv)
                },
            )?;

        // Check SW x coordinate:
        // x_sw * (1 - y_ed) = 1/B (1 + y_ed) + A/3B (1 - y_ed)
        // Multiplication by - 1 => x_sw * (y_ed - 1) = -1/B (1 + y_ed) + A/3B (1 - y_ed)
        // Write (1 + y_ed) as (y_ed + 2 - 1) => x_sw * (y_ed - 1) = -1/B (y_ed - 1) - 2/B + A/3B (y_ed - 1)
        // Gathering by (y_ed - 1) => (x_sw + 1/B - A/3B) * (y_ed - 1) = -2/B
        {
            let minus_two_over_b = NonNativeFieldGadget::<SimulatedFieldElement, FieldElement>::from_value(
                cs.ns(|| "hardcode -2_over_B"),
                &(-b_inv * &SimulatedFieldElement::from(2u8)) //TODO: This can be precomputed
            );

            sw_pk_x_coordinate_g
                .add_constant(cs.ns(|| "x_sw + 1_over_B"), &b_inv)?
                .sub_constant(cs.ns(|| "x_sw + 1_over_B - A_over_3B"), &(a_over_three * &b_inv))? //TODO: This can be precomputed
                .mul_equals(
                    cs.ns(|| "(x_sw + 1_over_B - A_over_3B) * (y_ed - 1) = -2_over_B"),
                    &y_ed_minus_one,
                    &minus_two_over_b
                )?;
        }

        // Alloc y coordinate in sw representation
        let sw_pk_y_coordinate_g =
            NonNativeFieldGadget::<SimulatedFieldElement, FieldElement>::alloc(
                cs.ns(|| "alloc y coord in SW"),
                || {
                    let b_inv = <SimulatedCurveParameters as MontgomeryModelParameters>::COEFF_B
                        .inverse()
                        .expect("B inverse must exist");

                    let one_plus_te_y_coord = one_plus_y_ed.get_value().get()?;
                    let one_minus_te_y_coord = -y_ed_minus_one.get_value().get()?;

                    let one_plus_te_y_coord_over_one_minus_te_y_coord = one_plus_te_y_coord
                        * one_minus_te_y_coord.inverse().ok_or_else(|| {
                            SynthesisError::Other(
                                "Should be able to compute inverse of (1 - y_te)".to_string(),
                            )
                        })?;

                    let te_x_coord_inv = te_pk_x_coordinate_g
                        .get_value()
                        .get()?
                        .inverse()
                        .ok_or_else(|| {
                            SynthesisError::Other(
                                "Should be able to compute inverse of x_te".to_string(),
                            )
                        })?;

                    Ok(b_inv * one_plus_te_y_coord_over_one_minus_te_y_coord * te_x_coord_inv)
                },
            )?;

        // Check SW y coordinate
        // y_sw * (x_ed(y_ed - 1)B) = -(1 + y_ed)
        {
            let b_x_ed_times_one_minus_y_ed = y_ed_minus_one
                .mul(cs.ns(|| "x_ed(y_ed - 1)"), &te_pk_x_coordinate_g)?
                .mul_by_constant(
                    cs.ns(|| "x_ed(y_ed - 1)B"),
                    &<SimulatedCurveParameters as MontgomeryModelParameters>::COEFF_B,
                )?;

            let minus_one_plus_y_ed = one_plus_y_ed.negate(cs.ns(|| "-(1 + y_ed)"))?;

            sw_pk_y_coordinate_g.mul_equals(
                cs.ns(|| "check y sw"),
                &b_x_ed_times_one_minus_y_ed,
                &minus_one_plus_y_ed,
            )?;
        }

        Ok(ECPointSimulationGadget::new(
            sw_pk_x_coordinate_g,
            sw_pk_y_coordinate_g,
            Boolean::Constant(false),
        ))
    }

    /// Extract TE point from y coordinate and x sign, then convert it to SW and output it.
    fn get_sw_pk_from_te_pk<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        te_pk_x_sign_bit_g: Boolean,
        te_pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
    ) -> Result<ECPointSimulationGadget, SynthesisError> {
        // Reconstruct TE x coordinate
        let te_pk_x_coordinate_g = Self::get_te_pk_x_from_x_sign_and_y(
            cs.ns(|| "Reconstruct te x coordinate"),
            te_pk_x_sign_bit_g,
            &te_pk_y_coordinate_g,
        )?;

        // Convert TE point to a SW one
        Self::convert_te_to_sw_point(
            cs.ns(|| "convert TE pk to SW"),
            te_pk_x_coordinate_g,
            te_pk_y_coordinate_g,
        )
    }

    /// Extract pk x coordinate sign and pk y coordinate from pk bits, assumed to be in LE
    pub(crate) fn get_x_sign_and_y_coord_from_pk_bits<
        CS: ConstraintSystemAbstract<FieldElement>,
    >(
        mut cs: CS,
        public_key_bits_g: &[Boolean; SC_PUBLIC_KEY_LENGTH * 8],
    ) -> Result<
        (
            Boolean,
            NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
        ),
        SynthesisError,
    > {
        let mut pk_bits_g = *public_key_bits_g;
        pk_bits_g.reverse(); // BE

        // Get the Boolean corresponding to the sign of the x coordinate
        let pk_x_sign_bit_g = pk_bits_g[0];

        // Read the y coordinate of the public key in TE form
        let pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement> =
            NonNativeFieldGadget::from_bits(cs.ns(|| "alloc pk y coordinate"), &pk_bits_g[1..])?;

        Ok((pk_x_sign_bit_g, pk_y_coordinate_g))
    }

    pub(crate) fn _enforce_pk_ownership<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        te_pk_x_sign_bit_g: Boolean,
        te_pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
        secret_key_bits_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
    ) -> Result<(), SynthesisError> {
        // Convert the TE pk to a SW one
        let expected_public_key_g = Self::get_sw_pk_from_te_pk(
            cs.ns(|| "Convert TE pk to SW pk"),
            te_pk_x_sign_bit_g,
            te_pk_y_coordinate_g,
        )?;

        // Compute public key from secret key
        let current_public_key_g = ECPointSimulationGadget::mul_bits_fixed_base(
            &SimulatedSWGroup::prime_subgroup_generator().into_projective(),
            cs.ns(|| "G^sk"),
            &secret_key_bits_g,
        )?;

        // Enforce equality with the one computed from pk bits
        current_public_key_g
            .enforce_equal(cs.ns(|| "expected_pk == actual_pk"), &expected_public_key_g)?;

        Ok(())
    }

    /// Enforce ownership of the public key in the Sc Utxo/FT by enforcing its derivation from the secret key.
    /// secret key and public key bits are assumed to be in little endian bit order.
    pub fn enforce_pk_ownership<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        csw_data_g: &CswProverDataGadget,
        should_enforce_utxo_withdrawal_g: &Boolean,
    ) -> Result<(), SynthesisError> {
        // Get public_key_y_coord and x sign from both sc utxo and ft and select the correct one
        let (pk_x_sign_bit_g, pk_y_coordinate_g) = {
            let (utxo_pk_x_sign_bit_g, utxo_pk_y_coordinate_g) =
                Self::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "unpack utxo pk bits"),
                    &csw_data_g.utxo_data_g.input_g.output_g.spending_pub_key_g,
                )?;

            let ft_pk_bits_g: [Boolean; SC_PUBLIC_KEY_LENGTH * 8] = csw_data_g
                .ft_data_g
                .ft_output_g
                .receiver_pub_key_g
                .iter()
                .flat_map(|b| b.into_bits_le())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let (ft_pk_x_sign_bit_g, ft_pk_y_coordinate_g) =
                Self::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "unpack ft pk bits"),
                    &ft_pk_bits_g,
                )?;

            let selected_pk_x_sign_bit_g = Boolean::conditionally_select(
                cs.ns(|| "select x sign bit"),
                &should_enforce_utxo_withdrawal_g,
                &utxo_pk_x_sign_bit_g,
                &ft_pk_x_sign_bit_g,
            )?;

            let selected_pk_y_coordinate_g = NonNativeFieldGadget::conditionally_select(
                cs.ns(|| "select pk_y_coordinate_g"),
                &should_enforce_utxo_withdrawal_g,
                &utxo_pk_y_coordinate_g,
                &ft_pk_y_coordinate_g,
            )?;

            (selected_pk_x_sign_bit_g, selected_pk_y_coordinate_g)
        };

        // Conditionally select the secret key
        let mut secret_key_bits_g =
            Vec::<Boolean>::with_capacity(SIMULATED_SCALAR_FIELD_MODULUS_BITS);

        for i in 0..SIMULATED_SCALAR_FIELD_MODULUS_BITS {
            let secret_key_bit_g = Boolean::conditionally_select(
                cs.ns(|| format!("read secret key bit {}", i)),
                &should_enforce_utxo_withdrawal_g,
                &csw_data_g.utxo_data_g.input_g.secret_key_g[i],
                &csw_data_g.ft_data_g.ft_input_secret_key_g[i],
            )?;
            secret_key_bits_g.push(secret_key_bit_g);
        }

        Self::_enforce_pk_ownership(
            cs.ns(|| "enforce ownership inner"),
            pk_x_sign_bit_g,
            pk_y_coordinate_g,
            secret_key_bits_g.try_into().unwrap(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::deserialize_fe_unchecked;

    use super::*;
    use algebra::ToBits;
    use r1cs_core::{ConstraintSystem, ConstraintSystemDebugger, SynthesisMode};

    use serial_test::*;

    #[serial]
    #[test]
    fn test_sc_public_key_gadget() {
        let test_sc_secrets = vec![
            "50d5e4c0b15402013941a3c525c6af85e7ab8a2da39a59707211ddd53def965e",
            "1089ba2f1bee0bbc8f2270541bb22595026fe7d828033845d5ed82f31386b65d",
        ];

        let test_sc_te_public_keys = vec![
            "f165e1e5f7c290e52f2edef3fbab60cbae74bfd3274f8e5ee1de3345c954a166",
            "cc1983469486418cd66dcdc8664677c263487b736840cfd1532e144386fa7610",
        ];

        let test_case = |test_sc_secret: &str,
                         test_sc_public_key: &str,
                         cs: &mut ConstraintSystem<FieldElement>| {
            // Parse pk LE bits and alloc them
            let pk_bytes = hex::decode(test_sc_public_key).unwrap();
            let pk_bits = bytes_to_bits(pk_bytes.as_slice());
            let pk_bits_g =
                Vec::<Boolean>::alloc(cs.ns(|| "alloc pk bits"), || Ok(pk_bits.as_slice()))
                    .unwrap();

            // Parse sk LE bits and alloc them
            let sk_bytes = hex::decode(test_sc_secret).unwrap();
            let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

            // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
            let mut sk_bits = sk.write_bits();
            sk_bits.reverse(); // LE
            let sk_bits_g =
                Vec::<Boolean>::alloc(cs.ns(|| "alloc sk bits"), || Ok(sk_bits.as_slice()))
                    .unwrap();

            // Get sign and y coord from pk bits
            let (te_pk_x_sign_g, te_pk_y_coord_g) =
                ScPublicKeyGadget::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "get te pk x sign and y coordinate"),
                    &(pk_bits_g.try_into().unwrap()),
                )
                .unwrap();

            // Enforce pk ownership
            ScPublicKeyGadget::_enforce_pk_ownership(
                cs.ns(|| "enforce pk ownership"),
                te_pk_x_sign_g,
                te_pk_y_coord_g,
                sk_bits_g.try_into().unwrap(),
            )
            .unwrap();
        };

        // Positive test cases
        for (test_sc_secret, test_sc_public_key) in
            test_sc_secrets.iter().zip(test_sc_te_public_keys.iter())
        {
            let mut cs = ConstraintSystem::<FieldElement>::new(SynthesisMode::Debug);
            test_case(test_sc_secret, test_sc_public_key, &mut cs);
            assert!(cs.is_satisfied());
        }

        // Negative test cases
        for (test_sc_secret, test_sc_public_key) in test_sc_secrets
            .into_iter()
            .rev()
            .zip(test_sc_te_public_keys.into_iter())
        {
            let mut cs = ConstraintSystem::<FieldElement>::new(SynthesisMode::Debug);
            test_case(test_sc_secret, test_sc_public_key, &mut cs);
            assert!(!cs.is_satisfied());
        }
    }
}
