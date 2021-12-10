use std::{borrow::Borrow, convert::TryInto};

use cctp_primitives::type_mapping::{FieldElement, FIELD_CAPACITY, FIELD_SIZE};
use primitives::bytes_to_bits;
use r1cs_core::{ConstraintSystemAbstract, SynthesisError};
use r1cs_std::{
    boolean::Boolean,
    prelude::{AllocGadget, ConstantGadget, EqGadget},
    to_field_gadget_vec::ToConstraintFieldGadget,
    uint32::UInt32,
    uint64::UInt64,
    FromBitsGadget, FromGadget, ToBitsGadget,
};

use crate::{
    constants::constants::CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER, CswFtOutputData, CswProverData,
    CswUtxoInputData, CswUtxoOutputData, FieldElementGadget, GingerMHTBinaryGadget,
    WithdrawalCertificateData, MC_RETURN_ADDRESS_BYTES, PHANTOM_SECRET_KEY_BITS,
    SIMULATED_FIELD_BYTE_SIZE, SIMULATED_SCALAR_FIELD_MODULUS_BITS, read_field_element_from_buffer_with_padding,
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
            &WithdrawalCertificateData::get_phantom_data(num_custom_fields),
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

        for custom_field in value.custom_fields.iter() {
            let custom_field_g = FieldElementGadget::from_value(
                cs.ns(|| "alloc constant custom_fields"),
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
        let b8 = self
            .custom_fields_g
            .is_eq(cs.ns(|| "is eq custom_fields"), &other.custom_fields_g)?;

        Boolean::kary_and(
            cs.ns(|| "is_eq CswUtxoOutputDataGadget"),
            &[b1, b2, b3, b4, b5, b6, b7, b8],
        )
    }
}

#[derive(PartialEq, Eq)]
pub struct CswUtxoOutputDataGadget {
    pub spending_pub_key_g: [Boolean; SIMULATED_FIELD_BYTE_SIZE * 8],
    pub amount_g: UInt64,
    pub nonce_g: UInt64,
    pub custom_hash_g: [Boolean; FIELD_SIZE * 8],
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

        // TODO: to save some constraints, it would be possible to allocate amount and nonce as Vec<Boolean>
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
    pub secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
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

        Boolean::kary_and(cs.ns(|| "is_eq CswUtxoInputDataGadget"), &[b1, b2])
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

        let receiver_pub_key_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc receiver pub key"), || Ok(bytes_to_bits(&receiver_pub_key?)))?
                .try_into()
                .map_err(|_| {
                    SynthesisError::Other(format!(
                        "invalid size for public key, expected {} bits",
                        SIMULATED_FIELD_BYTE_SIZE * 8
                    ))
                })?;

        let payback_addr_data_hash_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc payback addr data hash"), || Ok(bytes_to_bits(&payback_addr_data_hash?)))?
            .try_into()
            .map_err(|_| {
                SynthesisError::Other(format!(
                    "invalid size for payback_addr_data_hash, expected {} bits",
                    MC_RETURN_ADDRESS_BYTES * 8
                ))
            })?;

        let tx_hash_g = Vec::<Boolean>::alloc(cs.ns(|| "alloc tx hash"), || Ok(bytes_to_bits(&tx_hash?)))?
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

        bits.extend_from_slice(&self.receiver_pub_key_g);
        bits.extend_from_slice(&self.payback_addr_data_hash_g);
        bits.extend_from_slice(&self.tx_hash_g);

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

pub struct CswProverDataGadget {
    // public inputs [START]
    pub genesis_constant_g: Option<FieldElementGadget>,
    pub mcb_sc_txs_com_end_g: FieldElementGadget,
    pub sc_last_wcert_hash_g: FieldElementGadget,
    pub amount_g: FieldElementGadget,
    pub nullifier_g: FieldElementGadget,
    pub receiver_g: FieldElementGadget,
    // public inputs [END]

    // witnesses [START]
    pub last_wcert_g: WithdrawalCertificateDataGadget,
    pub input_g: CswUtxoInputDataGadget,
    pub mst_path_to_output_g: GingerMHTBinaryGadget,
    pub ft_input_g: CswFtOutputDataGadget,
    pub ft_input_secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
    pub mcb_sc_txs_com_start_g: FieldElementGadget,
    pub merkle_path_to_sc_hash_g: GingerMHTBinaryGadget,
    pub ft_tree_path_g: GingerMHTBinaryGadget,
    pub sc_creation_commitment_g: FieldElementGadget,
    pub scb_btr_tree_root_g: FieldElementGadget,
    pub wcert_tree_root_g: FieldElementGadget,
    pub sc_txs_com_hashes_g: Vec<FieldElementGadget>,
    // witnesses [END]
}

impl FromGadget<CswProverData, FieldElement> for CswProverDataGadget {
    fn from<CS: ConstraintSystemAbstract<FieldElement>>(
        data: CswProverData,
        mut cs: CS,
    ) -> Result<Self, SynthesisError> {
        let mut genesis_constant_g = None;
        if data.sys_data.genesis_constant.is_some() {
            genesis_constant_g = Some(
                FieldElementGadget::alloc_input(cs.ns(|| "alloc genesis constant"), || {
                    Ok(data.sys_data.genesis_constant.unwrap())
                })?
            );
        }

        let mcb_sc_txs_com_end_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc mcb sc txs com end"), || {
                Ok(data.sys_data.mcb_sc_txs_com_end)
            })?;

        let sc_last_wcert_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc sc last wcert hash"), || {
                Ok(data.sys_data.sc_last_wcert_hash)
            })?;

        let amount_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc amount"), || Ok(FieldElement::from(data.sys_data.amount)))?;

        let nullifier_g = FieldElementGadget::alloc_input(cs.ns(|| "alloc nullifier"), || {
            Ok(data.sys_data.nullifier)
        })?;

        let receiver_g = FieldElementGadget::alloc_input(cs.ns(|| "alloc receiver"), || {
            read_field_element_from_buffer_with_padding(&data.sys_data.receiver)
                .map_err(|e| SynthesisError::Other(e.to_string()))
        })?;

        let last_wcert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc last wcert"), || {
                Ok(data.last_wcert.clone())
            })?;

        let input_g = CswUtxoInputDataGadget::alloc(cs.ns(|| "alloc input"), || {
            Ok(data.utxo_data.input.clone())
        })?;

        let mst_path_to_output_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc mst path to output"), || {
                Ok(data.utxo_data.mst_path_to_output.clone())
            })?;

        let ft_input_g = CswFtOutputDataGadget::alloc(cs.ns(|| "alloc ft input"), || {
            Ok(data.ft_data.ft_output.clone())
        })?;

        let ft_input_secret_key_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc ft input secret key"), || {
                Ok(data.ft_data.ft_input_secret_key)
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
                Ok(data.ft_data.mcb_sc_txs_com_start)
            })?;

        let merkle_path_to_sc_hash_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc merkle path to sc hash"), || {
                Ok(&data.ft_data.merkle_path_to_sc_hash)
            })?;

        let ft_tree_path_g = GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc ft tree path"), || {
            Ok(data.ft_data.ft_tree_path.clone())
        })?;

        let sc_creation_commitment_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc scb btr tree root"), || {
                Ok(data.ft_data.sc_creation_commitment)
            })?;

        let scb_btr_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc scb btr tree root"), || {
                Ok(data.ft_data.scb_btr_tree_root)
            })?;

        let wcert_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc wcert tree root"), || {
                Ok(data.ft_data.wcert_tree_root)
            })?;

        assert!(data.ft_data.sc_txs_com_hashes.len() == CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER);
        let mut sc_txs_com_hashes_g = Vec::with_capacity(CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER);

        for index in 0..data.ft_data.sc_txs_com_hashes.len() {
            let sc_txs_com_hash_g = FieldElementGadget::alloc(
                cs.ns(|| format!("alloc sc txs com hash {}", index)),
                || Ok(data.ft_data.sc_txs_com_hashes[index]),
            )?;
            sc_txs_com_hashes_g.push(sc_txs_com_hash_g);
        }

        let new_instance = Self {
            genesis_constant_g,
            mcb_sc_txs_com_end_g,
            sc_last_wcert_hash_g,
            amount_g,
            nullifier_g,
            receiver_g,
            last_wcert_g,
            input_g,
            mst_path_to_output_g,
            ft_input_g,
            ft_input_secret_key_g,
            mcb_sc_txs_com_start_g,
            merkle_path_to_sc_hash_g,
            ft_tree_path_g,
            sc_creation_commitment_g,
            scb_btr_tree_root_g,
            wcert_tree_root_g,
            sc_txs_com_hashes_g,
        };

        Ok(new_instance)
    }
}
