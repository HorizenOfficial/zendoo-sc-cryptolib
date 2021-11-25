use std::{borrow::Borrow, convert::TryInto};

use cctp_primitives::type_mapping::{FieldElement, FIELD_CAPACITY};
use r1cs_core::{ConstraintSystemAbstract, SynthesisError};
use r1cs_std::{
    boolean::Boolean,
    fields::FieldGadget,
    prelude::{AllocGadget, ConstantGadget, EqGadget},
    to_field_gadget_vec::ToConstraintFieldGadget,
    FromBitsGadget, FromGadget, ToBitsGadget,
};

use crate::{
    constants::constants::CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER, CswFtInputData, CswProverData,
    CswUtxoInputData, CswUtxoOutputData, FieldElementGadget, GingerMHTBinaryGadget,
    WithdrawalCertificateData, PHANTOM_SECRET_KEY_BITS, SIMULATED_FIELD_BYTE_SIZE,
    SIMULATED_SCALAR_FIELD_MODULUS_BITS,
};

#[derive(Clone)]
pub struct WithdrawalCertificateDataGadget {
    pub ledger_id_g: FieldElementGadget,
    pub epoch_id_g: FieldElementGadget,
    pub bt_list_hash_g: FieldElementGadget,
    pub quality_g: FieldElementGadget,
    pub mcb_sc_txs_com_g: FieldElementGadget,
    pub ft_min_fee_g: FieldElementGadget,
    pub btr_min_fee_g: FieldElementGadget,
    pub scb_new_mst_root_g: FieldElementGadget,
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
            bt_list_hash,
            quality,
            mcb_sc_txs_com,
            ft_min_fee,
            btr_min_fee,
            scb_new_mst_root,
        ) = match f() {
            Ok(certificate_data) => {
                let certificate_data = certificate_data.borrow().clone();
                (
                    Ok(certificate_data.ledger_id),
                    Ok(certificate_data.epoch_id),
                    Ok(certificate_data.bt_list_hash),
                    Ok(certificate_data.quality),
                    Ok(certificate_data.mcb_sc_txs_com),
                    Ok(certificate_data.ft_min_fee),
                    Ok(certificate_data.btr_min_fee),
                    Ok(certificate_data.scb_new_mst_root),
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

        let epoch_id_g = FieldElementGadget::alloc(cs.ns(|| "alloc epoch id"), || epoch_id)?;

        let bt_list_hash_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc bt list hash"), || bt_list_hash)?;

        let quality_g = FieldElementGadget::alloc(cs.ns(|| "alloc quality"), || quality)?;

        let mcb_sc_txs_com_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc mcb sc txs com"), || mcb_sc_txs_com)?;

        let ft_min_fee_g = FieldElementGadget::alloc(cs.ns(|| "alloc ft min fee"), || ft_min_fee)?;

        let btr_min_fee_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc btr min fee"), || btr_min_fee)?;

        let scb_new_mst_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc scb new mst root"), || scb_new_mst_root)?;

        let new_instance = Self {
            ledger_id_g,
            epoch_id_g,
            bt_list_hash_g,
            quality_g,
            mcb_sc_txs_com_g,
            ft_min_fee_g,
            btr_min_fee_g,
            scb_new_mst_root_g,
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

#[derive(PartialEq, Eq)]
pub struct CswUtxoOutputDataGadget {
    pub spending_pub_key_g: [Boolean; SIMULATED_FIELD_BYTE_SIZE * 8],
    pub amount_g: FieldElementGadget,
    pub nonce_g: FieldElementGadget,
    pub custom_hash_g: FieldElementGadget,
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
        let amount_g = FieldElementGadget::alloc(cs.ns(|| "alloc amount"), || amount)?;

        let nonce_g = FieldElementGadget::alloc(cs.ns(|| "alloc nonce"), || nonce)?;

        let custom_hash_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc custom hash"), || custom_hash)?;

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
        mut cs: CS,
        value: &CswUtxoOutputData,
    ) -> Self {
        let spending_pub_key_g = value
            .spending_pub_key
            .iter()
            .map(|&bit| Boolean::Constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let amount_g = FieldElementGadget::from_value(cs.ns(|| "alloc amount_g"), &value.amount);

        let nonce_g = FieldElementGadget::from_value(cs.ns(|| "alloc nonce_g"), &value.nonce);

        let custom_hash_g =
            FieldElementGadget::from_value(cs.ns(|| "alloc custom hash"), &value.custom_hash);

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
            custom_hash: self.custom_hash_g.get_value().unwrap(),
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
        let bits = self
            .spending_pub_key_g
            .to_bits(cs.ns(|| "spending_pub_key_g to bits"))
            .unwrap();

        let mut elements = bits
            .chunks(FIELD_CAPACITY)
            .enumerate()
            .map(|(index, chunk)| {
                FieldElementGadget::from_bits(cs.ns(|| format!("from bits le {}", index)), chunk)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        elements.push(self.amount_g.clone());
        elements.push(self.nonce_g.clone());
        elements.push(self.custom_hash_g.clone());

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
pub struct CswFtInputDataGadget {
    pub amount_g: FieldElementGadget,
    pub receiver_pub_key_g: [Boolean; SIMULATED_FIELD_BYTE_SIZE * 8],
    pub payback_addr_data_hash_g: FieldElementGadget,
    pub tx_hash_g: FieldElementGadget,
    pub out_idx_g: FieldElementGadget,
}

impl CswFtInputDataGadget {
    pub fn is_phantom<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Boolean, SynthesisError> {
        let phantom_ft_input_g = CswFtInputDataGadget::from_value(
            cs.ns(|| "alloc constant FT input phantom gadget"),
            &CswFtInputData::default(),
        );

        self.is_eq(cs.ns(|| "is FT output phantom"), &phantom_ft_input_g)
    }
}

impl AllocGadget<CswFtInputData, FieldElement> for CswFtInputDataGadget {
    fn alloc<F, T, CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CswFtInputData>,
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

        let amount_g = FieldElementGadget::alloc(cs.ns(|| "alloc amount"), || amount)?;

        let receiver_pub_key_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc receiver pub key"), || receiver_pub_key)?
                .try_into()
                .map_err(|_| {
                    SynthesisError::Other(format!(
                        "invalid size for public key, expected {} bits",
                        SIMULATED_FIELD_BYTE_SIZE * 8
                    ))
                })?;

        let payback_addr_data_hash_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc payback addr data hash"), || {
                payback_addr_data_hash
            })?;

        let tx_hash_g = FieldElementGadget::alloc(cs.ns(|| "alloc tx hash"), || tx_hash)?;

        let out_idx_g = FieldElementGadget::alloc(cs.ns(|| "alloc out idx"), || out_idx)?;

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
        T: Borrow<CswFtInputData>,
    {
        unimplemented!()
    }
}

impl ConstantGadget<CswFtInputData, FieldElement> for CswFtInputDataGadget {
    fn from_value<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        value: &CswFtInputData,
    ) -> Self {
        let amount_g = FieldElementGadget::from_value(cs.ns(|| "alloc amount"), &value.amount);
        let receiver_pub_key_g = value
            .receiver_pub_key
            .iter()
            .map(|&bit| Boolean::constant(bit))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let payback_addr_data_hash_g = FieldElementGadget::from_value(
            cs.ns(|| "alloc payback addr data hash"),
            &value.payback_addr_data_hash,
        );
        let tx_hash_g = FieldElementGadget::from_value(cs.ns(|| "alloc tx hash"), &value.tx_hash);
        let out_idx_g = FieldElementGadget::from_value(cs.ns(|| "alloc out idx"), &value.out_idx);

        Self {
            amount_g,
            receiver_pub_key_g,
            payback_addr_data_hash_g,
            tx_hash_g,
            out_idx_g,
        }
    }

    fn get_constant(&self) -> CswFtInputData {
        CswFtInputData {
            amount: self.amount_g.get_constant(),
            receiver_pub_key: self
                .receiver_pub_key_g
                .iter()
                .map(|byte| byte.get_value().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            payback_addr_data_hash: self.payback_addr_data_hash_g.get_constant(),
            tx_hash: self.tx_hash_g.get_constant(),
            out_idx: self.out_idx_g.get_constant(),
        }
    }
}

impl EqGadget<FieldElement> for CswFtInputDataGadget {
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

impl ToConstraintFieldGadget<FieldElement> for CswFtInputDataGadget {
    type FieldGadget = FieldElementGadget;

    fn to_field_gadget_elements<CS: ConstraintSystemAbstract<FieldElement>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<FieldElementGadget>, SynthesisError> {
        let mut elements = vec![self.amount_g.clone()];

        let bits = self
            .receiver_pub_key_g
            .to_bits(cs.ns(|| "receiver_pub_key_g to bits"))
            .unwrap();

        elements.extend(
            bits.chunks(FIELD_CAPACITY)
                .enumerate()
                .map(|(index, chunk)| {
                    FieldElementGadget::from_bits(
                        cs.ns(|| format!("from bits le {}", index)),
                        chunk,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
        );

        elements.push(self.payback_addr_data_hash_g.clone());
        elements.push(self.tx_hash_g.clone());
        elements.push(self.out_idx_g.clone());

        Ok(elements)
    }
}

pub struct CswProverDataGadget {
    // public inputs [START]
    pub genesis_constant_g: FieldElementGadget,
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
    pub ft_input_g: CswFtInputDataGadget,
    pub ft_input_secret_key_g: [Boolean; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
    pub mcb_sc_txs_com_start_g: FieldElementGadget,
    pub merkle_path_to_sc_hash_g: GingerMHTBinaryGadget,
    pub ft_tree_path_g: GingerMHTBinaryGadget,
    pub scb_btr_tree_root_g: FieldElementGadget,
    pub wcert_tree_root_g: FieldElementGadget,
    pub sc_txs_com_hashes_g: Vec<FieldElementGadget>, // witnesses [END]
}

impl FromGadget<CswProverData, FieldElement> for CswProverDataGadget {
    fn from<CS: ConstraintSystemAbstract<FieldElement>>(
        data: CswProverData,
        mut cs: CS,
    ) -> Result<Self, SynthesisError> {
        let genesis_constant_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc genesis constant"), || {
                Ok(data.genesis_constant)
            })?;

        let mcb_sc_txs_com_end_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc mcb sc txs com end"), || {
                Ok(data.mcb_sc_txs_com_end)
            })?;

        let sc_last_wcert_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc sc last wcert hash"), || {
                Ok(data.sc_last_wcert_hash)
            })?;

        let amount_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc amount"), || Ok(data.amount))?;

        let nullifier_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc nullifier"), || Ok(data.nullifier))?;

        let receiver_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc receiver"), || Ok(data.receiver))?;

        let last_wcert_g =
            WithdrawalCertificateDataGadget::alloc(cs.ns(|| "alloc last wcert"), || {
                Ok(data.last_wcert.clone())
            })?;

        let input_g =
            CswUtxoInputDataGadget::alloc(cs.ns(|| "alloc input"), || Ok(data.input.clone()))?;

        let mst_path_to_output_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc mst path to output"), || {
                Ok(data.mst_path_to_output.clone())
            })?;

        let ft_input_g =
            CswFtInputDataGadget::alloc(cs.ns(|| "alloc ft input"), || Ok(data.ft_input.clone()))?;

        let ft_input_secret_key_g =
            Vec::<Boolean>::alloc(cs.ns(|| "alloc ft input secret key"), || {
                Ok(data.ft_input_secret_key)
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
                Ok(data.mcb_sc_txs_com_start)
            })?;

        let merkle_path_to_sc_hash_g =
            GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc merkle path to sc hash"), || {
                Ok(&data.merkle_path_to_sc_hash)
            })?;

        let ft_tree_path_g = GingerMHTBinaryGadget::alloc(cs.ns(|| "alloc ft tree path"), || {
            Ok(data.ft_tree_path.clone())
        })?;

        let scb_btr_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc scb btr tree root"), || {
                Ok(data.scb_btr_tree_root)
            })?;

        let wcert_tree_root_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc wcert tree root"), || {
                Ok(data.wcert_tree_root)
            })?;

        assert!(data.sc_txs_com_hashes.len() == CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER);
        let mut sc_txs_com_hashes_g = Vec::with_capacity(CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER);

        for index in 0..data.sc_txs_com_hashes.len() {
            let sc_txs_com_hash_g = FieldElementGadget::alloc(
                cs.ns(|| format!("alloc sc txs com hash {}", index)),
                || Ok(data.sc_txs_com_hashes[index]),
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
            scb_btr_tree_root_g,
            wcert_tree_root_g,
            sc_txs_com_hashes_g,
        };

        Ok(new_instance)
    }
}
