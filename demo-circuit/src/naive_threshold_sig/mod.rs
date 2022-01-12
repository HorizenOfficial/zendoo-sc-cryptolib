#[cfg(test)]
pub mod tests;

use algebra::{Field, PrimeField, ToBits};

use primitives::signature::schnorr::field_based_schnorr::{
    FieldBasedSchnorrPk, FieldBasedSchnorrSignature,
};
use r1cs_crypto::{
    crh::{FieldBasedHashGadget, TweedleFrPoseidonHashGadget as PoseidonHashGadget},
    signature::{
        schnorr::field_based_schnorr::{
            FieldBasedSchnorrPkGadget, FieldBasedSchnorrSigGadget,
            FieldBasedSchnorrSigVerificationGadget,
        },
        FieldBasedSigGadget,
    },
};

use r1cs_std::{
    alloc::AllocGadget,
    bits::{boolean::Boolean, uint64::UInt64, FromBitsGadget},
    eq::EqGadget,
    fields::{fp::FpGadget, FieldGadget},
    instantiated::tweedle::TweedleDumGadget as CurveGadget,
    Assignment,
};

use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use crate::{constants::NaiveThresholdSigParams, type_mapping::*};

use lazy_static::*;
use std::marker::PhantomData;

lazy_static! {
    pub static ref NULL_CONST: NaiveThresholdSigParams = NaiveThresholdSigParams::new();
}

//Sig types
pub(crate) type SchnorrSigGadget = FieldBasedSchnorrSigGadget<FieldElement, G2Projective>;
pub(crate) type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    FieldElement,
    G2Projective,
    CurveGadget,
    FieldHash,
    PoseidonHashGadget,
>;
pub(crate) type SchnorrPkGadget =
    FieldBasedSchnorrPkGadget<FieldElement, G2Projective, CurveGadget>;

//Field types
pub(crate) type FrGadget = FpGadget<FieldElement>;

#[derive(Clone)]
pub struct NaiveTresholdSignature<F: PrimeField> {
    //Witnesses
    pks: Vec<Option<FieldBasedSchnorrPk<G2Projective>>>, //pk_n = g^sk_n
    //sig_n = sign(sk_n, H(epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount))
    sigs: Vec<Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>>,
    threshold: Option<FieldElement>,
    b: Vec<Option<bool>>,
    sc_id: Option<FieldElement>,
    epoch_number: Option<FieldElement>,
    end_cumulative_sc_tx_comm_tree_root: Option<FieldElement>,
    mr_bt: Option<FieldElement>,
    ft_min_amount: Option<u64>,
    btr_fee: Option<u64>,

    //Other
    max_pks: usize,
    _field: PhantomData<F>,
}

impl<F: PrimeField> NaiveTresholdSignature<F> {
    pub fn new(
        pks: Vec<FieldBasedSchnorrPk<G2Projective>>,
        sigs: Vec<Option<FieldBasedSchnorrSignature<FieldElement, G2Projective>>>,
        threshold: FieldElement,
        b: FieldElement,
        sc_id: FieldElement,
        epoch_number: FieldElement,
        end_cumulative_sc_tx_comm_tree_root: FieldElement,
        mr_bt: FieldElement,
        ft_min_amount: u64,
        btr_fee: u64,
        max_pks: usize,
    ) -> Self {
        //Convert b to the needed bool vector
        let b_bool = {
            let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
            let b_bits = b.write_bits();
            let to_skip = FieldElement::size_in_bits() - (log_max_pks + 1);
            b_bits[to_skip..]
                .to_vec()
                .iter()
                .map(|&b| Some(b))
                .collect::<Vec<_>>()
        };
        Self {
            pks: pks.iter().map(|&pk| Some(pk)).collect::<Vec<_>>(),
            sigs,
            threshold: Some(threshold),
            b: b_bool,
            epoch_number: Some(epoch_number),
            sc_id: Some(sc_id),
            end_cumulative_sc_tx_comm_tree_root: Some(end_cumulative_sc_tx_comm_tree_root),
            mr_bt: Some(mr_bt),
            ft_min_amount: Some(ft_min_amount),
            btr_fee: Some(btr_fee),
            max_pks,
            _field: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<FieldElement> for NaiveTresholdSignature<F> {
    fn generate_constraints<CS: ConstraintSystem<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        //Internal checks
        let log_max_pks = (self.max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
        assert_eq!(self.max_pks, self.pks.len());
        assert_eq!(self.max_pks, self.sigs.len());
        assert_eq!(log_max_pks + 1, self.b.len());

        //Check pks are consistent with self.hash_commitment

        //Allocate public keys as witnesses
        let mut pks_g = Vec::with_capacity(self.max_pks);

        for (i, pk) in self.pks.iter().enumerate() {
            // It's safe to not perform any check when allocating the pks,
            // considering that the pks are hashed, so they should be public
            // at some point, therefore verifiable by everyone.
            let pk_g =
                SchnorrPkGadget::alloc_without_check(cs.ns(|| format!("alloc_pk_{}", i)), || {
                    pk.ok_or(SynthesisError::AssignmentMissing)
                })?;
            pks_g.push(pk_g);
        }

        //Enforce pks_threshold_hash
        let mut pks_threshold_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
            cs.ns(|| "hash public keys"),
            pks_g
                .iter()
                .map(|pk| pk.pk.x.clone())
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

        //Allocate threshold as witness
        let t_g = FrGadget::alloc(cs.ns(|| "alloc threshold"), || {
            self.threshold.ok_or(SynthesisError::AssignmentMissing)
        })?;

        pks_threshold_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(H(pks), threshold)"),
            &[pks_threshold_hash_g, t_g.clone()],
        )?;

        //Check signatures

        //Reconstruct message as H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)

        // Alloc field elements
        let sc_id_g = FrGadget::alloc(cs.ns(|| "alloc sc id"), || {
            self.sc_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let epoch_number_g = FrGadget::alloc(cs.ns(|| "alloc epoch number"), || {
            self.epoch_number.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mr_bt_g = FrGadget::alloc(cs.ns(|| "alloc mr_bt"), || {
            self.mr_bt.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let end_cumulative_sc_tx_comm_tree_root_g = FrGadget::alloc(
            cs.ns(|| "alloc end_cumulative_sc_tx_comm_tree_root"),
            || {
                self.end_cumulative_sc_tx_comm_tree_root
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Alloc btr_fee and ft_min_amount
        let btr_fee_g = UInt64::alloc(cs.ns(|| "alloc btr_fee"), self.btr_fee)?;

        let ft_min_amount_g =
            UInt64::alloc(cs.ns(|| "alloc ft_min_amount"), self.ft_min_amount)?;

        // Pack them into a single field element
        let fees_bits = {
            let mut bits = btr_fee_g.to_bits_le();
            bits.reverse();

            let mut ft_min_amount_bits = ft_min_amount_g.to_bits_le();
            ft_min_amount_bits.reverse();

            bits.append(&mut ft_min_amount_bits);
            bits
        };

        let fees_g = FrGadget::from_bits(
            cs.ns(|| "pack(btr_fee, ft_min_amount)"),
            fees_bits.as_slice(),
        )?;

        let message_g = PoseidonHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)"),
            &[sc_id_g.clone(), epoch_number_g.clone(), mr_bt_g.clone(), end_cumulative_sc_tx_comm_tree_root_g.clone(), fees_g.clone()],
        )?;

        let mut sigs_g = Vec::with_capacity(self.max_pks);

        //Allocate signatures as witnesses
        for (i, sig) in self.sigs.iter().enumerate() {
            let sig_g = SchnorrSigGadget::alloc(cs.ns(|| format!("alloc_sig_{}", i)), || {
                sig.ok_or(SynthesisError::AssignmentMissing)
            })?;
            sigs_g.push(sig_g);
        }

        let mut verdicts = Vec::with_capacity(self.max_pks);

        //Check signatures verification verdict on message
        for (i, (pk_g, sig_g)) in pks_g.iter().zip(sigs_g.iter()).enumerate() {
            let v = SchnorrVrfySigGadget::enforce_signature_verdict(
                cs.ns(|| format!("check_sig_verdict_{}", i)),
                pk_g,
                sig_g,
                message_g.clone(),
            )?;
            verdicts.push(v);
        }

        //Count valid signatures
        let mut valid_signatures = FrGadget::zero(cs.ns(|| "alloc valid signatures count"))?;
        for (i, v) in verdicts.iter().enumerate() {
            valid_signatures = valid_signatures.conditionally_add_constant(
                cs.ns(|| format!("add_verdict_{}", i)),
                v,
                FieldElement::one(),
            )?;
        }

        //Enforce cert_data_hash
        let cert_data_hash_g = {
            let wcert_sysdata_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H(sc_id, epoch_number, bt_root, valid_sigs, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)"),
                &[sc_id_g, epoch_number_g, mr_bt_g, valid_signatures.clone(), end_cumulative_sc_tx_comm_tree_root_g, fees_g],
            )?;
            PoseidonHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H(proof_data (not present), cert_data_hash)"),
                &[wcert_sysdata_hash_g],
            )
        }?;

        //Check pks_threshold_hash (constant)
        let expected_pks_threshold_hash_g =
            FrGadget::alloc_input(cs.ns(|| "alloc constant as input"), || {
                let pks_threshold_hash_val = pks_threshold_hash_g.get_value().get()?;
                Ok(pks_threshold_hash_val)
            })?;

        pks_threshold_hash_g.enforce_equal(
            cs.ns(|| "pks_threshold_hash: expected == actual"),
            &expected_pks_threshold_hash_g,
        )?;

        // Check cert_data_hash
        let expected_cert_data_hash_g =
            FrGadget::alloc_input(cs.ns(|| "alloc input cert_data_hash_g"), || {
                let cert_data_hash_val = cert_data_hash_g.get_value().get()?;
                Ok(cert_data_hash_val)
            })?;

        cert_data_hash_g.enforce_equal(
            cs.ns(|| "cert_data_hash: expected == actual"),
            &expected_cert_data_hash_g,
        )?;

        //Alloc the b's as witnesses
        let mut bs_g = Vec::with_capacity(log_max_pks + 1);
        for (i, b) in self.b.iter().enumerate() {
            let b_g = Boolean::alloc(cs.ns(|| format!("alloc b_{}", i)), || {
                b.ok_or(SynthesisError::AssignmentMissing)
            })?;
            bs_g.push(b_g);
        }

        //Pack the b's into a field element
        let b_field = FrGadget::from_bits(
            cs.ns(|| "pack the b's into a field element"),
            bs_g.as_slice(),
        )?;

        //Enforce threshold
        valid_signatures
            .sub(cs.ns(|| "valid_signatures - threshold"), &t_g)?
            .enforce_equal(cs.ns(|| "threshold check"), &b_field)?;

        Ok(())
    }
}

#[allow(dead_code)]
pub fn get_instance_for_setup(max_pks: usize) -> NaiveTresholdSignature<FieldElement> {
    //Istantiating supported number of pks and sigs
    let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;

    // Create parameters for our circuit
    NaiveTresholdSignature::<FieldElement> {
        pks: vec![None; max_pks],
        sigs: vec![None; max_pks],
        threshold: None,
        b: vec![None; log_max_pks + 1],
        sc_id: None,
        epoch_number: None,
        end_cumulative_sc_tx_comm_tree_root: None,
        mr_bt: None,
        ft_min_amount: None,
        btr_fee: None,
        max_pks,
        _field: PhantomData,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::ProjectiveCurve;
    use cctp_primitives::{
        proving_system::init::{get_g1_committer_key, load_g1_committer_key},
        utils::commitment_tree::DataAccumulator,
    };
    use primitives::{
        crh::FieldBasedHash,
        signature::{
            schnorr::field_based_schnorr::FieldBasedSchnorrSignatureScheme,
            FieldBasedSignatureScheme,
        },
    };
    use rand::{rngs::OsRng, Rng};

    type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<FieldElement, G2Projective, FieldHash>;

    fn generate_test_proof(
        max_pks: usize,
        valid_sigs: usize,
        threshold: usize,
        wrong_pks_threshold_hash: bool,
        wrong_cert_data_hash: bool,
        index_pk: CoboundaryMarlinProverKey,
        zk: bool,
    ) -> Result<(CoboundaryMarlinProof, Vec<FieldElement>), Error> {
        //Istantiate rng
        let mut rng = OsRng::default();
        let mut h = FieldHash::init_constant_length(5, None);

        //Generate message to sign
        let sc_id: FieldElement = rng.gen();
        let epoch_number: FieldElement = rng.gen();
        let mr_bt: FieldElement = rng.gen();
        let end_cumulative_sc_tx_comm_tree_root: FieldElement = rng.gen();
        let btr_fee: u64 = rng.gen();
        let ft_min_amount: u64 = rng.gen();
        let fees_field_elements = {
            let fes = DataAccumulator::init()
                .update(btr_fee)?
                .update(ft_min_amount)?
                .get_field_elements()?;
            assert_eq!(fes.len(), 1);
            fes[0]
        };
        let message = h
            .update(sc_id)
            .update(epoch_number)
            .update(mr_bt)
            .update(end_cumulative_sc_tx_comm_tree_root)
            .update(fees_field_elements)
            .finalize()
            .unwrap();

        //Generate another random message used to simulate a non-valid signature
        let invalid_message: FieldElement = rng.gen();

        let mut pks = vec![];
        let mut sigs = vec![];

        for _ in 0..valid_sigs {
            let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
            let sig = SchnorrSigScheme::sign(&mut rng, &pk, &sk, message).unwrap();
            pks.push(pk);
            sigs.push(Some(sig));
        }

        for _ in 0..(max_pks - valid_sigs) {
            //Sample a random boolean and decide if generating a non valid signature or a null one
            let generate_null: bool = rng.gen();
            let (pk, sig) = if generate_null {
                (NULL_CONST.null_pk, NULL_CONST.null_sig)
            } else {
                let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
                let sig = SchnorrSigScheme::sign(&mut rng, &pk, &sk, invalid_message).unwrap();
                (pk, sig)
            };
            pks.push(pk);
            sigs.push(Some(sig));
        }

        //Generate b
        let t_field = FieldElement::from_repr(FieldBigInteger::from(threshold as u64));
        let valid_field = FieldElement::from_repr(FieldBigInteger::from(valid_sigs as u64));
        let b_field = valid_field - &t_field;

        //Compute pks_threshold_hash
        let mut h = FieldHash::init_constant_length(pks.len(), None);
        pks.iter().for_each(|pk| {
            h.update(pk.0.into_affine().x);
        });
        let pks_hash = h.finalize().unwrap();
        let pks_threshold_hash = if !wrong_pks_threshold_hash {
            FieldHash::init_constant_length(2, None)
                .update(pks_hash)
                .update(t_field)
                .finalize()
                .unwrap()
        } else {
            rng.gen()
        };

        //Compute cert_data_hash
        let cert_data_hash = if !wrong_cert_data_hash {
            let wcert_sysdata_hash = FieldHash::init_constant_length(6, None)
                .update(sc_id)
                .update(epoch_number)
                .update(mr_bt)
                .update(valid_field)
                .update(end_cumulative_sc_tx_comm_tree_root)
                .update(fees_field_elements)
                .finalize()
                .unwrap();
            FieldHash::init_constant_length(1, None)
                .update(wcert_sysdata_hash)
                .finalize()
                .unwrap()
        } else {
            rng.gen()
        };

        //Create proof for our circuit
        let c = NaiveTresholdSignature::<FieldElement>::new(
            pks,
            sigs,
            t_field,
            b_field,
            sc_id,
            epoch_number,
            end_cumulative_sc_tx_comm_tree_root,
            mr_bt,
            ft_min_amount,
            btr_fee,
            max_pks,
        );

        //Return proof and public inputs if success
        let rng = &mut OsRng;
        let ck_g1 = get_g1_committer_key().unwrap();
        match CoboundaryMarlin::prove(
            &index_pk,
            ck_g1.as_ref().unwrap(),
            c,
            zk,
            if zk { Some(rng) } else { None },
        ) {
            Ok(proof) => {
                let public_inputs = vec![pks_threshold_hash, cert_data_hash];
                Ok((MarlinProof(proof), public_inputs))
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    #[test]
    fn test_naive_threshold_circuit() {
        let n = 6;
        let zk = false;

        load_g1_committer_key(1 << 17, 1 << 15).unwrap();
        let ck = get_g1_committer_key().unwrap();
        let circ = get_instance_for_setup(n);

        let params = CoboundaryMarlin::index(ck.as_ref().unwrap(), circ).unwrap();

        //Generate proof with correct witnesses and v > t
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, false, false, params.0.clone(), zk).unwrap();
        assert!(CoboundaryMarlin::verify(
            &params.1,
            ck.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());

        //Generate proof with insufficient valid signatures
        //TODO: Restore after fixing https://github.com/HorizenLabs/marlin/issues/12
        /*let (proof, public_inputs) =
            generate_test_proof(n, 4, 5, false, false, params.0.clone(), zk).unwrap();
        assert!(!CoboundaryMarlin::verify(&params.1, ck.as_ref().unwrap(),public_inputs.as_slice(), &proof).unwrap());
        */

        //Generate proof with bad pks_threshold_hash
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, true, false, params.0.clone(), zk).unwrap();
        assert!(!CoboundaryMarlin::verify(
            &params.1,
            ck.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());

        //Generate proof with bad cert_data_hash
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, false, true, params.0.clone(), zk).unwrap();
        assert!(!CoboundaryMarlin::verify(
            &params.1,
            ck.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());
    }
}
