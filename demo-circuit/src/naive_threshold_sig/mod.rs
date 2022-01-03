use algebra::{Field, PrimeField, ProjectiveCurve, ToBits};

use primitives::{
    crh::FieldBasedHash,
    signature::schnorr::field_based_schnorr::{FieldBasedSchnorrPk, FieldBasedSchnorrSignature},
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
};

use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};

use crate::{constants::NaiveThresholdSigParams, type_mapping::*};
use cctp_primitives::utils::commitment_tree::DataAccumulator;

use lazy_static::*;

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
pub struct NaiveTresholdSignature {
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
    custom_fields: Option<Vec<FieldElement>>,

    // Public inputs
    pks_threshold_hash: Option<FieldElement>,
    cert_data_hash: Option<FieldElement>,

    //Other
    max_pks: usize,
}

impl NaiveTresholdSignature {
    pub fn get_instance_for_setup(max_pks: usize, custom_fields_len: usize) -> Self {
        //Istantiating supported number of pks and sigs
        let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;

        // Create parameters for our circuit
        NaiveTresholdSignature {
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
            pks_threshold_hash: None,
            cert_data_hash: None,
            max_pks,
            custom_fields: if custom_fields_len == 0 {
                None
            } else {
                Some(vec![FieldElement::zero(); custom_fields_len])
            },
        }
    }

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
        valid_signatures: u64,
        custom_fields: Option<Vec<FieldElement>>,
    ) -> Self {
        //Convert needed variables into field elements
        let fees_field_elements = {
            let fes = DataAccumulator::init()
                .update(btr_fee)
                .unwrap()
                .update(ft_min_amount)
                .unwrap()
                .get_field_elements()
                .unwrap();
            assert_eq!(fes.len(), 1);
            fes[0]
        };
        let quality = FieldElement::from(valid_signatures);

        //Compute pks_threshold_hash
        let mut h = FieldHash::init_constant_length(pks.len(), None);
        pks.iter().for_each(|pk| {
            h.update(pk.0.into_affine().x);
        });
        let pks_hash = h.finalize().unwrap();
        let pks_threshold_hash = FieldHash::init_constant_length(2, None)
            .update(pks_hash)
            .update(threshold)
            .finalize()
            .unwrap();

        //Compute cert_data_hash
        let cert_data_hash = {
            // Compute wcert_sysdata_hash
            let wcert_sysdata_hash = FieldHash::init_constant_length(6, None)
                .update(sc_id)
                .update(epoch_number)
                .update(mr_bt)
                .update(quality)
                .update(end_cumulative_sc_tx_comm_tree_root)
                .update(fees_field_elements)
                .finalize()
                .unwrap();

            // Compute custom_fields hash taking into account the presence, or not, of custom_fields
            let to_hash = if let Some(custom_fields) = custom_fields.clone() {
                let mut h = FieldHash::init_constant_length(custom_fields.len(), None);
                custom_fields.into_iter().for_each(|custom_field| {
                    h.update(custom_field);
                });
                let custom_fields_hash = h.finalize().unwrap();
                vec![custom_fields_hash, wcert_sysdata_hash]
            } else {
                vec![wcert_sysdata_hash]
            };

            let mut h = FieldHash::init_constant_length(to_hash.len(), None);
            to_hash.into_iter().for_each(|custom_field| {
                h.update(custom_field);
            });
            h.finalize().unwrap()
        };

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
            pks_threshold_hash: Some(pks_threshold_hash),
            cert_data_hash: Some(cert_data_hash),
            custom_fields,
        }
    }
}

impl ConstraintSynthesizer<FieldElement> for NaiveTresholdSignature {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
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

        // Alloc custom_fields and enforce their hash, if they are present
        let custom_fields_hash_g = if let Some(custom_fields) = self.custom_fields.clone() {
            let custom_fields_g = Vec::<FrGadget>::alloc(cs.ns(|| "alloc custom fields"), || {
                Ok(custom_fields.as_slice())
            })?;
            let custom_fields_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H(custom_fields)"),
                custom_fields_g.as_slice(),
            )?;
            Some(custom_fields_hash_g)
        } else {
            None
        };

        // Alloc btr_fee and ft_min_amount
        let btr_fee_g = UInt64::alloc(cs.ns(|| "alloc btr_fee"), self.btr_fee)?;

        let ft_min_amount_g = UInt64::alloc(cs.ns(|| "alloc ft_min_amount"), self.ft_min_amount)?;

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

        let message_g = {
            let mut preimage = vec![
                sc_id_g.clone(),
                epoch_number_g.clone(),
                mr_bt_g.clone(),
                end_cumulative_sc_tx_comm_tree_root_g.clone(),
                fees_g.clone(),
            ];
            if custom_fields_hash_g.is_some() {
                preimage.push(custom_fields_hash_g.clone().unwrap())
            }; // Add custom_fields_hash if present
            PoseidonHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount, [H(custom_fields)])"),
                preimage.as_slice(),
            )
        }?;

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

            let preimage = if custom_fields_hash_g.is_some() {
                vec![custom_fields_hash_g.unwrap(), wcert_sysdata_hash_g]
            } else {
                vec![wcert_sysdata_hash_g]
            };

            PoseidonHashGadget::enforce_hash_constant_length(
                cs.ns(|| "H([custom_fields], cert_data_hash)"),
                preimage.as_slice(),
            )
        }?;

        //Check pks_threshold_hash (constant)
        let expected_pks_threshold_hash_g =
            FrGadget::alloc_input(cs.ns(|| "alloc constant as input"), || {
                self.pks_threshold_hash
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        pks_threshold_hash_g.enforce_equal(
            cs.ns(|| "pks_threshold_hash: expected == actual"),
            &expected_pks_threshold_hash_g,
        )?;

        // Check cert_data_hash
        let expected_cert_data_hash_g =
            FrGadget::alloc_input(cs.ns(|| "alloc input cert_data_hash_g"), || {
                self.cert_data_hash.ok_or(SynthesisError::AssignmentMissing)
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

#[cfg(test)]
mod test {
    use crate::{SUPPORTED_SEGMENT_SIZE, MAX_SEGMENT_SIZE};

    use super::*;
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
    use r1cs_core::debug_circuit;
    use rand::{rngs::OsRng, Rng};

    use serial_test::*;

    type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<FieldElement, G2Projective, FieldHash>;

    fn get_test_circuit_instance(
        max_pks: usize,
        num_custom_fields: usize,
        valid_sigs: usize,
        threshold: usize,
        wrong_pks_threshold_hash: bool,
        wrong_cert_data_hash: bool,
    ) -> NaiveTresholdSignature {
        //Istantiate rng
        let mut rng = OsRng::default();
        let mut h =
            FieldHash::init_constant_length(5 + if num_custom_fields > 0 { 1 } else { 0 }, None);

        //Generate message to sign
        let sc_id: FieldElement = rng.gen();
        let epoch_number: FieldElement = rng.gen();
        let mr_bt: FieldElement = rng.gen();
        let end_cumulative_sc_tx_comm_tree_root: FieldElement = rng.gen();
        let btr_fee: u64 = rng.gen();
        let ft_min_amount: u64 = rng.gen();
        let custom_fields = if num_custom_fields > 0 {
            Some(
                (0..num_custom_fields)
                    .map(|_| rng.gen())
                    .collect::<Vec<FieldElement>>(),
            )
        } else {
            None
        };
        let custom_fields_hash = if num_custom_fields > 0 {
            let mut h = FieldHash::init_constant_length(num_custom_fields, None);
            custom_fields
                .clone()
                .unwrap()
                .into_iter()
                .for_each(|custom_field| {
                    h.update(custom_field);
                });
            Some(h.finalize().unwrap())
        } else {
            None
        };

        let fees_field_elements = {
            let fes = DataAccumulator::init()
                .update(btr_fee)
                .unwrap()
                .update(ft_min_amount)
                .unwrap()
                .get_field_elements()
                .unwrap();
            assert_eq!(fes.len(), 1);
            fes[0]
        };
        h.update(sc_id)
            .update(epoch_number)
            .update(mr_bt)
            .update(end_cumulative_sc_tx_comm_tree_root)
            .update(fees_field_elements);

        if custom_fields_hash.is_some() {
            h.update(custom_fields_hash.unwrap());
        }

        let message = h.finalize().unwrap();

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

        //Return concrete circuit instance
        let mut c = NaiveTresholdSignature::new(
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
            valid_sigs as u64,
            custom_fields,
        );

        if wrong_pks_threshold_hash {
            c.pks_threshold_hash = Some(rng.gen());
        }
        if wrong_cert_data_hash {
            c.cert_data_hash = Some(rng.gen());
        }

        c
    }
    fn generate_test_proof(
        max_pks: usize,
        valid_sigs: usize,
        threshold: usize,
        num_custom_fields: usize,
        wrong_pks_threshold_hash: bool,
        wrong_cert_data_hash: bool,
        index_pk: CoboundaryMarlinProverKey,
        zk: bool,
    ) -> Result<(CoboundaryMarlinProof, Vec<FieldElement>), Error> {
        // Get concrete and correct circuit instance. We want to test error cases in verification only.
        let c = get_test_circuit_instance(
            max_pks,
            num_custom_fields,
            valid_sigs,
            threshold,
            false,
            false,
        );

        //Return proof and public inputs if success
        let rng = &mut OsRng;
        let ck_g1 = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();
        match CoboundaryMarlin::prove(
            &index_pk,
            &ck_g1,
            c.clone(),
            zk,
            if zk { Some(rng) } else { None },
        ) {
            Ok(proof) => {
                let public_inputs = vec![
                    if !wrong_pks_threshold_hash {
                        c.pks_threshold_hash.unwrap()
                    } else {
                        rng.gen()
                    },
                    if !wrong_cert_data_hash {
                        c.cert_data_hash.unwrap()
                    } else {
                        rng.gen()
                    },
                ];
                Ok((MarlinProof(proof), public_inputs))
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    #[serial]
    #[test]
    fn test_prove_verify_naive_threshold_circuit() {
        let n = 6;
        let zk = false;

        let _ = load_g1_committer_key(MAX_SEGMENT_SIZE - 1);
        let ck = get_g1_committer_key(Some(SUPPORTED_SEGMENT_SIZE - 1)).unwrap();
        let circ = NaiveTresholdSignature::get_instance_for_setup(n, 1);

        let params = CoboundaryMarlin::index(&ck, circ).unwrap();

        //Generate proof with correct witnesses and v > t
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, 1, false, false, params.0.clone(), zk).unwrap();
        assert!(CoboundaryMarlin::verify(
            &params.1,
            &ck,
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());

        //Generate proof with bad pks_threshold_hash
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, 1, true, false, params.0.clone(), zk).unwrap();
        assert!(!CoboundaryMarlin::verify(
            &params.1,
            &ck,
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());

        //Generate proof with bad cert_data_hash
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, 1, false, true, params.0.clone(), zk).unwrap();
        assert!(!CoboundaryMarlin::verify(
            &params.1,
            &ck,
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());
    }

    #[serial]
    #[test]
    fn test_naive_threshold_circuit_is_satisfied() {
        let mut rng = OsRng::default();
        let n = 6;
        let num_custom_fields = rng.gen_range(1..10);

        for i in vec![0, num_custom_fields] {
            println!("Test success case with v > t");
            let v = rng.gen_range(1..n);
            let t = rng.gen_range(0..v);
            let c = get_test_circuit_instance(n, i, v, t, false, false);
            assert!(debug_circuit(c).unwrap().is_none());
            println!("Ok !");

            println!("Test success case with v == t");
            let v = rng.gen_range(1..n);
            let t = v;
            let c = get_test_circuit_instance(n, i, v, t, false, false);
            assert!(debug_circuit(c).unwrap().is_none());
            println!("Ok !");

            println!("Test negative case with v < t");
            let t = rng.gen_range(1..n);
            let v = rng.gen_range(0..t);
            let c = get_test_circuit_instance(n, i, v, t, false, false);
            assert!(debug_circuit(c).unwrap().is_some());
            println!("Ok !");

            println!("Test case v = t = 0");
            let c = get_test_circuit_instance(n, i, 0, 0, false, false);
            assert!(debug_circuit(c).unwrap().is_none());
            println!("Ok !");

            println!("Test case v = t = n");
            let c = get_test_circuit_instance(n, i, n, n, false, false);
            assert!(debug_circuit(c).unwrap().is_none());
            println!("Ok !");

            println!("Test case v = n and t = 0");
            let c = get_test_circuit_instance(n, i, n, 0, false, false);
            assert!(debug_circuit(c).unwrap().is_none());
            println!("Ok !");

            println!("Test negative case v = 0 and t = n");
            let c = get_test_circuit_instance(n, i, 0, n, false, false);
            assert!(debug_circuit(c).unwrap().is_some());
            println!("Ok !");

            println!("Test negative case wrong pks_threshold_hash");
            let v = rng.gen_range(1..n);
            let t = rng.gen_range(0..v);
            let c = get_test_circuit_instance(n, i, v, t, true, false);
            assert!(debug_circuit(c).unwrap().is_some());
            println!("Ok !");

            println!("Test negative case wrong wcert_sysdata_hash");
            let v = rng.gen_range(1..n);
            let t = rng.gen_range(0..v);
            let c = get_test_circuit_instance(n, i, v, t, false, true);
            assert!(debug_circuit(c).unwrap().is_some());
            println!("Ok !");
        }
    }
}
