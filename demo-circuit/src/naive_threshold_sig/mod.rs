#[cfg(test)]
pub mod tests;

use algebra::{fields::mnt4753::Fr as MNT4Fr, curves::mnt6753::G1Projective as MNT6G1Projective, Field, PrimeField, ToBits};
use primitives::{
    signature::schnorr::field_based_schnorr::FieldBasedSchnorrSignature,
    crh::MNT4PoseidonHash,
};
use r1cs_crypto::{
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSigGadget, FieldBasedSchnorrSigVerificationGadget},
        FieldBasedSigGadget,
    },
    crh::{MNT4PoseidonHashGadget, FieldBasedHashGadget},
};

use r1cs_std::{
    groups::curves::short_weierstrass::mnt::mnt6::mnt6753::MNT6G1Gadget,
    fields::{
        fp::FpGadget, FieldGadget,
    },
    alloc::AllocGadget,
    bits::{
        boolean::Boolean, FromBitsGadget,
    },
    eq::EqGadget,
};

use r1cs_core::{ConstraintSystem, ConstraintSynthesizer, SynthesisError};

use crate::constants::NaiveThresholdSigParams;

use std::marker::PhantomData;
use rand::rngs::OsRng;
use lazy_static::*;

lazy_static! {
    pub static ref NULL_CONST: NaiveThresholdSigParams = { NaiveThresholdSigParams::new() };
}

//Sig types
type SchnorrSigGadget = FieldBasedSchnorrSigGadget<MNT4Fr>;
type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    MNT4Fr, MNT6G1Projective, MNT6G1Gadget, MNT4PoseidonHash, MNT4PoseidonHashGadget
>;

//Field types
type MNT4FrGadget = FpGadget<MNT4Fr>;

pub struct NaiveTresholdSignature<F: PrimeField>{

    //Witnesses
    pks:                   Vec<Option<MNT6G1Projective>>,
    sigs:                  Vec<Option<FieldBasedSchnorrSignature<MNT4Fr>>>,
    threshold:             Option<MNT4Fr>,
    b:                     Vec<Option<bool>>,

    //Public inputs
    message:               Option<MNT4Fr>,
    hash_commitment:       Option<MNT4Fr>, //H(H(pks), threshold)

    //Other
    n:                     usize,
    _field:                PhantomData<F>,
}

impl<F: PrimeField>NaiveTresholdSignature<F> {
    pub fn new(
        mut pks:               Vec<MNT6G1Projective>,
        mut sigs:              Vec<FieldBasedSchnorrSignature<MNT4Fr>>,
        threshold:             MNT4Fr,
        b:                     MNT4Fr,
        message:               MNT4Fr,
        hash_commitment:       MNT4Fr,
        n:                     usize,
    ) -> Self {

        //Add null pks and null sigs as padding to reach size n, if needed
        for _ in pks.len()..n {
            pks.push(NULL_CONST.null_pk);
        }

        for _ in sigs.len()..n {
            sigs.push(NULL_CONST.null_sig);
        }

        //Convert b to the needed bool vector
        let b_bool = {
            let b_len = (n.next_power_of_two() as u64).trailing_zeros() as usize;
            let b_bits = b.write_bits();
            let to_skip = MNT4Fr::size_in_bits() - (b_len + 1);
            b_bits[to_skip..].to_vec().iter().map(|&b| Some(b)).collect::<Vec<_>>()
        };
        Self{
            pks: pks.iter().map(|&pk| Some(pk)).collect::<Vec<_>>(),
            sigs: sigs.iter().map(|&sig| Some(sig)).collect::<Vec<_>>(),
            threshold: Some(threshold),
            b: b_bool,
            message: Some(message),
            hash_commitment: Some(hash_commitment),
            n,
            _field: PhantomData
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<MNT4Fr> for NaiveTresholdSignature<F> {
    fn generate_constraints<CS: ConstraintSystem<MNT4Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

        //Internal checks
        let log_n = (self.n.next_power_of_two() as u64).trailing_zeros() as usize;
        assert_eq!(self.n, self.pks.len());
        assert_eq!(self.n, self.sigs.len());
        assert_eq!(log_n + 1, self.b.len());

        //Check pks are consistent with self.hash_commitment

        //Allocate hash_commitment as public input
        let expected_hash_commitment_g = MNT4FrGadget::alloc_input(
            cs.ns(|| "alloc hash commitment"),
            || self.hash_commitment.ok_or(SynthesisError::AssignmentMissing)
        )?;

        //Allocate public keys as witnesses
        let mut pks_g = Vec::with_capacity(self.n);

        for (i, pk) in self.pks.iter().enumerate() {
            // It's safe to not perform any check when allocating the pks,
            // considering that the pks are hashed, so they should be public
            // at some point, therefore verifiable by everyone.
            let pk_g = MNT6G1Gadget::alloc_without_check(
                cs.ns(|| format!("alloc_pk_{}", i)),
                || pk.ok_or(SynthesisError::AssignmentMissing)
            )?;
            pks_g.push(pk_g);
        }

        //Check pks
        let mut actual_hash_commitment_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "hash public keys"),
            pks_g.iter().map(|pk| pk.x.clone()).collect::<Vec<_>>().as_slice(),
        )?;

        //Allocate threshold as witness
        let t_g = MNT4FrGadget::alloc(
            cs.ns(|| "alloc threshold"),
            || self.threshold.ok_or(SynthesisError::AssignmentMissing)
        )?;

        //Check hash commitment
        actual_hash_commitment_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
            cs.ns(|| "H(H(pks), threshold)"),
            &[actual_hash_commitment_g, t_g.clone()],
        )?;

        expected_hash_commitment_g.enforce_equal(
            cs.ns(|| "check hash commitment"),
            &actual_hash_commitment_g,
        )?;

        //Check signatures

        //Allocate message as public input
        let message_g = MNT4FrGadget::alloc_input(
            cs.ns(|| "alloc message"),
            || self.message.ok_or(SynthesisError::AssignmentMissing)
        )?;

        let mut sigs_g = Vec::with_capacity(self.n);

        //Allocate signatures as witnesses
        for (i, sig) in self.sigs.iter().enumerate() {
            let sig_g = SchnorrSigGadget::alloc(
                cs.ns(|| format!("alloc_sig_{}", i)),
                || sig.ok_or(SynthesisError::AssignmentMissing)
            )?;
            sigs_g.push(sig_g);
        }

        let mut verdicts = Vec::with_capacity(self.n);

        //Check signatures verification verdict
        for (i ,(pk_g, sig_g))
            in pks_g.iter().zip(sigs_g.iter()).enumerate() {

            let v = SchnorrVrfySigGadget::enforce_signature_verdict(
                cs.ns(|| format!("check_sig_verdict_{}", i)),
                pk_g,
                sig_g,
                &[message_g.clone()],
            )?;
            verdicts.push(v);
        }

        //Count valid signatures
        let mut valid_signatures = MNT4FrGadget::zero(cs.ns(|| "alloc valid signatures count"))?;
        for (i, v) in verdicts.iter().enumerate() {
            valid_signatures = valid_signatures.conditionally_add_constant(
                cs.ns(|| format!("add_verdict_{}", i)),
                v,
                MNT4Fr::one(),
            )?;
        }

        //Alloc the b's as witnesses
        let mut bs_g = Vec::with_capacity(log_n + 1);
        for (i, b) in self.b.iter().enumerate(){
            let b_g = Boolean::alloc(
                cs.ns(|| format!("alloc b_{}", i)),
                || b.ok_or(SynthesisError::AssignmentMissing)
            )?;
            bs_g.push(b_g);
        }

        //Pack the b's into a field element
        let b_field = MNT4FrGadget::from_bits(
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

use algebra::curves::mnt4753::MNT4;
use proof_systems::groth16::{Parameters, generator::generate_random_parameters};

#[allow(dead_code)]
pub fn generate_parameters(n: usize) -> Result<Parameters<MNT4>, SynthesisError> {

    //Istantiating rng
    let mut rng = OsRng::default();

    //Istantiating supported number of pks and sigs
    let log_n = (n.next_power_of_two() as u64).trailing_zeros() as usize;

    // Create parameters for our circuit
    let c = NaiveTresholdSignature::<MNT4Fr> {
        pks: vec![None; n],
        sigs: vec![None; n],
        threshold: None,
        b: vec![None; log_n + 1],
        message: None,
        hash_commitment: None,
        n,
        _field: PhantomData
    };

    let params = generate_random_parameters::<MNT4, _, _>(c, &mut rng);
    params
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::{curves::mnt4753::MNT4, ToBits, BigInteger768, ProjectiveCurve};
    use primitives::{
        crh::FieldBasedHash,
        signature::{
            FieldBasedSignatureScheme, schnorr::field_based_schnorr::FieldBasedSchnorrSignatureScheme,
        },
    };
    use proof_systems::groth16::{
        Parameters,
        Proof, create_random_proof,
        prepare_verifying_key, verify_proof,
    };
    use rand::{
        Rng, rngs::OsRng
    };

    type SchnorrSig = FieldBasedSchnorrSignatureScheme<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash>;

    fn generate_test_proof(
        n: usize,
        v: usize,
        t: usize,
        bad_hash_commitment: bool,
        params: Parameters<MNT4>,
    ) -> Result<(Proof<MNT4>, Vec<MNT4Fr>), SynthesisError> {

        //Istantiate rng
        let mut rng = OsRng::default();

        //Istantiate supported number of pks and sigs
        let log_n = (n.next_power_of_two() as u64).trailing_zeros() as usize;

        //Generate random message to sign
        let message: MNT4Fr = rng.gen();

        //Generate another random message used to simulate a non-valid signature
        let invalid_message: MNT4Fr = rng.gen();

        let mut pks = vec![];
        let mut sigs = vec![];

        for _ in 0..v {
            let (pk, sk) = SchnorrSig::keygen(&mut rng);
            let sig = SchnorrSig::sign(&mut rng, &pk, &sk, &[message]).unwrap();
            pks.push(Some(pk));
            sigs.push(Some(sig));
        }

        for _ in 0..(n-v){
            //Sample a random boolean and decide if generating a non valid signature or a null one
            let generate_null: bool = rng.gen();
            let (pk, sig) = if generate_null {
                (NULL_CONST.null_pk, NULL_CONST.null_sig)
            } else {

                let (pk, sk) = SchnorrSig::keygen(&mut rng);
                let sig = SchnorrSig::sign(&mut rng, &pk, &sk, &[invalid_message]).unwrap();
                (pk, sig)
            };
            pks.push(Some(pk));
            sigs.push(Some(sig));
        }

        let message = Some(message);

        //Generate b
        let t_field = MNT4Fr::from_repr(BigInteger768::from(t as u64));
        let valid_field = MNT4Fr::from_repr(BigInteger768::from(v as u64));
        let b_field = valid_field - &t_field;
        let threshold = Some(t_field);

        //Convert b to bits
        let b_bits = b_field.write_bits();
        let to_skip = MNT4Fr::size_in_bits() - (log_n + 1);
        let b = b_bits[to_skip..].iter().map(|b| Some(*b)).collect::<Vec<_>>();

        //Compute hash commitment
        let hash_input = pks.iter().map(|pk| pk.unwrap().into_affine().x).collect::<Vec<_>>();
        let hash_commitment = if !bad_hash_commitment {
            let tmp = MNT4PoseidonHash::evaluate(hash_input.as_slice()).unwrap();
            Some(MNT4PoseidonHash::evaluate(&[tmp, t_field]).unwrap())
        } else {
            let rand_f: MNT4Fr = rng.gen();
            Some(rand_f)
        };

        //Create proof for our circuit
        let c = NaiveTresholdSignature::<MNT4Fr> {
            pks, sigs, threshold, b, message, hash_commitment, n, _field: PhantomData
        };

        //Return proof and public inputs if success
        let start = std::time::Instant::now();
        let proof = match create_random_proof(c, &params, &mut rng) {
            Ok(proof) => {
                let public_inputs = vec![hash_commitment.unwrap(), message.unwrap()];
                Ok((proof, public_inputs))
            }
            Err(e) => Err(e)
        };
        println!("Proof creation time: {:?}", start.elapsed());
        proof
    }

    #[test]
    fn test_naive_threshold_circuit() {
        let n = 16;
        let params = generate_parameters(n).unwrap();
        let pvk = prepare_verifying_key(&params.vk);

        //Generate proof with correct witnesses and v > t
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, false, params.clone()).unwrap();
        assert!(verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());

        //Generate proof with bad hash_commitment
        let (proof, public_inputs) =
            generate_test_proof(n, 5, 4, true, params.clone()).unwrap();
        assert!(!verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());

        //Generate proof with insufficient valid signatures
        let (proof, public_inputs) =
            generate_test_proof(n, 4, 5, false, params.clone()).unwrap();
        assert!(!verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap());
    }
}