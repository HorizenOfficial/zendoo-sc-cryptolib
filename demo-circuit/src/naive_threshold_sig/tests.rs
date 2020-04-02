use algebra::{
    BigInteger768,
    fields::mnt4753::Fr as MNT4Fr,
    curves::mnt6753::G1Projective as MNT6G1Projective, ProjectiveCurve,
    Field, PrimeField, ToBits, FromBits
};

use primitives::{
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme},
        FieldBasedSignatureScheme,
    },
    crh::{FieldBasedHash, MNT4PoseidonHash},
};
use r1cs_crypto::{
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSigGadget, FieldBasedSchnorrSigVerificationGadget},
        FieldBasedSigGadget,
    },
    crh::{MNT4PoseidonHashGadget, FieldBasedHashGadget}
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
    eq::EqGadget, test_constraint_system::TestConstraintSystem,
};

use r1cs_core::ConstraintSystem;
use crate::constants::NaiveThresholdSigParams;

use rand::{
    Rng, rngs::OsRng
};

use lazy_static::*;

lazy_static! {
    pub static ref NULL_CONST: NaiveThresholdSigParams = { NaiveThresholdSigParams::new() };
}

//Sig types
type SchnorrSig = FieldBasedSchnorrSignatureScheme<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash>;
type SchnorrSigGadget = FieldBasedSchnorrSigGadget<MNT4Fr>;
type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    MNT4Fr, MNT6G1Projective, MNT6G1Gadget, MNT4PoseidonHash, MNT4PoseidonHashGadget
>;

//Field types
type MNT4FrGadget = FpGadget<MNT4Fr>;

struct NaiveTresholdSignatureTest{

    //Witnesses
    pks:                   Vec<MNT6G1Projective>,
    sigs:                  Vec<FieldBasedSchnorrSignature<MNT4Fr>>,
    threshold:             MNT4Fr,
    b:                     Vec<bool>,

    //Public inputs
    message:               MNT4Fr,
    hash_commitment:       MNT4Fr,

    //Other
    n:                     usize,
}


fn generate_inputs
(
    n: usize,
    v: usize,
    t: usize,
    bad_hash_commitment: bool,
) -> NaiveTresholdSignatureTest
{
    //*************************INPUTS GENERATION********************************
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
        pks.push(pk);
        sigs.push(sig);
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
        pks.push(pk);
        sigs.push(sig);
    }

    assert_eq!(pks.len(), n);
    assert_eq!(sigs.len(), n);

    let valid = MNT4Fr::from_repr(BigInteger768::from(v as u64));
    let threshold = MNT4Fr::from_repr(BigInteger768::from(t as u64));
    let b_field = valid - &threshold;

    //Convert b to bits
    let b_bits = b_field.write_bits();
    let to_skip = MNT4Fr::size_in_bits() - (log_n + 1);

    // If v < t then b_field will be "negative" and the (log_n + 1) MSB bits
    // won't be able to encode this number. Therefore the checks below make sense only
    // in a positive case.
    if v >= t {
        //Additional checks on b
        {
            assert_eq!(b_field, MNT4Fr::read_bits(b_bits[to_skip..].to_vec()).unwrap());
            let zero_vec = vec![false; to_skip];
            assert_eq!(b_bits[..to_skip].to_vec(), zero_vec);
        }
    }

    let b = b_bits[to_skip..].to_vec();

    //Compute hash commitment
    let hash_input = pks.iter().map(|pk| pk.into_affine().x).collect::<Vec<_>>();
    let hash_commitment = if !bad_hash_commitment {
        let tmp = MNT4PoseidonHash::evaluate(hash_input.as_slice()).unwrap();
        MNT4PoseidonHash::evaluate(&[tmp, threshold]).unwrap()
    } else {
        let rand_f: MNT4Fr = rng.gen();
        rand_f
    };

    NaiveTresholdSignatureTest {
        pks, sigs, threshold, b, message, hash_commitment, n,
    }
}

fn generate_constraints(
    c: NaiveTresholdSignatureTest,
    mut cs: TestConstraintSystem<MNT4Fr>,
) -> bool
{
    //Internal checks
    let log_n = (c.n.next_power_of_two() as u64).trailing_zeros() as usize;
    assert_eq!(c.n, c.pks.len());
    assert_eq!(c.n, c.sigs.len());
    assert_eq!(log_n + 1, c.b.len());

    //Check pks are consistent with hash_commitment

    //Allocate hash_commitment as public input
    let expected_hash_commitment_g = MNT4FrGadget::alloc_input(
        cs.ns(|| "alloc hash commitment"),
        || Ok(c.hash_commitment)
    ).unwrap();

    //Allocate public keys as witnesses
    let mut pks_g = Vec::with_capacity(c.n);

    for (i, pk) in c.pks.iter().enumerate() {
        let pk_g = MNT6G1Gadget::alloc(
            cs.ns(|| format!("alloc_pk_{}", i)),
            || Ok(pk)
        ).unwrap();
        pks_g.push(pk_g);
    }

    //Check pks
    let mut actual_hash_commitment_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "hash public keys"),
        pks_g.iter().map(|pk| pk.x.clone()).collect::<Vec<_>>().as_slice(),
    ).unwrap();

    //Allocate threshold as public input
    let t_g = MNT4FrGadget::alloc(
        cs.ns(|| "alloc threshold"),
        || Ok(c.threshold)
    ).unwrap();

    //Chech hash commitment

    actual_hash_commitment_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "H(H(pks), threshold)"),
        &[actual_hash_commitment_g, t_g.clone()],
    ).unwrap();

    expected_hash_commitment_g.enforce_equal(
        cs.ns(|| "check public keys"),
        &actual_hash_commitment_g,
    ).unwrap();

    //Check signatures

    //Allocate message as public input
    let message_g = MNT4FrGadget::alloc_input(
        cs.ns(|| "alloc message"),
        || Ok(c.message)
    ).unwrap();

    let mut sigs_g = Vec::with_capacity(c.n);

    //Allocate signatures as witnesses
    for (i, sig) in c.sigs.iter().enumerate() {
        let sig_g = SchnorrSigGadget::alloc(
            cs.ns(|| format!("alloc_sig_{}", i)),
            || Ok(sig)
        ).unwrap();
        sigs_g.push(sig_g);
    }

    let mut verdicts = Vec::with_capacity(c.n);

    //Check signatures verification verdict
    for (i, (pk_g, sig_g))
        in pks_g.iter().zip(sigs_g.iter()).enumerate() {
        let v = SchnorrVrfySigGadget::enforce_signature_verdict(
            cs.ns(|| format!("check_sig_verdict_{}", i)),
            pk_g,
            sig_g,
            &[message_g.clone()],
        ).unwrap();
        verdicts.push(v);
    }

    //Count valid signatures
    let mut valid_signatures = MNT4FrGadget::zero(cs.ns(|| "alloc valid signatures count")).unwrap();
    for (i, v) in verdicts.iter().enumerate() {
        valid_signatures = valid_signatures.conditionally_add_constant(
            cs.ns(|| format!("add_verdict_{}", i)),
            v,
            MNT4Fr::one(),
        ).unwrap();
    }

    //Alloc the b's as witnesses
    let mut bs_g = Vec::with_capacity(log_n + 1);
    for (i, b) in c.b.iter().enumerate() {
        let b_g = Boolean::alloc(
            cs.ns(|| format!("alloc b_{}", i)),
            || Ok(b)
        ).unwrap();
        bs_g.push(b_g);
    }

    //Pack the b's into a field element
    let b_field = MNT4FrGadget::from_bits(
        cs.ns(|| "pack the b's into a field element"),
        bs_g.as_slice(),
    ).unwrap();

    //Enforce threshold
    valid_signatures
        .sub(cs.ns(|| "valid_signatures - threshold"), &t_g).unwrap()
        .enforce_equal(cs.ns(|| "threshold check"), &b_field).unwrap();

    if !cs.is_satisfied() {
        println!("**********Unsatisfied Constraints***********");
        println!("{:?}", cs.which_is_unsatisfied());
    }

    cs.is_satisfied()
}

#[test]
fn random_naive_threshold_sig_test() {
    let mut rng = OsRng::default();

    let n = 16;
    for t in 0..n + 1 {
        let v: usize = rng.gen_range(0, n + 1);
        let satisfiable = v >= t;

        println!("************THRESHOLD {}****************", t);
        println!("Valid signatures: {}", v);
        println!("CS satisfiable: {}", satisfiable);

        let c = generate_inputs(n, v, t, false);
        let cs = TestConstraintSystem::<MNT4Fr>::new();
        let is_satisfied = generate_constraints(c, cs);

        // The output must be false whenever the cs should be satisfiable
        // but it actually isn't and viceversa. This behaviour can be
        // encoded with a XNOR.
        assert!(!(satisfiable ^ is_satisfied));
        println!("Ok!");
    }
}

#[test]
fn naive_threshold_sig_test_all_cases() {
    let mut rng = OsRng::default();
    let n = 16;

    println!("Test success case with v > t");
    let v = rng.gen_range(1, n);
    let t = rng.gen_range(0, v);
    let c = generate_inputs(n, v, t, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test success case with v == t");
    let v = rng.gen_range(1, n);
    let t = v;
    let c = generate_inputs(n, v, t, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case with v < t");
    let t = rng.gen_range(1, n);
    let v = rng.gen_range(0, t);
    let c = generate_inputs(n, v, t, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = t = 0");
    let c = generate_inputs(n, 0, 0, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = t = n");
    let c = generate_inputs(n, n, n, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = n and t = 0");
    let c = generate_inputs(n, n, 0, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case v = 0 and t = n");
    let c = generate_inputs(n, 0, n, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case wrong pks");
    let v = rng.gen_range(1, n);
    let t = rng.gen_range(0, v);
    let c = generate_inputs(n, v, t, true);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");
}