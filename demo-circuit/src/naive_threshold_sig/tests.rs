use algebra::{
    Field, PrimeField, ToBits, Curve,
};

use primitives::{
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSignature, FieldBasedSchnorrPk},
        FieldBasedSignatureScheme,
    },
    crh::FieldBasedHash,
};
use r1cs_crypto::{
    signature::FieldBasedSigGadget,
    crh::{TweedleFrPoseidonHashGadget as PoseidonHashGadget, FieldBasedHashGadget}
};

use r1cs_std::{
    fields::FieldGadget,
    alloc::AllocGadget,
    bits::{
        boolean::Boolean, FromBitsGadget,
    },
    eq::EqGadget, test_constraint_system::TestConstraintSystem,
};

use r1cs_core::ConstraintSystem;
use crate::{
    constants::NaiveThresholdSigParams, type_mapping::*, naive_threshold_sig::*,
};

use rand::{
    Rng, rngs::OsRng
};

use lazy_static::*;
use r1cs_std::bits::uint64::UInt64;
use cctp_primitives::utils::commitment_tree::ByteAccumulator;

lazy_static! {
    pub static ref NULL_CONST: NaiveThresholdSigParams = NaiveThresholdSigParams::new();
}

struct NaiveTresholdSignatureTest {

    //Witnesses
    pks:                                    Vec<FieldBasedSchnorrPk<G2>>,
    sigs:                                   Vec<FieldBasedSchnorrSignature<FieldElement, G2>>,
    threshold:                              FieldElement,
    b:                                      Vec<bool>,
    sc_id:                                  FieldElement,
    epoch_number:                           FieldElement,
    end_cumulative_sc_tx_comm_tree_root:    FieldElement,
    mr_bt:                                  FieldElement,
    ft_min_amount:                          u64,
    btr_fee:                                u64,

    //Public inputs
    pks_threshold_hash:                     FieldElement,
    cert_data_hash:                         FieldElement,

    //Other
    max_pks:                                usize,
}

fn generate_inputs
(
    max_pks:                  usize,
    valid_sigs:               usize,
    threshold:                usize,
    wrong_pks_threshold_hash: bool,
    wrong_cert_data_hash:     bool,
) -> NaiveTresholdSignatureTest
{
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
        let fes = ByteAccumulator::init()
            .update(btr_fee).unwrap()
            .update(ft_min_amount).unwrap()
            .get_field_elements().unwrap();
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
        sigs.push(sig);
    }

    for _ in 0..(max_pks-valid_sigs){
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
        sigs.push(sig);
    }

    //Generate b
    let t_field = FieldElement::from_repr(FieldBigInteger::from(threshold as u64));
    let valid_field = FieldElement::from_repr(FieldBigInteger::from(valid_sigs as u64));
    let b_field = valid_field - &t_field;
    let b_bool = {
        let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
        let to_skip = FieldElement::size_in_bits() - (log_max_pks + 1);
        b_field.write_bits()[to_skip..].to_vec()
    };

    //Compute pks_threshold_hash
    let mut h = FieldHash::init_constant_length(pks.len(), None);
    pks.iter().for_each(|pk| { h.update(pk.0.into_affine().unwrap().x); });
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

    //Create instance of the circuit
    NaiveTresholdSignatureTest {
        pks,
        sigs,
        threshold: t_field,
        b: b_bool,
        sc_id,
        epoch_number,
        end_cumulative_sc_tx_comm_tree_root,
        mr_bt,
        ft_min_amount,
        btr_fee,
        pks_threshold_hash,
        cert_data_hash,
        max_pks,
    }
}

fn generate_constraints(
    c: NaiveTresholdSignatureTest,
    mut cs: TestConstraintSystem<FieldElement>,
) -> bool
{
    //Internal checks
    let log_max_pks = (c.max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
    assert_eq!(c.max_pks, c.pks.len());
    assert_eq!(c.max_pks, c.sigs.len());
    assert_eq!(log_max_pks + 1, c.b.len());

    //Check pks are consistent with c.hash_commitment

    //Allocate public keys as witnesses
    let mut pks_g = Vec::with_capacity(c.max_pks);

    for (i, pk) in c.pks.iter().enumerate() {
        // It's safe to not perform any check when allocating the pks,
        // considering that the pks are hashed, so they should be public
        // at some point, therefore verifiable by everyone.
        let pk_g = SchnorrPkGadget::alloc_without_check(
            cs.ns(|| format!("alloc_pk_{}", i)),
            || Ok(pk)
        ).unwrap();
        pks_g.push(pk_g);
    }

    //Check pks
    let mut pks_threshold_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
        cs.ns(|| "hash public keys"),
        pks_g.iter().map(|pk| pk.pk.x.clone()).collect::<Vec<_>>().as_slice(),
    ).unwrap();

    //Allocate threshold as witness
    let t_g = FrGadget::alloc(
        cs.ns(|| "alloc threshold"),
        || Ok(c.threshold)
    ).unwrap();

    //Check hash commitment
    pks_threshold_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
        cs.ns(|| "H(H(pks), threshold)"),
        &[pks_threshold_hash_g, t_g.clone()],
    ).unwrap();

    //Check signatures
    //Reconstruct message as H(epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)

    // Alloc field elements
    let sc_id_g = FrGadget::alloc(
        cs.ns(|| "alloc sc id"),
        || Ok(c.sc_id)
    ).unwrap();

    let epoch_number_g = FrGadget::alloc(
        cs.ns(|| "alloc epoch number"),
        || Ok(c.epoch_number)
    ).unwrap();

    let mr_bt_g = FrGadget::alloc(
        cs.ns(|| "alloc mr_bt"),
        || Ok(c.mr_bt)
    ).unwrap();

    let end_cumulative_sc_tx_comm_tree_root_g = FrGadget::alloc(
        cs.ns(|| "alloc end_cumulative_sc_tx_comm_tree_root"),
        || Ok(c.end_cumulative_sc_tx_comm_tree_root)
    ).unwrap();

    // Alloc btr_fee and ft_min_amount
    let btr_fee_g = UInt64::alloc(
        cs.ns(|| "alloc btr_fee"),
        Some(c.btr_fee)
    ).unwrap();

    let ft_min_amount_g = UInt64::alloc(
        cs.ns(|| "alloc ft_min_amount"),
        Some(c.ft_min_amount)
    ).unwrap();

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
        fees_bits.as_slice()
    ).unwrap();

    let message_g = PoseidonHashGadget::enforce_hash_constant_length(
        cs.ns(|| "H(sc_id, epoch_number, bt_root, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)"),
        &[sc_id_g.clone(), epoch_number_g.clone(), mr_bt_g.clone(), end_cumulative_sc_tx_comm_tree_root_g.clone(), fees_g.clone()],
    ).unwrap();

    let mut sigs_g = Vec::with_capacity(c.max_pks);

    //Allocate signatures as witnesses
    for (i, sig) in c.sigs.iter().enumerate() {
        let sig_g = SchnorrSigGadget::alloc(
            cs.ns(|| format!("alloc_sig_{}", i)),
            || Ok(sig)
        ).unwrap();
        sigs_g.push(sig_g);
    }

    let mut verdicts = Vec::with_capacity(c.max_pks);

    //Check signatures verification verdict on message
    for (i ,(pk_g, sig_g))
        in pks_g.iter().zip(sigs_g.iter()).enumerate() {

        let v = SchnorrVrfySigGadget::enforce_signature_verdict(
            cs.ns(|| format!("check_sig_verdict_{}", i)),
            pk_g,
            sig_g,
            message_g.clone(),
        ).unwrap();
        verdicts.push(v);
    }

    //Count valid signatures
    let mut valid_signatures = FrGadget::zero(cs.ns(|| "alloc valid signatures count")).unwrap();
    for (i, v) in verdicts.iter().enumerate() {
        valid_signatures = valid_signatures.conditionally_add_constant(
            cs.ns(|| format!("add_verdict_{}", i)),
            v,
            FieldElement::one(),
        ).unwrap();
    }

    //Enforce cert_data_hash
    let cert_data_hash_g =  {
        let wcert_sysdata_hash_g = PoseidonHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(sc_id, epoch_number, bt_root, valid_sigs, end_cumulative_sc_tx_comm_tree_root, btr_fee, ft_min_amount)"),
            &[sc_id_g, epoch_number_g, mr_bt_g, valid_signatures.clone(), end_cumulative_sc_tx_comm_tree_root_g, fees_g],
        ).unwrap();
        PoseidonHashGadget::enforce_hash_constant_length(
            cs.ns(|| "H(proof_data (not present), cert_data_hash)"),
            &[wcert_sysdata_hash_g]
        )
    }.unwrap();


    //Check pks_threshold_hash (constant)
    let expected_pks_threshold_hash_g = FrGadget::alloc_input(
        cs.ns(|| "alloc constant as input"),
        || Ok(c.pks_threshold_hash)
    ).unwrap();

    pks_threshold_hash_g.enforce_equal(
        cs.ns(|| "pks_threshold_hash: expected == actual"),
        &expected_pks_threshold_hash_g
    ).unwrap();


    // Check cert_data_hash
    let expected_cert_data_hash_g = FrGadget::alloc_input(
        cs.ns(|| "alloc input cert_data_hash_g"),
        || Ok(c.cert_data_hash)
    ).unwrap();

    cert_data_hash_g.enforce_equal(
        cs.ns(|| "cert_data_hash: expected == actual"),
        &expected_cert_data_hash_g
    ).unwrap();

    //Alloc the b's as witnesses
    let mut bs_g = Vec::with_capacity(log_max_pks + 1);
    for (i, b) in c.b.iter().enumerate(){
        let b_g = Boolean::alloc(
            cs.ns(|| format!("alloc b_{}", i)),
            || Ok(b)
        ).unwrap();
        bs_g.push(b_g);
    }

    //Pack the b's into a field element
    let b_field = FrGadget::from_bits(
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

    let n = 5;
    for _ in 0..10 {
        let v = 5;
        let t = 4;
        let satisfiable = v >= t;

        println!("************THRESHOLD {}****************", t);
        println!("Valid signatures: {}", v);
        println!("CS satisfiable: {}", satisfiable);

        let c = generate_inputs(n, v, t, false, false);
        let cs = TestConstraintSystem::<FieldElement>::new();
        let is_satisfied = generate_constraints(c, cs);

        // The output must be false whenever the cs should be satisfiable
        // but it actually isn't, and viceversa. This behaviour can be
        // encoded with a XNOR.
        assert!(!(satisfiable ^ is_satisfied));
        println!("Ok!");
    }
}

#[test]
fn naive_threshold_sig_test_all_cases() {
    let mut rng = OsRng::default();
    let n = 6;

    println!("Test success case with v > t");
    let v = rng.gen_range(1..n);
    let t = rng.gen_range(0..v);
    let c = generate_inputs(n, v, t, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test success case with v == t");
    let v = rng.gen_range(1..n);
    let t = v;
    let c = generate_inputs(n, v, t, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case with v < t");
    let t = rng.gen_range(1..n);
    let v = rng.gen_range(0..t);
    let c = generate_inputs(n, v, t, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = t = 0");
    let c = generate_inputs(n, 0, 0, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = t = n");
    let c = generate_inputs(n, n, n, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = n and t = 0");
    let c = generate_inputs(n, n, 0, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case v = 0 and t = n");
    let c = generate_inputs(n, 0, n, false, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case wrong pks_threshold_hash");
    let v = rng.gen_range(1..n);
    let t = rng.gen_range(0..v);
    let c = generate_inputs(n, v, t, true, false);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case wrong wcert_sysdata_hash");
    let v = rng.gen_range(1..n);
    let t = rng.gen_range(0..v);
    let c = generate_inputs(n, v, t, false, true);
    let cs = TestConstraintSystem::<FieldElement>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");
}