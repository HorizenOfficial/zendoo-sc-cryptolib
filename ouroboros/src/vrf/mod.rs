use algebra::curves::mnt6753::G1Projective as MNT6G1Projective;
use algebra::fields::mnt4753::{Fq as MNT4Fq, Fr as MNT4Fr};
use algebra::ProjectiveCurve;
use crypto_primitives::{crh::{
    MNT4PoseidonHash,
    bowe_hopwood::{
        BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters,
    },
    pedersen::PedersenWindow,
}, vrf::{
    FieldBasedVrf,
    ecvrf::{
        FieldBasedEcVrf, FieldBasedEcVrfProof,
    },
}};
use std::ops::Mul;
use rand::rngs::OsRng;

#[derive(Clone)]
struct TestWindow {}
impl PedersenWindow for TestWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 2;
}

type BHMNT6 = BoweHopwoodPedersenCRH<MNT6G1Projective, TestWindow>;
type BHMNT6Parameters = BoweHopwoodPedersenParameters<MNT6G1Projective>;
type MNT4Vrf = FieldBasedEcVrf<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash, BHMNT6>;
type MNT4VrfProof = FieldBasedEcVrfProof<MNT4Fr, MNT6G1Projective>;

pub fn ouroboros_create_proof
(
    pp: BHMNT6Parameters,
    epoch_randomness: MNT4Fr,
    _slot_number: u32,
    sk: MNT4Fq,
    _forger_stake: u64,
    _total_forgers_stake: u64
) -> Option<(MNT4VrfProof, MNT4VrfProof)> {

    //Example calling code
    let rng = &mut OsRng;
    let pk = MNT6G1Projective::prime_subgroup_generator().mul(&sk);
    match MNT4Vrf::prove(rng, &pp, &pk, &sk, &[epoch_randomness]) {
        Ok(proof) => Some((proof.clone(), proof)),
        _ => None,
    }
}

pub fn ouroboros_check_proof
(
    pp: BHMNT6Parameters,
    proof: (MNT4VrfProof, MNT4VrfProof),
    epoch_randomness: MNT4Fr,
    _slot_number: u32,
    forger_pk: MNT6G1Projective,
    _forger_stake: u64,
    _total_forgers_stake: u64,

) -> Option<(MNT4Fr, MNT4Fr)> {
    //Example calling code
    match (
        MNT4Vrf::verify(&pp, &forger_pk, &[epoch_randomness], &proof.0),
        MNT4Vrf::verify(&pp, &forger_pk, &[epoch_randomness], &proof.1),
        )
    {
        (Ok(o1), Ok(o2)) => Some((o1, o2)),
        _ => None,
    }
}

// NOTE: To simplify I put all the concrete types and didn't templatize anything. Actually this could
// be easily templatized, and when calling the functions passing values of the concrete types. The
// templatized version of the above functions looks like this:

pub fn ouroboros_create_proof_templatized<S: FieldBasedVrf>
(
    _pp: S::GHParams,
    _epoch_randomness: S::Data,
    _slot_number: u32,
    _sk: S::SecretKey,
    _forger_stake: u64,
    _total_forgers_stake: u64
) -> Option<(S::Proof, S::Proof)> {unimplemented!()}

pub fn ouroboros_check_proof_templatized<S: FieldBasedVrf>
(
    _pp: S::GHParams,
    _proof: (S::Proof, S::Proof),
    _epoch_randomness: S::Data,
    _slot_number: u32,
    _forger_pk: S::PublicKey,
    _forger_stake: u64,
    _total_forgers_stake: u64,

) -> Option<(S::Data, S::Data)> {unimplemented!()}

// In this way it could be possible to do what Oleks suggested: however, it may be necessary to pass
// the public key in the function `ouroboros_create_proof_templatized` because the trait doesn't
// expose the fact that a S::PublicKey is a `ProjectiveCurve` implementing the method `prime_subgroup_
// generator` (it can be easily done with a little bit of loss of generality though)