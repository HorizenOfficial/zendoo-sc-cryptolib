use algebra::curves::tweedle::dum::G2Projective;
use algebra::fields::tweedle::{Fq as Fs, Fr};
use primitives::{crh::{
    TweedleFrPoseidonHash as PoseidonHash,
    bowe_hopwood::{
        BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters,
    },
    pedersen::PedersenWindow,
}, vrf::{
    FieldBasedVrf,
    ecvrf::{
        FieldBasedEcVrf, FieldBasedEcVrfProof, FieldBasedEcVrfPk,
    },
}};
use rand::rngs::OsRng;
use primitives::vrf::ecvrf::FieldBasedEcVrfPk;

#[derive(Clone)]
struct TestWindow {}
impl PedersenWindow for TestWindow {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 2;
}

type GroupHash = BoweHopwoodPedersenCRH<G2Projective, TestWindow>;
type GroupHashParameters = BoweHopwoodPedersenParameters<G2Projective>;
type EcVrfScheme = FieldBasedEcVrf<Fr, G2Projective, PoseidonHash, GroupHash>;
type EcVrfProof = FieldBasedEcVrfProof<Fr, G2Projective>;
type EcVrfPk = FieldBasedEcVrfPk<G2Projective>;

pub fn ouroboros_create_proof
(
    pp: &GroupHashParameters,
    epoch_randomness: &Fr,
    _slot_number: u32,
    pk: &EcVrfPk,
    sk: &Fs,
    _forger_stake: u64,
    _total_forgers_stake: u64
) -> Option<(EcVrfProof, EcVrfProof)> {

    //Example calling code
    let rng = &mut OsRng;
    match EcVrfScheme::prove(rng, pp, pk, sk, &[*epoch_randomness]) {
        Ok(proof) => Some((proof.clone(), proof)),
        _ => None,
    }
}

pub fn ouroboros_check_proof
(
    pp: &GroupHashParameters,
    proof: (&EcVrfProof, &EcVrfProof),
    epoch_randomness: &Fr,
    _slot_number: u32,
    forger_pk: &EcVrfPk,
    _forger_stake: u64,
    _total_forgers_stake: u64,

) -> Option<(Fr, Fr)> {
    //Example calling code
    match (
        EcVrfScheme::proof_to_hash(pp, forger_pk, &[*epoch_randomness], proof.0),
        EcVrfScheme::proof_to_hash(pp, forger_pk, &[*epoch_randomness], proof.1),
        )
    {
        (Ok(o1), Ok(o2)) => Some((o1, o2)),
        _ => None,
    }
}