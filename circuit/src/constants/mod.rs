use algebra::{
    fields::mnt4753::Fr,
    curves::mnt6753::{G1Projective, G1Affine},
    biginteger::BigInteger768 as BigInteger,
    Field, PrimeField, ProjectiveCurve, AffineCurve,
    ToBits
};

use crypto_primitives::{
    crh::pedersen::PedersenWindow,
    signature::schnorr::field_impl::FieldBasedSchnorrSignature
};

pub mod constants;

pub struct NaiveThresholdSigParams{
    pub null_sig:   FieldBasedSchnorrSignature<Fr>,
    pub null_pk:    G1Projective,
}

impl NaiveThresholdSigParams {
    pub fn new() -> Self {
        let e = Fr::one();
        let s = e.clone();
        let null_sig = FieldBasedSchnorrSignature::<Fr>{e, s};

        let x = Fr::from_repr(
            BigInteger([
                17938625038075785283,
                16508371799393812784,
                15483496128959353847,
                2048968449075429543,
                3813485155185031268,
                17391196392872785798,
                443815587061199304,
                809911665634108871,
                3203999612048336978,
                5914744227561871782,
                11028425691428698474,
                321931059609498,
            ]));

        let y = Fr::from_repr(
            BigInteger([
                7591787525067869101,
                4520664314106635126,
                3501384056613126553,
                11132452857411289821,
                1747040353565531240,
                7804288879143509255,
                10401228816538582578,
                249784886659832058,
                18437460134326584942,
                2601603098127689962,
                15861155813087701330,
                165630173916516,
            ]));

        let z = Fr::from_repr(
            BigInteger([
                13373016969058414402,
                5670427856875409064,
                11667651089292452217,
                1113053963617943770,
                12325313033510771412,
                11510260603202358114,
                3606323059104122008,
                6452324570546309730,
                4644558993695221281,
                1127165286758606988,
                10756108507984535957,
                135547536859714,
            ]));

        let null_pk = G1Projective::new(x, y, z);

        Self{null_sig, null_pk}
    }
}

#[derive(Clone)]
pub struct VRFWindow {}
impl PedersenWindow for VRFWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 2;
}

pub struct VRFParams{
    pub group_hash_generators: Vec<Vec<G1Projective>>,
}

impl VRFParams {
    pub fn new() -> Self {

        let gen_1 = G1Projective::new(
            Fr::from_repr(
                BigInteger([
                    5396716016628894442,
                    16250347609008978884,
                    16400026874508537807,
                    10600089309195725443,
                    11944350598763714573,
                    2786537730813240282,
                    2015510033179394938,
                    3299088900708041044,
                    15128041131726196610,
                    5318740608959163911,
                    2933105954867468309,
                    83897518704478,
                ])),
            Fr::from_repr(
                BigInteger([
                    13468382616245414545,
                    16290186479897558800,
                    12925105321291855571,
                    3891803802780255771,
                    17698947054166096401,
                    17998405614620065768,
                    16621291522318174175,
                    11623058996253770026,
                    17190152583483448914,
                    14896007825055454618,
                    13061929096323544340,
                    390383849930062,
                ])),
            Fr::from_repr(
                BigInteger([
                    13373016969058414402,
                    5670427856875409064,
                    11667651089292452217,
                    1113053963617943770,
                    12325313033510771412,
                    11510260603202358114,
                    3606323059104122008,
                    6452324570546309730,
                    4644558993695221281,
                    1127165286758606988,
                    10756108507984535957,
                    135547536859714,
                ])),
        );

        let gen_2 = G1Projective::new(
            Fr::from_repr(
                BigInteger([
                    16938015810328924015,
                    7595565542203433025,
                    893702455010499521,
                    12666324982058459803,
                    2543921901818494643,
                    1473610353719394482,
                    4040564965617176901,
                    2160693189112035292,
                    11443207615946539506,
                    14310461526530619301,
                    6541239471591817974,
                    74923674694220,
                ])),
            Fr::from_repr(
                BigInteger([
                    8953771389691604184,
                    15164443554240298251,
                    2246296914081141450,
                    1647244817446500736,
                    13791268742047804496,
                    7712141360798675312,
                    13477424548833542279,
                    14232084298308623228,
                    17640535737826677007,
                    2300966962968597128,
                    4476346818178979344,
                    37543374044242,
                ])),
            Fr::from_repr(
                BigInteger([
                    13373016969058414402,
                    5670427856875409064,
                    11667651089292452217,
                    1113053963617943770,
                    12325313033510771412,
                    11510260603202358114,
                    3606323059104122008,
                    6452324570546309730,
                    4644558993695221281,
                    1127165286758606988,
                    10756108507984535957,
                    135547536859714,
                ])),
        );

        let group_hash_generators = Self::compute_group_hash_table([gen_1, gen_2].to_vec());

        Self{group_hash_generators}
    }

    pub(crate) fn compute_group_hash_table(generators: Vec<G1Projective>)
    -> Vec<Vec<G1Projective>>
    {
        let mut gen_table = Vec::new();
        for i in 0..VRFWindow::NUM_WINDOWS {
            let mut generators_for_segment = Vec::new();
            let mut base = generators[i];
            for _ in 0..VRFWindow::WINDOW_SIZE {
                generators_for_segment.push(base);
                for _ in 0..4 {
                    base.double_in_place();
                }
            }
            gen_table.push(generators_for_segment);
        }
        gen_table
    }
}

#[allow(dead_code)]
fn hash_to_curve(
    tag: &[u8],
    personalization: &[u8]
) -> G1Projective {
    use blake2s_simd::{
        Hash, Params
    };
    use algebra::{
        FpParameters, FromCompressedBits
    };

    let compute_chunk =
        |tag: &[u8], personalization: &[u8]| -> Hash {
            Params::new()
                .hash_length(32)
                .personal(personalization)
                .to_state()
                .update(constants::GH_FIRST_BLOCK)
                .update(tag)
                .finalize()
        };

    let tag_len = tag.len();
    let mut tag = tag.clone().to_vec();
    tag.push(0u8);

    let g = loop {

        let mut chunks = vec![];
        let bigint_size = (Fr::size_in_bits() + <Fr as PrimeField>::Params::REPR_SHAVE_BITS as usize)/8;
        let chunk_num = if bigint_size % 32 == 0 { bigint_size/32 } else { (bigint_size/32) + 1};

        for _ in 0..chunk_num {
            chunks.extend_from_slice(compute_chunk(tag.as_slice(), personalization).as_ref());
            tag[tag_len] += 1;
        }

        //Get field element from `chunks`
        let fe = match Fr::from_random_bytes(&chunks[..bigint_size]) {
            Some(fe) => fe,
            None => continue
        };

        //Get point from chunks
        let mut fe_bits = fe.write_bits();
        fe_bits.push(false); //We don't want an infinity point
        fe_bits.push(false); //We decide to choose the even y coordinate
        let g = match G1Affine::decompress(fe_bits) {
            Ok(g) => g,
            Err(_) => continue
        };

        break(g)
    };
    g.into_projective()
}


#[test]
fn test_pk_null_gen() {
    let tag = b"Strontium Sr 90";
    let personalization = constants::NULL_PK_PERSONALIZATION;
    let htc_out = hash_to_curve(tag, personalization);
    println!("{:#?}", htc_out);
    let null_pk = NaiveThresholdSigParams::new().null_pk;
    assert_eq!(htc_out, null_pk);
}

#[test]
fn test_vrf_group_hash_gen() {
    let personalization = constants::VRF_GROUP_HASH_GENERATORS_PERSONALIZATION;

    //Gen1
    let tag = b"Magnesium Mg 12";
    let htc_g1_out = hash_to_curve(tag, personalization);
    println!("{:#?}", htc_g1_out);

    //Gen2
    let tag = b"Gold Au 79";
    let htc_g2_out = hash_to_curve(tag, personalization);
    println!("{:#?}", htc_g2_out);

    //Check GH generators
    let gh_generators = VRFParams::compute_group_hash_table(
        [htc_g1_out, htc_g2_out].to_vec()
    );
    assert_eq!(gh_generators, VRFParams::new().group_hash_generators);
}