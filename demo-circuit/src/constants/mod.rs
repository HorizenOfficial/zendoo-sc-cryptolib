use algebra::{
    fields::tweedle::Fq as Fr,
    curves::tweedle::dee::Projective,
    biginteger::BigInteger256 as BigInteger,
    Field, PrimeField, ProjectiveCurve,
};

use primitives::{
    crh::pedersen::PedersenWindow,
    signature::schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignature, FieldBasedSchnorrPk,
    }
};

pub mod constants;

pub struct NaiveThresholdSigParams{
    pub null_sig:   FieldBasedSchnorrSignature<Fr, Projective>,
    pub null_pk:    FieldBasedSchnorrPk<Projective>,
}

impl NaiveThresholdSigParams {
    pub fn new() -> Self {
        let e = Fr::one();
        let s = e.clone();
        let null_sig = FieldBasedSchnorrSignature::<Fr, Projective>::new(e, s);

        let x = Fr::from_repr(
            BigInteger(
                [
                    12035525611691125070,
                    2718616596026025238,
                    9975628352372511576,
                    2747295074563971616
                ],
            )
        );

        let y = Fr::from_repr(
            BigInteger(
                [
                    5331171409760468070,
                    16463677157546155673,
                    17641414461844182447,
                    494927661522368813,
                ],
            )
        );

        let z = Fr::from_repr(
            BigInteger(
                [
                    1,
                    0,
                    0,
                    0,
                ],
            )
        );

        let null_pk = FieldBasedSchnorrPk(Projective::new(x, y, z));

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
    pub group_hash_generators: Vec<Vec<Projective>>,
}

impl VRFParams {
    pub fn new() -> Self {

        let gen_1 = Projective::new(
        Fr::from_repr(
            BigInteger([
                504967749112164170,
                2872646935354280506,
                5771540424607741856,
                3532851791422854307,
            ])),
        Fr::from_repr(
            BigInteger([
                11007759008187642280,
                16116990241173382136,
                17912031078731955885,
                203584800139106297,
            ])),
        Fr::from_repr(
            BigInteger([
                1,
                0,
                0,
                0,
            ])),
        );

        let gen_2 = Projective::new(
        Fr::from_repr(
            BigInteger([
                3508597432913599250,
                12328919698483580016,
                11406370637118763643,
                3802712649637469844,
            ])),
        Fr::from_repr(
            BigInteger([
                11996917753320897860,
                16716285440779602605,
                14982255493126248028,
                1533718642375758253,
            ])),
        Fr::from_repr(
            BigInteger([
                1,
                0,
                0,
                0,
            ])),
        );

        let group_hash_generators = Self::compute_group_hash_table([gen_1, gen_2].to_vec());

        Self{group_hash_generators}
    }

    pub(crate) fn compute_group_hash_table(generators: Vec<Projective>)
    -> Vec<Vec<Projective>>
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

#[cfg(test)]
mod test
{
    use algebra::{curves::tweedle::dee::Affine, FpParameters, FromCompressedBits, AffineCurve};
    use super::*;
    use blake2s_simd::{
        Hash, Params
    };
    use bit_vec::BitVec;

    fn hash_to_curve<F: PrimeField, G: AffineCurve + FromCompressedBits>(
        tag: &[u8],
        personalization: &[u8]
    ) -> Option<G> {

        let compute_chunk =
            |input: &[u8], personalization: &[u8]| -> Hash {
                Params::new()
                    .hash_length(32)
                    .personal(personalization)
                    .to_state()
                    .update(constants::GH_FIRST_BLOCK)
                    .update(input)
                    .finalize()
            };

        // Append counter byte to tag
        let tag_len = tag.len();
        let mut tag = tag.to_vec();
        tag.push(0u8);

        // Compute number of hashes to be concatenated in order to obtain a field element
        let field_size = F::size_in_bits();
        let bigint_size = (field_size + F::Params::REPR_SHAVE_BITS as usize)/8;
        let chunk_num = if bigint_size % 32 == 0 { bigint_size/32 } else { (bigint_size/32) + 1};
        let max_value = u8::max_value();
        let mut g = None;

        while tag[tag_len] <= max_value {

            let mut chunks = vec![];

            //chunk_0 = H(tag), chunk_1 = H(chunk_0) = H(H(tag)), ..., chunk_i = H(chunk_i-1)
            let mut prev_hash = tag.clone();
            for _ in 0..chunk_num {
                let hash = compute_chunk(prev_hash.as_slice(), personalization);
                chunks.extend_from_slice(hash.as_ref());
                prev_hash = hash.as_ref().to_vec();
            }

            tag[tag_len] += 1u8;

            //Mask away REPR_SHAVE_BITS
            let mut chunk_bits = BitVec::from_bytes(chunks.as_slice());
            for i in field_size..(bigint_size * 8) {
                chunk_bits.set(i, false);
            }

            //Get field element from `chunks`
            let chunk_bytes = chunk_bits.to_bytes();
            let fe = match F::from_random_bytes(&chunk_bytes[..bigint_size]) {
                Some(fe) => fe,
                None => continue
            };

            //Get point from chunks
            let mut fe_bits = fe.write_bits();
            fe_bits.push(false); //We don't want an infinity point
            fe_bits.push(false); //We decide to choose the even y coordinate
            match G::decompress(fe_bits) {
                Ok(point) => {
                    g = Some(point);
                    break;
                },
                Err(_) => continue
            };
        };
        g
    }


    #[test]
    fn test_pk_null_gen() {
        let tag = b"Strontium Sr 90";
        let personalization = constants::NULL_PK_PERSONALIZATION;
        let htc_out = hash_to_curve::<Fr, Affine>(tag, personalization)
            .unwrap()
            .into_projective();
        println!("{:#?}", htc_out);
        let null_pk = NaiveThresholdSigParams::new().null_pk.0;
        assert_eq!(htc_out, null_pk);
    }

    #[test]
    fn test_vrf_group_hash_gen() {
        let personalization = constants::VRF_GROUP_HASH_GENERATORS_PERSONALIZATION;

        //Gen1
        let tag = b"Magnesium Mg 12";
        let htc_g1_out = hash_to_curve::<Fr, Affine>(tag, personalization)
            .unwrap()
            .into_projective();

        //Gen2
        let tag = b"Gold Au 79";
        let htc_g2_out = hash_to_curve::<Fr, Affine>(tag, personalization)
            .unwrap()
            .into_projective();

        //Check GH generators
        let gh_generators = VRFParams::compute_group_hash_table(
            [htc_g1_out, htc_g2_out].to_vec()
        );
        assert_eq!(gh_generators, VRFParams::new().group_hash_generators);
    }
}