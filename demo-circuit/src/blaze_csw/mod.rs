//! The ceased sidechain withdrawal proof according to [[blaze]]. Used to recover a forward 
//! transfer / utxo (the latter whenever possible) in case that the sidechain is considered as ceased. 
//! The recoveries refer to the last confirmed sidechain certificate, which in this version is the one 
//! before the last valid certificate before ceasing (The epoch between these two certificates is 
//! considered as reverted). 
pub mod constraints;

pub mod data_structures;
pub use self::data_structures::*;

use std::convert::TryInto;

use crate::{
    read_field_element_from_buffer_with_padding, SimulatedCurveParameters, SimulatedFieldElement,
    SimulatedSWGroup, SimulatedScalarFieldElement, SimulatedTEGroup, SC_PUBLIC_KEY_LENGTH,
    SIMULATED_SCALAR_FIELD_BYTE_SIZE,
};
use algebra::{AffineCurve, Field, MontgomeryModelParameters, SquareRootField, TEModelParameters};
use cctp_primitives::{
    type_mapping::{Error, FieldElement, FIELD_SIZE},
    utils::serialization::{deserialize_from_buffer, serialize_to_buffer},
};

/// Split this FieldElement into two FieldElements.
/// Split will happen at the specified index: one FieldElement will be read from
/// the original bytes [0..index) and the other ones from the original bytes [index..FIELD_ELEMENT_LENGTH)
pub fn split_field_element_at_index(
    fe: &FieldElement,
    idx: usize,
) -> Result<(FieldElement, FieldElement), Error> {
    // Check idx
    if idx >= FIELD_SIZE || idx == 0 {
        return Err(Error::from(format!(
            "Invalid split idx. Min: 1, Max: {}, Found: {}",
            FIELD_SIZE - 1,
            idx
        )));
    }

    // Serialize FieldElement
    let fe_bytes = serialize_to_buffer(fe, None)?;

    // Split, deserialize and return
    Ok((
        read_field_element_from_buffer_with_padding(&fe_bytes[..idx])?,
        read_field_element_from_buffer_with_padding(&fe_bytes[idx..])?,
    ))
}

/// The inverse of the 'split_field_element_at_index' function.
/// Join fe1.bytes[0..index1) and fe2.bytes[0..index2) in a single byte array, returning error if
/// this would exceed FIELD_SIZE and try to deserialize a FieldElement out of it.
/// If 'check_zero_after_idx' is enabled, the function will check that fe1.byte[index1..] and fe2.bytes[index2..]
/// are all 0s.
pub fn combine_field_elements_at_index(
    fe_1: &FieldElement,
    idx_1: usize,
    fe_2: &FieldElement,
    idx_2: usize,
    check_zero_after_idx: bool,
) -> Result<FieldElement, Error> {
    // Check that the resulting array dimension wouldn't be bigger than FIELD_ELEMENT_LENGTH
    if idx_1 + idx_2 > FIELD_SIZE {
        return Err(Error::from(
            "Invalid values for index1 + index2: the resulting array would overflow FIELD_SIZE",
        ));
    }

    // Get bytes of each FieldElement
    let fe_1_bytes = serialize_to_buffer(fe_1, None)?;
    let fe_2_bytes = serialize_to_buffer(fe_2, None)?;

    // Perform zero check
    if check_zero_after_idx
        && (&fe_1_bytes[idx_1..]).iter().any(|b| b != &0u8)
        && (&fe_2_bytes[idx_2..]).iter().any(|b| b != &0u8)
    {
        return Err(Error::from("check zero after idx failed"));
    }

    // Combine bytes
    let combined_fe_bytes = [&fe_1_bytes[..idx_1], &fe_2_bytes[..idx_2]].concat();

    // Deserialize and return FieldElement out of the combined bytes
    let combined_fe = read_field_element_from_buffer_with_padding(combined_fe_bytes.as_slice())?;

    Ok(combined_fe)
}

/// Deserialize a SimulatedScalarFieldElement from 'bytes', interpreted as LE.
/// Function won't pretend to read a field element below the modulus and apply reduction if required.
pub fn deserialize_fe_unchecked(bytes: Vec<u8>) -> SimulatedScalarFieldElement {
    let mut acc = SimulatedScalarFieldElement::zero();
    let two = SimulatedScalarFieldElement::one().double();
    for (i, byte) in bytes
        .iter()
        .enumerate()
        .take(SIMULATED_SCALAR_FIELD_BYTE_SIZE)
    {
        let mut num = SimulatedScalarFieldElement::from(*byte);
        num *= two.pow(&[(8 * i) as u64]);
        acc += num;
    }
    acc
}

fn convert_te_point_to_sw_point(te_point: SimulatedTEGroup) -> SimulatedSWGroup {
    let one = SimulatedFieldElement::one();

    let b_inv = <SimulatedCurveParameters as MontgomeryModelParameters>::COEFF_B
        .inverse()
        .expect("B inverse must exist");

    let a_over_three = <SimulatedCurveParameters as MontgomeryModelParameters>::COEFF_A
        * (SimulatedFieldElement::from(3u8)
            .inverse()
            .expect("Must be able to compute 3.inverse() in SimulatedField"));

    let one_plus_te_y_coord = one + te_point.y;
    let one_minus_te_y_coord = one - te_point.y;
    let te_x_coord_inv = te_point
        .x
        .inverse()
        .expect("Should be able to compute 1/te_x");
    let one_plus_te_y_coord_over_one_minus_te_y_coord = one_plus_te_y_coord
        * one_minus_te_y_coord
            .inverse()
            .expect("Should be able to compute inverse of (1 - y_te) ");

    let sw_x_coord = (one_plus_te_y_coord_over_one_minus_te_y_coord + a_over_three) * b_inv;
    let sw_y_coord = b_inv * one_plus_te_y_coord_over_one_minus_te_y_coord * te_x_coord_inv;

    let sw_point = SimulatedSWGroup::new(sw_x_coord, sw_y_coord, false);

    debug_assert!(sw_point.group_membership_test());

    sw_point
}

/// Convert a sc pk, expressed in TE form, to SW, to be able to use it inside the blaze csw circuit.
pub fn convert_te_pk_to_sw_pk(
    mut te_pk_bytes: [u8; SC_PUBLIC_KEY_LENGTH],
) -> Result<[u8; SC_PUBLIC_KEY_LENGTH], Error> {
    // First, let's reconstruct the TE point corresponding to te_pk_bytes

    // Fetch the sign of the x coordinate
    let te_pk_x_sign = (te_pk_bytes[SC_PUBLIC_KEY_LENGTH - 1] & (1 << 7)) != 0u8;

    // Mask away the sign byte
    te_pk_bytes[SC_PUBLIC_KEY_LENGTH - 1] &= 0x7F;

    // Deserialize the y coordinate
    let te_pk_y = deserialize_from_buffer::<SimulatedFieldElement>(&te_pk_bytes, None, None)?;

    // Reconstruct the x coordinate from the y coordinate and the sign
    let te_pk_x = {
        let numerator = te_pk_y.square() - SimulatedFieldElement::one();
        let denominator = (te_pk_y.square() * SimulatedCurveParameters::COEFF_D)
            - <SimulatedCurveParameters as TEModelParameters>::COEFF_A;
        let x2 = denominator.inverse().map(|denom| denom * numerator);
        x2.and_then(|x2| x2.sqrt()).map(|x| {
            let negx = -x;
            if x.is_odd() ^ te_pk_x_sign {
                negx
            } else {
                x
            }
        })
    }
    .ok_or_else(|| Error::from("Invalid pk. Unable to reconstruct x coordinate."))?;

    // Reconstruct the TE point and check that it's on curve
    let te_pk = SimulatedTEGroup::new(te_pk_x, te_pk_y);
    if te_pk.is_zero() || !te_pk.group_membership_test() {
        return Err(Error::from("Error: invalid pk"));
    }

    // Now, convert the TE point to a SW one.
    // Conversion formulas:
    // https://en.wikipedia.org/wiki/Montgomery_curve#Equivalence_with_twisted_Edwards_curves
    // https://en.wikipedia.org/wiki/Montgomery_curve#Equivalence_with_Weierstrass_curves
    let sw_pk = convert_te_point_to_sw_point(te_pk);

    // Store the sign (last bit) of the X coordinate
    // The value is left-shifted to be used later in an OR operation
    let y_sign = if sw_pk.y.is_odd() { 1 << 7 } else { 0u8 };

    // Extract the public key bytes as Y coordinate
    let x_coordinate = sw_pk.x;
    let mut pk_bytes = serialize_to_buffer(&x_coordinate, None).unwrap();

    // Use the last (null) bit of the public key to store the sign of the X coordinate
    // Before this operation, the last bit of the public key (Y coordinate) is always 0 due to the field modulus
    let len = pk_bytes.len();
    pk_bytes[len - 1] |= y_sign;

    Ok(pk_bytes.try_into().unwrap())
}

#[cfg(test)]
mod test {
    use super::*;
    use serial_test::*;

    #[serial]
    #[test]
    fn split_combine_test() {
        use algebra::{Field, UniformRand};
        use rand::thread_rng;

        let rng = &mut thread_rng();
        // Positive case
        for i in 1..FIELD_SIZE {
            let fe = FieldElement::rand(rng);
            let (fe_1, fe_2) = split_field_element_at_index(&fe, i).unwrap();

            // Restore by combining bits
            let restored_fe =
                combine_field_elements_at_index(&fe_1, i, &fe_2, FIELD_SIZE - i, true).unwrap();
            assert_eq!(fe, restored_fe);

            // Also this way of restoring (used inside CSW circuit) should work
            let pow = FieldElement::one().double().pow(&[(i * 8) as u64]);
            let restored_fe = fe_1 + (pow * fe_2);
            assert_eq!(fe, restored_fe);
        }
    }

    #[serial]
    #[test]
    fn test_key_generation_conversion_rust() {
        use crate::SimulatedTEGroup;
        use algebra::{AffineCurve, Field, ProjectiveCurve};
        use std::ops::Mul;

        let test_sc_secrets = vec![
            "50d5e4c0b15402013941a3c525c6af85e7ab8a2da39a59707211ddd53def965e",
            "70057ef1805240ab9bf2772c0e25a3b57c5911e7dca4120f8e265d750ed77346",
            "1089ba2f1bee0bbc8f2270541bb22595026fe7d828033845d5ed82f31386b65d",
            "305510ff60436930d09ccb8e2321211967aadfe904f30ccb13f600786f9e297a",
            "c80155e642065ca1cc575f69fa658f837b880df76771a335f40ce27240735443",
            "50e8a8b680918c1840bedfa1650e53f94c8823e81f6efd24d9e37fedfab9344f",
            "98b4a1c05a44708014a895d27923c7c20f3260e1bc9f2d5edcd6996e4d017944",
            "b840b87072d095849d433ec11ddd49b138f1823dae16268dcbe46d8035635e74",
            "b07b2199ad9258449889686423a3c9382cf428355ac348bce40c9d639edf6759",
            "302fcad55ae4b8f54ab3ab01eaf171873d38676075dff601e4b12a377c7c217d",
            "001d2489d7b8caab450822ee6393d0b9324da8af67fda2b2cba19b46f64de852",
            "3811067e9f19d35b2f7487eeb08076a9c4a459dec10791095ebae03bb613f375",
        ];

        let test_sc_te_public_keys = vec![
            "f165e1e5f7c290e52f2edef3fbab60cbae74bfd3274f8e5ee1de3345c954a166",
            "8f80338eef733ec67c601349c4a8251393b28deb722cfd0a91907744a26d3dab",
            "cc1983469486418cd66dcdc8664677c263487b736840cfd1532e144386fa7610",
            "88166617f91bc145b243c2ae6e1088f1208bf17311cca74dbf032fee25b219e0",
            "6f97404947a00311785785217b1759b002cbae16da26e0801f0dcbe4e00d5f45",
            "fb7a8589cbe59427b2e9c91a5091bf43cf2080f1d4f1947af0d214ca825076f0",
            "30da57cda802def8dfd764812f2e3c82eb2871b2a14e3bb634f2195ef733796d",
            "622c8cb09b558fecfc60ce1ec4b1e3014fe04f4628e06cad58ce9ded4d192a2d",
            "3733056f59780d2f17adf073582634940c6ae57d530345d28e9b6b7cf1d3dcfb",
            "423cb2cdd87b3e612517cf77e68d918914b0705d8937ef7e25b24a53620bc9d1",
            "f5206f3569998819efc57e83e8521110e9414c8dca8c5e96c173366e9acd958f",
            "f1785d4d2f6017ad7a25f795db5beb48d38d6f8cd44dcc3b7f321b8e2a5352fd",
        ];

        for (test_sc_secret, test_sc_public_key) in
            test_sc_secrets.into_iter().zip(test_sc_te_public_keys)
        {
            // hex string to byte array
            let secret_bytes = hex::decode(test_sc_secret).unwrap();

            // deserialize fe without caring about overflowing the modulus
            let secret = deserialize_fe_unchecked(secret_bytes);

            // Compute GENERATOR_TE^SECRET
            let te_public_key = SimulatedTEGroup::prime_subgroup_generator()
                .into_projective()
                .mul(&secret)
                .into_affine();

            assert!(te_public_key.group_membership_test());

            // Store the sign (last bit) of the X coordinate
            // The value is left-shifted to be used later in an OR operation
            let x_sign = if te_public_key.x.is_odd() {
                1 << 7
            } else {
                0u8
            };

            // Extract the public key bytes as Y coordinate
            let y_coordinate = te_public_key.y;
            let mut te_pk_bytes = serialize_to_buffer(&y_coordinate, None).unwrap();

            // Use the last (null) bit of the public key to store the sign of the X coordinate
            // Before this operation, the last bit of the public key (Y coordinate) is always 0 due to the field modulus
            let len = te_pk_bytes.len();
            te_pk_bytes[len - 1] |= x_sign;

            // Convert byte array to hex string
            assert_eq!(hex::encode(te_pk_bytes.clone()), test_sc_public_key);

            // Check that GENERATOR_SW^SECRET = convert_to_sw(TE_PK)
            let sw_public_key = SimulatedSWGroup::prime_subgroup_generator()
                .into_projective()
                .mul(&secret)
                .into_affine();

            assert!(sw_public_key.group_membership_test());
            assert_eq!(sw_public_key, convert_te_point_to_sw_point(te_public_key));

            // Check that the conversion from te_pk_bytes to sw_pk_bytes is consistent
            // with the computed SW point
            let sw_pk_bytes = convert_te_pk_to_sw_pk(te_pk_bytes.try_into().unwrap()).unwrap();

            let y_sign = if sw_public_key.y.is_odd() {
                1 << 7
            } else {
                0u8
            };
            let x_coordinate = sw_public_key.x;
            let mut expected_sw_pk_bytes = serialize_to_buffer(&x_coordinate, None).unwrap();
            let len = expected_sw_pk_bytes.len();
            expected_sw_pk_bytes[len - 1] |= y_sign;

            let expected_sw_pk_bytes: [u8; SC_PUBLIC_KEY_LENGTH] =
                expected_sw_pk_bytes.try_into().unwrap();
            assert_eq!(sw_pk_bytes, expected_sw_pk_bytes);
        }
    }
}
