use cctp_primitives::{
    type_mapping::{Error, FieldElement, FIELD_SIZE},
    utils::serialization::serialize_to_buffer,
};
use r1cs_std::boolean::Boolean;

use crate::read_field_element_from_buffer_with_padding;

pub fn boolean_slice_to_string(vec: &[Boolean]) -> String {
    let mut result = String::new();
    for item in vec {
        if item.get_value().is_none() {
            return String::from("");
        }
        result.push_str(&format!(
            "{}",
            if item.get_value().unwrap() { '1' } else { '0' }
        ));
    }
    result
}

pub fn bool_slice_to_string(vec: &[bool]) -> String {
    let mut result = String::new();
    for item in vec {
        result.push_str(&format!("{}", if *item { '1' } else { '0' }));
    }
    result
}

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

#[cfg(test)]
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
        let restored_fe = fe_1 + &(pow * &fe_2);
        assert_eq!(fe, restored_fe);
    }
}
