use r1cs_std::boolean::Boolean;

pub fn boolean_slice_to_string(vec: &[Boolean]) -> String {
    let mut result = String::new();
    for i in 0..vec.len() {
        if vec[i].get_value().is_none() {
            return String::from("");
        }
        result.push_str(&format!(
            "{}",
            if vec[i].get_value().unwrap() {
                '1'
            } else {
                '0'
            }
        ));
    }
    result
}

pub fn bool_slice_to_string(vec: &[bool]) -> String {
    let mut result = String::new();
    for i in 0..vec.len() {
        result.push_str(&format!("{}", if vec[i] { '1' } else { '0' }));
    }
    result
}