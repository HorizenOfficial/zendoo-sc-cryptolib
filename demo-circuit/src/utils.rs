use r1cs_std::boolean::Boolean;

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
