use super::*;

pub(crate) fn read_raw_pointer<'a, T>(env: &JNIEnv, input: *const T) -> &'a T {
    if input.is_null() {
        throw_and_exit!(
            env,
            "java/lang/NullPointerException",
            "Received null pointer"
        );
    }
    unsafe { &*input }
}

pub(crate) fn read_mut_raw_pointer<'a, T>(env: &JNIEnv, input: *mut T) -> &'a mut T {
    if input.is_null() {
        throw_and_exit!(
            env,
            "java/lang/NullPointerException",
            "Received null pointer"
        );
    }
    unsafe { &mut *input }
}

pub(crate) fn read_nullable_raw_pointer<'a, T>(input: *const T) -> Option<&'a T> {
    unsafe { input.as_ref() }
}

pub(crate) fn serialize_from_raw_pointer<T: CanonicalSerialize>(
    _env: &JNIEnv,
    to_write: *const T,
    compressed: Option<bool>,
) -> Vec<u8> {
    serialize_to_buffer(read_raw_pointer(&_env, to_write), compressed)
        .expect(format!("unable to write {} to buffer", type_name::<T>()).as_str())
}

pub(crate) fn return_jobject<'a, T: Sized>(
    _env: &'a JNIEnv,
    obj: T,
    class_path: &str,
) -> JObject<'a> {
    //Return field element
    let obj_ptr: jlong = jlong::from(Box::into_raw(Box::new(obj)) as i64);

    let obj_class = _env
        .find_class(class_path)
        .expect("Should be able to find class");

    _env.new_object(obj_class, "(J)V", &[JValue::Long(obj_ptr)])
        .expect("Should be able to create new jobject")
}

pub(crate) fn return_field_element(_env: &JNIEnv, fe: FieldElement) -> jobject {
    return_jobject(_env, fe, "com/horizen/librustsidechains/FieldElement").into_inner()
}

pub(crate) fn deserialize_to_jobject<T: CanonicalDeserialize + SemanticallyValid>(
    _env: &JNIEnv,
    obj_bytes: jbyteArray,
    checked: Option<jboolean>, // Can be none for types with trivial checks or without themn
    compressed: Option<jboolean>, // Can be none for uncompressable types
    class_path: &str,
) -> jobject {
    let obj_bytes = _env
        .convert_byte_array(obj_bytes)
        .expect("Cannot read bytes.");

    let obj = deserialize_from_buffer::<T>(
        obj_bytes.as_slice(),
        checked.map(|jni_bool| jni_bool == JNI_TRUE),
        compressed.map(|jni_bool| jni_bool == JNI_TRUE),
    );

    match obj {
        Ok(obj) => *return_jobject(&_env, obj, class_path),
        Err(_) => std::ptr::null::<jobject>() as jobject,
    }
}

pub(crate) fn serialize_from_jobject<T: CanonicalSerialize>(
    _env: &JNIEnv,
    obj: JObject,
    ptr_name: &str,
    compressed: Option<jboolean>, // Can be none for uncompressable types
) -> jbyteArray {
    let pointer = _env
        .get_field(obj, ptr_name, "J")
        .expect("Cannot get object raw pointer.");

    let obj_bytes = serialize_from_raw_pointer(
        _env,
        pointer.j().unwrap() as *const T,
        compressed.map(|jni_bool| jni_bool == JNI_TRUE),
    );

    _env.byte_array_from_slice(obj_bytes.as_slice())
        .expect("Cannot write object.")
}

pub(crate) fn parse_jbyte_array_to_vec(
    _env: &JNIEnv,
    java_byte_array: &jbyteArray,
    length: usize,
) -> Vec<u8> {
    let vec = _env
        .convert_byte_array(*java_byte_array)
        .expect("Should be able to convert to Rust array");

    if vec.len() != length {
        panic!(
            "Retrieved array size {} expected to be {}.",
            vec.len(),
            length
        );
    }

    vec
}

pub(crate) fn get_byte_array(_env: &JNIEnv, java_byte_array: &jbyteArray, buffer: &mut [u8]) {
    let vec = _env
        .convert_byte_array(*java_byte_array)
        .expect("Should be able to convert to Rust array");

    for (pos, e) in vec.iter().enumerate() {
        buffer[pos] = *e;
    }
}

fn parse_jbyte_array_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> jbyteArray {
    _env.get_field(obj, name, "[B")
        .expect(format!("Should be able to read {} field", name).as_str())
        .l()
        .unwrap()
        .cast()
}

#[allow(unused)]
pub(crate) fn parse_byte_array_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> Vec<u8> {
    _env.convert_byte_array(parse_jbyte_array_from_jobject(_env, obj, name))
        .unwrap()
}

pub(crate) fn parse_fixed_size_byte_array_from_jobject<const N: usize>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> [u8; N] {
    let j_bytes = parse_jbyte_array_from_jobject(_env, obj, name);
    parse_jbyte_array_to_vec(_env, &j_bytes, N)
        .try_into()
        .unwrap()
}

pub(crate) fn parse_fixed_size_bits_from_jbytearray_in_jobject<const N: usize>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> [bool; N] {
    let j_bytes = parse_jbyte_array_from_jobject(_env, obj, name);
    let len = (N as f32 / 8f32).ceil() as usize;
    let fixed_bytes = parse_jbyte_array_to_vec(_env, &j_bytes, len);
    bytes_to_bits(&fixed_bytes)[..N].try_into().unwrap()
}

pub(crate) fn parse_long_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> u64 {
    _env.get_field(obj, name, "J")
        .expect(format!("Should be able to read {} field", name).as_str())
        .j()
        .unwrap() as u64
}

pub(crate) fn parse_int_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> u32 {
    _env.get_field(obj, name, "I")
        .expect(format!("Should be able to read {} field", name).as_str())
        .i()
        .unwrap() as u32
}

pub(crate) fn parse_field_element_from_jobject<'a>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> &'a FieldElement {
    let field_object = _env
        .get_field(obj, name, "Lcom/horizen/librustsidechains/FieldElement;")
        .expect(format!("Should be able to get {} FieldElement", name).as_str())
        .l()
        .unwrap();

    let f = _env
        .get_field(field_object, "fieldElementPointer", "J")
        .expect("Should be able to get field fieldElementPointer");

    read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
}

pub(crate) fn parse_merkle_path_from_jobject<'a>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> &'a GingerMHTPath {
    let path_obj = _env
        .get_field(obj, name, "Lcom/horizen/merkletreenative/MerklePath")
        .expect("Should be able to get MerklePath field")
        .l()
        .unwrap();

    let t = _env
        .get_field(path_obj, "merklePathPointer", "J")
        .expect("Should be able to get field merklePathPointer");

    read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
}

pub(crate) fn cast_joption_to_rust_option<'a>(
    _env: &'a JNIEnv,
    obj: JObject<'a>,
    opt_name: &str,
    wrapped_obj_class_path: &str,
) -> Option<JObject<'a>> {
    // Parse Optional object
    let opt_object = _env
        .get_field(obj, opt_name, "Ljava/util/Optional;")
        .expect(format!("Should be able to get {} Optional", opt_name).as_str())
        .l()
        .unwrap();

    if !_env
        .call_method(opt_object, "isPresent", "()Z", &[])
        .expect("Should be able to call isPresent method on Optional object")
        .z()
        .unwrap()
    {
        None
    } else {
        Some(
            _env.call_method(
                opt_object,
                "get",
                format!("()L{};", wrapped_obj_class_path).as_str(),
                &[],
            )
            .expect("Should be able to unwrap a non empty Optional")
            .l()
            .unwrap(),
        )
    }
}

pub(crate) fn parse_jobject_array_from_jobject(
    _env: &JNIEnv,
    obj: JObject,
    field_name: &str,
    list_obj_name: &str,
) -> jobjectArray {
    _env.get_field(obj, field_name, format!("[L{};", list_obj_name).as_str())
        .expect(format!("Should be able to get {}", field_name).as_str())
        .l()
        .unwrap()
        .cast()
}
