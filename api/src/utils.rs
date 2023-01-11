use super::*;

macro_rules! log {
    ($msg: expr) => {{
        eprintln!("[{}:{}.{}] {:?}", file!(), line!(), column!(), $msg)
    }};
}

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
        .unwrap_or_else(|_| panic!("unable to write {} to buffer", type_name::<T>()))
}

pub(crate) fn return_jobject<'a, T: Sized>(
    _env: &'a JNIEnv,
    obj: T,
    class_path: &str,
) -> JObject<'a> {
    //Return field element
    let obj_ptr: jlong = Box::into_raw(Box::new(obj)) as i64;

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
        Err(e) => {
            log!(format!(
                "Error while deserializing {:?}: {:?}",
                class_path, e
            ));
            std::ptr::null::<jobject>() as jobject
        }
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
        .unwrap_or_else(|_| panic!("Should be able to read {} field", name))
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

#[allow(unused)]
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
        .unwrap_or_else(|_| panic!("Should be able to read {} field", name))
        .j()
        .unwrap() as u64
}

pub(crate) fn parse_int_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> u32 {
    _env.get_field(obj, name, "I")
        .unwrap_or_else(|_| panic!("Should be able to read {} field", name))
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
        .unwrap_or_else(|_| panic!("Should be able to get {} FieldElement", name))
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
        .get_field(obj, name, "Lcom/horizen/merkletreenative/MerklePath;")
        .expect("Should be able to get MerklePath field")
        .l()
        .unwrap();

    let t = _env
        .get_field(path_obj, "merklePathPointer", "J")
        .expect("Should be able to get field merklePathPointer");

    read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
}

pub(crate) fn cast_joptionint_to_rust_option<'a>(
    _env: &'a JNIEnv,
    opt_int: JObject<'a>,
) -> Option<u32> {
    if !_env
        .call_method(opt_int, "isPresent", "()Z", &[])
        .expect("Should be able to call isPresent method on OptionalInt object")
        .z()
        .unwrap()
    {
        None
    } else {
        Some(
            _env.call_method(opt_int, "getAsInt", "()I", &[])
                .expect("Should be able to unwrap a non empty Optional")
                .i()
                .unwrap() as u32,
        )
    }
}

pub(crate) fn parse_joption_from_jobject<'a>(
    _env: &'a JNIEnv,
    obj: JObject<'a>,
    opt_name: &str,
) -> Option<JObject<'a>> {
    // Parse Optional object
    let opt_object = _env
        .get_field(obj, opt_name, "Ljava/util/Optional;")
        .unwrap_or_else(|_| panic!("Should be able to get {} Optional", opt_name))
        .l()
        .unwrap();

    // Cast it to Rust option
    cast_joption_to_rust_option(_env, opt_object)
}

pub(crate) fn cast_joption_to_rust_option<'a>(
    _env: &'a JNIEnv,
    opt_object: JObject<'a>,
) -> Option<JObject<'a>> {
    if !_env
        .call_method(opt_object, "isPresent", "()Z", &[])
        .expect("Should be able to call isPresent method on Optional object")
        .z()
        .unwrap()
    {
        None
    } else {
        Some(
            _env.call_method(opt_object, "get", "()Ljava/lang/Object;", &[])
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
        .unwrap_or_else(|_| panic!("Should be able to get {}", field_name))
        .l()
        .unwrap()
        .cast()
}

pub(crate) fn extract_custom_fields(
    _env: &JNIEnv,
    _custom_fields_list: jobjectArray,
) -> Option<Vec<FieldElement>> {
    // Read custom fields if they are present
    let mut custom_fields_list = None;

    let custom_fields_list_size = _env
        .get_array_length(_custom_fields_list)
        .expect("Should be able to get custom_fields_list size");

    if custom_fields_list_size > 0 {
        let cfl_iter = JObjectArrayIter::new(_env, _custom_fields_list);
        let custom_fields: Vec<FieldElement> =
            cfl_iter.map(|c| *convert_field_element(_env, c)).collect();
        custom_fields_list = Some(custom_fields);
    }
    custom_fields_list
}

pub(crate) fn extract_public_key(
    _env: &JNIEnv,
    _key_list: jobjectArray,
) -> Vec<FieldBasedSchnorrPk<G2Projective>> {
    JObjectArrayIter::new(&_env, _key_list)
        .map(|s| {
            let pk = *convert_public_key(_env, s);
            FieldBasedSchnorrPk(pk.into_projective())
        })
        .collect()
}

pub(crate) fn extract_backward_transfers(
    _env: &JNIEnv,
    _bt_list: jobjectArray,
) -> Vec<BackwardTransfer> {
    // Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env
        .get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env
                .get_object_array_element(_bt_list, i)
                .unwrap_or_else(|_| panic!("Should be able to get elem {} of bt_list array", i));

            let p = _env
                .call_method(o, "getPublicKeyHash", "()[B", &[])
                .expect("Should be able to call getPublicKeyHash method")
                .l()
                .unwrap()
                .cast();

            let pk: [u8; 20] = _env
                .convert_byte_array(p)
                .expect("Should be able to convert to Rust byte array")
                .try_into()
                .expect("Should be able to write into fixed buffer of size 20");

            let a = _env
                .call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method")
                .j()
                .unwrap() as u64;

            bt_list.push((a, pk));
        }
    }

    bt_list
        .into_iter()
        .map(|bt_raw| BackwardTransfer {
            pk_dest: bt_raw.1,
            amount: bt_raw.0,
        })
        .collect::<Vec<_>>()
}

pub(crate) struct JObjectArrayIter<'a> {
    env: &'a JNIEnv<'a>,
    object_array: jobjectArray,
    index: jsize,
    length: jsize,
}

impl<'a> Iterator for JObjectArrayIter<'a> {
    type Item = JObject<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.length {
            None
        } else {
            let res = self
                .env
                .get_object_array_element(self.object_array, self.index)
                .unwrap_or_else(|_| panic!("Should be able to get list item at {}", self.index));
            self.index += 1;
            Some(res)
        }
    }
}

impl<'a> JObjectArrayIter<'a> {
    pub fn new(env: &'a JNIEnv, object_array: jobjectArray) -> Self {
        let length = env
            .get_array_length(object_array)
            .expect("Should be able to get list size");
        Self {
            env,
            object_array,
            index: 0,
            length,
        }
    }
}

pub(crate) fn convert_field_element<'a>(_env: &'a JNIEnv, _from: JObject) -> &'a FieldElement {
    convert_jobject(_env, _from, "fieldElementPointer")
}

pub(crate) fn convert_public_key<'a>(_env: &'a JNIEnv, _from: JObject) -> &'a SchnorrPk {
    convert_jobject(_env, _from, "publicKeyPointer")
}

#[allow(dead_code)]
pub(crate) fn convert_signature<'a>(_env: &'a JNIEnv, _from: JObject) -> &'a SchnorrSig {
    convert_jobject(_env, _from, "signaturePointer")
}

pub(crate) fn convert_option_signature(_env: &JNIEnv, _from: JObject) -> Option<SchnorrSig> {
    convert_option_jobject(_env, _from, "signaturePointer")
}

pub(crate) fn convert_jobject<'a, T>(_env: &'a JNIEnv, _from: JObject, name: &str) -> &'a T {
    let f = _env
        .get_field(_from, name, "J")
        .unwrap_or_else(|_| panic!("Should be able to get field {}", name));

    read_raw_pointer(&_env, f.j().unwrap() as *const T)
}

pub(crate) fn convert_option_jobject<T: Copy>(
    _env: &JNIEnv,
    _from: JObject,
    name: &str,
) -> Option<T> {
    let s = _env
        .get_field(_from, name, "J")
        .unwrap_or_else(|_| panic!("Should be able to get field {}", name));

    read_nullable_raw_pointer(s.j().unwrap() as *const T).copied()
}
