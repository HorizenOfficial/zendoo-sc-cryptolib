use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jboolean, jint, jlong, jobject};
use crate::{read_raw_pointer, read_mut_raw_pointer};
use crate::ginger_calls::{FieldElement, leaf_to_index, GingerMHTPath, Error};
use crate::zenbox_smt::*;
use std::any::TypeId;
use std::ptr::null_mut;

fn get_field_name<'a, T: 'static>() -> &'a str {
    if TypeId::of::<T>() == TypeId::of::<ZenBoxSMT>(){
        "merkleTreePointer"
    } else if TypeId::of::<T>() == TypeId::of::<FieldElement>(){
        "fieldElementPointer"
    } else {
        panic!("Unknown type of a pointer")
    }
}

fn get_raw_ptr<T: 'static>(env: &JNIEnv, ptr: JObject) -> *mut T {
    let field_name = get_field_name::<T>();
    let fe = env.get_field(ptr, field_name, "J")
        .expect(&("Should be able to get field ".to_owned() + field_name));
    fe.j().unwrap() as *mut T
}

fn unwrap_ptr<'a, T: 'static>(env: &JNIEnv, ptr: JObject) -> &'a T {
    read_raw_pointer(get_raw_ptr(env, ptr))
}

fn unwrap_mut_ptr<'a, T: 'static>(env: &JNIEnv, ptr: JObject) -> &'a mut T {
    read_mut_raw_pointer(get_raw_ptr(env, ptr))
}

fn create_zenbox_smt_object(env: &JNIEnv, class: &JClass, zmt_result: Result<ZenBoxSMT, Error>) -> jobject {
    // Wrapping zmt into a Box and getting a raw pointer as jlong
    let zmt_ptr: jlong = jlong::from(
        if let Ok(zmt) = zmt_result {
            Box::into_raw(Box::new(zmt)) as i64
        } else {
            null_mut::<ZenBoxSMT>() as i64
        }
    );
    // Create and return new ZenBoxSMT Java-object
    env.new_object(*class, "(J)V", &[JValue::Long(zmt_ptr)])
        .expect("Should be able to create new ZenBoxMerkleTree object")
        .into_inner()
}

fn create_field_element_object(env: &JNIEnv, field_element_opt: Option<FieldElement>) -> jobject {
    let fe_ptr: jlong = jlong::from(
        if let Some(field_element) = field_element_opt {
            Box::into_raw(Box::new(field_element)) as i64
        } else {
            null_mut::<FieldElement>() as i64
        }
    );
    let fe_class = env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    env.new_object(fe_class, "(J)V", &[JValue::Long(fe_ptr)])
        .expect("Cannot create FieldElement object.")
        .into_inner()
}

fn create_merkle_path_object(env: &JNIEnv, path: GingerMHTPath) -> jobject {
    let path_ptr: jlong = jlong::from(Box::into_raw(Box::new(path)) as i64);

    let path_class = env.find_class("com/horizen/merkletreenative/MerklePath")
        .expect("Cannot find MerklePath class.");

    env.new_object(path_class, "(J)V", &[JValue::Long(path_ptr)])
        .expect("Cannot create MerklePath object.")
        .into_inner()
}

////////////ZENBOX MERKLE TREE

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeInit(
    _env: JNIEnv,
    _class: JClass,
    _height: jint,
    _db_path: JString,
) -> jobject
{
    let db_path = _env.get_string(_db_path)
        .expect("Should be able to read jstring as Rust String");

    create_zenbox_smt_object(
        &_env,
        &_class,
        get_zenbox_smt( // Creating new ZenBoxSMT at the Rust side
            _height as usize,
            db_path.to_str().unwrap(),
        )
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeGetPosition(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
) -> jlong
{
    get_position_in_zenbox_smt(
        unwrap_ptr(&_env, _tree),
        unwrap_ptr(&_env, _leaf)
    ) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeGetAbsolutePosition(
    _env: JNIEnv,
    _class: JClass,
    _leaf: JObject,
    _height: jint,
) -> jlong
{
    leaf_to_index(
        unwrap_ptr(&_env, _leaf),
        _height as usize
    ) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeIsPositionEmpty(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong,
) -> jboolean
{
    is_position_empty_in_zenbox_smt(
        unwrap_ptr(&_env, _tree),
        _position as u64
    ) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeIsBoxSpent(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong,
) -> jboolean
{
    is_box_spent(
        unwrap_ptr(&_env, _tree),
        _position as u64
    ) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeAddBox(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
    _position: jlong,
)
{
    add_box_to_zenbox_smt(
        unwrap_mut_ptr(&_env, _tree),
        unwrap_ptr(&_env, _leaf),
        _position as u64
    );
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeRemoveBox(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong,
)
{
    remove_box_from_zenbox_smt(
        unwrap_mut_ptr(&_env, _tree),
        _position as u64
    );
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeGetBox(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong
) -> jobject
{
    create_field_element_object(
        &_env,
        get_box_from_zenbox_smt(
            unwrap_ptr(&_env, _tree),
            _position as u64
        )
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeStateRoot(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    create_field_element_object(
        &_env,
        Some(get_state_root(
            unwrap_ptr(&_env, _tree)
        ))
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeBitvectorRoot(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    create_field_element_object(
        &_env,
        Some(get_bitvector_root(
            unwrap_ptr(&_env, _tree)
        ))
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeGetStateMerklePath(
    _env: JNIEnv,
    _tree: JObject,
    _leaf_position: jlong,
) -> jobject
{
    create_merkle_path_object(
        &_env,
        get_state_path(
            unwrap_mut_ptr(&_env, _tree),
            _leaf_position as u64
        )
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeGetBitvectorMerklePath(
    _env: JNIEnv,
    _tree: JObject,
    _leaf_position: jlong,
) -> jobject
{
    create_merkle_path_object(
        &_env,
        get_bitvector_path(
            unwrap_mut_ptr(&_env, _tree),
            _leaf_position as u64
        )
    )
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeResetBitvector(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut ZenBoxSMT,
) -> jlong
{
    if !_tree.is_null(){
        let zmt = unsafe { Box::from_raw(_tree) };
        let new_zmt = reset_bitvector(*zmt).unwrap();
        jlong::from(Box::into_raw(Box::new(new_zmt)) as i64)
    } else {
        return 0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeFlush(
    _env: JNIEnv,
    _tree: JObject,
)
{
    flush_zenbox_smt(unwrap_mut_ptr(&_env, _tree))
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeFree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut ZenBoxSMT,
)
{
    if !_tree.is_null(){
        drop(unsafe { Box::from_raw(_tree) })
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_ZenBoxMerkleTree_nativeFreeAndDestroy(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut ZenBoxSMT,
)
{
    if !_tree.is_null(){
        let tree = read_mut_raw_pointer(_tree);
        set_zenbox_smt_persistency(tree, false);

        drop(unsafe { Box::from_raw(_tree) });
    }
}
