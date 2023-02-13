use jni::{JNIEnv, objects::{JObject, JValue}, sys::jlong, errors::Error};

use crate::utils::{read_raw_pointer, read_mut_raw_pointer};

/// Define how to map the entity into a native Rust reference. It is implemented just for
/// everything that can be converted into a `JObject`.
pub(crate) trait AsNativeRef<'j, 'e:'j, T: JNINativeWrapper>: Sized + Into<JObject<'j>>{
    /// Return a reference to a Rust object that is wrapped on Java (maybe with a raw pointer)
    fn as_native_ref(self, env: JNIEnv<'e>) -> Result<&'j T, jni::errors::Error> {
        env.get_field(self, T::INNER_FIELD, "J")
            .and_then(|field| field.j())
            .map(|fe| read_raw_pointer(&env, fe as *const T))
    }

    /// Return a reference to a Rust object that is wrapped on Java (maybe with a raw pointer).
    /// It will panic if something go wrong.
    fn as_native_ref_unchecked(self, env: JNIEnv<'e>) -> &'j T {
        Self::as_native_ref(self, env)
            .expect(&format!("Should be able to get field {}", T::INNER_FIELD))
    }
}

/// Define how to map the entity into a native mutable Rust reference. It is implemented just for
/// everything that can be converted into a `JObject`.
pub(crate) trait AsNativeRefMut<'j, 'e:'j, T: JNINativeWrapper>: AsNativeRef<'j, 'e, T> {
    /// Return a mutable reference to a Rust object that is wrapped on Java (maybe with a 
    /// raw pointer)
    fn as_native_mut_ref(self, env: JNIEnv<'e>) -> Result<&'j mut T, jni::errors::Error>{
        env.get_field(self, T::INNER_FIELD, "J")
            .and_then(|field| field.j())
            .map(|fe| read_mut_raw_pointer(&env, fe as *mut T))
    }

    /// Return a mutable reference to a Rust object that is wrapped on Java (maybe with a raw pointer).
    /// It will panic if something go wrong.
    fn as_native_ref_mut_unchecked(self, env: JNIEnv<'e>) -> &'j mut T {
        Self::as_native_mut_ref(self, env)
            .expect(&format!("Should be able to get field {}", T::INNER_FIELD))
    }
}

impl<'j, 'e: 'j, T: JNINativeWrapper, J: Into<JObject<'j>>> AsNativeRef<'j, 'e, T> for J {}
impl<'j, 'e: 'j, T: JNINativeWrapper, J: Into<JObject<'j>>> AsNativeRefMut<'j, 'e, T> for J {}

/// Define a simple java wrapper that hold the rust raw pointer in 
/// a `long` java value stored in the `INNER_FIELD` field. You should
/// define the package in `JAVA_PACKAGE` and the java class name
/// in `INNER_FIELD`.
pub(crate) trait JNINativeWrapper: Sized {
    /// The complete java package of the Wrapper class
    const JAVA_PACKAGE: &'static str;
    /// The java class name
    const JAVA_CLASS: &'static str;
    /// The inner field name
    const INNER_FIELD: &'static str;

    /// Return the Java object that wrap the Rust one
    fn wrap(self, env: JNIEnv) -> Result<JObject, Error> {
        let ptr: jlong = Box::into_raw(Box::new(self)) as i64;
        env
            .find_class(Self::path())
            .and_then(|cls| 
                env.new_object(cls, "(J)V", &[JValue::Long(ptr)])
            )
    }

    /// Return the Java object that wrap the Rust one. It will panic if something goes wrong.
    fn wrap_unchecked(self, env: JNIEnv) -> JObject {
        self.wrap(env)
            .expect(&format!("Should be able to create {} object", Self::JAVA_CLASS))
    }

    /// Dealloc the raw pointer
    fn free(ptr: *mut Self) {
        if ptr.is_null() {
            return;
        }
        drop(unsafe { Box::from_raw(ptr) });
    }

    /// The full path of the class
    fn path() -> String {
        format!("{}/{}", Self::JAVA_PACKAGE, Self::JAVA_CLASS)
    }
}
