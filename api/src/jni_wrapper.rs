use jni::{JNIEnv, objects::{JObject, JValue}, sys::jlong, errors::Error};

use crate::utils::{read_raw_pointer, read_mut_raw_pointer};


/// Define a simple java wrapper that hold the rust raw pointer in 
/// a `long` java value stored in the `INNER_FIELD` field.
pub(crate) trait JNINativeWrapper: Sized {
    /// The complete java package of the Wrapper class
    const JAVA_PACKAGE: &'static str;
    /// The java class name
    const JAVA_CLASS: &'static str;
    /// The inner field name
    const INNER_FIELD: &'static str;

    /// Return a reference to a Rust object that is wrapped on Java (maybe with a raw pointer)
    fn native<'a>(env: JNIEnv, wrapper: JObject) -> Result<&'a Self, jni::errors::Error> {
        env
            .get_field(wrapper, Self::INNER_FIELD, "J")
            .and_then(|field| field.j())
            .map(|fe| read_raw_pointer(&env, fe as *const Self))
    }

    /// Return a reference to a Rust object that is wrapped on Java (maybe with a raw pointer).
    /// It will panic if something go wrong.
    fn native_unchecked<'a>(env: JNIEnv, wrapper: JObject) -> &'a Self {
        Self::native(env, wrapper)
            .expect(&format!("Should be able to get field {}", Self::INNER_FIELD))
    }

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

/// If a struct implement this trait you can work also with the mutable reference
/// of the Rust elemt.
pub(crate) trait JNIMutNativeWrapper: JNINativeWrapper {
    /// Return a mutable reference to a Rust object that is wrapped on Java (maybe with a 
    /// raw pointer)
    fn native_mut<'a>(env: JNIEnv, wrapper: JObject) -> Result<&'a mut Self, jni::errors::Error> {
        env
            .get_field(wrapper, Self::INNER_FIELD, "J")
            .and_then(|field| field.j())
            .map(|fe| read_mut_raw_pointer(&env, fe as *mut Self))
    }

    /// Return a mutable reference to a Rust object that is wrapped on Java (maybe with a raw pointer).
    /// It will panic if something go wrong.
    fn native_mut_unchecked<'a>(env: JNIEnv, wrapper: JObject) -> &'a mut Self {
        Self::native_mut(env, wrapper)
            .expect(&format!("Should be able to get field {}", Self::INNER_FIELD))
    }
}
