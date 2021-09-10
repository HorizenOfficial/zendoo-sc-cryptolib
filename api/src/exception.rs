use jni::JNIEnv;
use std::{error::Error, any::Any};

/// Tries to get meaningful description from panic-error.
pub(crate) fn any_to_string(any: Box<dyn Any + Send>) -> String {
    if let Some(s) = any.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = any.downcast_ref::<String>() {
        s.clone()
    } else if let Some(error) = any.downcast_ref::<Box<dyn Error + Send>>() {
        error.to_string()
    } else {
        "Unknown error occurred".to_string()
    }
}

pub(crate) fn _throw_inner(env: &JNIEnv, exception: &str, description: &str) {
    // Do nothing if there is a pending Java-exception that will be thrown
    // automatically by the JVM when the native method returns.
    if !env.exception_check().unwrap() {
        let exception_class = env.find_class(exception)
            .expect(&format!("Unable to find {} class", exception));

        env.throw_new(exception_class, description)
            .expect(&format!("Should be able to throw {}", exception));
    }
}

/// Calls a corresponding `JNIEnv` method and immediately returns to the Java caller.
/// WARNING: Always run this function from within a catch_unwind closure.
/// It's a bit dirty but it allows to mimic the behaviour of an exception thrown in Java.
pub(crate) fn throw(env: &JNIEnv, exception: &str, description: &str) {
    // If _throw_inner panics, and this function is called from within a catch_unwind
    // closure as it's supposed to be, a RuntimeException will be thrown (if called
    // from a function built using the ffi_export! macro).
    _throw_inner(env, exception, description);
    panic!("Thrown exception: {} for reason: {}", exception, description)
}

/// Transform a function into an implementation of a Java side native function.
/// Requirements:
/// 1) The name of the function must still obey to JNI standards;
/// 2) First argument must be of type JNIEnv;
/// This macro also automatically wraps the function body into a catch_unwind()
/// closure, and returns a RuntimeException in case of panic, without unwinding
/// into the caller.
/// Note: In order to do this, the library must be compiled with panic = "unwind".
macro_rules! ffi_export {

    // For functions returning jobject
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $env:ident : $env_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> jobject $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "system" fn $fn_name($env: $env_ty, $($arg : $arg_ty),*) -> jobject {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $body)) {
                Ok(x) => return x,
                Err(e1) => {
                    match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(
                        move || _throw_inner(&$env, "java/lang/RuntimeException", &any_to_string(e1))
                    )) {
                        Ok(_) => std::ptr::null::<jobject>() as jobject,
                        Err(e2) => {
                            // At this level, _throw_inner call shouldn't panic. But if, for some reason,
                            // it panics again, then we have no choice but to abort the process (to avoid
                            // unwinding across the FFI)
                            eprintln!("{:?}", &any_to_string(e2));
                            std::process::abort();
                        }
                    }
                }
            }
        }
    );

    // For functions returning jbyteArray
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $env:ident : $env_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> jbyteArray $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "system" fn $fn_name($env: $env_ty, $($arg : $arg_ty),*) -> jobject {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $body)) {
                Ok(x) => return x,
                Err(e1) => {
                    match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(
                        move || _throw_inner(&$env, "java/lang/RuntimeException", &any_to_string(e1))
                    )) {
                        Ok(_) => std::ptr::null::<jobject>() as jobject,
                        Err(e2) => {
                            // At this level, _throw_inner call shouldn't panic. But if, for some reason,
                            // it panics again, then we have no choice but to abort the process (to avoid
                            // unwinding across the FFI)
                            eprintln!("{:?}", &any_to_string(e2));
                            std::process::abort();
                        }
                    }
                }
            }
        }
    );

    // For functions returning a type implementing Default
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $env:ident : $env_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> $ret_ty:ty $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "system" fn $fn_name($env : $env_ty, $($arg : $arg_ty),*) -> $ret_ty {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| $body)) {
                Ok(x) => return x,
                Err(e1) => {
                    match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(
                        move || _throw_inner(&$env, "java/lang/RuntimeException", &any_to_string(e1))
                    )) {
                        Ok(_) => <$ret_ty as Default>::default(),
                        Err(e2) => {
                            // At this level, _throw_inner call shouldn't panic. But if, for some reason,
                            // it panics again, then we have no choice but to abort the process (to avoid
                            // unwinding across the FFI)
                            eprintln!("{:?}", &any_to_string(e2));
                            std::process::abort();
                        }
                    }
                }
            }
        }
    );

    // For functions returning void
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
             $env:ident : $env_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "system" fn $fn_name($env : $env_ty, $($arg : $arg_ty),*) {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $body)) {
                Ok(x) => return x,
                Err(e1) => {
                    match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(
                        move || _throw_inner(&$env, "java/lang/RuntimeException", &any_to_string(e1))
                    )) {
                        Ok(_) => {},
                        Err(e2) => {
                            // At this level, _throw_inner call shouldn't panic. But if, for some reason,
                            // it panics again, then we have no choice but to abort the process (to avoid
                            // unwinding across the FFI)
                            eprintln!("{:?}", &any_to_string(e2));
                            std::process::abort();
                        }
                    }
                }
            }
        }
    );
}