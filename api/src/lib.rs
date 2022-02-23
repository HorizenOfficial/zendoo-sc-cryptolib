#![allow(
    clippy::upper_case_acronyms,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::try_err,
    clippy::map_collect_result_unit,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::suspicious_op_assign_impl,
    clippy::suspicious_arithmetic_impl,
    clippy::assertions_on_constants
)]

pub mod cctp_calls;
pub mod rust_jni;

#[macro_export]
macro_rules! log {
    ($msg: expr) => {{
        eprintln!("[{}:{}.{}] {:?}", file!(), line!(), column!(), $msg)
    }};
}