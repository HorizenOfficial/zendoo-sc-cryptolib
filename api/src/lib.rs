#![allow(
    clippy::upper_case_acronyms,
    clippy::too_many_arguments,
    clippy::try_err,
    clippy::map_collect_result_unit,
    clippy::not_unsafe_ptr_arg_deref
)]

use type_mappings::{instantiated::tweedle::*, macros::*};

mod cctp_calls;
mod rust_jni;
pub const MC_PK_SIZE: usize = 20;
