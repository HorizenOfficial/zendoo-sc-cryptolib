#![deny(
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![deny(
    unused_qualifications,
    variant_size_differences,
    stable_features,
    unreachable_pub
)]
#![deny(
    non_shorthand_field_patterns,
    unused_attributes,
    unused_imports,
    unused_extern_crates
)]
#![deny(
    renamed_and_removed_lints,
    stable_features,
    unused_allocation,
    unused_comparisons,
    bare_trait_objects
)]
#![deny(
    const_err,
    unused_must_use,
    unused_mut,
    unused_unsafe,
    private_in_public,
    unsafe_code
)]
#![forbid(unsafe_code)]
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

pub mod naive_threshold_sig;
pub mod utils;
pub use self::naive_threshold_sig::*;

pub mod constants;
pub use self::constants::*;

pub mod type_mapping;
pub use self::type_mapping::*;

pub mod blaze_csw;
pub use self::blaze_csw::*;

use algebra::SerializationError;
use cctp_primitives::{
    proving_system::{
        compute_proof_vk_size, error::ProvingSystemError, init::get_g1_committer_key,
        ProvingSystem, ZendooProverKey, ZendooVerifierKey,
    },
    utils::serialization::write_to_file,
};
use r1cs_core::ConstraintSynthesizer;
use std::path::Path;

//Will return error if buffer.len > FIELD_SIZE. If buffer.len < FIELD_SIZE, padding 0s will be added
pub fn read_field_element_from_buffer_with_padding(
    buffer: &[u8],
) -> Result<FieldElement, SerializationError> {
    let buff_len = buffer.len();

    //Pad to reach field element size
    let mut new_buffer = Vec::new();
    new_buffer.extend_from_slice(buffer);

    for _ in buff_len..FIELD_SIZE {
        new_buffer.push(0u8)
    } //Add padding zeros to reach field size

    algebra::serialize::CanonicalDeserialize::deserialize(new_buffer.as_slice())
}

/// Utility function: generate and save to specified paths the SNARK proving and
/// verification key associated to circuit `circ`. Check that their sizes are
/// compatible with `max_proof_size` and `max_vk_size`.
pub fn generate_circuit_keypair<C: ConstraintSynthesizer<FieldElement>>(
    circ: C,
    proving_system: ProvingSystem,
    pk_path: &Path,
    vk_path: &Path,
    max_proof_plus_vk_size: usize,
    zk: bool,
    compress_pk: Option<bool>,
    compress_vk: Option<bool>,
) -> Result<(), Error> {
    let g1_ck = get_g1_committer_key()?;
    match proving_system {
        ProvingSystem::Undefined => return Err(ProvingSystemError::UndefinedProvingSystem)?,
        ProvingSystem::CoboundaryMarlin => {
            let index = CoboundaryMarlin::get_index_info(circ)?;
            let (proof_size, vk_size) = compute_proof_vk_size(
                g1_ck.as_ref().unwrap().comm_key.len().next_power_of_two(),
                index.index_info,
                zk,
                proving_system,
            );
            if proof_size + vk_size > max_proof_plus_vk_size {
                return Err(ProvingSystemError::SetupFailed(format!(
                    "Circuit is too complex: Max supported proof + vk size: {}, Actual proof + vk size: {}",
                    max_proof_plus_vk_size, proof_size + vk_size
                )))?;
            }
            let (pk, vk) =
                CoboundaryMarlin::circuit_specific_setup(g1_ck.as_ref().unwrap(), index)?;
            write_to_file(&ZendooProverKey::CoboundaryMarlin(pk), pk_path, compress_pk)?;
            write_to_file(
                &ZendooVerifierKey::CoboundaryMarlin(vk),
                vk_path,
                compress_vk,
            )?;
        }
        ProvingSystem::Darlin => unimplemented!(),
    }

    Ok(())
}
