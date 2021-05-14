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

pub mod naive_threshold_sig;
pub use self::naive_threshold_sig::*;

pub mod constants;
pub use self::constants::*;

pub mod type_mapping;
pub use self::type_mapping::*;


use r1cs_core::ConstraintSynthesizer;
use cctp_primitives::{
    proving_system::{
        ProvingSystem, ZendooProverKey, ZendooVerifierKey,
        init::get_g1_committer_key,
        error::ProvingSystemError
    },
    utils::serialization::write_to_file,
};
use std::path::Path;

/// Utility function: generate and save to specified paths the SNARK proving and
/// verification key associated to circuit `circ`.
pub fn generate_circuit_keypair<C: ConstraintSynthesizer<FieldElement>>(
    circ: C,
    proving_system: ProvingSystem,
    pk_path: &Path,
    vk_path: &Path,
) -> Result<(), Error>
{
    let g1_ck = get_g1_committer_key()?;
    match proving_system {
        ProvingSystem::Undefined => return Err(ProvingSystemError::UndefinedProvingSystem)?,
        ProvingSystem::CoboundaryMarlin => {
            let (pk, vk) = CoboundaryMarlin::index(g1_ck.as_ref().unwrap(), circ)?;
            write_to_file(&ZendooProverKey::CoboundaryMarlin(pk), pk_path)?;
            write_to_file(&ZendooVerifierKey::CoboundaryMarlin(vk), vk_path)?;
        },
        ProvingSystem::Darlin => unimplemented!()
    }

    Ok(())
}