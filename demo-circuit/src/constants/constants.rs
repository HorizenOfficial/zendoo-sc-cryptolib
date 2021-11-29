//ASCII hex string
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"53756e4d65726375727956656e757345617274684d6172734a75706974657253";

// BLAKE2s invocation personalizations

/// BLAKE2s Personalization for NULL_PK in NaiveThresholdSigCircuit
pub const NULL_PK_PERSONALIZATION: &[u8; 8] = b"ZenullPK";

// Group hash personalizations
/// BLAKE2s Personalization for Group hash generators used for VRF.
pub const VRF_GROUP_HASH_GENERATORS_PERSONALIZATION: &[u8; 8] = b"ZenVrfPH";

// TODO: define the correct max value.
// It might be a parameter of the circuit (since it depends on the epoch length and it is fixed after creation).
pub const CSW_TRANSACTION_COMMITMENT_HASHES_NUMBER: usize = 100;

pub enum BoxType {
    NonCoinBox = 0,
    CoinBox = 1,
}
