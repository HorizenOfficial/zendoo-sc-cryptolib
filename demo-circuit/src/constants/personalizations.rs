//ASCII hex string
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"53756e4d65726375727956656e757345617274684d6172734a75706974657253";

// BLAKE2s invocation personalizations

/// BLAKE2s Personalization for NULL_PK in NaiveThresholdSigCircuit
pub const CERT_NULL_PK_PERSONALIZATION: &[u8; 8] = b"ZenullPK";

/// BLAKE2s Personalization for NULL_TE_PK in CSWCircuit
pub const CSW_NULL_TE_PK_PERSONALIZATION: &[u8; 8] = b"ZenCSWPK";

// Group hash personalizations
/// BLAKE2s Personalization for Group hash generators used for VRF.
pub const VRF_GROUP_HASH_GENERATORS_PERSONALIZATION: &[u8; 8] = b"ZenVrfPH";

pub enum BoxType {
    NonCoinBox = 0,
    CoinBox = 1,
}
