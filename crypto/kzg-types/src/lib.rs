use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use derivative::Derivative;
use ethereum_hashing::hash_fixed;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz_derive::{Decode, Encode};
use tree_hash::{Hash256, PackedEncoding, TreeHash};

pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_BLOB: usize = 131072;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_PROOF: usize = 48;
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

#[derive(Debug)]
pub enum Error {
    /// An error from the underlying kzg library.
    Kzg(String),
    /// A prover/verifier error from the rust-eth-kzg library.
    PeerDASKZG(rust_eth_kzg::Error),
    /// The kzg verification failed
    KzgVerificationFailed,
    /// Misc indexing error
    InconsistentArrayLength(String),
    /// Error reconstructing data columns.
    ReconstructFailed(String),
    /// Kzg was not initialized with PeerDAS enabled.
    DASContextUninitialized,
}

#[derive(PartialEq, Hash, Clone, Copy, Encode, Decode)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgProof(pub [u8; BYTES_PER_PROOF]);

impl KzgProof {
    /// Creates a valid proof using [`G1_POINT_AT_INFINITY`]
    pub fn empty() -> Self {
        let mut bytes = [0; BYTES_PER_PROOF];
        bytes[0] = 0xc0;
        Self(bytes)
    }
}

impl fmt::Display for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0))
    }
}

impl From<[u8; BYTES_PER_PROOF]> for KzgProof {
    fn from(bytes: [u8; BYTES_PER_PROOF]) -> Self {
        Self(bytes)
    }
}

impl From<KzgProof> for [u8; BYTES_PER_PROOF] {
    fn from(from: KzgProof) -> [u8; BYTES_PER_PROOF] {
        from.0
    }
}

impl TreeHash for KzgProof {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; BYTES_PER_PROOF]>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; BYTES_PER_PROOF]>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl Serialize for KzgProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KzgProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

impl FromStr for KzgProof {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("0x") {
            let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
            if bytes.len() == BYTES_PER_PROOF {
                let mut kzg_proof_bytes = [0; BYTES_PER_PROOF];
                kzg_proof_bytes[..].copy_from_slice(&bytes);
                Ok(Self(kzg_proof_bytes))
            } else {
                Err(format!(
                    "InvalidByteLength: got {}, expected {}",
                    bytes.len(),
                    BYTES_PER_PROOF
                ))
            }
        } else {
            Err("must start with 0x".to_string())
        }
    }
}

impl Debug for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0))
    }
}

impl arbitrary::Arbitrary<'_> for KzgProof {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BYTES_PER_PROOF];
        u.fill_buffer(&mut bytes)?;
        Ok(KzgProof(bytes))
    }
}

#[derive(Derivative, Clone, Copy, Encode, Decode)]
#[derivative(PartialEq, Eq, Hash)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgCommitment(pub [u8; BYTES_PER_COMMITMENT]);

impl KzgCommitment {
    pub fn calculate_versioned_hash(&self) -> Hash256 {
        let mut versioned_hash = hash_fixed(&self.0);
        versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
        Hash256::from_slice(versioned_hash.as_slice())
    }

    pub fn empty_for_testing() -> Self {
        KzgCommitment([0; BYTES_PER_COMMITMENT])
    }
}

impl Display for KzgCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for i in &self.0[0..2] {
            write!(f, "{:02x}", i)?;
        }
        write!(f, "…")?;
        for i in &self.0[BYTES_PER_COMMITMENT - 2..BYTES_PER_COMMITMENT] {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl TreeHash for KzgCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl Serialize for KzgCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

impl<'de> Deserialize<'de> for KzgCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

impl FromStr for KzgCommitment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("0x") {
            let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
            if bytes.len() == BYTES_PER_COMMITMENT {
                let mut kzg_commitment_bytes = [0; BYTES_PER_COMMITMENT];
                kzg_commitment_bytes[..].copy_from_slice(&bytes);
                Ok(Self(kzg_commitment_bytes))
            } else {
                Err(format!(
                    "InvalidByteLength: got {}, expected {}",
                    bytes.len(),
                    BYTES_PER_COMMITMENT
                ))
            }
        } else {
            Err("must start with 0x".to_string())
        }
    }
}

impl Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0))
    }
}

impl arbitrary::Arbitrary<'_> for KzgCommitment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BYTES_PER_COMMITMENT];
        u.fill_buffer(&mut bytes)?;
        Ok(KzgCommitment(bytes))
    }
}

#[test]
fn kzg_commitment_display() {
    let display_commitment_str = "0x53fa…adac";
    let display_commitment = KzgCommitment::from_str(
        "0x53fa09af35d1d1a9e76f65e16112a9064ce30d1e4e2df98583f0f5dc2e7dd13a4f421a9c89f518fafd952df76f23adac",
    )
    .unwrap()
    .to_string();

    assert_eq!(display_commitment, display_commitment_str);
}

#[test]
fn kzg_commitment_debug() {
    let debug_commitment_str =
        "0x53fa09af35d1d1a9e76f65e16112a9064ce30d1e4e2df98583f0f5dc2e7dd13a4f421a9c89f518fafd952df76f23adac";
    let debug_commitment = KzgCommitment::from_str(debug_commitment_str).unwrap();

    assert_eq!(format!("{debug_commitment:?}"), debug_commitment_str);
}
