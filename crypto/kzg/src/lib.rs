mod kzg_commitment;
mod kzg_proof;
pub mod trusted_setup;

use rand::Rng;
use rust_eth_kzg::{CellIndex, DASContext};
use std::fmt::Debug;

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof, trusted_setup::TrustedSetup};

pub use c_kzg::{
    Blob, Bytes32, Bytes48, KzgSettings, BYTES_PER_BLOB, BYTES_PER_COMMITMENT,
    BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB,
};

pub use rust_eth_kzg::{
    constants::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB},
    Cell, CellIndex as CellID, CellRef, TrustedSetup as PeerDASTrustedSetup,
};

// Note: `spec.number_of_columns` is a config and should match `CELLS_PER_EXT_BLOB` - however this
// is a constant in the KZG library - be aware that overriding `number_of_columns` will break KZG
// operations.
pub type CellsAndKzgProofs = ([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]);

pub type KzgBlobRef<'a> = &'a [u8; BYTES_PER_BLOB];

pub use kzg_types::{
    Error as InnerKzgError, KzgCommitment as InnerKzgCommitment, KzgProof as InnerKzgProof,
    VERSIONED_HASH_VERSION_KZG,
};

#[derive(Debug)]
pub struct KzgError(pub InnerKzgError);

impl From<c_kzg::Error> for KzgError {
    fn from(value: c_kzg::Error) -> Self {
        Self(InnerKzgError::Kzg(value.to_string()))
    }
}

/// A wrapper over a kzg library that holds the trusted setup parameters.
#[derive(Debug)]
pub struct Kzg {
    trusted_setup: KzgSettings,
    context: DASContext,
}

impl Kzg {
    pub fn new_from_trusted_setup_no_precomp(
        trusted_setup: TrustedSetup,
    ) -> Result<Self, KzgError> {
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);

        let context = DASContext::new(&peerdas_trusted_setup, rust_eth_kzg::UsePrecomp::No);

        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
            )?,
            context,
        })
    }

    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, KzgError> {
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);

        let context = DASContext::new(
            &peerdas_trusted_setup,
            rust_eth_kzg::UsePrecomp::Yes {
                width: rust_eth_kzg::constants::RECOMMENDED_PRECOMP_WIDTH,
            },
        );

        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
            )?,
            context,
        })
    }

    pub fn new_from_trusted_setup_das_enabled(
        trusted_setup: TrustedSetup,
    ) -> Result<Self, KzgError> {
        // Initialize the trusted setup using default parameters
        //
        // Note: One can also use `from_json` to initialize it from the consensus-specs
        // json string.
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);

        // It's not recommended to change the config parameter for precomputation as storage
        // grows exponentially, but the speedup is exponential - after a while the speedup
        // starts to become sublinear.
        let context = DASContext::new(
            &peerdas_trusted_setup,
            rust_eth_kzg::UsePrecomp::Yes {
                width: rust_eth_kzg::constants::RECOMMENDED_PRECOMP_WIDTH,
            },
        );

        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
            )?,
            context,
        })
    }

    fn context(&self) -> &DASContext {
        &self.context
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, KzgError> {
        c_kzg::KzgProof::compute_blob_kzg_proof(
            blob,
            &kzg_commitment.0 .0.into(),
            &self.trusted_setup,
        )
        .map(|proof| KzgProof(InnerKzgProof(proof.to_bytes().into_inner())))
        .map_err(Into::into)
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<(), KzgError> {
        if !c_kzg::KzgProof::verify_blob_kzg_proof(
            blob,
            &kzg_commitment.0 .0.into(),
            &kzg_proof.into(),
            &self.trusted_setup,
        )? {
            Err(KzgError(InnerKzgError::KzgVerificationFailed))
        } else {
            Ok(())
        }
    }

    /// Verify a batch of blob commitment proof triplets.
    ///
    /// Note: This method is slightly faster than calling `Self::verify_blob_kzg_proof` in a loop sequentially.
    /// TODO(pawan): test performance against a parallelized rayon impl.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Blob],
        kzg_commitments: &[KzgCommitment],
        kzg_proofs: &[KzgProof],
    ) -> Result<(), KzgError> {
        let commitments_bytes = kzg_commitments
            .iter()
            .map(|comm| Bytes48::from(comm.0 .0))
            .collect::<Vec<_>>();

        let proofs_bytes = kzg_proofs
            .iter()
            .map(|proof| Bytes48::from(proof.0 .0))
            .collect::<Vec<_>>();

        if !c_kzg::KzgProof::verify_blob_kzg_proof_batch(
            blobs,
            &commitments_bytes,
            &proofs_bytes,
            &self.trusted_setup,
        )? {
            Err(KzgError(InnerKzgError::KzgVerificationFailed))
        } else {
            Ok(())
        }
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> Result<KzgCommitment, KzgError> {
        c_kzg::KzgCommitment::blob_to_kzg_commitment(blob, &self.trusted_setup)
            .map(|commitment| KzgCommitment(InnerKzgCommitment(commitment.to_bytes().into_inner())))
            .map_err(Into::into)
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        blob: &Blob,
        z: &Bytes32,
    ) -> Result<(KzgProof, Bytes32), KzgError> {
        c_kzg::KzgProof::compute_kzg_proof(blob, z, &self.trusted_setup)
            .map(|(proof, y)| (KzgProof(proof.to_bytes().into_inner().into()), y))
            .map_err(Into::into)
    }

    /// Verifies a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KzgCommitment,
        z: &Bytes32,
        y: &Bytes32,
        kzg_proof: KzgProof,
    ) -> Result<bool, KzgError> {
        c_kzg::KzgProof::verify_kzg_proof(
            &kzg_commitment.into(),
            z,
            y,
            &kzg_proof.into(),
            &self.trusted_setup,
        )
        .map_err(Into::into)
    }

    /// Computes the cells and associated proofs for a given `blob`.
    pub fn compute_cells_and_proofs(
        &self,
        blob: KzgBlobRef<'_>,
    ) -> Result<CellsAndKzgProofs, KzgError> {
        let (cells, proofs) = self
            .context()
            .compute_cells_and_kzg_proofs(blob)
            .map_err(|e| KzgError(InnerKzgError::PeerDASKZG(e)))?;

        // Convert the proof type to a c-kzg proof type
        let c_kzg_proof = proofs.map(|xs| KzgProof(InnerKzgProof(xs)));
        Ok((cells, c_kzg_proof))
    }

    /// Computes the cells for a given `blob`.
    pub fn compute_cells(
        &self,
        blob: KzgBlobRef<'_>,
    ) -> Result<[Cell; CELLS_PER_EXT_BLOB], KzgError> {
        self.context()
            .compute_cells(blob)
            .map_err(|e| KzgError(InnerKzgError::PeerDASKZG(e)))
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    pub fn verify_cell_proof_batch(
        &self,
        cells: &[CellRef<'_>],
        kzg_proofs: &[Bytes48],
        columns: Vec<CellIndex>,
        kzg_commitments: &[Bytes48],
    ) -> Result<(), KzgError> {
        let proofs: Vec<_> = kzg_proofs.iter().map(|proof| proof.as_ref()).collect();
        let commitments: Vec<_> = kzg_commitments
            .iter()
            .map(|commitment| commitment.as_ref())
            .collect();
        let verification_result = self.context().verify_cell_kzg_proof_batch(
            commitments.to_vec(),
            columns,
            cells.to_vec(),
            proofs.to_vec(),
        );

        // Modify the result so it matches roughly what the previous method was doing.
        match verification_result {
            Ok(_) => Ok(()),
            Err(e) if e.invalid_proof() => Err(KzgError(InnerKzgError::KzgVerificationFailed)),
            Err(e) => Err(KzgError(InnerKzgError::PeerDASKZG(e))),
        }
    }

    pub fn recover_cells_and_compute_kzg_proofs(
        &self,
        cell_ids: &[u64],
        cells: &[CellRef<'_>],
    ) -> Result<CellsAndKzgProofs, KzgError> {
        let (cells, proofs) = self
            .context()
            .recover_cells_and_kzg_proofs(cell_ids.to_vec(), cells.to_vec())
            .map_err(|e| KzgError(InnerKzgError::PeerDASKZG(e)))?;

        // Convert the proof type to a c-kzg proof type
        let c_kzg_proof = proofs.map(|xs| KzgProof(kzg_types::KzgProof(xs)));
        Ok((cells, c_kzg_proof))
    }
}

pub fn random_valid_sidecar<E, R>(
    rng: &mut R,
    kzg: &Kzg,
) -> Result<(Blob, KzgCommitment, KzgProof), String>
where
    R: Rng,
{
    let mut blob_bytes = vec![0u8; BYTES_PER_BLOB];
    rng.fill_bytes(&mut blob_bytes);
    // Ensure that the blob is canonical by ensuring that
    // each field element contained in the blob is < BLS_MODULUS
    for byte in blob_bytes.iter_mut().step_by(BYTES_PER_FIELD_ELEMENT) {
        *byte = 0;
    }

    let blob = Blob::from_bytes(&blob_bytes)
        .map_err(|e| format!("error constructing random blob: {e:?}"))?;

    let commitment = kzg
        .blob_to_kzg_commitment(&blob)
        .map_err(|e| format!("error computing kzg commitment: {:?}", e))?;

    let proof = kzg
        .compute_blob_kzg_proof(&blob, commitment)
        .map_err(|e| format!("error computing kzg proof: {:?}", e))?;

    Ok((blob, commitment, proof))
}
