use kzg_types::KzgProof as InnerKzgProof;

#[derive(Copy, Clone, Debug)]
pub struct KzgProof(pub InnerKzgProof);

impl From<KzgProof> for c_kzg::Bytes48 {
    fn from(value: KzgProof) -> Self {
        value.0 .0.into()
    }
}
