use kzg_types::KzgCommitment as InnerKzgCommitment;

#[derive(Copy, Clone, Debug)]
pub struct KzgCommitment(pub InnerKzgCommitment);

impl From<KzgCommitment> for c_kzg::Bytes48 {
    fn from(value: KzgCommitment) -> Self {
        value.0 .0.into()
    }
}
