pub fn hash(data: &[u8]) -> u32 {
    data.iter().fold(2166136261u32, |h, b| (h ^ u32::from(*b)).wrapping_mul(16777619))
}
