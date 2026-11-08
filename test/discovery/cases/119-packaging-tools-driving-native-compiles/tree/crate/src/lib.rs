extern "C" {
    fn fasthash_bytes(data: *const u8, len: u32) -> u32;
}

pub fn hash(data: &[u8]) -> u32 {
    unsafe { fasthash_bytes(data.as_ptr(), data.len() as u32) }
}
