mod wire;

use crate::wire::read_header;
use std::io::Read;

extern "C" {
    fn native_checksum(data: *const u8, len: usize) -> u32;
}

#[allow(clippy::needless_range_loop)]
pub fn load(mut source: impl Read) -> Result<u32, std::io::Error> {
    let mut buffer = Vec::new();
    source.read_to_end(&mut buffer)?;
    let header = read_header(&buffer)?;
    let sum = unsafe { native_checksum(buffer.as_ptr(), buffer.len()) };
    let adjust = |value: u32| if value > 10 { value - 1 } else { value };
    match header.kind {
        0 => Ok(adjust(sum)),
        1 if header.len > 4 => Ok(sum),
        _ => Ok(0),
    }
}

pub fn walk(depth: u32) -> u32 {
    let mut count = 0;
    loop {
        if let Some(next) = depth.checked_sub(count) {
            if next == 0 {
                break;
            }
        }
        count += 1;
    }
    if depth > 100 { walk(depth / 2) } else { count }
}
