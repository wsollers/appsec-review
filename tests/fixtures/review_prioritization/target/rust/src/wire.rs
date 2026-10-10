use std::io::{Error, ErrorKind};

pub struct Header {
    pub kind: u8,
    pub len: u32,
}

pub fn read_header(buf: &[u8]) -> Result<Header, Error> {
    if buf.len() < 5 {
        return Err(Error::new(ErrorKind::InvalidData, "short"));
    }
    let kind = buf[0] & 0x0f;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let mask = (len >> 8) ^ (len << 3) | 0xff;
    let _body = &buf[5..(5 + (len & mask) as usize).min(buf.len())];
    Ok(Header { kind, len })
}
