//! Binary Wire Framing (`CKV1`) and Deterministic Little-Endian Serialization.
//!
//! Frame Layout (24-byte fixed header + variable payload):
//!   [0..4]   magic       : b"CKV1"
//!   [4]      version     : u8 = 1
//!   [5]      msg_type    : u8
//!   [6..8]   flags       : u16 (LE)
//!   [8..16]  req_id      : u64 (LE)
//!   [16..20] payload_len : u32 (LE, <= MAX_FRAME_PAYLOAD_LEN = 16 MiB)
//!   [20..24] crc32       : u32 (LE, IEEE CRC32 over header[0..20] || payload)
//!   [24..]   payload     : [u8; payload_len]

use std::fmt;
use std::io::{self, Read, Write};

use crate::crc32::crc32_pair;

pub const WIRE_MAGIC: [u8; 4] = *b"CKV1";
pub const WIRE_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_FRAME_PAYLOAD_LEN: usize = 16 * 1024 * 1024; // 16 MiB hard cap against OOM

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub msg_type: u8,
    pub flags: u16,
    pub req_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    BadMagic([u8; 4]),
    UnsupportedVersion(u8),
    FrameTooLarge(usize),
    CrcMismatch { expected: u32, actual: u32 },
    DecodeUnderflow(&'static str),
    InvalidEnumTag { context: &'static str, tag: u8 },
    InvalidUtf8,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "wire I/O error: {}", e),
            WireError::BadMagic(m) => write!(f, "bad wire magic: {:?}", m),
            WireError::UnsupportedVersion(v) => write!(f, "unsupported wire version: {}", v),
            WireError::FrameTooLarge(n) => write!(f, "frame payload too large: {} bytes", n),
            WireError::CrcMismatch { expected, actual } => {
                write!(f, "CRC32 mismatch: expected 0x{:08x}, got 0x{:08x}", expected, actual)
            }
            WireError::DecodeUnderflow(ctx) => write!(f, "decode buffer underflow in {}", ctx),
            WireError::InvalidEnumTag { context, tag } => {
                write!(f, "invalid enum tag {} in {}", tag, context)
            }
            WireError::InvalidUtf8 => write!(f, "invalid UTF-8 string in wire payload"),
        }
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

impl WireFrame {
    pub fn new(msg_type: u8, req_id: u64, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            flags: 0,
            req_id,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD_LEN {
            return Err(WireError::FrameTooLarge(self.payload.len()));
        }
        let payload_len = self.payload.len() as u32;
        let mut header_prefix = [0u8; 20];
        header_prefix[0..4].copy_from_slice(&WIRE_MAGIC);
        header_prefix[4] = WIRE_VERSION;
        header_prefix[5] = self.msg_type;
        header_prefix[6..8].copy_from_slice(&self.flags.to_le_bytes());
        header_prefix[8..16].copy_from_slice(&self.req_id.to_le_bytes());
        header_prefix[16..20].copy_from_slice(&payload_len.to_le_bytes());

        let checksum = crc32_pair(&header_prefix, &self.payload);

        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&header_prefix);
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        let raw = self.encode()?;
        writer.write_all(&raw)?;
        writer.flush()?;
        Ok(())
    }
}

/// Stateful incremental TCP stream decoder.
/// Safely reassembles frames even when TCP segments are fragmented down to 1 byte.
pub struct FrameDecoder {
    buf: Vec<u8>,
    read_pos: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(8192),
            read_pos: 0,
        }
    }

    pub fn push_bytes(&mut self, chunk: &[u8]) {
        if self.read_pos > 0 && self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        } else if self.read_pos >= 65536 && self.read_pos * 2 >= self.buf.len() {
            self.buf.drain(0..self.read_pos);
            self.read_pos = 0;
        }
        self.buf.extend_from_slice(chunk);
    }

    pub fn try_next_frame(&mut self) -> Result<Option<WireFrame>, WireError> {
        let avail = self.buf.len() - self.read_pos;
        if avail < HEADER_LEN {
            return Ok(None);
        }

        let hdr = &self.buf[self.read_pos..self.read_pos + HEADER_LEN];
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&hdr[0..4]);
        if magic != WIRE_MAGIC {
            return Err(WireError::BadMagic(magic));
        }

        let version = hdr[4];
        if version != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }

        let msg_type = hdr[5];
        let flags = u16::from_le_bytes([hdr[6], hdr[7]]);
        let req_id = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let payload_len = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(WireError::FrameTooLarge(payload_len));
        }

        let total_len = HEADER_LEN + payload_len;
        if avail < total_len {
            return Ok(None);
        }

        let expected_crc = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);
        let header_prefix = &self.buf[self.read_pos..self.read_pos + 20];
        let payload_slice = &self.buf[self.read_pos + HEADER_LEN..self.read_pos + total_len];
        let actual_crc = crc32_pair(header_prefix, payload_slice);
        if actual_crc != expected_crc {
            return Err(WireError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let payload = payload_slice.to_vec();
        self.read_pos += total_len;
        if self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        }

        Ok(Some(WireFrame {
            msg_type,
            flags,
            req_id,
            payload,
        }))
    }

    /// Blocking helper that reads chunks from `reader` until one complete frame is decoded or EOF.
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> Result<Option<WireFrame>, WireError> {
        let mut scratch = [0u8; 4096];
        loop {
            if let Some(frame) = self.try_next_frame()? {
                return Ok(Some(frame));
            }
            let n = reader.read(&mut scratch)?;
            if n == 0 {
                let rem = self.buf.len() - self.read_pos;
                if rem == 0 {
                    return Ok(None);
                }
                return Err(WireError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("EOF mid-frame with {} trailing bytes", rem),
                )));
            }
            self.push_bytes(&scratch[..n]);
        }
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ByteWriter {
    buf: Vec<u8>,
}

impl ByteWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(128),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    #[inline]
    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    #[inline]
    pub fn put_bool(&mut self, v: bool) {
        self.buf.push(if v { 1 } else { 0 });
    }

    #[inline]
    pub fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn put_bytes(&mut self, b: &[u8]) {
        self.put_u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    #[inline]
    pub fn put_str(&mut self, s: &str) {
        self.put_bytes(s.as_bytes());
    }

    #[inline]
    pub fn put_opt_bytes(&mut self, opt: &Option<Vec<u8>>) {
        match opt {
            Some(b) => {
                self.put_bool(true);
                self.put_bytes(b);
            }
            None => self.put_bool(false),
        }
    }

    #[inline]
    pub fn put_opt_u16(&mut self, opt: Option<u16>) {
        match opt {
            Some(v) => {
                self.put_bool(true);
                self.put_u16(v);
            }
            None => self.put_bool(false),
        }
    }
}

impl Default for ByteWriter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize, ctx: &'static str) -> Result<&'a [u8], WireError> {
        if self.pos + n > self.buf.len() {
            return Err(WireError::DecodeUnderflow(ctx));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    #[inline]
    pub fn get_u8(&mut self, ctx: &'static str) -> Result<u8, WireError> {
        Ok(self.take(1, ctx)?[0])
    }

    #[inline]
    pub fn get_bool(&mut self, ctx: &'static str) -> Result<bool, WireError> {
        match self.get_u8(ctx)? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(WireError::InvalidEnumTag { context: ctx, tag }),
        }
    }

    #[inline]
    pub fn get_u16(&mut self, ctx: &'static str) -> Result<u16, WireError> {
        let b = self.take(2, ctx)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn get_u32(&mut self, ctx: &'static str) -> Result<u32, WireError> {
        let b = self.take(4, ctx)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn get_u64(&mut self, ctx: &'static str) -> Result<u64, WireError> {
        let b = self.take(8, ctx)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    #[inline]
    pub fn get_bytes(&mut self, ctx: &'static str) -> Result<Vec<u8>, WireError> {
        let len = self.get_u32(ctx)? as usize;
        if len > MAX_FRAME_PAYLOAD_LEN {
            return Err(WireError::FrameTooLarge(len));
        }
        Ok(self.take(len, ctx)?.to_vec())
    }

    #[inline]
    pub fn get_str(&mut self, ctx: &'static str) -> Result<String, WireError> {
        let bytes = self.get_bytes(ctx)?;
        String::from_utf8(bytes).map_err(|_| WireError::InvalidUtf8)
    }

    #[inline]
    pub fn get_opt_bytes(&mut self, ctx: &'static str) -> Result<Option<Vec<u8>>, WireError> {
        if self.get_bool(ctx)? {
            Ok(Some(self.get_bytes(ctx)?))
        } else {
            Ok(None)
        }
    }

    #[inline]
    pub fn get_opt_u16(&mut self, ctx: &'static str) -> Result<Option<u16>, WireError> {
        if self.get_bool(ctx)? {
            Ok(Some(self.get_u16(ctx)?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_byte_fragmented_stream_reassembly_and_crc() {
        let f1 = WireFrame::new(0x20, 42, b"hello_chronos".to_vec());
        let f2 = WireFrame::new(0x22, 99, vec![1, 2, 3, 4, 5, 6, 7]);
        let mut stream = f1.encode().unwrap();
        stream.extend_from_slice(&f2.encode().unwrap());

        let mut dec = FrameDecoder::new();
        let mut out = Vec::new();
        // Feed 1 byte at a time to simulate extreme TCP fragmentation
        for b in &stream {
            dec.push_bytes(&[*b]);
            if let Some(frame) = dec.try_next_frame().unwrap() {
                out.push(frame);
            }
        }
        assert_eq!(out, vec![f1, f2]);

        // Flip 1 bit in payload and verify CRC32 rejection
        let mut corrupted = WireFrame::new(0x01, 7, b"integrity".to_vec())
            .encode()
            .unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        dec.push_bytes(&corrupted);
        assert!(matches!(
            dec.try_next_frame(),
            Err(WireError::CrcMismatch { .. })
        ));
    }
}
