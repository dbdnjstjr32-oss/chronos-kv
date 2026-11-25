//! IEEE 802.3 CRC32 implementation (polynomial 0xEDB88320).
//! Bit-for-bit identical to Python's `zlib.crc32(data) & 0xffffffff`.

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (c & 1) != 0 {
                c = 0xEDB8_8320u32 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = build_crc32_table();

pub struct Crc32Hasher {
    state: u32,
}

impl Crc32Hasher {
    #[inline]
    pub fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    #[inline]
    pub fn update(&mut self, bytes: &[u8]) {
        let mut c = self.state;
        for &b in bytes {
            let idx = ((c ^ (b as u32)) & 0xFF) as usize;
            c = CRC32_TABLE[idx] ^ (c >> 8);
        }
        self.state = c;
    }

    #[inline]
    pub fn finalize(self) -> u32 {
        !self.state
    }
}

impl Default for Crc32Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(bytes);
    h.finalize()
}

#[inline]
pub fn crc32_pair(a: &[u8], b: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(a);
    h.update(b);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_ieee_crc32_check_value() {
        // Standard IEEE 802.3 test vector: "123456789" -> 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_pair(b"1234", b"56789"), 0xCBF4_3926);
    }
}
