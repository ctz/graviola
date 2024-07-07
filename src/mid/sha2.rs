pub struct Sha256Context {
    h: [u32; 8],
    blockwise: Blockwise<64>,
    nblocks: usize,
}

impl Sha256Context {
    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            blockwise: Blockwise::new(),
            nblocks: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let bytes = self.blockwise.add_leading(bytes);

        if let Some(block) = self.blockwise.take() {
            self.update_block(&block);
        }

        let mut chunks = bytes.chunks_exact(Self::BLOCK_SZ);
        for block in &mut chunks {
            self.update_block(block.try_into().unwrap());
        }

        self.blockwise.add_trailing(chunks.remainder());
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bytes = self.nblocks * Self::BLOCK_SZ + self.blockwise.used;
        let bits = bytes * 8;

        // add padding
        self.update(&[0x80]);

        while self.blockwise.used != Self::BLOCK_SZ - 8 {
            self.update(&[0x00]);
        }

        self.update(&(bits as u64).to_be_bytes());
        debug_assert_eq!(self.blockwise.used, 0);

        let mut r = [0u8; 32];
        r[0..4].copy_from_slice(&self.h[0].to_be_bytes());
        r[4..8].copy_from_slice(&self.h[1].to_be_bytes());
        r[8..12].copy_from_slice(&self.h[2].to_be_bytes());
        r[12..16].copy_from_slice(&self.h[3].to_be_bytes());
        r[16..20].copy_from_slice(&self.h[4].to_be_bytes());
        r[20..24].copy_from_slice(&self.h[5].to_be_bytes());
        r[24..28].copy_from_slice(&self.h[6].to_be_bytes());
        r[28..32].copy_from_slice(&self.h[7].to_be_bytes());
        r
    }

    fn update_block(&mut self, block: &[u8; 64]) {
        crate::low::sha256_compress_blocks(&mut self.h, block);
        self.nblocks += 1;
    }

    const BLOCK_SZ: usize = 64;
}

struct Blockwise<const N: usize> {
    buffer: [u8; N],
    used: usize,
}

impl<const N: usize> Blockwise<N> {
    fn new() -> Self {
        Self {
            buffer: [0u8; N],
            used: 0,
        }
    }

    fn add_leading<'a>(&mut self, bytes: &'a [u8]) -> &'a [u8] {
        let space = N - self.used;
        let take = core::cmp::min(bytes.len(), space);
        let (taken, returned) = bytes.split_at(take);
        self.buffer[self.used..self.used + take].copy_from_slice(taken);
        self.used += take;
        returned
    }

    fn take(&mut self) -> Option<[u8; N]> {
        if self.used == N {
            self.used = 0;
            Some(self.buffer)
        } else {
            None
        }
    }

    ///
    fn add_trailing(&mut self, trailing: &[u8]) {
        self.buffer[..trailing.len()].copy_from_slice(trailing);
        self.used += trailing.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smoke() {
        let mut ctx = Sha256Context::new();
        for _ in 0..32 {
            ctx.update(b"hello");
        }
        println!("{:02x?}", ctx.finish());
    }

    #[test]
    fn hello() {
        let mut ctx = Sha256Context::new();
        ctx.update(b"hello");
        assert_eq!(&ctx.finish(),
                   b"\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24");
    }
}
