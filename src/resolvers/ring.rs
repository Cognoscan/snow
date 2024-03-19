use super::CryptoResolver;
use crate::{
    constants::{CIPHERKEYLEN, TAGLEN},
    params::{CipherChoice, DHChoice, HashChoice},
    types::{Cipher, Dh, Hash, Random},
    Error,
};
use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    digest,
    rand::{SecureRandom, SystemRandom},
};

/// A resolver that chooses [ring](https://github.com/briansmith/ring)-backed
/// primitives when available.
#[allow(clippy::module_name_repetitions)]
#[derive(Default)]
pub struct RingResolver;

#[cfg(feature = "ring")]
impl CryptoResolver for RingResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(RingRng::default()))
    }

    fn resolve_dh(&self, _choice: &DHChoice) -> Option<Box<dyn Dh>> {
        None
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match *choice {
            HashChoice::SHA256 => Some(Box::new(HashSHA256::default())),
            HashChoice::SHA512 => Some(Box::new(HashSHA512::default())),
            _ => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match *choice {
            CipherChoice::AESGCM => Some(Box::new(CipherAESGCM::default())),
            CipherChoice::ChaChaPoly => Some(Box::new(CipherChaChaPoly::default())),
            #[cfg(feature = "xchachapoly")]
            CipherChoice::XChaChaPoly => None,
        }
    }
}

struct RingRng {
    rng: SystemRandom,
}

impl Default for RingRng {
    fn default() -> Self {
        Self { rng: SystemRandom::new() }
    }
}

impl rand_core::RngCore for RingRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.fill(dest).map_err(|e| rand_core::Error::new(e))
    }
}

impl rand_core::CryptoRng for RingRng {}

impl Random for RingRng {}

struct CipherAESGCM {
    // NOTE: LessSafeKey is chosen here because nonce atomicity is handled outside of this structure.
    // See ring documentation for more details on the naming choices.
    key: LessSafeKey,
}

impl Default for CipherAESGCM {
    fn default() -> Self {
        CipherAESGCM {
            key: LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &[0u8; 32]).unwrap()),
        }
    }
}

impl Cipher for CipherAESGCM {
    fn name(&self) -> &'static str {
        "AESGCM"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.key = aead::LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key).unwrap());
    }

    fn encrypt_in_place(&self, nonce: u64, authtext: &[u8], buffer: &mut [u8]) -> [u8; TAGLEN] {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(&nonce.to_be_bytes(), &mut nonce_bytes[4..]);

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let ring_tag = self
            .key
            .seal_in_place_separate_tag(
                nonce,
                aead::Aad::from(authtext),
                buffer,
            )
            .unwrap();
        let mut tag = [0u8; 16];
        copy_slices!(ring_tag.as_ref(), tag);
        tag
    }

    fn decrypt_in_place(
        &self,
        nonce: u64,
        authtext: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAGLEN],
    ) -> Result<(), Error> {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(&nonce.to_be_bytes(), &mut nonce_bytes[4..]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let tag = aead::Tag::from(*tag);

        self
            .key
            .open_in_place_separate_tag(nonce, aead::Aad::from(authtext), tag, buffer, 0..)
            .map_err(|_| Error::Decrypt)?;
        Ok(())
    }
}

struct CipherChaChaPoly {
    // NOTE: LessSafeKey is chosen here because nonce atomicity is to be ensured outside of this structure.
    // See ring documentation for more details on the naming choices.
    key: aead::LessSafeKey,
}

impl Default for CipherChaChaPoly {
    fn default() -> Self {
        Self {
            key: LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &[0u8; 32]).unwrap()),
        }
    }
}

impl Cipher for CipherChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap());
    }

    fn encrypt_in_place(&self, nonce: u64, authtext: &[u8], buffer: &mut [u8]) -> [u8; TAGLEN] {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[4..]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let ring_tag = self
            .key
            .seal_in_place_separate_tag(
                nonce,
                aead::Aad::from(authtext),
                buffer,
            )
            .unwrap();
        let mut tag = [0u8; 16];
        copy_slices!(ring_tag.as_ref(), tag);
        tag
    }

    fn decrypt_in_place(
        &self,
        nonce: u64,
        authtext: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAGLEN],
    ) -> Result<(), Error> {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[4..]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let tag = aead::Tag::from(*tag);

        self
            .key
            .open_in_place_separate_tag(nonce, aead::Aad::from(authtext), tag, buffer, 0..)
            .map_err(|_| Error::Decrypt)?;
        Ok(())
    }
}
struct HashSHA256 {
    context: digest::Context,
}

impl Default for HashSHA256 {
    fn default() -> Self {
        Self { context: digest::Context::new(&digest::SHA256) }
    }
}

impl Hash for HashSHA256 {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(&digest::SHA256);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out[..32].copy_from_slice(self.context.clone().finish().as_ref());
    }
}

struct HashSHA512 {
    context: digest::Context,
}

impl Default for HashSHA512 {
    fn default() -> Self {
        Self { context: digest::Context::new(&digest::SHA512) }
    }
}

impl Hash for HashSHA512 {
    fn name(&self) -> &'static str {
        "SHA512"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.context = digest::Context::new(&digest::SHA512);
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out[..64].copy_from_slice(self.context.clone().finish().as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn test_randomness_sanity() {
        use std::collections::HashSet;

        let mut samples = HashSet::new();
        let mut rng = RingRng::default();
        for _ in 0..100_000 {
            let mut buf = vec![0u8; 128];
            rng.fill_bytes(&mut buf);
            assert!(samples.insert(buf));
        }
    }
}
