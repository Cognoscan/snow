use crate::{
    constants::{CIPHERKEYLEN, TAGLEN},
    error::{Error, InitStage, StateProblem},
    types::Cipher,
};

pub(crate) struct CipherState {
    cipher:  Box<dyn Cipher>,
    n:       u64,
    has_key: bool,
}

impl CipherState {
    pub fn new(cipher: Box<dyn Cipher>) -> Self {
        Self { cipher, n: 0, has_key: false }
    }

    pub fn name(&self) -> &'static str {
        self.cipher.name()
    }

    pub fn set(&mut self, key: &[u8; CIPHERKEYLEN], n: u64) {
        self.cipher.set(key);
        self.n = n;
        self.has_key = true;
    }

    pub fn encrypt_ad_in_place(
        &mut self,
        authtext: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAGLEN], Error> {
        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into());
        }

        validate_nonce(self.n)?;
        let tag = self.cipher.encrypt_in_place(self.n, authtext, buffer);

        // We have validated this will not wrap around.
        self.n += 1;

        Ok(tag)
    }

    pub fn decrypt_ad_in_place(
        &mut self,
        authtext: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAGLEN],
    ) -> Result<(), Error> {
        if buffer.len() < TAGLEN {
            return Err(Error::Decrypt);
        }

        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into());
        }

        validate_nonce(self.n)?;
        self.cipher.decrypt_in_place(self.n, authtext, buffer, tag)?;

        // We have validated this will not wrap around.
        self.n += 1;

        Ok(())
    }

    pub fn encrypt_in_place(&mut self, buffer: &mut [u8]) -> Result<[u8; TAGLEN], Error> {
        self.encrypt_ad_in_place(&[0u8; 0], buffer)
    }

    pub fn decrypt_in_place(&mut self, buffer: &mut [u8], tag: &[u8; TAGLEN]) -> Result<(), Error> {
        self.decrypt_ad_in_place(&[0u8; 0], buffer, tag)
    }

    pub fn rekey(&mut self) {
        self.cipher.rekey();
    }

    pub fn rekey_manually(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.cipher.set(key);
    }

    pub fn nonce(&self) -> u64 {
        self.n
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }
}

pub(crate) struct CipherStates(pub CipherState, pub CipherState);

impl CipherStates {
    pub fn new(initiator: CipherState, responder: CipherState) -> Result<Self, Error> {
        if initiator.name() != responder.name() {
            return Err(InitStage::ValidateCipherTypes.into());
        }

        Ok(CipherStates(initiator, responder))
    }

    pub fn rekey_initiator(&mut self) {
        self.0.rekey();
    }

    pub fn rekey_initiator_manually(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.0.rekey_manually(key);
    }

    pub fn rekey_responder(&mut self) {
        self.1.rekey();
    }

    pub fn rekey_responder_manually(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.1.rekey_manually(key);
    }
}

pub(crate) struct StatelessCipherState {
    cipher:  Box<dyn Cipher>,
    has_key: bool,
}

impl StatelessCipherState {
    pub fn encrypt_ad_in_place(
        &self,
        nonce: u64,
        authtext: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAGLEN], Error> {
        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into());
        }

        validate_nonce(nonce)?;

        Ok(self.cipher.encrypt_in_place(nonce, authtext, buffer))
    }

    pub fn decrypt_ad_in_place(
        &self,
        nonce: u64,
        authtext: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAGLEN],
    ) -> Result<(), Error> {
        if buffer.len() < TAGLEN {
            return Err(Error::Decrypt);
        }

        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into());
        }

        validate_nonce(nonce)?;

        self.cipher.decrypt_in_place(nonce, authtext, buffer, tag)
    }

    pub fn encrypt_in_place(&self, nonce: u64, buffer: &mut [u8]) -> Result<[u8; TAGLEN], Error> {
        self.encrypt_ad_in_place(nonce, &[], buffer)
    }

    pub fn decrypt_in_place(&self, nonce: u64, buffer: &mut [u8], tag: &[u8; TAGLEN]) -> Result<(), Error> {
        self.decrypt_ad_in_place(nonce, &[], buffer, tag)
    }

    pub fn rekey(&mut self) {
        self.cipher.rekey();
    }

    pub fn rekey_manually(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.cipher.set(key);
    }
}

/// Validates that a nonce value has not exceeded the maximum
/// defined by the Noise spec.
fn validate_nonce(current: u64) -> Result<(), Error> {
    // 2^64-1 is reserved and may not be used in the state machine (5.1).
    //
    // It is used by the default cipher rekey function (4.2).
    if current == u64::MAX {
        Err(Error::State(StateProblem::Exhausted))
    } else {
        Ok(())
    }
}

impl From<CipherState> for StatelessCipherState {
    fn from(other: CipherState) -> Self {
        Self { cipher: other.cipher, has_key: other.has_key }
    }
}

pub(crate) struct StatelessCipherStates(pub StatelessCipherState, pub StatelessCipherState);

impl From<CipherStates> for StatelessCipherStates {
    fn from(other: CipherStates) -> Self {
        StatelessCipherStates(other.0.into(), other.1.into())
    }
}

impl StatelessCipherStates {
    pub fn rekey_initiator(&mut self) {
        self.0.rekey();
    }

    pub fn rekey_initiator_manually(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.0.rekey_manually(key);
    }

    pub fn rekey_responder(&mut self) {
        self.1.rekey();
    }

    pub fn rekey_responder_manually(&mut self, key: &[u8; CIPHERKEYLEN]) {
        self.1.rekey_manually(key);
    }
}
