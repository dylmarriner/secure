//! Local key hierarchy primitives for Secure.
//!
//! This crate intentionally covers only local key hierarchy and envelope handling. Messaging
//! cryptography belongs to the reviewed messaging protocol implementation, not here.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SVK1";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const VAULT_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = VAULT_KEY_LEN + TAG_LEN;
const FIXED_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
    #[error("invalid Argon2id parameters")]
    InvalidKdfParameters,
    #[error("Argon2id key derivation failed")]
    KeyDerivationFailed,
    #[error("vault-key encryption failed")]
    EncryptionFailed,
    #[error("vault-key authentication failed")]
    AuthenticationFailed,
    #[error("invalid vault-key envelope")]
    InvalidEnvelope,
    #[error("subkey derivation failed")]
    SubkeyDerivationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Profile {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Profile {
    pub const RECOMMENDED_V1: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    fn validate(self) -> Result<Self, CryptoError> {
        if !(8 * 1024..=1024 * 1024).contains(&self.memory_kib)
            || !(1..=10).contains(&self.iterations)
            || !(1..=16).contains(&self.parallelism)
        {
            return Err(CryptoError::InvalidKdfParameters);
        }
        Ok(self)
    }

    fn params(self) -> Result<Params, CryptoError> {
        let profile = self.validate()?;
        Params::new(
            profile.memory_kib,
            profile.iterations,
            profile.parallelism,
            Some(VAULT_KEY_LEN),
        )
        .map_err(|_| CryptoError::InvalidKdfParameters)
    }
}

pub struct VaultKey(Zeroizing<[u8; VAULT_KEY_LEN]>);

impl VaultKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; VAULT_KEY_LEN];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; VAULT_KEY_LEN] {
        &self.0
    }

    pub fn derive_subkey(
        &self,
        purpose: SubkeyPurpose,
    ) -> Result<Zeroizing<[u8; VAULT_KEY_LEN]>, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"secure-local-key-hierarchy-v1"), self.as_bytes());
        let mut output = Zeroizing::new([0_u8; VAULT_KEY_LEN]);
        hkdf.expand(purpose.label(), &mut *output)
            .map_err(|_| CryptoError::SubkeyDerivationFailed)?;
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubkeyPurpose {
    DatabaseV1,
    LocalConfigV1,
}

impl SubkeyPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::DatabaseV1 => b"database-v1",
            Self::LocalConfigV1 => b"local-config-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultKeyEnvelope {
    profile: Argon2Profile,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl VaultKeyEnvelope {
    pub fn seal(
        passphrase: &[u8],
        key: &VaultKey,
        profile: Argon2Profile,
    ) -> Result<Self, CryptoError> {
        let profile = profile.validate()?;
        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut salt)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;

        let wrapping_key = derive_wrapping_key(passphrase, &salt, profile)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let aad = authenticated_header(profile, &salt, &nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: key.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(CryptoError::EncryptionFailed);
        }

        Ok(Self {
            profile,
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn open(&self, passphrase: &[u8]) -> Result<VaultKey, CryptoError> {
        let wrapping_key = derive_wrapping_key(passphrase, &self.salt, self.profile)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let aad = authenticated_header(self.profile, &self.salt, &self.nonce);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );

        if plaintext.len() != VAULT_KEY_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }

        let mut key = [0_u8; VAULT_KEY_LEN];
        key.copy_from_slice(&plaintext);
        Ok(VaultKey(Zeroizing::new(key)))
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(FIXED_HEADER_LEN + self.ciphertext.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(FORMAT_VERSION);
        encoded.extend_from_slice(&self.profile.memory_kib.to_be_bytes());
        encoded.extend_from_slice(&self.profile.iterations.to_be_bytes());
        encoded.extend_from_slice(&self.profile.parallelism.to_be_bytes());
        encoded.extend_from_slice(&self.salt);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != FIXED_HEADER_LEN + CIPHERTEXT_LEN || &bytes[..4] != MAGIC {
            return Err(CryptoError::InvalidEnvelope);
        }

        let mut cursor = 4;
        let version = read_u8(bytes, &mut cursor)?;
        if version != FORMAT_VERSION {
            return Err(CryptoError::InvalidEnvelope);
        }

        let profile = Argon2Profile {
            memory_kib: read_u32(bytes, &mut cursor)?,
            iterations: read_u32(bytes, &mut cursor)?,
            parallelism: read_u32(bytes, &mut cursor)?,
        }
        .validate()?;

        let salt = read_array::<SALT_LEN>(bytes, &mut cursor)?;
        let nonce = read_array::<NONCE_LEN>(bytes, &mut cursor)?;
        let ciphertext_len = read_u32(bytes, &mut cursor)? as usize;
        if ciphertext_len != CIPHERTEXT_LEN || bytes.len() != cursor + ciphertext_len {
            return Err(CryptoError::InvalidEnvelope);
        }

        Ok(Self {
            profile,
            salt,
            nonce,
            ciphertext: bytes[cursor..].to_vec(),
        })
    }
}

fn derive_wrapping_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    profile: Argon2Profile,
) -> Result<Zeroizing<[u8; VAULT_KEY_LEN]>, CryptoError> {
    let params = profile.params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; VAULT_KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output)
}

fn authenticated_header(
    profile: Argon2Profile,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FIXED_HEADER_LEN - 4);
    aad.extend_from_slice(MAGIC);
    aad.push(FORMAT_VERSION);
    aad.extend_from_slice(&profile.memory_kib.to_be_bytes());
    aad.extend_from_slice(&profile.iterations.to_be_bytes());
    aad.extend_from_slice(&profile.parallelism.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, CryptoError> {
    let value = *bytes.get(*cursor).ok_or(CryptoError::InvalidEnvelope)?;
    *cursor += 1;
    Ok(value)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, CryptoError> {
    let raw = read_array::<4>(bytes, cursor)?;
    Ok(u32::from_be_bytes(raw))
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], CryptoError> {
    let end = cursor
        .checked_add(N)
        .ok_or(CryptoError::InvalidEnvelope)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(CryptoError::InvalidEnvelope)?;
    let mut output = [0_u8; N];
    output.copy_from_slice(slice);
    *cursor = end;
    Ok(output)
}
