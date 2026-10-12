//! Encrypted attachment streaming for Secure.
//!
//! Every attachment gets its own random 256-bit key, independent of the vault master key and
//! every other attachment's key ([`AttachmentKey`]). Content is authenticated-encrypted with
//! XChaCha20-Poly1305 under the STREAM online-AEAD construction
//! (`chacha20poly1305::aead::stream`, RustCrypto's implementation of the construction from
//! ["Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"][stream-paper]):
//! fixed-size plaintext chunks, each independently authenticated and bound to its position in
//! the stream and to whether it is the final chunk. That last part is what gives "interrupted
//! upload/download cannot be mistaken for a valid complete object" - a truncated ciphertext is
//! missing the specially-flagged final chunk, so decryption of what should be the final chunk
//! fails authentication rather than silently succeeding on a partial object.
//!
//! Content type and expected size are stored in a header that is itself included as associated
//! data (AAD) on every chunk, so tampering with either invalidates every chunk's authentication
//! tag, not just a separate unauthenticated header field sitting next to the real ciphertext.
//!
//! Ingest and export are bounded-memory: exactly one chunk (64 KiB plaintext, or plaintext +
//! 16-byte AEAD tag as ciphertext) is held at a time, streamed straight from/to the caller's
//! `Read`/`Write`. The header's `expected_size` field is never trusted for allocation - it is
//! attacker-controlled information carried for the caller's own use (e.g. progress display),
//! not something this crate sizes a buffer from.
//!
//! [stream-paper]: https://eprint.iacr.org/2015/189.pdf
//!
//! # Scope
//!
//! This crate provides the encryption/decryption primitives, opaque object naming, and the
//! on-disk object store with transactional export ([`store`]). It does not persist attachment
//! keys (that is `secure-storage`'s `attachments.attachment_key` column) and does not generate
//! thumbnails. Burn integration is split by ownership: `secure-storage::burn` destroys the keys
//! and durably queues the object names in the same transaction; the desktop runtime then deletes
//! those objects through [`store::AttachmentStore::remove_object`] and acknowledges each one, so
//! cleanup resumes after a crash. See `docs/security-remediation-plan.md` Phase R6.

use std::io::{self, Read, Write};

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
use chacha20poly1305::aead::{KeyInit, Payload};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

pub mod store;

const KEY_LEN: usize = 32;
const MAGIC: &[u8; 4] = b"SATT";
const FORMAT_VERSION: u8 = 1;
/// XChaCha20Poly1305's nonce is 24 bytes; the STREAM `LE31` primitive reserves the last 4 bytes
/// for its internal counter/last-block flag, leaving 20 bytes of random prefix per attachment.
const NONCE_PREFIX_LEN: usize = 20;
const TAG_LEN: usize = 16;
/// Plaintext bytes per chunk. Chosen as a round, ordinary streaming buffer size - large enough
/// to keep per-chunk AEAD overhead (16-byte tag, STREAM's own bookkeeping) negligible relative
/// to throughput, small enough that "one chunk in memory at a time" is a real bound, not a
/// technicality.
const CHUNK_SIZE: usize = 64 * 1024;
const CIPHERTEXT_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LEN;

#[derive(Debug, Error)]
pub enum AttachmentError {
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
    #[error("content type is too long to encode")]
    ContentTypeTooLong,
    #[error("invalid or corrupt attachment header")]
    InvalidHeader,
    #[error("attachment encryption failed")]
    Encryption,
    #[error("attachment authentication failed: ciphertext is corrupt, tampered with, or truncated")]
    Decryption,
    #[error("object name is not a valid opaque attachment name")]
    InvalidObjectName,
    #[error("export destination must name a file")]
    InvalidDestination,
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

/// A random, independent 256-bit key for exactly one attachment. Never derived from the vault
/// master key or shared between attachments - see the security architecture's "attachment keys
/// are independent and persist only inside the encrypted vault" invariant. Persisting it is the
/// caller's responsibility (the `attachments.attachment_key` column); this type only generates
/// and carries it in memory, zeroing on drop.
pub struct AttachmentKey(Zeroizing<[u8; KEY_LEN]>);

impl AttachmentKey {
    pub fn generate() -> Result<Self, AttachmentError> {
        let mut bytes = [0_u8; KEY_LEN];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AttachmentError::RandomnessUnavailable)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Reconstruct a key from previously-persisted bytes (e.g. read back from
    /// `attachments.attachment_key`). Does not validate the bytes in any way beyond length -
    /// there is nothing to validate a raw symmetric key against.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Content type and size recovered from a successfully decrypted attachment's authenticated
/// header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMetadata {
    pub content_type: String,
    pub expected_size: u64,
}

/// A random, opaque on-disk object name, unrelated to the attachment's original filename.
/// Lower-hex encoded, matching the random-id convention `secure-storage` already uses for
/// record ids.
pub fn random_object_name() -> Result<String, AttachmentError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AttachmentError::RandomnessUnavailable)?;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Encrypt `reader`'s content under `key` into `writer`, in bounded-memory chunks, prefixed
/// with an authenticated header carrying `content_type` and `expected_size`.
///
/// `expected_size` is not verified against how many bytes `reader` actually produces - it is
/// carried for the caller's own use (e.g. progress display) and is authenticated so it cannot
/// be tampered with in transit, not validated as a promise about the stream's real length.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &AttachmentKey,
    content_type: &str,
    expected_size: u64,
    mut reader: R,
    mut writer: W,
) -> Result<(), AttachmentError> {
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_prefix)
        .map_err(|_| AttachmentError::RandomnessUnavailable)?;

    let header = encode_header(&nonce_prefix, content_type, expected_size)?;
    writer.write_all(&header)?;

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
    let mut encryptor = EncryptorLE31::from_aead(cipher, GenericArray::from_slice(&nonce_prefix));

    let mut buf = vec![0_u8; CHUNK_SIZE];
    loop {
        let filled = fill_or_eof(&mut reader, &mut buf)?;
        if filled < CHUNK_SIZE {
            let ciphertext = encryptor
                .encrypt_last(Payload {
                    msg: &buf[..filled],
                    aad: &header,
                })
                .map_err(|_| AttachmentError::Encryption)?;
            writer.write_all(&ciphertext)?;
            break;
        }

        let ciphertext = encryptor
            .encrypt_next(Payload {
                msg: &buf[..filled],
                aad: &header,
            })
            .map_err(|_| AttachmentError::Encryption)?;
        writer.write_all(&ciphertext)?;
    }

    Ok(())
}

/// Decrypt an object written by [`encrypt_stream`] under `key`, streaming plaintext to `writer`
/// in bounded-memory chunks, returning the authenticated metadata recovered from the header.
///
/// Fails with [`AttachmentError::Decryption`] - not a panic, not a silently-truncated partial
/// write - for a wrong key, a tampered header, tampered chunk content, or a ciphertext that was
/// truncated before its properly-flagged final chunk.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &AttachmentKey,
    mut reader: R,
    mut writer: W,
) -> Result<AttachmentMetadata, AttachmentError> {
    let header = read_header(&mut reader)?;

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
    let mut decryptor =
        DecryptorLE31::from_aead(cipher, GenericArray::from_slice(&header.nonce_prefix));

    let mut buf = vec![0_u8; CIPHERTEXT_CHUNK_SIZE];
    loop {
        let filled = fill_or_eof(&mut reader, &mut buf)?;
        if filled < CIPHERTEXT_CHUNK_SIZE {
            let plaintext = decryptor
                .decrypt_last(Payload {
                    msg: &buf[..filled],
                    aad: &header.raw,
                })
                .map_err(|_| AttachmentError::Decryption)?;
            writer.write_all(&plaintext)?;
            break;
        }

        let plaintext = decryptor
            .decrypt_next(Payload {
                msg: &buf[..filled],
                aad: &header.raw,
            })
            .map_err(|_| AttachmentError::Decryption)?;
        writer.write_all(&plaintext)?;
    }

    Ok(AttachmentMetadata {
        content_type: header.content_type,
        expected_size: header.expected_size,
    })
}

struct Header {
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    content_type: String,
    expected_size: u64,
    /// The exact bytes written by [`encode_header`], used verbatim as AAD on every chunk so
    /// the header the caller reads back is exactly the header that was authenticated.
    raw: Vec<u8>,
}

fn encode_header(
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    content_type: &str,
    expected_size: u64,
) -> Result<Vec<u8>, AttachmentError> {
    let content_type_bytes = content_type.as_bytes();
    let content_type_len: u16 = content_type_bytes
        .len()
        .try_into()
        .map_err(|_| AttachmentError::ContentTypeTooLong)?;

    let mut header =
        Vec::with_capacity(MAGIC.len() + 1 + NONCE_PREFIX_LEN + 2 + content_type_bytes.len() + 8);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(nonce_prefix);
    header.extend_from_slice(&content_type_len.to_be_bytes());
    header.extend_from_slice(content_type_bytes);
    header.extend_from_slice(&expected_size.to_be_bytes());
    Ok(header)
}

fn read_header<R: Read>(reader: &mut R) -> Result<Header, AttachmentError> {
    let fixed_len = MAGIC.len() + 1 + NONCE_PREFIX_LEN + 2;
    let mut fixed = vec![0_u8; fixed_len];
    reader
        .read_exact(&mut fixed)
        .map_err(|_| AttachmentError::InvalidHeader)?;

    if &fixed[..MAGIC.len()] != MAGIC {
        return Err(AttachmentError::InvalidHeader);
    }
    if fixed[MAGIC.len()] != FORMAT_VERSION {
        return Err(AttachmentError::InvalidHeader);
    }

    let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&fixed[MAGIC.len() + 1..MAGIC.len() + 1 + NONCE_PREFIX_LEN]);

    let content_type_len =
        u16::from_be_bytes([fixed[fixed_len - 2], fixed[fixed_len - 1]]) as usize;
    let mut content_type_bytes = vec![0_u8; content_type_len];
    reader
        .read_exact(&mut content_type_bytes)
        .map_err(|_| AttachmentError::InvalidHeader)?;
    let content_type = String::from_utf8(content_type_bytes.clone())
        .map_err(|_| AttachmentError::InvalidHeader)?;

    let mut size_bytes = [0_u8; 8];
    reader
        .read_exact(&mut size_bytes)
        .map_err(|_| AttachmentError::InvalidHeader)?;
    let expected_size = u64::from_be_bytes(size_bytes);

    let mut raw = Vec::with_capacity(fixed.len() + content_type_bytes.len() + size_bytes.len());
    raw.extend_from_slice(&fixed);
    raw.extend_from_slice(&content_type_bytes);
    raw.extend_from_slice(&size_bytes);

    Ok(Header {
        nonce_prefix,
        content_type,
        expected_size,
        raw,
    })
}

/// Fill `buf` from `reader` as completely as possible, looping over short reads, stopping only
/// when `buf` is full or `reader` reports EOF (`read` returning `0`). Returns the number of
/// bytes actually filled - less than `buf.len()` only at true EOF, never due to a merely
/// partial single `read` call, since `std::io::Read::read` is explicitly permitted to fill less
/// than the whole buffer even when more data remains.
fn fill_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AttachmentKey {
        AttachmentKey::generate().expect("test randomness must be available")
    }

    fn roundtrip(plaintext: &[u8], content_type: &str) -> (Vec<u8>, AttachmentMetadata) {
        let key = key();
        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key,
            content_type,
            plaintext.len() as u64,
            plaintext,
            &mut ciphertext,
        )
        .expect("encrypt");

        let mut decrypted = Vec::new();
        let metadata =
            decrypt_stream(&key, ciphertext.as_slice(), &mut decrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
        (ciphertext, metadata)
    }

    #[test]
    fn round_trips_an_empty_attachment() {
        let (_ciphertext, metadata) = roundtrip(b"", "text/plain");
        assert_eq!(metadata.content_type, "text/plain");
        assert_eq!(metadata.expected_size, 0);
    }

    #[test]
    fn round_trips_a_small_attachment() {
        let plaintext = b"a short message";
        let (_ciphertext, metadata) = roundtrip(plaintext, "text/plain");
        assert_eq!(metadata.expected_size, plaintext.len() as u64);
    }

    #[test]
    fn round_trips_an_attachment_spanning_multiple_chunks() {
        // Exercises the chunk boundary itself: exactly two full chunks plus a partial third,
        // so both encrypt_next/decrypt_next (non-final) and encrypt_last/decrypt_last (final)
        // paths run, and the exact-multiple-of-chunk-size EOF-detection edge case is covered
        // by the two-full-chunks portion.
        let plaintext = vec![0x5A_u8; CHUNK_SIZE * 2 + 1234];
        let (_ciphertext, metadata) = roundtrip(&plaintext, "application/octet-stream");
        assert_eq!(metadata.expected_size, plaintext.len() as u64);
    }

    #[test]
    fn round_trips_an_attachment_exactly_one_chunk_long() {
        let plaintext = vec![0x11_u8; CHUNK_SIZE];
        roundtrip(&plaintext, "application/octet-stream");
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let plaintext = b"secret contents";
        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key(),
            "text/plain",
            plaintext.len() as u64,
            plaintext.as_slice(),
            &mut ciphertext,
        )
        .expect("encrypt");

        let mut decrypted = Vec::new();
        let error = decrypt_stream(&key(), ciphertext.as_slice(), &mut decrypted)
            .expect_err("wrong key must fail");
        assert!(matches!(error, AttachmentError::Decryption));
    }

    #[test]
    fn tampered_chunk_content_fails_authentication() {
        let key = key();
        let plaintext = vec![0x7_u8; CHUNK_SIZE + 100];
        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key,
            "text/plain",
            plaintext.len() as u64,
            plaintext.as_slice(),
            &mut ciphertext,
        )
        .expect("encrypt");

        let flip_at = ciphertext.len() - 10;
        ciphertext[flip_at] ^= 0xFF;

        let mut decrypted = Vec::new();
        let error = decrypt_stream(&key, ciphertext.as_slice(), &mut decrypted)
            .expect_err("tampered ciphertext must fail");
        assert!(matches!(error, AttachmentError::Decryption));
    }

    #[test]
    fn tampered_header_fails_authentication() {
        let key = key();
        let mut ciphertext = Vec::new();
        encrypt_stream(&key, "text/plain", 5, b"hello".as_slice(), &mut ciphertext)
            .expect("encrypt");

        // Flip a byte inside the authenticated header's expected_size trailer - binary, so any
        // bit flip stays a structurally valid header (read_header still parses it), meaning
        // this can only fail at the AAD/AEAD authentication stage, proving the header content
        // itself is bound into the AAD and not just the nonce.
        let expected_size_offset = ciphertext.len() - 8 - b"hello".len() - TAG_LEN;
        ciphertext[expected_size_offset] ^= 0xFF;

        let mut decrypted = Vec::new();
        let error = decrypt_stream(&key, ciphertext.as_slice(), &mut decrypted)
            .expect_err("tampered header must fail");
        assert!(matches!(error, AttachmentError::Decryption));
    }

    #[test]
    fn truncated_ciphertext_is_rejected_not_accepted_as_a_shorter_valid_object() {
        let key = key();
        let plaintext = vec![0x3_u8; CHUNK_SIZE * 2];
        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key,
            "text/plain",
            plaintext.len() as u64,
            plaintext.as_slice(),
            &mut ciphertext,
        )
        .expect("encrypt");

        // Drop the final (properly last-block-flagged) chunk. What remains is a header plus
        // one real encrypt_next chunk - decrypting that chunk as if it were the last must fail,
        // because the STREAM construction binds the last-block flag into the tag.
        let truncated = &ciphertext[..ciphertext.len() - (CHUNK_SIZE + TAG_LEN)];

        let mut decrypted = Vec::new();
        let error = decrypt_stream(&key, truncated, &mut decrypted)
            .expect_err("truncated ciphertext must not decrypt as if complete");
        assert!(matches!(error, AttachmentError::Decryption));
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key(),
            "text/plain",
            5,
            b"hello".as_slice(),
            &mut ciphertext,
        )
        .expect("encrypt");
        ciphertext[0] = b'X';

        let mut decrypted = Vec::new();
        let error = decrypt_stream(&key(), ciphertext.as_slice(), &mut decrypted)
            .expect_err("bad magic must be rejected");
        assert!(matches!(error, AttachmentError::InvalidHeader));
    }

    #[test]
    fn object_names_are_random_and_do_not_reveal_a_filename() {
        let first = random_object_name().expect("random name");
        let second = random_object_name().expect("random name");
        assert_ne!(first, second);
        assert_eq!(first.len(), 32, "128-bit id, lower-hex encoded");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn plaintext_does_not_appear_anywhere_in_the_ciphertext() {
        let secret = b"the quick brown fox jumps over the lazy dog, verbatim";
        let (ciphertext, _metadata) = roundtrip(secret, "text/plain");
        let haystack = &ciphertext;
        let found = haystack
            .windows(secret.len())
            .any(|window| window == secret.as_slice());
        assert!(!found, "plaintext must not appear in the ciphertext");
    }
}
