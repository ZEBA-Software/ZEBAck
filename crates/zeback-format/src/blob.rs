//! Blob: ein Block, wie er gespeichert und übertragen wird.
//!
//! ```text
//! Byte 0     Formatversion
//! Byte 1     Schalter: Bit 0 = zstd, Bit 1 = verschlüsselt
//! Byte 2–5   Länge des Klartexts (u32, Little Endian)
//! dann       verschlüsselt:   24 Byte Nonce, Chiffrat, 16 Byte Prüfwert
//!            unverschlüsselt: die (komprimierten) Daten
//! ```

use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, Payload};

use crate::FORMAT_VERSION;
use crate::crypto::{RepoKeys, random};
use crate::error::{Error, Result};
use crate::id::ChunkId;

/// Größter erlaubter Block (Klartext). Schützt vor übergroßen und „Kompressionsbomben“-Blobs.
pub const MAX_PLAIN_LEN: usize = 16 * 1024 * 1024;

pub const HEADER_LEN: usize = 6;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

const FLAG_ZSTD: u8 = 0b01;
const FLAG_ENCRYPTED: u8 = 0b10;
const KNOWN_FLAGS: u8 = FLAG_ZSTD | FLAG_ENCRYPTED;

const ZSTD_LEVEL: i32 = 3;

/// Was sich einem Blob ohne Schlüssel ansehen lässt. Der Server prüft damit jeden Upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobInfo {
    pub compressed: bool,
    pub encrypted: bool,
    pub plain_len: usize,
}

impl BlobInfo {
    /// Liest und prüft den Kopf eines Blobs.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let header = blob.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        if header[0] != FORMAT_VERSION {
            return Err(Error::Version(header[0]));
        }
        let flags = header[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::Flags(flags));
        }
        let plain_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if plain_len > MAX_PLAIN_LEN {
            return Err(Error::TooLarge(plain_len));
        }
        let info = Self { compressed: flags & FLAG_ZSTD != 0, encrypted: flags & FLAG_ENCRYPTED != 0, plain_len };
        let body = blob.len() - HEADER_LEN;
        if info.encrypted && body < NONCE_LEN + TAG_LEN {
            return Err(Error::Truncated);
        }
        // Unkomprimierte Daten müssen genau so lang sein, wie der Kopf sagt.
        let payload = if info.encrypted { body - NONCE_LEN - TAG_LEN } else { body };
        if !info.compressed && payload != plain_len {
            return Err(Error::Truncated);
        }
        Ok(info)
    }
}

/// Verpackt und öffnet Blobs eines Repositorys.
pub enum Sealer {
    /// Repository ohne Verschlüsselung
    Plain,
    Encrypted(RepoKeys),
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Schlüssel gehören in keine Fehlermeldung und kein Protokoll.
        f.write_str(if self.is_encrypted() { "Sealer::Encrypted(***)" } else { "Sealer::Plain" })
    }
}

impl Sealer {
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Sealer::Encrypted(_))
    }

    /// Kennung eines Blocks. Bei Verschlüsselung geht der Schlüssel mit ein: Ohne ihn lässt
    /// sich nicht prüfen, ob eine bekannte Datei im Repository liegt.
    pub fn chunk_id(&self, plain: &[u8]) -> ChunkId {
        match self {
            Sealer::Plain => ChunkId(*blake3::hash(plain).as_bytes()),
            Sealer::Encrypted(keys) => ChunkId(*blake3::keyed_hash(&keys.id_key, plain).as_bytes()),
        }
    }

    /// Startwert für [`crate::Chunker`]; 0 bei unverschlüsselten Repositories.
    pub fn chunker_seed(&self) -> u64 {
        match self {
            Sealer::Plain => 0,
            Sealer::Encrypted(keys) => keys.chunker_seed,
        }
    }

    /// Macht aus einem Block einen Blob: komprimieren, falls es etwas bringt, dann verschlüsseln.
    pub fn seal(&self, id: &ChunkId, plain: &[u8]) -> Result<Vec<u8>> {
        if plain.len() > MAX_PLAIN_LEN {
            return Err(Error::TooLarge(plain.len()));
        }
        let packed = zstd::bulk::compress(plain, ZSTD_LEVEL).ok().filter(|packed| packed.len() < plain.len());
        let mut flags = 0;
        if packed.is_some() {
            flags |= FLAG_ZSTD;
        }
        if self.is_encrypted() {
            flags |= FLAG_ENCRYPTED;
        }
        let payload = packed.as_deref().unwrap_or(plain);

        let mut header = [0u8; HEADER_LEN];
        header[0] = FORMAT_VERSION;
        header[1] = flags;
        header[2..6].copy_from_slice(&(plain.len() as u32).to_le_bytes());

        let mut blob = Vec::with_capacity(HEADER_LEN + NONCE_LEN + payload.len() + TAG_LEN);
        blob.extend_from_slice(&header);
        match self {
            Sealer::Plain => blob.extend_from_slice(payload),
            Sealer::Encrypted(keys) => {
                let mut nonce = [0u8; NONCE_LEN];
                random(&mut nonce)?;
                let sealed = keys
                    .cipher
                    .encrypt(&XNonce::from(nonce), Payload { msg: payload, aad: &aad(&header, id) })
                    .map_err(|_| Error::Decrypt)?;
                blob.extend_from_slice(&nonce);
                blob.extend_from_slice(&sealed);
            }
        }
        Ok(blob)
    }

    /// Öffnet einen Blob und prüft, dass der Inhalt zur Kennung passt.
    pub fn open(&self, id: &ChunkId, blob: &[u8]) -> Result<Vec<u8>> {
        let info = BlobInfo::parse(blob)?;
        let (header, body) = blob.split_at(HEADER_LEN);
        let payload = match (self, info.encrypted) {
            (Sealer::Plain, false) => std::borrow::Cow::Borrowed(body),
            (Sealer::Plain, true) => return Err(Error::NeedsKey),
            // Ein unverschlüsselter Blob in einem verschlüsselten Repository ist untergeschoben.
            (Sealer::Encrypted(_), false) => return Err(Error::Unencrypted),
            (Sealer::Encrypted(keys), true) => {
                let (nonce, sealed) = body.split_at(NONCE_LEN);
                let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("Länge geprüft");
                let header: [u8; HEADER_LEN] = header.try_into().expect("Länge geprüft");
                let opened = keys
                    .cipher
                    .decrypt(&XNonce::from(nonce), Payload { msg: sealed, aad: &aad(&header, id) })
                    .map_err(|_| Error::Decrypt)?;
                std::borrow::Cow::Owned(opened)
            }
        };
        let plain = if info.compressed {
            zstd::bulk::decompress(&payload, info.plain_len).map_err(|_| Error::Decompress)?
        } else {
            payload.into_owned()
        };
        if plain.len() != info.plain_len {
            return Err(Error::Decompress);
        }
        if self.chunk_id(&plain) != *id {
            return Err(Error::IdMismatch);
        }
        Ok(plain)
    }
}

/// Mitgeprüfte Daten: Kopf und Kennung. Damit lässt sich weder der Kopf ändern noch ein Blob
/// unter einer anderen Kennung ablegen.
fn aad(header: &[u8; HEADER_LEN], id: &ChunkId) -> [u8; HEADER_LEN + 32] {
    let mut aad = [0u8; HEADER_LEN + 32];
    aad[..HEADER_LEN].copy_from_slice(header);
    aad[HEADER_LEN..].copy_from_slice(id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;

    fn encrypted(byte: u8) -> Sealer {
        Sealer::Encrypted(RepoKeys::derive(&MasterKey::from_bytes([byte; 32])))
    }

    /// Daten, die sich nicht komprimieren lassen.
    fn noise(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new().update(b"noise").finalize_xof().fill(&mut out);
        out
    }

    #[test]
    fn round_trip_plain_and_encrypted() {
        let text = b"Hallo ZEBack ".repeat(1000);
        for sealer in [Sealer::Plain, encrypted(7)] {
            for plain in [&text[..], &noise(5000)[..], &[][..]] {
                let id = sealer.chunk_id(plain);
                let blob = sealer.seal(&id, plain).unwrap();
                let info = BlobInfo::parse(&blob).unwrap();
                assert_eq!(info.encrypted, sealer.is_encrypted());
                assert_eq!(info.plain_len, plain.len());
                assert_eq!(sealer.open(&id, &blob).unwrap(), plain);
            }
        }
    }

    #[test]
    fn compresses_only_when_smaller() {
        let sealer = Sealer::Plain;
        let text = vec![b'a'; 100_000];
        let blob = sealer.seal(&sealer.chunk_id(&text), &text).unwrap();
        assert!(BlobInfo::parse(&blob).unwrap().compressed);
        assert!(blob.len() < 1000);

        let random = noise(100_000);
        let blob = sealer.seal(&sealer.chunk_id(&random), &random).unwrap();
        assert!(!BlobInfo::parse(&blob).unwrap().compressed);
        assert_eq!(blob.len(), HEADER_LEN + random.len());
    }

    #[test]
    fn ids_depend_on_the_key() {
        let data = b"gleiche Daten";
        let plain = Sealer::Plain.chunk_id(data);
        let a = encrypted(1).chunk_id(data);
        let b = encrypted(2).chunk_id(data);
        assert_ne!(plain, a);
        assert_ne!(a, b);
        assert_eq!(a, encrypted(1).chunk_id(data));
    }

    #[test]
    fn encryption_hides_the_content() {
        let sealer = encrypted(3);
        let plain = noise(4096);
        let id = sealer.chunk_id(&plain);
        let first = sealer.seal(&id, &plain).unwrap();
        let second = sealer.seal(&id, &plain).unwrap();
        // Jede Nonce ist neu: derselbe Block ergibt nie zweimal denselben Blob.
        assert_ne!(first, second);
        assert!(!first.windows(32).any(|window| window == &plain[..32]));
    }

    #[test]
    fn detects_tampering() {
        let sealer = encrypted(4);
        let plain = b"wichtige Daten ".repeat(100);
        let id = sealer.chunk_id(&plain);
        let blob = sealer.seal(&id, &plain).unwrap();
        // Jedes einzelne Byte zählt: Kopf, Nonce, Chiffrat, Prüfwert.
        for position in 0..blob.len() {
            let mut broken = blob.clone();
            broken[position] ^= 0x01;
            assert!(sealer.open(&id, &broken).is_err(), "Änderung an Byte {position} blieb unbemerkt");
        }
        assert!(sealer.open(&id, &blob[..blob.len() - 1]).is_err());
    }

    #[test]
    fn detects_tampering_without_encryption() {
        let sealer = Sealer::Plain;
        let plain = noise(2000);
        let id = sealer.chunk_id(&plain);
        let mut blob = sealer.seal(&id, &plain).unwrap();
        blob[HEADER_LEN + 10] ^= 0x01;
        assert!(matches!(sealer.open(&id, &blob), Err(Error::IdMismatch)));
    }

    #[test]
    fn rejects_swapped_blobs_and_wrong_keys() {
        let sealer = encrypted(5);
        let (one, two) = (b"Block eins".to_vec(), b"Block zwei".to_vec());
        let (id_one, id_two) = (sealer.chunk_id(&one), sealer.chunk_id(&two));
        let blob_one = sealer.seal(&id_one, &one).unwrap();
        // Blob unter falscher Kennung
        assert!(matches!(sealer.open(&id_two, &blob_one), Err(Error::Decrypt)));
        // Falscher Schlüssel
        assert!(matches!(encrypted(6).open(&id_one, &blob_one), Err(Error::Decrypt)));
        // Kein Schlüssel
        assert!(matches!(Sealer::Plain.open(&id_one, &blob_one), Err(Error::NeedsKey)));
        // Unverschlüsselter Blob in verschlüsseltem Repository
        let plain_blob = Sealer::Plain.seal(&id_one, &one).unwrap();
        assert!(matches!(sealer.open(&id_one, &plain_blob), Err(Error::Unencrypted)));
    }

    #[test]
    fn parse_rejects_malformed_headers() {
        assert!(matches!(BlobInfo::parse(&[1, 0, 0]), Err(Error::Truncated)));
        assert!(matches!(BlobInfo::parse(&[9, 0, 0, 0, 0, 0]), Err(Error::Version(9))));
        assert!(matches!(BlobInfo::parse(&[1, 0x80, 0, 0, 0, 0]), Err(Error::Flags(0x80))));
        // Länge über dem Limit
        assert!(matches!(BlobInfo::parse(&[1, 1, 0xff, 0xff, 0xff, 0xff]), Err(Error::TooLarge(_))));
        // Verschlüsselt, aber ohne Platz für Nonce und Prüfwert
        assert!(matches!(BlobInfo::parse(&[1, 2, 0, 0, 0, 0, 1, 2, 3]), Err(Error::Truncated)));
        // Unkomprimiert, Länge passt nicht
        assert!(matches!(BlobInfo::parse(&[1, 0, 5, 0, 0, 0, 1, 2, 3]), Err(Error::Truncated)));
    }

    #[test]
    fn refuses_a_decompression_bomb() {
        // Kopf behauptet 10 Bytes, die Daten entpacken sich zu 1 MiB.
        let bomb = zstd::bulk::compress(&vec![0u8; 1 << 20], 3).unwrap();
        let mut blob = vec![1, FLAG_ZSTD, 10, 0, 0, 0];
        blob.extend_from_slice(&bomb);
        let id = ChunkId([0; 32]);
        assert!(matches!(Sealer::Plain.open(&id, &blob), Err(Error::Decompress)));
    }

    #[test]
    fn refuses_oversized_blocks() {
        let big = vec![0u8; MAX_PLAIN_LEN + 1];
        assert!(matches!(Sealer::Plain.seal(&ChunkId([0; 32]), &big), Err(Error::TooLarge(_))));
    }
}
