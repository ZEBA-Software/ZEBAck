//! Schlüssel eines Repositorys.
//!
//! Aus dem Hauptschlüssel entstehen drei voneinander unabhängige Werte: der Schlüssel für
//! Block-Kennungen, der Schlüssel für die Daten und der Startwert für das Schneiden der Blöcke.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const CONTEXT_ID: &str = "ZEBack 2026-11-19 Blockformat v1: Schluessel fuer Kennungen";
const CONTEXT_DATA: &str = "ZEBack 2026-11-19 Blockformat v1: Schluessel fuer Daten";
const CONTEXT_CHUNKER: &str = "ZEBack 2026-11-19 Blockformat v1: Startwert fuer Blockgrenzen";

/// Füllt den Puffer mit Zufallszahlen des Betriebssystems.
pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// Hauptschlüssel eines Repositorys. Wird beim Verwerfen aus dem Speicher gelöscht.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn generate() -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        random(key.as_mut_slice())?;
        Ok(Self(key))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Die aus dem Hauptschlüssel abgeleiteten Schlüssel.
pub struct RepoKeys {
    pub(crate) id_key: Zeroizing<[u8; 32]>,
    pub(crate) cipher: XChaCha20Poly1305,
    pub(crate) chunker_seed: u64,
}

impl RepoKeys {
    pub fn derive(master: &MasterKey) -> Self {
        let id_key = Zeroizing::new(blake3::derive_key(CONTEXT_ID, master.as_bytes()));
        let data_key = Zeroizing::new(blake3::derive_key(CONTEXT_DATA, master.as_bytes()));
        let seed = Zeroizing::new(blake3::derive_key(CONTEXT_CHUNKER, master.as_bytes()));
        let mut seed8 = [0u8; 8];
        seed8.copy_from_slice(&seed[..8]);
        Self {
            id_key,
            cipher: XChaCha20Poly1305::new_from_slice(data_key.as_slice()).expect("Schlüssel hat 32 Bytes"),
            // 0 hieße „kein Startwert“ und ergäbe dieselben Grenzen wie ohne Verschlüsselung.
            chunker_seed: u64::from_le_bytes(seed8).max(1),
        }
    }
}
