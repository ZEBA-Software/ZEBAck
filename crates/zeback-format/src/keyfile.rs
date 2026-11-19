//! Schlüsseldatei: der Hauptschlüssel, verpackt mit einem Passwort.
//!
//! Aus dem Passwort entsteht mit Argon2id ein Schlüssel, der nur den Hauptschlüssel
//! verschlüsselt. So lässt sich das Passwort ändern, ohne die Sicherungen neu zu schreiben.
//! Die Datei darf auf dem Server liegen: Ohne Passwort ist sie wertlos.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{MasterKey, random};
use crate::error::{Error, Result};

const VERSION: u32 = 1;
const KDF: &str = "argon2id";
const AAD: &[u8] = b"ZEBack Schluesseldatei v1";

/// Obergrenzen beim Öffnen. Eine manipulierte Datei könnte sonst Arbeitsspeicher und
/// Rechenzeit des Clients beliebig binden.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_PASSES: u32 = 16;
const MAX_LANES: u32 = 16;

/// Aufwand für die Ableitung aus dem Passwort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfCost {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Default for KdfCost {
    /// 64 MiB, 3 Durchläufe: die zweite Empfehlung aus RFC 9106.
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, passes: 3, lanes: 4 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyFile {
    pub version: u32,
    pub kdf: String,
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    /// Hex, 16 Bytes
    pub salt: String,
    /// Hex, 24 Bytes
    pub nonce: String,
    /// Hex: verschlüsselter Hauptschlüssel mit Prüfwert
    pub wrapped: String,
}

impl KeyFile {
    /// Verpackt den Hauptschlüssel mit dem Passwort.
    pub fn create(password: &str, master: &MasterKey, cost: KdfCost) -> Result<Self> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        random(&mut salt)?;
        random(&mut nonce)?;
        let wrapping = derive(password, &salt, cost)?;
        let wrapped = cipher(&wrapping)
            .encrypt(&XNonce::from(nonce), Payload { msg: master.as_bytes(), aad: AAD })
            .map_err(|_| Error::KeyFile("Verschlüsseln fehlgeschlagen"))?;
        Ok(Self {
            version: VERSION,
            kdf: KDF.into(),
            memory_kib: cost.memory_kib,
            passes: cost.passes,
            lanes: cost.lanes,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            wrapped: hex::encode(wrapped),
        })
    }

    /// Holt den Hauptschlüssel mit dem Passwort heraus.
    pub fn unlock(&self, password: &str) -> Result<MasterKey> {
        if self.version != VERSION {
            return Err(Error::KeyFile("unbekannte Version"));
        }
        if self.kdf != KDF {
            return Err(Error::KeyFile("unbekanntes Verfahren"));
        }
        if self.memory_kib > MAX_MEMORY_KIB || self.passes > MAX_PASSES || self.lanes > MAX_LANES {
            return Err(Error::KeyFile("Aufwand über dem Limit"));
        }
        let salt = hex::decode(&self.salt).map_err(|_| Error::KeyFile("Salt"))?;
        let mut nonce = [0u8; 24];
        hex::decode_to_slice(&self.nonce, &mut nonce).map_err(|_| Error::KeyFile("Nonce"))?;
        let wrapped = hex::decode(&self.wrapped).map_err(|_| Error::KeyFile("Schlüssel"))?;

        let cost = KdfCost { memory_kib: self.memory_kib, passes: self.passes, lanes: self.lanes };
        let wrapping = derive(password, &salt, cost)?;
        let opened = Zeroizing::new(
            cipher(&wrapping)
                .decrypt(&XNonce::from(nonce), Payload { msg: &wrapped, aad: AAD })
                .map_err(|_| Error::WrongPassword)?,
        );
        let bytes: [u8; 32] = opened.as_slice().try_into().map_err(|_| Error::KeyFile("Schlüssellänge"))?;
        Ok(MasterKey::from_bytes(bytes))
    }
}

fn derive(password: &str, salt: &[u8], cost: KdfCost) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.memory_kib, cost.passes, cost.lanes, Some(32))
        .map_err(|_| Error::KeyFile("Aufwand ungültig"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|_| Error::KeyFile("Ableitung fehlgeschlagen"))?;
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("Schlüssel hat 32 Bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wenig Aufwand, damit die Tests schnell bleiben.
    const FAST: KdfCost = KdfCost { memory_kib: 64, passes: 1, lanes: 1 };

    #[test]
    fn unlocks_with_the_right_password_only() {
        let master = MasterKey::from_bytes([42; 32]);
        let file = KeyFile::create("geheim", &master, FAST).unwrap();
        assert_eq!(file.unlock("geheim").unwrap().as_bytes(), master.as_bytes());
        assert!(matches!(file.unlock("Geheim"), Err(Error::WrongPassword)));
        assert!(matches!(file.unlock(""), Err(Error::WrongPassword)));
    }

    #[test]
    fn survives_json_and_differs_each_time() {
        let master = MasterKey::generate().unwrap();
        let first = KeyFile::create("pw", &master, FAST).unwrap();
        let second = KeyFile::create("pw", &master, FAST).unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.wrapped, second.wrapped);
        let json = serde_json::to_string(&first).unwrap();
        assert!(!json.contains(&hex::encode(master.as_bytes())));
        let read: KeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(read.unlock("pw").unwrap().as_bytes(), master.as_bytes());
    }

    #[test]
    fn rejects_tampered_files() {
        let file = KeyFile::create("pw", &MasterKey::from_bytes([1; 32]), FAST).unwrap();

        let mut costly = file.clone();
        costly.memory_kib = u32::MAX;
        assert!(matches!(costly.unlock("pw"), Err(Error::KeyFile(_))));

        let mut other_cost = file.clone();
        other_cost.passes = 2;
        assert!(matches!(other_cost.unlock("pw"), Err(Error::WrongPassword)));

        let mut broken = file.clone();
        let flipped = if broken.wrapped.starts_with('0') { "1" } else { "0" };
        broken.wrapped.replace_range(0..1, flipped);
        assert!(matches!(broken.unlock("pw"), Err(Error::WrongPassword)));

        let mut version = file;
        version.version = 2;
        assert!(matches!(version.unlock("pw"), Err(Error::KeyFile(_))));
    }

    #[test]
    fn default_cost_works() {
        let master = MasterKey::from_bytes([9; 32]);
        let file = KeyFile::create("pw", &master, KdfCost::default()).unwrap();
        assert_eq!(file.unlock("pw").unwrap().as_bytes(), master.as_bytes());
    }
}
