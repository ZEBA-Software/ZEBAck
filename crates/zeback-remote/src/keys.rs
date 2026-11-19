//! Vom Passwort zum Schlüssel eines Repositorys.

use zeback_format::keyfile::KdfCost;
use zeback_format::{KeyFile, MasterKey, RepoKeys, Sealer};

use crate::client::{RepoInfo, ServerClient};
use crate::error::{Error, Result};

/// Öffnet das Repository zum Lesen und Schreiben.
///
/// * Unverschlüsselt: kein Passwort nötig.
/// * Verschlüsselt, noch ohne Schlüsseldatei: Dieses Gerät ist das erste. Es erzeugt den
///   Hauptschlüssel, verpackt ihn mit dem Passwort und legt die Schlüsseldatei auf dem
///   Server ab.
/// * Verschlüsselt, mit Schlüsseldatei: Das Passwort öffnet sie. Ein falsches Passwort
///   ergibt einen Fehler, für den [`Error::is_wrong_password`] gilt.
///
/// Das Passwort verlässt dieses Gerät nie; der Server bekommt nur die Schlüsseldatei.
pub fn open_sealer(client: &ServerClient, repo: &RepoInfo, password: Option<&str>) -> Result<Sealer> {
    if !repo.encrypted {
        return Ok(Sealer::Plain);
    }
    let password = password.filter(|password| !password.is_empty()).ok_or(Error::PasswordRequired)?;
    if let Some(key) = &repo.key {
        return unlock(key, password);
    }

    let master = MasterKey::generate()?;
    let key = KeyFile::create(password, &master, KdfCost::default())?;
    match client.put_key(&key) {
        Ok(()) => Ok(Sealer::Encrypted(RepoKeys::derive(&master))),
        // Ein anderes Gerät war schneller: Dann gilt dessen Schlüsseldatei.
        Err(error) if error.code() == Some("key_exists") => {
            let key = client.repo()?.key.ok_or_else(|| Error::Protocol("Der Server nennt die Schlüsseldatei nicht.".into()))?;
            unlock(&key, password)
        }
        Err(error) => Err(error),
    }
}

fn unlock(key: &KeyFile, password: &str) -> Result<Sealer> {
    Ok(Sealer::Encrypted(RepoKeys::derive(&key.unlock(password)?)))
}
