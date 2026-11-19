//! Fehler beim Lesen und Schreiben des Blockformats.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Blob ist zu kurz")]
    Truncated,
    #[error("unbekannte Formatversion {0}")]
    Version(u8),
    #[error("unbekannte Schalter im Blob ({0:#04x})")]
    Flags(u8),
    #[error("Block ist zu groß ({0} Bytes)")]
    TooLarge(usize),
    #[error("Blob ist verschlüsselt, es ist aber kein Schlüssel geladen")]
    NeedsKey,
    #[error("Blob ist unverschlüsselt, das Repository verlangt Verschlüsselung")]
    Unencrypted,
    #[error("Entschlüsseln fehlgeschlagen: falscher Schlüssel oder beschädigte Daten")]
    Decrypt,
    #[error("Entpacken fehlgeschlagen: beschädigte Daten")]
    Decompress,
    #[error("Inhalt passt nicht zur Kennung des Blocks")]
    IdMismatch,
    #[error("Kennung ist ungültig")]
    InvalidId,
    #[error("Schlüsseldatei ist ungültig: {0}")]
    KeyFile(&'static str),
    #[error("falsches Passwort oder beschädigte Schlüsseldatei")]
    WrongPassword,
    #[error("Zufallszahlen sind nicht verfügbar")]
    Random,
    #[error("Sicherungsbeschreibung ist ungültig: {0}")]
    Snapshot(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
