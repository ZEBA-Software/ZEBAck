use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Der Server hat die Anfrage abgelehnt. `message` ist sein Text für den Benutzer.
    #[error("{message}")]
    Server { status: u16, code: String, message: String },
    #[error("Der Server ist nicht erreichbar: {0}")]
    Transport(String),
    #[error("Unerwartete Antwort des Servers: {0}")]
    Protocol(String),
    #[error("Das Repository ist verschlüsselt. Es wird ein Passwort gebraucht.")]
    PasswordRequired,
    #[error("Abgebrochen")]
    Cancelled,
    /// Eine Datei der Quelle ließ sich nicht öffnen oder lesen. Die Sicherung selbst ist
    /// davon nicht betroffen und kann mit der nächsten Datei weitermachen.
    #[error("Datei nicht lesbar: {0}")]
    Source(#[source] io::Error),
    #[error(transparent)]
    Format(#[from] zeback_format::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Error {
    /// Kürzel des Servers für diesen Fehler, z. B. `worm_locked` oder `quota_exceeded`.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Server { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Die Sicherung ist gesperrt (WORM) und lässt sich noch nicht löschen.
    pub fn is_locked(&self) -> bool {
        self.code() == Some("worm_locked")
    }

    /// Token fehlt, ist falsch oder wurde dem Gerät entzogen.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Error::Server { status: 401, .. })
    }

    pub fn is_wrong_password(&self) -> bool {
        matches!(self, Error::Format(zeback_format::Error::WrongPassword))
    }
}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Self {
        match error {
            ureq::Error::Io(error) => Error::Transport(error.to_string()),
            other => Error::Transport(other.to_string()),
        }
    }
}
