//! Zwischendatei für die Dateiliste einer Sicherung.
//!
//! Bei Hunderttausenden Dateien wird die Liste zu groß für den Arbeitsspeicher. Sie liegt
//! deshalb während der Arbeit in einer Datei im Temp-Ordner, die beim Verwerfen verschwindet.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;

pub(crate) struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// Legt eine neue, leere Datei an. Nur der eigene Benutzer kann sie lesen (unter Windows
    /// regelt das der Temp-Ordner des Profils).
    pub(crate) fn create() -> io::Result<(Self, File)> {
        let mut name = [0u8; 12];
        zeback_format::crypto::random(&mut name).map_err(io::Error::other)?;
        let name: String = name.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("zeback-{name}.tmp"));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok((Self { path }, file))
    }

    pub(crate) fn open(&self) -> io::Result<File> {
        File::open(&self.path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
