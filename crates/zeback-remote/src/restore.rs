//! Eine Sicherung lesen: Dateiliste holen, Dateien zurückholen, prüfen.

use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};

use zeback_format::snapshot::{self, Entry, EntryKind, SNAPSHOT_FORMAT, SnapshotHeader};
use zeback_format::{ChunkId, Sealer};

use crate::backup::Progress;
use crate::client::ServerClient;
use crate::error::{Error, Result};
use crate::temp::TempFile;

/// So viele Blöcke werden auf einmal angefragt (im Mittel rund 64 MiB).
const FETCH_IDS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub files: u64,
    pub bytes: u64,
}

pub struct SnapshotReader<'a> {
    client: &'a ServerClient,
    sealer: &'a Sealer,
    pub header: SnapshotHeader,
    tree: TempFile,
}

/// Holt Blöcke in der angegebenen Reihenfolge und reicht ihren Klartext an `sink`. Jeder
/// Block wird beim Öffnen gegen seine Kennung geprüft.
fn read_chunks(
    client: &ServerClient,
    sealer: &Sealer,
    ids: &[ChunkId],
    progress: &dyn Progress,
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<()> {
    let mut rest = ids;
    while !rest.is_empty() {
        if progress.cancelled() {
            return Err(Error::Cancelled);
        }
        let batch = &rest[..rest.len().min(FETCH_IDS)];
        let records = client.fetch_some(batch)?;
        for (id, blob) in &records {
            let plain = sealer.open(id, blob)?;
            sink(&plain)?;
            progress.add(plain.len() as u64);
        }
        rest = &rest[records.len()..];
    }
    Ok(())
}

impl<'a> SnapshotReader<'a> {
    /// Öffnet die Sicherung mit diesem Kopf und lädt ihre Dateiliste.
    pub fn open(client: &'a ServerClient, sealer: &'a Sealer, header: ChunkId) -> Result<Self> {
        let mut json = Vec::new();
        read_chunks(client, sealer, &[header], &crate::NoProgress, |plain| {
            json.extend_from_slice(plain);
            Ok(())
        })?;
        let header: SnapshotHeader = serde_json::from_slice(&json).map_err(zeback_format::Error::Snapshot)?;
        if header.format != SNAPSHOT_FORMAT {
            return Err(Error::Protocol(format!("Die Sicherung hat Format {}, bekannt ist {SNAPSHOT_FORMAT}.", header.format)));
        }

        let (tree, file) = TempFile::create()?;
        let mut out = BufWriter::new(file);
        read_chunks(client, sealer, &header.tree, &crate::NoProgress, |plain| out.write_all(plain))?;
        out.flush()?;
        Ok(Self { client, sealer, header, tree })
    }

    /// Die Einträge der Sicherung in der Reihenfolge, in der sie gesichert wurden.
    pub fn entries(&self) -> Result<impl Iterator<Item = Result<Entry>> + use<>> {
        let file = self.tree.open()?;
        Ok(snapshot::read_entries(BufReader::new(file)).map(|entry| entry.map_err(Error::from)))
    }

    /// Schreibt den Inhalt einer Datei nach `out`.
    pub fn restore_file(&self, entry: &Entry, out: &mut impl Write, progress: &dyn Progress) -> Result<()> {
        let mut written = 0u64;
        read_chunks(self.client, self.sealer, &entry.chunks, progress, |plain| {
            written += plain.len() as u64;
            out.write_all(plain)
        })?;
        if written != entry.size {
            return Err(Error::Protocol(format!("{}: {} Bytes erwartet, {written} erhalten.", entry.path, entry.size)));
        }
        Ok(())
    }

    /// Liest jede Datei der Sicherung vollständig vom Server und prüft jeden Block. Danach
    /// steht fest, dass sich die Sicherung wiederherstellen lässt.
    pub fn verify(&self, progress: &dyn Progress) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        for entry in self.entries()? {
            let entry = entry?;
            if entry.kind == EntryKind::File {
                self.restore_file(&entry, &mut io::sink(), progress)?;
                report.files += 1;
                report.bytes += entry.size;
            }
        }
        if report.files != self.header.files || report.bytes != self.header.bytes {
            return Err(Error::Protocol(format!(
                "Die Sicherung nennt {} Dateien ({} Bytes), gefunden wurden {} ({} Bytes).",
                self.header.files, self.header.bytes, report.files, report.bytes
            )));
        }
        Ok(report)
    }
}

/// Macht aus dem Pfad eines Eintrags einen Pfad unterhalb des Zielordners – oder `None`,
/// wenn der Pfad aus dem Zielordner hinausführen würde.
///
/// Die Dateiliste kommt vom Server. Ein manipulierter Eintrag wie `../../Windows/x.dll`
/// oder `C:\x` darf beim Wiederherstellen nie außerhalb des gewählten Ordners landen.
pub fn safe_relative_path(entry_path: &str) -> Option<PathBuf> {
    if entry_path.is_empty() || entry_path.contains('\\') || entry_path.contains(':') || entry_path.contains('\0') {
        return None;
    }
    let mut safe = PathBuf::new();
    for part in entry_path.split('/') {
        // Unter Windows schneidet das Dateisystem Punkte und Leerzeichen am Ende ab: „.. “ wäre „..“.
        let trimmed = part.trim_end_matches(['.', ' ']);
        if part.is_empty() || trimmed.is_empty() {
            return None;
        }
        safe.push(part);
    }
    // Zur Sicherheit noch einmal so, wie das Betriebssystem den Pfad liest.
    Path::new(&safe).components().all(|component| matches!(component, Component::Normal(_))).then_some(safe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_paths_pass() {
        assert_eq!(safe_relative_path("Dokumente/Brief.docx"), Some(PathBuf::from("Dokumente").join("Brief.docx")));
        assert_eq!(safe_relative_path("a"), Some(PathBuf::from("a")));
        assert_eq!(safe_relative_path("Fotos/2026/Urlaub (1)/bild.jpg").unwrap().components().count(), 4);
        assert!(safe_relative_path("Ordner/.versteckt").is_some());
        assert!(safe_relative_path("Ordner/datei.tar.gz").is_some());
    }

    #[test]
    fn escaping_paths_are_refused() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a/./b",
            "a//b",
            "a/",
            "..",
            ".",
            "a/.. /b",
            "a/.../b",
            "C:/Windows/x",
            "C:\\Windows\\x",
            "a\\..\\b",
            "\\\\server\\share\\x",
            "a/b\0c",
            "a/ /b",
            "datei.txt:strom",
        ] {
            assert_eq!(safe_relative_path(bad), None, "{bad:?}");
        }
    }
}
