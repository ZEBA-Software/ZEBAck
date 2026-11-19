//! Beschreibung einer Sicherung.
//!
//! Die Dateiliste ist eine Zeile JSON je Eintrag. Sie wird wie Dateiinhalt in Blöcke
//! geschnitten und gespeichert; der Kopf nennt die Kennungen dieser Blöcke.

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::id::ChunkId;

pub const SNAPSHOT_FORMAT: u32 = 1;

/// Kopf einer Sicherung.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub format: u32,
    /// Zeitpunkt nach RFC 3339, z. B. `2026-11-19T09:30:00+01:00`
    pub created: String,
    pub computer: String,
    pub user: String,
    /// Profilordner zum Zeitpunkt der Sicherung, z. B. `C:\Users\anna`
    #[serde(default)]
    pub profile_dir: String,
    pub tool_version: String,
    pub encrypted: bool,
    pub roots: Vec<Root>,
    pub files: u64,
    pub bytes: u64,
    /// Blöcke der Dateiliste, in Reihenfolge
    pub tree: Vec<ChunkId>,
}

/// Was der Client dem Server beim Abschluss einer Sicherung im Klartext mitteilt. Der Kopf
/// selbst liegt als Block im Repository und ist dort verschlüsselt, wenn das Repository es ist.
/// Das Dashboard zeigt nur diese Angaben.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Kennung des Blocks, der den [`SnapshotHeader`] als JSON enthält
    pub header: ChunkId,
    pub created: String,
    pub computer: String,
    pub user: String,
    pub files: u64,
    pub bytes: u64,
}

/// Ein gesicherter Ordner oder eine einzeln gesicherte Datei.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Root {
    /// Name auf oberster Ebene der Sicherung
    pub name: String,
    pub original_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

/// Ein Eintrag der Dateiliste.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Pfad innerhalb der Sicherung mit `/` als Trenner, beginnend mit dem Namen des Roots
    pub path: String,
    pub kind: EntryKind,
    #[serde(default)]
    pub size: u64,
    /// Änderungszeit in Sekunden seit 1970
    #[serde(default)]
    pub mtime: i64,
    /// Windows-Dateiattribute
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attrs: u32,
    /// Blöcke des Inhalts, in Reihenfolge
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<ChunkId>,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// Schreibt einen Eintrag als eine Zeile.
pub fn write_entry(out: &mut impl Write, entry: &Entry) -> io::Result<()> {
    serde_json::to_writer(&mut *out, entry).map_err(io::Error::other)?;
    out.write_all(b"\n")
}

/// Liest die Einträge einer Dateiliste.
pub fn read_entries(input: impl BufRead) -> impl Iterator<Item = Result<Entry>> {
    input.lines().filter(|line| !matches!(line, Ok(text) if text.is_empty())).map(|line| Ok(serde_json::from_str(&line?)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip_as_lines() {
        let entries = vec![
            Entry { path: "Dokumente".into(), kind: EntryKind::Dir, size: 0, mtime: 1_700_000_000, attrs: 16, chunks: vec![] },
            Entry {
                path: "Dokumente/Brief \"neu\"\n.docx".into(),
                kind: EntryKind::File,
                size: 12,
                mtime: -5,
                attrs: 0,
                chunks: vec![ChunkId([1; 32]), ChunkId([2; 32])],
            },
        ];
        let mut list = Vec::new();
        for entry in &entries {
            write_entry(&mut list, entry).unwrap();
        }
        assert_eq!(list.iter().filter(|byte| **byte == b'\n').count(), entries.len());
        let read: Vec<Entry> = read_entries(&list[..]).collect::<Result<_>>().unwrap();
        assert_eq!(read, entries);
    }

    #[test]
    fn a_broken_line_is_an_error() {
        let list = b"{\"path\":\"a\",\"kind\":\"dir\"}\nkaputt\n";
        let read: Vec<Result<Entry>> = read_entries(&list[..]).collect();
        assert!(read[0].is_ok());
        assert!(read[1].is_err());
    }

    #[test]
    fn header_round_trip() {
        let header = SnapshotHeader {
            format: SNAPSHOT_FORMAT,
            created: "2026-11-19T09:30:00+01:00".into(),
            computer: "PC01".into(),
            user: "anna".into(),
            profile_dir: "C:\\Users\\anna".into(),
            tool_version: "0.22.0".into(),
            encrypted: true,
            roots: vec![Root { name: "Dokumente".into(), original_path: "C:\\Users\\anna\\Documents".into(), kind: Some("documents".into()), files: 3, bytes: 99 }],
            files: 3,
            bytes: 99,
            tree: vec![ChunkId([7; 32])],
        };
        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(serde_json::from_str::<SnapshotHeader>(&json).unwrap(), header);
    }
}
