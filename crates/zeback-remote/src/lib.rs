//! Sichern und Wiederherstellen gegen einen ZEBack Server.
//!
//! Dieses Crate kennt keine Oberfläche und kein Windows. Es bekommt Dateien gereicht und
//! macht daraus eine Sicherung im Blockformat ([`zeback_format`]): in Blöcke schneiden, nur
//! Fehlendes hochladen, abschließen. Umgekehrt holt es Sicherungen Block für Block zurück
//! und prüft dabei jeden Block gegen seine Kennung.
//!
//! Ablauf einer Sicherung:
//!
//! 1. [`ServerClient::pair`] (einmalig) oder [`ServerClient::new`] mit gespeichertem Token
//! 2. [`open_sealer`] – legt beim ersten Mal den Schlüssel an, sonst öffnet es ihn
//! 3. [`SnapshotWriter`] – Ordner und Dateien hinzufügen, dann [`SnapshotWriter::finish`]

mod backup;
mod client;
mod error;
mod keys;
mod restore;
mod temp;

pub use backup::{BackupStats, FileOutcome, NoProgress, Progress, SnapshotMeta, SnapshotWriter};
pub use client::{Health, RepoInfo, ServerClient, SnapshotInfo, Uploaded, normalize_url};
pub use error::{Error, Result};
pub use keys::open_sealer;
pub use restore::{SnapshotReader, VerifyReport, safe_relative_path};
pub use zeback_format::snapshot::{Entry, EntryKind, Root, SnapshotHeader};
pub use zeback_format::{ChunkId, Sealer};
