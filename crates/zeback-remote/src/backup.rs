//! Eine Sicherung schreiben.
//!
//! [`SnapshotWriter`] bekommt Ordner und Dateien gereicht. Dateien schneidet er in Blöcke,
//! fragt den Server stapelweise, welche davon fehlen, und lädt nur diese hoch. Was sich seit
//! der vorigen Sicherung nicht geändert hat (gleiche Größe, gleiche Änderungszeit), liest er
//! gar nicht erst: Die Blöcke stehen schon auf dem Server.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};

use zeback_format::snapshot::{self, Entry, EntryKind, Root, SNAPSHOT_FORMAT, SnapshotHeader, SnapshotSummary};
use zeback_format::{ChunkId, Chunker, Sealer, wire};

use crate::client::{ServerClient, SnapshotInfo};
use crate::error::{Error, Result};
use crate::restore::SnapshotReader;
use crate::temp::TempFile;

/// So viel Klartext sammelt sich, bevor der Server gefragt und hochgeladen wird.
const FLUSH_BYTES: usize = 32 * 1024 * 1024;
/// Spätestens nach so vielen Blöcken wird gefragt – wichtig bei vielen kleinen Dateien.
const FLUSH_CHUNKS: usize = 4096;

/// Fortschritt und Abbruch. Die Oberfläche hängt hier ihre Anzeige ein.
pub trait Progress: Sync {
    /// So viele Bytes der Quelle sind verarbeitet (gelesen oder als unverändert erkannt).
    fn add(&self, _bytes: u64) {}
    /// Soll die Arbeit abbrechen?
    fn cancelled(&self) -> bool {
        false
    }
}

/// Kein Fortschritt, kein Abbruch.
pub struct NoProgress;
impl Progress for NoProgress {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupStats {
    pub files: u64,
    pub dirs: u64,
    /// Größe aller gesicherten Dateien
    pub bytes: u64,
    /// Dateien, die unverändert aus der vorigen Sicherung übernommen wurden
    pub reused_files: u64,
    /// Blöcke, die der Server noch nicht hatte
    pub new_chunks: u64,
    /// Tatsächlich übertragene Bytes (nach Kompression und Verschlüsselung)
    pub uploaded_bytes: u64,
}

/// Was aus einer Datei geworden ist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOutcome {
    /// Gelesen und in Blöcke geschnitten
    Stored,
    /// Unverändert seit der vorigen Sicherung, nicht gelesen
    Reused,
}

/// Angaben zur Sicherung, die nicht aus den Dateien selbst kommen.
#[derive(Clone, Debug, Default)]
pub struct SnapshotMeta {
    /// Zeitpunkt nach RFC 3339
    pub created: String,
    pub computer: String,
    pub user: String,
    pub tool_version: String,
    pub roots: Vec<Root>,
}

pub struct SnapshotWriter<'a> {
    client: &'a ServerClient,
    sealer: &'a Sealer,
    progress: &'a dyn Progress,
    /// Blöcke, die noch nicht beim Server angefragt sind
    pending: Vec<(ChunkId, Vec<u8>)>,
    pending_ids: HashSet<ChunkId>,
    pending_bytes: usize,
    /// Blöcke, die sicher auf dem Server liegen
    known: HashSet<ChunkId>,
    /// Alle Blöcke, die diese Sicherung braucht
    refs: HashSet<ChunkId>,
    /// Dateien der vorigen Sicherung nach Pfad
    previous: HashMap<String, Entry>,
    tree: BufWriter<File>,
    tree_file: TempFile,
    stats: BackupStats,
}

impl<'a> SnapshotWriter<'a> {
    pub fn new(client: &'a ServerClient, sealer: &'a Sealer, progress: &'a dyn Progress) -> Result<Self> {
        let (tree_file, file) = TempFile::create()?;
        Ok(Self {
            client,
            sealer,
            progress,
            pending: Vec::new(),
            pending_ids: HashSet::new(),
            pending_bytes: 0,
            known: HashSet::new(),
            refs: HashSet::new(),
            previous: HashMap::new(),
            tree: BufWriter::new(file),
            tree_file,
            stats: BackupStats::default(),
        })
    }

    /// Nimmt eine frühere Sicherung als Grundlage: Dateien, die seitdem gleich geblieben
    /// sind, werden nicht noch einmal gelesen.
    ///
    /// Übernommen wird nur, was der Server noch hat. Fehlt ein Block (etwa weil die alte
    /// Sicherung inzwischen gelöscht und aufgeräumt wurde), wird die Datei neu gelesen.
    pub fn use_previous(&mut self, snapshot: &SnapshotInfo) -> Result<()> {
        let reader = SnapshotReader::open(self.client, self.sealer, snapshot.header)?;
        let mut files = HashMap::new();
        let mut ids = HashSet::new();
        for entry in reader.entries()? {
            let entry = entry?;
            if entry.kind == EntryKind::File {
                ids.extend(entry.chunks.iter().copied());
                files.insert(entry.path.clone(), entry);
            }
        }
        let ids: Vec<ChunkId> = ids.into_iter().collect();
        let missing: HashSet<ChunkId> = self.client.missing(&ids)?.into_iter().collect();
        self.known.extend(ids.into_iter().filter(|id| !missing.contains(id)));
        self.previous = files;
        Ok(())
    }

    fn check(&self) -> Result<()> {
        if self.progress.cancelled() { Err(Error::Cancelled) } else { Ok(()) }
    }

    fn write_entry(&mut self, entry: &Entry) -> Result<()> {
        Ok(snapshot::write_entry(&mut self.tree, entry)?)
    }

    /// Trägt einen Ordner ein. `path` ist der Pfad in der Sicherung mit `/` als Trenner.
    pub fn add_dir(&mut self, path: &str, mtime: i64, attrs: u32) -> Result<()> {
        self.stats.dirs += 1;
        self.write_entry(&Entry { path: path.to_string(), kind: EntryKind::Dir, size: 0, mtime, attrs, chunks: Vec::new() })
    }

    /// Sichert eine Datei. `open` wird nur gerufen, wenn die Datei wirklich gelesen werden
    /// muss. Schlägt das Öffnen oder Lesen fehl, kommt der Fehler zurück und die Datei fehlt
    /// in der Sicherung; alles Übrige bleibt gültig, die Sicherung kann weiterlaufen.
    pub fn add_file<R: Read>(
        &mut self,
        path: &str,
        size: u64,
        mtime: i64,
        attrs: u32,
        open: impl FnOnce() -> io::Result<R>,
    ) -> Result<FileOutcome> {
        self.check()?;
        if let Some(old) = self.previous.get(path)
            && old.size == size
            && old.mtime == mtime
            && old.chunks.iter().all(|id| self.known.contains(id))
        {
            let entry = Entry { attrs, ..old.clone() };
            self.refs.extend(entry.chunks.iter().copied());
            self.write_entry(&entry)?;
            self.stats.files += 1;
            self.stats.reused_files += 1;
            self.stats.bytes += size;
            self.progress.add(size);
            return Ok(FileOutcome::Reused);
        }

        let (chunks, read) = self.store(open()?)?;
        // Die Datei kann sich seit dem Zählen geändert haben: Es gilt, was gelesen wurde.
        self.write_entry(&Entry { path: path.to_string(), kind: EntryKind::File, size: read, mtime, attrs, chunks })?;
        self.stats.files += 1;
        self.stats.bytes += read;
        Ok(FileOutcome::Stored)
    }

    /// Schneidet einen Datenstrom in Blöcke und merkt sie zum Hochladen vor.
    fn store(&mut self, reader: impl Read) -> Result<(Vec<ChunkId>, u64)> {
        let mut ids = Vec::new();
        let mut total = 0u64;
        for chunk in Chunker::new(reader, self.sealer.chunker_seed()) {
            self.check()?;
            let chunk = chunk?;
            total += chunk.len() as u64;
            self.progress.add(chunk.len() as u64);
            ids.push(self.queue(chunk)?);
        }
        Ok((ids, total))
    }

    fn queue(&mut self, chunk: Vec<u8>) -> Result<ChunkId> {
        let id = self.sealer.chunk_id(&chunk);
        self.refs.insert(id);
        if !self.known.contains(&id) && self.pending_ids.insert(id) {
            self.pending_bytes += chunk.len();
            self.pending.push((id, chunk));
            if self.pending_bytes >= FLUSH_BYTES || self.pending.len() >= FLUSH_CHUNKS {
                self.flush()?;
            }
        }
        Ok(id)
    }

    /// Fragt den Server nach den vorgemerkten Blöcken und lädt die fehlenden hoch.
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let ids: Vec<ChunkId> = self.pending.iter().map(|(id, _)| *id).collect();
        let missing: HashSet<ChunkId> = self.client.missing(&ids)?.into_iter().collect();
        let to_send: Vec<&(ChunkId, Vec<u8>)> = self.pending.iter().filter(|(id, _)| missing.contains(id)).collect();

        let mut records = Vec::new();
        for blob in seal_all(self.sealer, &to_send)? {
            let (id, blob) = blob?;
            if !records.is_empty() && records.len() + wire::RECORD_HEADER_LEN + blob.len() > wire::UPLOAD_BATCH_BYTES {
                self.send(&mut records)?;
            }
            wire::push_record(&mut records, &id, &blob);
            self.stats.new_chunks += 1;
        }
        self.send(&mut records)?;

        self.known.extend(ids);
        self.pending.clear();
        self.pending_ids.clear();
        self.pending_bytes = 0;
        Ok(())
    }

    fn send(&mut self, records: &mut Vec<u8>) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        self.check()?;
        self.client.upload(records)?;
        self.stats.uploaded_bytes += records.len() as u64;
        records.clear();
        Ok(())
    }

    /// Schließt die Sicherung ab: Dateiliste und Kopf hochladen, dann dem Server melden.
    /// Erst danach ist die Sicherung auf dem Server sichtbar.
    pub fn finish(mut self, meta: SnapshotMeta) -> Result<(SnapshotInfo, BackupStats)> {
        self.tree.flush()?;
        let tree_file = self.tree_file.open()?;
        // Die Dateiliste zählt nicht zum Fortschritt der Quelle.
        let progress = std::mem::replace(&mut self.progress, &NoProgress);
        let (tree, _) = self.store(tree_file)?;
        self.progress = progress;

        let header = SnapshotHeader {
            format: SNAPSHOT_FORMAT,
            created: meta.created,
            computer: meta.computer,
            user: meta.user,
            tool_version: meta.tool_version,
            encrypted: self.sealer.is_encrypted(),
            roots: meta.roots,
            files: self.stats.files,
            bytes: self.stats.bytes,
            tree,
        };
        let header_json = serde_json::to_vec(&header).map_err(|error| Error::Protocol(error.to_string()))?;
        // Der Kopf muss in einen Block passen; das tut er, solange es nicht Tausende Quellordner sind.
        if header_json.len() > zeback_format::chunker::MIN_CHUNK {
            return Err(Error::Protocol("Die Sicherung hat zu viele Quellordner.".into()));
        }
        let header_id = self.queue(header_json)?;
        self.flush()?;
        self.check()?;

        let summary = SnapshotSummary {
            header: header_id,
            created: header.created,
            computer: header.computer,
            user: header.user,
            files: header.files,
            bytes: header.bytes,
        };
        let refs: Vec<ChunkId> = self.refs.iter().copied().collect();
        let info = self.client.commit(&summary, &refs)?;
        Ok((info, self.stats))
    }
}

/// Komprimiert und verschlüsselt Blöcke auf mehreren Kernen. Die Reihenfolge bleibt erhalten.
fn seal_all(sealer: &Sealer, chunks: &[&(ChunkId, Vec<u8>)]) -> Result<Vec<Result<(ChunkId, Vec<u8>)>>> {
    let workers = std::thread::available_parallelism().map_or(1, usize::from).min(8).min(chunks.len().max(1));
    if workers <= 1 {
        return Ok(chunks.iter().map(|(id, data)| Ok((*id, sealer.seal(id, data)?))).collect());
    }
    let per_worker = chunks.len().div_ceil(workers);
    let sealed = std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .chunks(per_worker)
            .map(|part| scope.spawn(move || part.iter().map(|(id, data)| Ok((*id, sealer.seal(id, data)?))).collect::<Vec<_>>()))
            .collect();
        handles.into_iter().map(|handle| handle.join()).collect::<std::result::Result<Vec<_>, _>>()
    });
    match sealed {
        Ok(parts) => Ok(parts.into_iter().flatten().collect()),
        Err(_) => Err(Error::Protocol("Ein Arbeitsfaden ist abgestürzt.".into())),
    }
}
