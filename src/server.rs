//! Sicherungsziel „ZEBack Server“.
//!
//! Anders als bei allen anderen Zielen entsteht hier keine ZIP-Datei. Die Dateien gehen in
//! Blöcken an den Server; was er schon hat, wird nicht noch einmal übertragen, und was sich
//! seit der letzten Sicherung nicht geändert hat, wird gar nicht erst gelesen. Die eigentliche
//! Arbeit steckt im Crate `zeback-remote`; dieses Modul verbindet sie mit Quellen, Fortschritt
//! und Meldungen des Programms.

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Local};
use zeback_remote::{EntryKind, Progress, RepoInfo, Root, Sealer, ServerClient, SnapshotInfo, SnapshotMeta, SnapshotReader, SnapshotWriter};

use crate::backup::{self, BackupJob, Manifest, ManifestRoot, Source};
use crate::job::{Cancelled, Reporter};
use crate::restore::{self, ArchiveInfo, Conflict, Mapping, RestoreJob, RestoreSummary};
use crate::util::fmt_bytes;
use crate::verify::VerifyReport;

/// Adresse des Servers und das Token, das dieses Gerät beim Koppeln bekommen hat.
#[derive(Clone)]
pub struct ServerLogin {
    pub url: String,
    pub token: String,
}

impl std::fmt::Debug for ServerLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Das Token soll in keiner Fehlermeldung und keinem Protokoll auftauchen.
        write!(f, "ServerLogin {{ url: {:?}, token: *** }}", self.url)
    }
}

/// Ergebnis des Koppelns.
#[derive(Clone)]
pub struct Paired {
    pub token: String,
    pub repository: String,
    pub encrypted: bool,
    pub worm_days: i64,
}

/// Ein Repository, das bereit ist: verbunden und – falls verschlüsselt – mit Schlüssel.
pub struct Ready {
    client: ServerClient,
    repo: RepoInfo,
    sealer: Sealer,
}

/// Was eine Sicherung zum Server ergeben hat.
pub struct ServerOutcome {
    pub files: u64,
    pub bytes: u64,
    /// Tatsächlich übertragene Bytes
    pub uploaded: u64,
    pub skipped_errors: u64,
    pub skipped_online: u64,
    pub encrypted: bool,
    /// Wo die Sicherung liegt, für die Erfolgsmeldung
    pub place: String,
}

fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// Macht aus einem Fehler der Server-Anbindung eine Meldung, mit der man etwas anfangen kann.
fn explain(error: zeback_remote::Error) -> anyhow::Error {
    use zeback_remote::Error;
    match error {
        Error::Cancelled => anyhow!(Cancelled),
        ref unauthorized if unauthorized.is_unauthorized() => anyhow!(t!(
            "Der Server kennt dieses Gerät nicht (mehr). Bitte unter „Sicherungsziele“ neu verbinden.",
            "The server does not know this device (any more). Please connect it again under “Backup targets”."
        )),
        ref wrong if wrong.is_wrong_password() => anyhow!(t!(
            "Das Passwort passt nicht zu diesem Tresor. Es gilt das Passwort der ersten Sicherung dorthin.",
            "The password does not match this vault. Use the password of the first backup made to it."
        )),
        Error::PasswordRequired => anyhow!(t!(
            "Dieser Tresor ist verschlüsselt. Schalte beim Sichern „Mit Passwort verschlüsseln“ ein und gib das Passwort an.",
            "This vault is encrypted. Turn on “Encrypt with password” for the backup and enter the password."
        )),
        other => anyhow!(other),
    }
}

/// Koppelt dieses Gerät mit dem Code aus dem Dashboard des Servers.
pub fn pair(url: &str, code: &str) -> Result<Paired> {
    let name = match computer_name() {
        name if name.is_empty() => "PC".to_string(),
        name => name,
    };
    let (client, repo) = ServerClient::pair(crate::nextcloud::new_agent(), url, code, &name).map_err(explain)?;
    Ok(Paired { token: client.token().to_string(), repository: repo.name, encrypted: repo.encrypted, worm_days: repo.worm_days })
}

/// Ein Satz für „Ziel prüfen“.
pub fn describe(login: &ServerLogin) -> Result<String> {
    let client = ServerClient::new(crate::nextcloud::new_agent(), &login.url, login.token.clone());
    let repo = client.repo().map_err(explain)?;
    let snapshots = client.snapshots().map_err(explain)?;
    let mut text = tr!(
        "Verbunden mit {} – Tresor „{}“, {}, {} Sicherung(en).",
        "Connected to {} – vault “{}”, {}, {} backup(s).",
        client.base_url(),
        repo.name,
        if repo.encrypted { t!("verschlüsselt", "encrypted") } else { t!("unverschlüsselt", "not encrypted") },
        snapshots.len()
    );
    if repo.worm_days > 0 {
        text.push_str(&tr!(
            " Neue Sicherungen sind {} Tage gegen Löschen gesperrt.",
            " New backups are locked against deletion for {} days.",
            repo.worm_days
        ));
    }
    Ok(text)
}

/// Verbindet sich und öffnet das Repository. `password` ist das Passwort der Verschlüsselung.
pub fn open(login: &ServerLogin, password: Option<&str>, rep: &Reporter) -> Result<Ready> {
    let client = ServerClient::new(crate::nextcloud::new_agent(), &login.url, login.token.clone());
    let repo = client.repo().map_err(explain)?;
    if repo.encrypted && repo.key.is_none() && password.is_some() {
        rep.log(t!(
            "Erste Sicherung in diesen Tresor: Der Schlüssel wird angelegt und mit deinem Passwort geschützt.",
            "First backup to this vault: the key is created and protected with your password."
        ));
    }
    let sealer = zeback_remote::open_sealer(&client, &repo, password).map_err(explain)?;
    Ok(Ready { client, repo, sealer })
}

/// Meldet den Fortschritt gedrosselt an die Oberfläche und reicht den Abbruch durch.
struct Meter<'a> {
    rep: &'a Reporter,
    done: AtomicU64,
    total: u64,
    last: Mutex<Instant>,
}

impl<'a> Meter<'a> {
    fn new(rep: &'a Reporter, total: u64) -> Self {
        rep.progress(0, total);
        Self { rep, done: AtomicU64::new(0), total, last: Mutex::new(Instant::now()) }
    }
}

impl Progress for Meter<'_> {
    fn add(&self, bytes: u64) {
        let done = self.done.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if let Ok(mut last) = self.last.try_lock()
            && last.elapsed() >= Duration::from_millis(60)
        {
            *last = Instant::now();
            self.rep.progress(done.min(self.total), self.total);
        }
    }

    fn cancelled(&self) -> bool {
        self.rep.cancelled()
    }
}

#[cfg(windows)]
fn attributes(meta: &std::fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}

#[cfg(not(windows))]
fn attributes(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// Die jüngste Sicherung dieses Rechners und Benutzers: Grundlage für „nur Geändertes lesen“.
fn previous_of<'a>(snapshots: &'a [SnapshotInfo], computer: &str, user: &str) -> Option<&'a SnapshotInfo> {
    // Der Server liefert die neueste zuerst.
    snapshots.iter().find(|snapshot| snapshot.computer == computer && snapshot.user == user)
}

/// Sichert die Quellen in das Repository.
pub fn backup(job: &BackupJob, sources: &[Source], name: &str, ready: &Ready, rep: &Reporter) -> Result<ServerOutcome> {
    let Ready { client, repo, sealer } = ready;
    if !repo.encrypted && job.password.is_some() {
        rep.warn(tr!(
            "„{name}“: Dieser Tresor ist auf dem Server als unverschlüsselt angelegt. Das Passwort wird dort nicht verwendet.",
            "“{name}”: this vault was created unencrypted on the server. The password is not used there."
        ));
    }
    let computer = computer_name();

    rep.status(t!("Dateien werden gezählt …", "Counting files …"));
    let (_, total_bytes) = backup::scan(sources, job.skip_online_only, Path::new(""), None, rep)?;
    let meter = Meter::new(rep, total_bytes);
    let mut writer = SnapshotWriter::new(client, sealer, &meter).map_err(explain)?;

    let snapshots = client.snapshots().map_err(explain)?;
    if let Some(previous) = previous_of(&snapshots, &computer, &job.profile_name) {
        rep.status(tr!("„{name}“: Vorige Sicherung wird gelesen …", "“{name}”: reading the previous backup …"));
        match writer.use_previous(previous) {
            Ok(()) => {}
            Err(zeback_remote::Error::Cancelled) => return Err(anyhow!(Cancelled)),
            // Ohne Grundlage wird eben alles gelesen; übertragen wird trotzdem nur Fehlendes.
            Err(error) => rep.warn(tr!(
                "„{name}“: Die vorige Sicherung ließ sich nicht lesen ({error}). Alle Dateien werden neu gelesen.",
                "“{name}”: the previous backup could not be read ({error}). All files are read again."
            )),
        }
    }

    let (mut skipped_errors, mut skipped_online) = (0u64, 0u64);
    let mut roots = Vec::new();
    let mut used_names = HashSet::new();
    for src in sources {
        let root = backup::root_name(src, &mut used_names);
        rep.status(tr!("Sichere {} …", "Backing up {} …", src.path.display()));
        let mut stats = Root {
            name: root.clone(),
            original_path: src.path.to_string_lossy().into_owned(),
            kind: src.kind.clone(),
            files: 0,
            bytes: 0,
        };
        for entry in src.walk() {
            rep.check()?;
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    rep.warn(tr!("Übersprungen (kein Zugriff): {e}", "Skipped (no access): {e}"));
                    skipped_errors += 1;
                    continue;
                }
            };
            let file_type = entry.file_type();
            // Verknüpfungen/Junctions (z. B. "Eigene Bilder") nicht verfolgen.
            if entry.depth() > 0 && file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let in_backup = backup::entry_name(&root, path.strip_prefix(&src.path).unwrap_or(Path::new("")));
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(e) => {
                    rep.warn(tr!("Übersprungen: {} ({e})", "Skipped: {} ({e})", path.display()));
                    skipped_errors += 1;
                    continue;
                }
            };
            let (size, mtime) = backup::file_stamp(&meta);
            if file_type.is_dir() {
                writer.add_dir(&in_backup, mtime, attributes(&meta)).map_err(explain)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if job.skip_online_only && backup::is_online_only(&meta) {
                skipped_online += 1;
                continue;
            }
            match writer.add_file(&in_backup, size, mtime, attributes(&meta), || File::open(path)) {
                Ok(_) => {
                    stats.files += 1;
                    stats.bytes += size;
                }
                Err(zeback_remote::Error::Source(e)) => {
                    rep.warn(tr!("Übersprungen: {} ({e})", "Skipped: {} ({e})", path.display()));
                    skipped_errors += 1;
                }
                Err(error) => return Err(explain(error)),
            }
        }
        roots.push(stats);
    }

    rep.status(tr!("„{name}“: Sicherung wird abgeschlossen …", "“{name}”: finishing the backup …"));
    let meta = SnapshotMeta {
        created: Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        computer,
        user: job.profile_name.clone(),
        profile_dir: job.profile_dir.to_string_lossy().into_owned(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        roots,
    };
    let (info, stats) = writer.finish(meta).map_err(explain)?;
    rep.progress(total_bytes, total_bytes);

    rep.log(tr!(
        "„{name}“: {} Dateien ({}) gesichert, davon {} unverändert übernommen. Übertragen: {}.",
        "“{name}”: {} files ({}) backed up, {} of them taken over unchanged. Transferred: {}.",
        stats.files,
        fmt_bytes(stats.bytes),
        stats.reused_files,
        fmt_bytes(stats.uploaded_bytes)
    ));
    if info.locked {
        rep.log(tr!(
            "„{name}“: Die Sicherung ist bis {} gegen Löschen gesperrt.",
            "“{name}”: the backup is locked against deletion until {}.",
            date(info.retain_until)
        ));
    }
    Ok(ServerOutcome {
        files: stats.files,
        bytes: stats.bytes,
        uploaded: stats.uploaded_bytes,
        skipped_errors,
        skipped_online,
        encrypted: sealer.is_encrypted(),
        place: tr!("{} / {} (Sicherung Nr. {})", "{} / {} (backup no. {})", host(client.base_url()), repo.name, info.id),
    })
}

/// Löscht alle Sicherungen dieses Rechners und Benutzers bis auf die `keep` neuesten.
/// Gesperrte Sicherungen (WORM) bleiben; das ist kein Fehler.
pub fn prune(login: &ServerLogin, name: &str, profile_name: &str, keep: u32, rep: &Reporter) -> u32 {
    let client = ServerClient::new(crate::nextcloud::new_agent(), &login.url, login.token.clone());
    let snapshots = match client.snapshots() {
        Ok(snapshots) => snapshots,
        Err(e) => {
            rep.warn(tr!("Aufräumen auf „{name}“ nicht möglich: {e}", "Cannot clean up on “{name}”: {e}"));
            return 0;
        }
    };
    let computer = computer_name();
    let (mut removed, mut locked) = (0, 0);
    let own = snapshots.iter().filter(|snapshot| snapshot.computer == computer && snapshot.user == profile_name);
    for old in own.skip(keep.max(1) as usize) {
        match client.delete_snapshot(old.id) {
            Ok(()) => {
                rep.log(tr!(
                    "Alte Sicherung gelöscht („{name}“): Nr. {} vom {}",
                    "Old backup deleted (“{name}”): no. {} of {}",
                    old.id,
                    date(old.received_at)
                ));
                removed += 1;
            }
            Err(e) if e.is_locked() => locked += 1,
            Err(e) => rep.warn(tr!(
                "Alte Sicherung Nr. {} auf „{name}“ nicht gelöscht: {e}",
                "Old backup no. {} on “{name}” was not deleted: {e}",
                old.id
            )),
        }
    }
    if locked > 0 {
        rep.log(tr!(
            "„{name}“: {locked} ältere Sicherung(en) sind noch gesperrt und bleiben, bis ihre Frist abläuft.",
            "“{name}”: {locked} older backup(s) are still locked and stay until their period ends."
        ));
    }
    removed
}

/// Adresse ohne `https://`, für Anzeigen.
pub fn host(url: &str) -> &str {
    let url = url.trim().trim_end_matches('/');
    url.strip_prefix("https://").unwrap_or(url)
}

fn date(seconds: i64) -> String {
    DateTime::from_timestamp(seconds, 0).map_or_else(String::new, |time| time.with_timezone(&Local).format("%d.%m.%Y").to_string())
}

/// Hält `anyhow` den Zusammenhang „Ziel X“ bereit, wie bei den anderen Zielarten.
pub fn open_named(name: &str, login: &ServerLogin, password: Option<&str>, rep: &Reporter) -> Result<Ready> {
    open(login, password, rep).with_context(|| tr!("Ziel „{name}“", "Target “{name}”"))
}

// ---------------------------------------------------------------------------- Wiederherstellen

/// Eine Sicherung auf einem ZEBack Server, wie die Suche sie findet. Diese Angaben nennt der
/// Server auch ohne Passwort; Ordner und Dateinamen gehören nicht dazu.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerSnapshot {
    pub id: i64,
    /// Kennung des Blocks mit dem Kopf der Sicherung
    pub header: zeback_remote::ChunkId,
    pub computer: String,
    pub user: String,
    pub files: u64,
    pub bytes: u64,
    /// Eingang auf dem Server, Sekunden seit 1970
    pub received_at: i64,
}

impl ServerSnapshot {
    /// Name in der Liste der gefundenen Sicherungen, z. B. `PC01 · anna · 4812 Dateien`.
    pub fn label(&self) -> String {
        let files = tr!("{} Dateien", "{} files", self.files);
        let who: Vec<&str> = [self.computer.as_str(), self.user.as_str()].into_iter().filter(|part| !part.is_empty()).collect();
        if who.is_empty() { files } else { format!("{} · {files}", who.join(" · ")) }
    }
}

/// Woher eine geöffnete Sicherung kommt, wenn sie auf einem ZEBack Server liegt.
#[derive(Clone, Debug)]
pub struct ServerSource {
    pub login: ServerLogin,
    /// Name des Sicherungsziels
    pub target_name: String,
    pub snapshot: ServerSnapshot,
}

/// Die Sicherungen des Repositorys, neueste zuerst.
pub fn list(login: &ServerLogin) -> Result<Vec<ServerSnapshot>> {
    let client = ServerClient::new(crate::nextcloud::new_agent(), &login.url, login.token.clone());
    Ok(client
        .snapshots()
        .map_err(explain)?
        .into_iter()
        .map(|snapshot| ServerSnapshot {
            id: snapshot.id,
            header: snapshot.header,
            computer: snapshot.computer,
            user: snapshot.user,
            files: snapshot.files,
            bytes: snapshot.bytes,
            received_at: snapshot.received_at,
        })
        .collect())
}

/// Verbindet sich zum Lesen. Anders als beim Sichern wird hier nie ein Schlüssel angelegt.
fn open_for_reading(login: &ServerLogin, password: Option<&str>) -> Result<Ready> {
    let client = ServerClient::new(crate::nextcloud::new_agent(), &login.url, login.token.clone());
    let repo = client.repo().map_err(explain)?;
    if repo.encrypted && repo.key.is_none() {
        anyhow::bail!(t!(
            "In diesem Tresor liegt noch kein Schlüssel. Er enthält keine Sicherung, die sich öffnen ließe.",
            "There is no key in this vault yet. It contains no backup that could be opened."
        ));
    }
    if repo.encrypted && password.is_none_or(str::is_empty) {
        anyhow::bail!(t!(
            "Diese Sicherung ist verschlüsselt. Bitte das Passwort eingeben.",
            "This backup is encrypted. Please enter the password."
        ));
    }
    let sealer = zeback_remote::open_sealer(&client, &repo, password).map_err(explain)?;
    Ok(Ready { client, repo, sealer })
}

/// Öffnet eine Sicherung auf dem Server und beschreibt sie so, wie die Wiederherstellung es
/// von einer ZIP-Datei kennt.
///
/// Ist das Repository verschlüsselt und kein Passwort angegeben, kommt eine „verschlossene“
/// Beschreibung zurück ([`ArchiveInfo::is_locked`]): Sie nennt nur, was der Server ohne
/// Passwort weiß. Mit dem Passwort noch einmal aufgerufen, kommt der ganze Inhalt.
pub fn inspect(source: &ServerSource, password: Option<&str>) -> Result<ArchiveInfo> {
    let client = ServerClient::new(crate::nextcloud::new_agent(), &source.login.url, source.login.token.clone());
    let repo = client.repo().map_err(explain)?;
    let snapshot = &source.snapshot;
    let path = std::path::PathBuf::from(format!(
        "{}/{}/{}",
        host(client.base_url()),
        repo.name,
        tr!("Sicherung Nr. {}", "Backup no. {}", snapshot.id)
    ));
    let mut info = ArchiveInfo {
        path,
        size: 0,
        entries: snapshot.files as usize,
        total_bytes: snapshot.bytes,
        manifest: None,
        encrypted: repo.encrypted,
        server: Some(source.clone()),
    };
    if repo.encrypted && password.is_none_or(str::is_empty) {
        return Ok(info);
    }

    let ready = open_for_reading(&source.login, password)?;
    let reader = SnapshotReader::open(&ready.client, &ready.sealer, snapshot.header).map_err(explain)?;
    let header = &reader.header;
    info.entries = header.files as usize;
    info.total_bytes = header.bytes;
    info.manifest = Some(Manifest {
        format: 1,
        created: header.created.clone(),
        computer: header.computer.clone(),
        user: header.user.clone(),
        profile_dir: header.profile_dir.clone(),
        encrypted: header.encrypted,
        tool_version: header.tool_version.clone(),
        roots: header
            .roots
            .iter()
            .map(|root| ManifestRoot {
                name: root.name.clone(),
                original_path: root.original_path.clone(),
                kind: root.kind.clone(),
                files: root.files,
                bytes: root.bytes,
            })
            .collect(),
        // Auf dem Server ist jede Sicherung vollständig; Ketten aus Teilsicherungen gibt es nicht.
        incremental: false,
        base: None,
    });
    Ok(info)
}

/// Die Dateien der Sicherung, für die Baumansicht zum Auswählen.
pub fn list_entries(source: &ServerSource, password: Option<&str>) -> Result<Vec<restore::Entry>> {
    let ready = open_for_reading(&source.login, password)?;
    let reader = SnapshotReader::open(&ready.client, &ready.sealer, source.snapshot.header).map_err(explain)?;
    let mut entries = Vec::new();
    for entry in reader.entries().map_err(explain)? {
        let entry = entry.map_err(explain)?;
        if entry.kind == EntryKind::File {
            entries.push(restore::Entry { path: entry.path, size: entry.size });
        }
    }
    Ok(entries)
}

/// Liest die ganze Sicherung vom Server und prüft jeden Block.
pub fn verify(source: &ServerSource, password: Option<&str>, rep: &Reporter) -> Result<VerifyReport> {
    let ready = open_for_reading(&source.login, password)?;
    let reader = SnapshotReader::open(&ready.client, &ready.sealer, source.snapshot.header).map_err(explain)?;
    rep.status(t!("Sicherung wird geprüft …", "Verifying backup …"));
    let meter = Meter::new(rep, reader.header.bytes);
    let report = reader.verify(&meter).map_err(|error| match error {
        zeback_remote::Error::Format(_) | zeback_remote::Error::Protocol(_) => explain(error).context(t!(
            "Die Sicherung auf dem Server ist beschädigt",
            "The backup on the server is damaged"
        )),
        other => explain(other),
    })?;
    rep.progress(reader.header.bytes, reader.header.bytes);
    Ok(VerifyReport { files: report.files, bytes: report.bytes })
}

/// Holt eine Sicherung vom Server zurück – mit denselben Regeln wie [`restore::run`] für
/// ZIP-Dateien: Zuordnung der Ordner, Auswahl einzelner Dateien, Umgang mit Vorhandenem.
pub fn restore(job: &RestoreJob, source: &ServerSource, rep: &Reporter) -> Result<RestoreSummary> {
    let started = Instant::now();
    let ready = open_for_reading(&source.login, job.password.as_deref())?;
    let reader = SnapshotReader::open(&ready.client, &ready.sealer, source.snapshot.header).map_err(explain)?;

    let mut summary = RestoreSummary { restored: 0, bytes: 0, skipped_existing: 0, failed: 0, duration: Duration::ZERO };
    let meter = Meter::new(rep, job.total_bytes);
    rep.status(t!("Dateien werden wiederhergestellt …", "Restoring files …"));

    for entry in reader.entries().map_err(explain)? {
        rep.check()?;
        let entry = entry.map_err(explain)?;
        // Die Dateiliste kommt vom Server: Kein Eintrag darf aus dem Zielordner hinausführen.
        let Some(rel) = zeback_remote::safe_relative_path(&entry.path) else {
            rep.warn(tr!("Unsicherer Pfad in der Sicherung übersprungen: {}", "Skipped unsafe path in the backup: {}", entry.path));
            summary.failed += 1;
            continue;
        };
        // Bei einer Auswahl einzelner Dateien alles andere auslassen.
        if let Some(only) = &job.only
            && !restore::is_selected(only, &entry.path)
        {
            continue;
        }
        let target = match &job.mapping {
            Mapping::Everything(dest) => dest.join(&rel),
            Mapping::Roots(roots) => {
                let mut components = rel.components();
                let Some(first) = components.next() else { continue };
                // Nicht ausgewählte Ordner auslassen.
                let Some(dest) = roots.get(first.as_os_str().to_string_lossy().as_ref()) else { continue };
                let rest = components.as_path();
                // Eine einzeln gesicherte Datei liegt auf der obersten Ebene: Ihr Ziel ist dann
                // schon der ganze Dateipfad.
                if rest.as_os_str().is_empty() { dest.clone() } else { dest.join(rest) }
            }
        };

        if entry.kind == EntryKind::Dir {
            if let Err(e) = std::fs::create_dir_all(&target) {
                rep.warn(tr!("Ordner kann nicht angelegt werden: {} ({e})", "Cannot create folder: {} ({e})", target.display()));
                summary.failed += 1;
            }
            continue;
        }
        if job.conflict == Conflict::Skip && target.exists() {
            summary.skipped_existing += 1;
            meter.add(entry.size);
            continue;
        }

        let modified = u64::try_from(entry.mtime).ok().filter(|secs| *secs > 0).map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        let mut fatal = None;
        let written = restore::replace_file(&target, modified, |out| {
            match reader.restore_file(&entry, out, &meter) {
                Ok(()) => Ok(entry.size),
                // Beschädigter Block oder Schreibfehler: Diese Datei fehlt, die übrigen gehen weiter.
                Err(error @ (zeback_remote::Error::Format(_) | zeback_remote::Error::Protocol(_) | zeback_remote::Error::Io(_))) => {
                    Err(anyhow!(error))
                }
                // Abbruch, Server nicht erreichbar, Zugang entzogen: Weitermachen hat keinen Sinn.
                Err(error) => {
                    fatal = Some(explain(error));
                    Err(anyhow!(Cancelled))
                }
            }
        });
        if let Some(error) = fatal {
            return Err(error);
        }
        match written {
            Ok(bytes) => {
                summary.restored += 1;
                summary.bytes += bytes;
            }
            Err(e) => {
                rep.warn(tr!("Nicht wiederhergestellt: {} ({e:#})", "Not restored: {} ({e:#})", target.display()));
                summary.failed += 1;
            }
        }
    }

    rep.progress(job.total_bytes, job.total_bytes);
    summary.duration = started.elapsed();
    Ok(summary)
}

/// Diese Tests brauchen einen echten ZEBack Server. Sie laufen nur, wenn die
/// Umgebungsvariable `ZEBACK_SERVER_BIN` auf dessen Programm zeigt; sonst tun sie nichts.
#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use super::*;
    use crate::backup::{BackupKind, Destination};
    use crate::config::{Compression, Target, TargetKind};
    use crate::job::Msg;
    use crate::jobs;

    const ADMIN: &str = "verwaltung-test-token-0123456789";
    const PASSWORD: &str = "ein langes Passwort";

    struct Live {
        url: String,
        dir: PathBuf,
        process: Child,
    }

    impl Drop for Live {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let _ = self.process.wait();
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    impl Live {
        fn start(label: &str) -> Option<Self> {
            let bin = std::env::var_os("ZEBACK_SERVER_BIN")?;
            let dir = std::env::temp_dir().join(format!("zeback-test-server-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            // Freien Port finden: kurz belegen, wieder freigeben.
            let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            let process = Command::new(bin)
                .env("ZEBACK_DATA", dir.join("data"))
                .env("ZEBACK_LISTEN", format!("127.0.0.1:{port}"))
                .env("ZEBACK_ADMIN_TOKEN", ADMIN)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let live = Self { url: format!("http://127.0.0.1:{port}"), dir, process };
            for _ in 0..100 {
                if ServerClient::health(&crate::nextcloud::new_agent(), &live.url).is_ok() {
                    return Some(live);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("ZEBack Server ist nicht gestartet");
        }

        fn admin(&self, path: &str, body: String) -> String {
            let mut response = crate::nextcloud::new_agent()
                .post(format!("{}/api/v1/admin{path}", self.url))
                .header("Authorization", format!("Bearer {ADMIN}"))
                .content_type("application/json")
                .send(body.as_bytes())
                .unwrap();
            assert!(response.status().as_u16() < 300, "{path}: {}", response.status());
            response.body_mut().read_to_string().unwrap()
        }

        /// Zahl hinter `"<field>":` in einer JSON-Antwort.
        fn number(json: &str, field: &str) -> i64 {
            let rest = json.split(&format!("\"{field}\":")).nth(1).unwrap();
            rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap()
        }

        /// Legt Volume und Repository an und koppelt dieses Gerät.
        fn login(&self, name: &str, encrypted: bool, worm_days: u32) -> ServerLogin {
            let path = self.dir.join("volumes").join(name).to_string_lossy().replace('\\', "/");
            let volume = self.admin("/volumes", format!(r#"{{"name":"{name}","path":"{path}","worm_days":{worm_days}}}"#));
            let repository = self.admin(
                "/repositories",
                format!(r#"{{"volume_id":{},"name":"{name}","encrypted":{encrypted}}}"#, Self::number(&volume, "id")),
            );
            let code = self.admin(&format!("/repositories/{}/pairing-codes", Self::number(&repository, "id")), String::new());
            let code = code.split("\"code\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
            let paired = pair(&self.url, &code).unwrap();
            assert_eq!(paired.repository, name);
            assert_eq!((paired.encrypted, paired.worm_days), (encrypted, worm_days as i64));
            ServerLogin { url: self.url.clone(), token: paired.token }
        }
    }

    fn sample(dir: &Path) {
        fs::create_dir_all(dir.join("Unterordner/leer")).unwrap();
        fs::write(dir.join("Brief.txt"), "Sehr geehrte Damen und Herren, ".repeat(500)).unwrap();
        fs::write(dir.join("Unterordner/Größe – Übersicht.txt"), "äöüß €").unwrap();
        fs::write(dir.join("Unterordner/daten.bin"), vec![7u8; 700_000]).unwrap();
        fs::write(dir.join("leer.txt"), b"").unwrap();
    }

    fn job(source: &Path, destinations: Vec<Destination>, password: Option<&str>) -> BackupJob {
        BackupJob {
            profile_name: "anna".into(),
            profile_dir: source.to_path_buf(),
            sources: vec![Source::plain(source.to_path_buf(), None)],
            destinations,
            compression: Compression::default(),
            skip_online_only: false,
            verify: false,
            password: password.map(str::to_string),
            incremental: None,
        }
    }

    fn server(login: &ServerLogin) -> Destination {
        Destination::Server { name: "Server".into(), login: login.clone() }
    }

    /// Führt `work` aus und gibt Ergebnis und alle Meldungen ans Protokoll zurück.
    fn logged<T>(work: impl FnOnce(&Reporter) -> T) -> (T, String) {
        let (rep, rx, _cancel) = Reporter::new(|| {});
        let result = work(&rep);
        drop(rep);
        let text = rx.iter().filter_map(|msg| matches!(&msg, Msg::Log(_) | Msg::Warn(_)).then(|| match msg {
            Msg::Log(text) | Msg::Warn(text) => text,
            _ => unreachable!(),
        }));
        (result, text.collect::<Vec<_>>().join("\n"))
    }

    fn client(login: &ServerLogin) -> ServerClient {
        ServerClient::new(crate::nextcloud::new_agent(), &login.url, login.token.clone())
    }

    #[test]
    fn backs_up_to_a_server_and_only_sends_what_is_new() {
        let Some(live) = Live::start("sichern") else { return };
        let source = live.dir.join("quelle");
        sample(&source);
        let login = live.login("kunde-a", true, 0);

        let (summary, log) = logged(|rep| backup::run(&job(&source, vec![server(&login)], Some(PASSWORD)), rep));
        let summary = summary.unwrap();
        assert_eq!(summary.files, 4);
        assert_eq!(summary.zip_size, 0);
        assert!(summary.to_server && summary.encrypted);
        assert_eq!(summary.kind, BackupKind::Full);
        assert!(summary.uploaded > 0 && summary.uploaded < summary.bytes, "{} von {}", summary.uploaded, summary.bytes);
        assert_eq!(summary.saved.len(), 1);
        assert!(summary.saved[0].starts_with("Server: ") && summary.saved[0].contains("kunde-a"), "{:?}", summary.saved);
        assert!(log.contains("Der Schlüssel wird angelegt"), "{log}");
        assert!(log.contains("4 Dateien"), "{log}");

        // Zweiter Lauf ohne Änderungen: nichts wird neu gelesen, fast nichts übertragen.
        let (again, log) = logged(|rep| backup::run(&job(&source, vec![server(&login)], Some(PASSWORD)), rep));
        let again = again.unwrap();
        assert_eq!((again.files, again.bytes), (summary.files, summary.bytes));
        assert!(again.uploaded < 2000, "{} Bytes übertragen", again.uploaded);
        assert!(log.contains("davon 4 unverändert übernommen"), "{log}");

        // Was auf dem Server liegt, lässt sich mit dem Passwort zurückholen – unter den erwarteten Pfaden.
        let connection = client(&login);
        let repo = connection.repo().unwrap();
        let sealer = zeback_remote::open_sealer(&connection, &repo, Some(PASSWORD)).unwrap();
        let snapshots = connection.snapshots().unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].user, "anna");
        let reader = zeback_remote::SnapshotReader::open(&connection, &sealer, snapshots[0].header).unwrap();
        assert_eq!(reader.header.profile_dir, source.to_string_lossy());
        assert_eq!(reader.header.roots.len(), 1);
        assert_eq!((reader.header.roots[0].files, reader.header.roots[0].name.as_str()), (4, "quelle"));
        let entries: Vec<_> = reader.entries().unwrap().map(Result::unwrap).collect();
        let paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
        for expected in ["quelle", "quelle/Brief.txt", "quelle/Unterordner/leer", "quelle/Unterordner/Größe – Übersicht.txt", "quelle/leer.txt"] {
            assert!(paths.contains(&expected), "{expected} fehlt in {paths:?}");
        }
        let entry = entries.iter().find(|entry| entry.path == "quelle/Unterordner/Größe – Übersicht.txt").unwrap();
        let mut content = Vec::new();
        reader.restore_file(entry, &mut content, &zeback_remote::NoProgress).unwrap();
        assert_eq!(content, "äöüß €".as_bytes());
        assert_eq!(reader.verify(&zeback_remote::NoProgress).unwrap().files, 4);
    }

    #[test]
    fn zip_targets_and_a_server_work_side_by_side() {
        let Some(live) = Live::start("gemischt") else { return };
        let source = live.dir.join("quelle");
        sample(&source);
        let folder = live.dir.join("usb");
        fs::create_dir_all(&folder).unwrap();
        let login = live.login("gemischt", false, 0);

        let destinations = vec![Destination::folder(&folder), server(&login)];
        let (summary, log) = logged(|rep| backup::run(&job(&source, destinations, Some(PASSWORD)), rep));
        let summary = summary.unwrap();
        assert!(summary.zip_size > 0 && summary.to_server);
        assert_eq!(summary.saved.len(), 2);
        assert!(summary.local_path.as_ref().is_some_and(|zip| zip.is_file()));
        // Das Repository ist unverschlüsselt angelegt: Das Passwort gilt dort nicht, und das wird gesagt.
        assert!(log.contains("unverschlüsselt angelegt"), "{log}");
        assert_eq!(client(&login).snapshots().unwrap().len(), 1);
    }

    #[test]
    fn password_problems_are_explained() {
        let Some(live) = Live::start("passwort") else { return };
        let source = live.dir.join("quelle");
        sample(&source);
        let login = live.login("geheim", true, 0);
        let run = |password| logged(|rep| backup::run(&job(&source, vec![server(&login)], password), rep)).0;

        let missing = format!("{:#}", run(None).unwrap_err());
        assert!(missing.contains("Ziel „Server“") && missing.contains("ist verschlüsselt"), "{missing}");
        run(Some(PASSWORD)).unwrap();
        let wrong = format!("{:#}", run(Some("ein anderes Passwort")).unwrap_err());
        assert!(wrong.contains("Passwort passt nicht"), "{wrong}");
        // Fehlversuche hinterlassen keine Sicherung.
        assert_eq!(client(&login).snapshots().unwrap().len(), 1);

        // Ein entzogenes oder falsches Token führt zum Hinweis, neu zu koppeln.
        let stranger = ServerLogin { url: live.url.clone(), token: "falsch".into() };
        let refused = format!("{:#}", logged(|rep| backup::run(&job(&source, vec![server(&stranger)], Some(PASSWORD)), rep)).0.unwrap_err());
        assert!(refused.contains("neu verbinden"), "{refused}");
        assert!(!refused.contains("falsch"), "Token in der Meldung: {refused}");
    }

    #[test]
    fn cleaning_up_keeps_the_newest_and_respects_locks() {
        let Some(live) = Live::start("aufraeumen") else { return };
        let source = live.dir.join("quelle");
        sample(&source);

        let free = live.login("frei", false, 0);
        let free_job = job(&source, vec![server(&free)], None);
        for round in 0..3 {
            fs::write(source.join("Brief.txt"), format!("Fassung {round}")).unwrap();
            logged(|rep| backup::run(&free_job, rep)).0.unwrap();
        }
        assert_eq!(client(&free).snapshots().unwrap().len(), 3);
        let (removed, log) = logged(|rep| jobs::prune(&free_job, 2, rep));
        assert_eq!(removed, 1, "{log}");
        let left = client(&free).snapshots().unwrap();
        assert_eq!(left.len(), 2);
        assert!(left[0].received_at >= left[1].received_at);
        assert!(log.contains("Alte Sicherung gelöscht („Server“)"), "{log}");

        // Mit Sperrfrist bleibt alles liegen, und das Protokoll sagt, warum.
        let locked = live.login("gesperrt", false, 30);
        let locked_job = job(&source, vec![server(&locked)], None);
        for _ in 0..2 {
            let (summary, log) = logged(|rep| backup::run(&locked_job, rep));
            summary.unwrap();
            assert!(log.contains("gegen Löschen gesperrt"), "{log}");
        }
        let (removed, log) = logged(|rep| jobs::prune(&locked_job, 1, rep));
        assert_eq!(removed, 0);
        assert!(log.contains("1 ältere Sicherung(en) sind noch gesperrt"), "{log}");
        assert_eq!(client(&locked).snapshots().unwrap().len(), 2);
    }

    #[test]
    fn targets_are_checked_and_described() {
        let mut target = Target { id: 7, name: "Büro".into(), kind: TargetKind::Server, ..Target::default() };
        assert!(jobs::check_target(&target, "").unwrap_err().contains("Server-Adresse"));
        target.url = "https://backup.example.de/".into();
        assert!(jobs::check_target(&target, "").unwrap_err().contains("noch nicht verbunden"));
        assert_eq!(target.place(), "noch nicht verbunden");
        assert_eq!(target.summary(), "ZEBack Server · noch nicht verbunden");
        target.remote_dir = "PC01".into();
        assert_eq!(target.summary(), "ZEBack Server · backup.example.de / PC01");
        assert!(target.needs_password());
        assert_eq!(target.password_key().as_deref(), Some("zeback-server:https://backup.example.de/#7"));
        assert!(!TargetKind::Server.is_cloud());
        // Das Token landet im Ziel, taucht in dessen Debug-Ausgabe aber nicht auf.
        let destination = jobs::destination(&target, "geheimes-token").unwrap();
        assert!(matches!(&destination, Destination::Server { login, .. } if login.token == "geheimes-token"));
        assert!(!format!("{destination:?}").contains("geheimes-token"));

        let Some(live) = Live::start("pruefen") else { return };
        let login = live.login("anzeige", true, 14);
        let text = describe(&login).unwrap();
        assert!(text.contains("Tresor „anzeige“") && text.contains("verschlüsselt") && text.contains("14 Tage"), "{text}");
        assert!(pair(&live.url, "AAAA-BBBB-CCCC-DDDD").is_err());
    }

    fn target_of(login: &ServerLogin) -> (Target, String) {
        let target =
            Target { id: 1, name: "Server".into(), kind: TargetKind::Server, url: login.url.clone(), ..Target::default() };
        (target, login.token.clone())
    }

    /// Inhalt eines Ordners: Pfad → Dateiinhalt (`None` für Ordner).
    fn contents(dir: &Path) -> std::collections::BTreeMap<String, Option<Vec<u8>>> {
        walkdir::WalkDir::new(dir)
            .min_depth(1)
            .into_iter()
            .map(Result::unwrap)
            .map(|entry| {
                let name = entry.path().strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/");
                (name, entry.file_type().is_file().then(|| fs::read(entry.path()).unwrap()))
            })
            .collect()
    }

    /// Daten, die sich nicht komprimieren lassen.
    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn finds_opens_restores_and_verifies_backups_on_a_server() {
        use std::collections::{HashMap, HashSet};

        let Some(live) = Live::start("zurueck") else { return };
        let source = live.dir.join("quelle");
        sample(&source);
        fs::write(source.join("rauschen.bin"), noise(400_000)).unwrap();
        let login = live.login("zurueck", true, 0);
        logged(|rep| backup::run(&job(&source, vec![server(&login)], Some(PASSWORD)), rep)).0.unwrap();

        // Die Suche findet die Sicherung auf dem Server.
        let (found, _) = logged(|rep| jobs::find_backups(&[target_of(&login)], rep));
        assert_eq!(found.len(), 1);
        assert!(found[0].name.contains("anna") && found[0].name.ends_with("5 Dateien"), "{}", found[0].name);
        assert_eq!(found[0].target_name, "Server");
        assert!(found[0].modified.is_some() && found[0].size > 400_000);
        let jobs::Place::Server(snapshot) = found[0].place.clone() else { panic!("kein Server-Fund") };
        let from = ServerSource { login: login.clone(), target_name: "Server".into(), snapshot };

        // Ohne Passwort ist die Sicherung verschlossen: Der Server verrät nur Zahlen.
        let locked = inspect(&from, None).unwrap();
        assert!(locked.is_locked() && locked.encrypted && locked.manifest.is_none());
        assert_eq!((locked.entries, locked.size), (5, 0));
        assert!(!locked.fits_profile());
        let wrong = format!("{:#}", inspect(&from, Some("ein falsches Passwort")).unwrap_err());
        assert!(wrong.contains("Passwort passt nicht"), "{wrong}");

        // Mit Passwort: Ordner, Profil und Dateiliste sind da.
        let info = inspect(&from, Some(PASSWORD)).unwrap();
        assert!(!info.is_locked());
        let manifest = info.manifest.as_ref().unwrap();
        assert_eq!((manifest.user.as_str(), manifest.roots.len(), manifest.incremental), ("anna", 1, false));
        assert_eq!((manifest.roots[0].name.as_str(), manifest.roots[0].files), ("quelle", 5));
        assert_eq!(manifest.profile_dir, source.to_string_lossy());
        assert!(restore::chain_for(&info).is_none());
        assert_eq!(info.path.file_name().unwrap().to_string_lossy(), format!("Sicherung Nr. {}", from.snapshot.id));
        assert!(info.path.parent().unwrap().to_string_lossy().ends_with("/zurueck"));

        let entries = list_entries(&from, Some(PASSWORD)).unwrap();
        assert_eq!(entries.len(), 5);
        let tree = restore::Tree::build(&entries);
        let top: Vec<&str> = tree.children("quelle").iter().map(|node| node.name.as_str()).collect();
        assert_eq!(top, ["Unterordner", "Brief.txt", "leer.txt", "rauschen.bin"]);
        assert!(list_entries(&from, None).is_err());

        // Alles zurück in einen Ordner.
        let target = live.dir.join("zurueck");
        let all = |conflict| RestoreJob {
            archive: info.path.clone(),
            mapping: Mapping::Roots(HashMap::from([("quelle".to_string(), target.clone())])),
            conflict,
            total_bytes: info.total_bytes,
            password: Some(PASSWORD.into()),
            only: None,
        };
        let (summary, log) = logged(|rep| restore(&all(Conflict::Overwrite), &from, rep));
        let summary = summary.unwrap();
        assert_eq!((summary.restored, summary.failed, summary.skipped_existing), (5, 0, 0), "{log}");
        assert_eq!(contents(&target), contents(&source));
        // Auch die Änderungszeit kommt zurück.
        let modified = |path: &Path| backup::file_stamp(&fs::metadata(path).unwrap()).1;
        fs::File::options().write(true).open(source.join("leer.txt")).unwrap().set_modified(UNIX_EPOCH + Duration::from_secs(1_600_000_000)).unwrap();
        logged(|rep| backup::run(&job(&source, vec![server(&login)], Some(PASSWORD)), rep)).0.unwrap();
        let newest = ServerSource { snapshot: list(&login).unwrap().remove(0), ..from.clone() };
        logged(|rep| restore(&all(Conflict::Overwrite), &newest, rep)).0.unwrap();
        assert_eq!(modified(&target.join("leer.txt")), 1_600_000_000);

        // Vorhandenes behalten: Eine lokal geänderte Datei wird nicht überschrieben.
        fs::write(target.join("Brief.txt"), "lokal geändert").unwrap();
        let (summary, _) = logged(|rep| restore(&all(Conflict::Skip), &from, rep));
        let summary = summary.unwrap();
        assert_eq!((summary.restored, summary.skipped_existing), (0, 5));
        assert_eq!(fs::read_to_string(target.join("Brief.txt")).unwrap(), "lokal geändert");

        // Nur ein ausgewählter Unterordner, an einen frei gewählten Ort.
        let elsewhere = live.dir.join("auswahl");
        let picked = RestoreJob {
            mapping: Mapping::Everything(elsewhere.clone()),
            only: Some(HashSet::from(["quelle/Unterordner".to_string()])),
            ..all(Conflict::Overwrite)
        };
        let summary = logged(|rep| restore(&picked, &from, rep)).0.unwrap();
        assert_eq!(summary.restored, 2);
        let got: Vec<String> = contents(&elsewhere).into_keys().collect();
        assert_eq!(got, ["quelle", "quelle/Unterordner", "quelle/Unterordner/Größe – Übersicht.txt", "quelle/Unterordner/daten.bin", "quelle/Unterordner/leer"]);

        // Falsches Passwort beim Wiederherstellen: nichts wird angefasst.
        let untouched = live.dir.join("unberuehrt");
        let bad = RestoreJob { mapping: Mapping::Everything(untouched.clone()), password: Some("ein falsches Passwort".into()), ..all(Conflict::Overwrite) };
        assert!(logged(|rep| restore(&bad, &from, rep)).0.is_err());
        assert!(!untouched.exists());

        // Prüfen liest alles vom Server.
        let report = logged(|rep| verify(&from, Some(PASSWORD), rep)).0.unwrap();
        assert_eq!((report.files, report.bytes), (5, info.total_bytes));

        // Ein gekipptes Bit im größten Pack (mitten in rauschen.bin): Prüfen schlägt Alarm,
        // Wiederherstellen holt alles Übrige zurück und hinterlässt keine halbe Datei.
        let pack = walkdir::WalkDir::new(live.dir.join("volumes"))
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "pack"))
            .max_by_key(|entry| entry.metadata().unwrap().len())
            .unwrap()
            .into_path();
        let mut bytes = fs::read(&pack).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        fs::write(&pack, bytes).unwrap();

        let damaged = format!("{:#}", logged(|rep| verify(&from, Some(PASSWORD), rep)).0.unwrap_err());
        assert!(damaged.contains("beschädigt"), "{damaged}");
        let rescue = live.dir.join("rettung");
        let rescue_job = RestoreJob { mapping: Mapping::Everything(rescue.clone()), ..all(Conflict::Overwrite) };
        let (summary, log) = logged(|rep| restore(&rescue_job, &from, rep));
        let summary = summary.unwrap();
        assert_eq!((summary.restored, summary.failed), (4, 1), "{log}");
        assert!(log.contains("Nicht wiederhergestellt") && log.contains("rauschen.bin"), "{log}");
        let rescued: Vec<String> = contents(&rescue).into_keys().collect();
        assert!(!rescued.iter().any(|name| name.contains("rauschen") || name.ends_with(".pbtmp")), "{rescued:?}");
        assert_eq!(fs::read(rescue.join("quelle/Unterordner/daten.bin")).unwrap(), vec![7u8; 700_000]);
    }
}
