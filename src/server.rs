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
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Local};
use zeback_remote::{Progress, RepoInfo, Root, Sealer, ServerClient, SnapshotInfo, SnapshotMeta, SnapshotWriter};

use crate::backup::{self, BackupJob, Source};
use crate::job::{Cancelled, Reporter};
use crate::util::fmt_bytes;

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
            "Der Server kennt dieses Gerät nicht (mehr). Bitte unter „Sicherungsziele“ neu koppeln.",
            "The server does not know this device (any more). Please pair it again under “Backup targets”."
        )),
        ref wrong if wrong.is_wrong_password() => anyhow!(t!(
            "Das Passwort passt nicht zu diesem Repository. Es gilt das Passwort, mit dem zum ersten Mal dorthin gesichert wurde.",
            "The password does not match this repository. Use the password of the first backup made to it."
        )),
        Error::PasswordRequired => anyhow!(t!(
            "Dieses Repository ist verschlüsselt. Schalte beim Sichern „Mit Passwort verschlüsseln“ ein und gib das Passwort an.",
            "This repository is encrypted. Turn on “Encrypt with password” for the backup and enter the password."
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
        "Verbunden mit {} – Repository „{}“, {}, {} Sicherung(en).",
        "Connected to {} – repository “{}”, {}, {} backup(s).",
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
            "Erste Sicherung in dieses Repository: Der Schlüssel wird angelegt und mit deinem Passwort geschützt.",
            "First backup to this repository: the key is created and protected with your password."
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
            "„{name}“: Dieses Repository ist auf dem Server als unverschlüsselt angelegt. Das Passwort wird dort nicht verwendet.",
            "“{name}”: this repository was created unencrypted on the server. The password is not used there."
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
        assert!(refused.contains("neu koppeln"), "{refused}");
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
        assert!(jobs::check_target(&target, "").unwrap_err().contains("noch nicht gekoppelt"));
        assert_eq!(target.place(), "backup.example.de · noch nicht gekoppelt");
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
        assert!(text.contains("Repository „anzeige“") && text.contains("verschlüsselt") && text.contains("14 Tage"), "{text}");
        assert!(pair(&live.url, "AAAA-BBBB-CCCC-DDDD").is_err());
    }
}
