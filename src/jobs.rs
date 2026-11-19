//! Gespeicherte Aufträge ausführen: Ziele auflösen, Sicherung starten, alte Sicherungen
//! aufräumen und den Verlauf führen – mit Oberfläche oder ohne (`--run-job`).

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime};
use serde::{Deserialize, Serialize};

use crate::backup::{self, BackupJob, BackupKind, BackupSummary, Destination, Incremental, SmbLogin};
use crate::config::{self, Config, ReportMode, SavedJob, Target, TargetKind};
use crate::mail::Mail;
use crate::job::{Msg, Reporter};
use crate::nextcloud::{NcSettings, RemoteFile};
use crate::remote::RemoteSettings;
use crate::s3::S3Settings;
use crate::sftp::SftpSettings;
use crate::util::{fmt_bytes, fmt_duration};

/// So viele Einträge behält der Verlauf.
const MAX_HISTORY: usize = 200;

// ---------------------------------------------------------------------------- Ziele

/// Ist das Ziel vollständig eingerichtet? Sonst eine Meldung, was fehlt.
pub fn check_target(target: &Target, password: &str) -> Result<(), String> {
    let missing = |what: &str| {
        Err(tr!(
            "Ziel „{}“ ist unvollständig\n{what} fehlt. Bitte unter „Sicherungsziele“ ergänzen.",
            "Target “{}” is incomplete\n{what} is missing. Please add it under “Backup targets”.",
            target.name
        ))
    };
    match target.kind {
        TargetKind::Local | TargetKind::Smb if target.path.trim().is_empty() => missing(t!("Der Pfad", "The path")),
        TargetKind::Smb if !target.path.trim().starts_with("\\\\") => Err(tr!(
            "Ziel „{}“ ist ungültig\nEine Netzwerkfreigabe beginnt mit \\\\server\\freigabe.",
            "Target “{}” is invalid\nA network share starts with \\\\server\\share.",
            target.name
        )),
        kind if kind.is_cloud() && target.url.trim().is_empty() => {
            missing(t!("Die Server-Adresse", "The server address"))
        }
        TargetKind::S3 if target.path.trim().is_empty() => missing(t!("Der Bucket", "The bucket")),
        TargetKind::S3 if target.user.trim().is_empty() => missing(t!("Der Zugangsschlüssel", "The access key")),
        TargetKind::S3 if password.is_empty() => missing(t!("Der Geheimschlüssel", "The secret key")),
        kind if kind.is_cloud() && target.user.trim().is_empty() => missing(t!("Der Benutzername", "The user name")),
        TargetKind::Server if target.url.trim().is_empty() => missing(t!("Die Server-Adresse", "The server address")),
        TargetKind::Server if password.is_empty() => Err(tr!(
            "Ziel „{}“ ist noch nicht gekoppelt
Trage unter „Sicherungsziele“ den Kopplungscode aus dem Dashboard des Servers ein und wähle „Koppeln“.",
            "Target “{}” is not paired yet
Under “Backup targets”, enter the pairing code from the server's dashboard and choose “Pair”.",
            target.name
        )),
        _ if target.needs_password() && password.is_empty() => missing(t!("Das Passwort", "The password")),
        _ => Ok(()),
    }
}

/// Zugangsdaten eines Cloud-Ziels (Nextcloud, WebDAV, S3); `None` bei Ordnern und Freigaben.
pub fn remote_settings(target: &Target, password: &str) -> Result<Option<RemoteSettings>, String> {
    check_target(target, password)?;
    let dav = || NcSettings {
        url: target.url.trim().to_string(),
        user: target.user.trim().to_string(),
        password: password.to_string(),
        remote_dir: target.remote_dir.trim().to_string(),
    };
    Ok(match target.kind {
        TargetKind::Nextcloud => Some(RemoteSettings::Nextcloud(dav())),
        TargetKind::WebDav => Some(RemoteSettings::WebDav(dav())),
        TargetKind::S3 => Some(RemoteSettings::S3(S3Settings {
            endpoint: target.url.trim().to_string(),
            region: target.region.trim().to_string(),
            bucket: target.path.trim().to_string(),
            prefix: target.remote_dir.trim().to_string(),
            access_key: target.user.trim().to_string(),
            secret_key: password.to_string(),
        })),
        TargetKind::Sftp => Some(RemoteSettings::Sftp(SftpSettings {
            host: target.url.trim().to_string(),
            user: target.user.trim().to_string(),
            password: password.to_string(),
            key_file: target.path.trim().to_string(),
            remote_dir: target.remote_dir.trim().to_string(),
        })),
        TargetKind::Local | TargetKind::Smb | TargetKind::Server => None,
    })
}

/// Macht aus einem eingerichteten Ziel das, was die Sicherung braucht.
pub fn destination(target: &Target, password: &str) -> Result<Destination, String> {
    if let Some(settings) = remote_settings(target, password)? {
        return Ok(Destination::Cloud { name: target.name.clone(), settings });
    }
    Ok(match target.kind {
        TargetKind::Nextcloud | TargetKind::WebDav | TargetKind::S3 | TargetKind::Sftp => {
            unreachable!("Cloud-Ziele sind oben behandelt")
        }
        TargetKind::Local => {
            let path = PathBuf::from(target.path.trim());
            if !path.is_dir() {
                return Err(tr!(
                    "Ziel „{}“ ist nicht erreichbar\n{} – ist der USB-Stick bzw. das Laufwerk angeschlossen?",
                    "Target “{}” cannot be reached\n{} – is the USB stick or drive connected?",
                    target.name,
                    path.display()
                ));
            }
            Destination::Folder { name: target.name.clone(), path, login: None }
        }
        // Das „Passwort“ dieses Ziels ist das Token aus dem Koppeln.
        TargetKind::Server => Destination::Server {
            name: target.name.clone(),
            login: crate::server::ServerLogin { url: target.url.trim().to_string(), token: password.to_string() },
        },
        TargetKind::Smb => Destination::Folder {
            name: target.name.clone(),
            path: PathBuf::from(target.path.trim()),
            login: target
                .needs_password()
                .then(|| SmbLogin { user: target.user.trim().to_string(), password: password.to_string() }),
        },
    })
}

/// Alle Ziele in der Reihenfolge, in der gesichert wird: Ordner vor Freigaben vor Nextcloud,
/// damit die ZIP-Datei möglichst direkt auf einem Datenträger entsteht. ZEBack Server kommt
/// zuletzt; dorthin geht keine ZIP-Datei.
pub fn destinations(targets: &[&Target], password_of: &dyn Fn(&Target) -> String) -> Result<Vec<Destination>, String> {
    let mut result = Vec::new();
    for kind in [
        TargetKind::Local,
        TargetKind::Smb,
        TargetKind::Nextcloud,
        TargetKind::WebDav,
        TargetKind::S3,
        TargetKind::Sftp,
        TargetKind::Server,
    ] {
        for target in targets.iter().filter(|t| t.kind == kind) {
            result.push(destination(target, &password_of(target))?);
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------- Sicherungen finden

/// Wo eine gefundene Sicherung liegt.
#[derive(Clone, Debug, PartialEq)]
pub enum Place {
    /// Direkt lesbar: Ordner, USB-Stick oder Netzwerkfreigabe
    File(PathBuf),
    /// Auf einer Nextcloud; muss erst heruntergeladen werden
    Cloud(RemoteFile),
    /// Auf einem ZEBack Server; wird von dort direkt wiederhergestellt
    Server(crate::server::ServerSnapshot),
}

/// Eine Sicherung auf einem der Sicherungsziele.
#[derive(Clone, Debug, PartialEq)]
pub struct FoundBackup {
    pub target_id: u64,
    pub target_name: String,
    pub name: String,
    pub size: u64,
    pub modified: Option<DateTime<Local>>,
    pub place: Place,
}

/// Sucht auf allen Zielen nach ZIP-Sicherungen, neueste zuerst. Ein Ziel, das gerade nicht
/// erreichbar ist (USB-Stick nicht angesteckt), wird gemeldet und übersprungen.
pub fn find_backups(targets: &[(Target, String)], rep: &Reporter) -> Vec<FoundBackup> {
    let mut found = Vec::new();
    for (target, password) in targets {
        if rep.cancelled() {
            break;
        }
        rep.status(tr!("Suche auf „{}“ …", "Searching “{}” …", target.name));
        let result: Result<Vec<FoundBackup>> = (|| {
            let hit = |name: String, size: u64, modified, place| FoundBackup {
                target_id: target.id,
                target_name: target.name.clone(),
                name,
                size,
                modified,
                place,
            };
            match destination(target, password).map_err(|m| anyhow::anyhow!(m.replace('\n', " – ")))? {
                Destination::Cloud { settings, .. } => {
                    Ok(settings
                        .connect()?
                        .list()?
                        .into_iter()
                        .map(|file| hit(file.name.clone(), file.size, file.modified, Place::Cloud(file)))
                        .collect())
                }
                Destination::Server { login, .. } => Ok(crate::server::list(&login)?
                    .into_iter()
                    .map(|snapshot| {
                        let modified = DateTime::from_timestamp(snapshot.received_at, 0).map(|time| time.with_timezone(&Local));
                        hit(snapshot.label(), snapshot.bytes, modified, Place::Server(snapshot))
                    })
                    .collect()),
                Destination::Folder { path, login, .. } => {
                    if let Some(login) = &login {
                        crate::smb::connect(&path.to_string_lossy(), &login.user, &login.password)?;
                    }
                    let mut files = Vec::new();
                    for entry in fs::read_dir(&path)?.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        let Ok(meta) = entry.metadata() else { continue };
                        if meta.is_file() && name.to_ascii_lowercase().ends_with(".zip") {
                            let modified = meta.modified().ok().map(DateTime::<Local>::from);
                            files.push(hit(name, meta.len(), modified, Place::File(entry.path())));
                        }
                    }
                    Ok(files)
                }
            }
        })();
        match result {
            Ok(files) => found.extend(files),
            Err(e) => rep.warn(tr!(
                "Ziel „{}“ wurde nicht durchsucht: {e:#}",
                "Target “{}” was not searched: {e:#}",
                target.name
            )),
        }
    }
    found.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| b.name.cmp(&a.name)));
    found
}

// ---------------------------------------------------------------------------- Auftrag ausführen

/// Baut aus einem gespeicherten Auftrag die Sicherung. `password_of` liefert die Passwörter
/// der Ziele, `job_password` das Passwort für die Verschlüsselung.
pub fn build(
    saved: &SavedJob,
    cfg: &Config,
    password_of: &dyn Fn(&Target) -> String,
    job_password: Option<String>,
) -> Result<BackupJob, String> {
    let targets: Vec<&Target> =
        saved.target_ids.iter().filter_map(|id| cfg.targets.iter().find(|t| t.id == *id)).collect();
    if targets.is_empty() || targets.len() != saved.target_ids.len() {
        return Err(tr!(
            "Auftrag „{}“ hat kein gültiges Ziel\nEin Sicherungsziel dieses Auftrags fehlt oder wurde gelöscht. Bitte den Auftrag neu anlegen.",
            "Job “{}” has no valid target\nA backup target of this job is missing or was deleted. Please create the job again.",
            saved.name
        ));
    }
    if saved.sources.is_empty() {
        return Err(tr!("Auftrag „{}“ enthält keine Ordner", "Job “{}” contains no folders", saved.name));
    }
    let mut sources = saved.sources.clone();
    // Liegt ein Zielordner auf dem gesicherten Laufwerk, darf er sich nicht selbst sichern.
    for source in sources.iter_mut().filter(|s| s.kind.as_deref() == Some("drive")) {
        for target in targets.iter().filter(|t| t.kind == TargetKind::Local) {
            let path = PathBuf::from(target.path.trim().trim_end_matches('\\'));
            if !path.as_os_str().is_empty() && !source.exclude_paths.contains(&path) {
                source.exclude_paths.push(path);
            }
        }
    }
    let password = match (saved.encrypt, job_password) {
        (false, _) => None,
        (true, Some(password)) if !password.is_empty() => Some(password),
        (true, _) => {
            return Err(tr!(
                "Passwort für Auftrag „{}“ fehlt\nDas Verschlüsselungs-Passwort ist nicht mehr gespeichert. Bitte den Auftrag neu anlegen.",
                "Password for job “{}” is missing\nThe encryption password is no longer stored. Please create the job again.",
                saved.name
            ));
        }
    };
    Ok(BackupJob {
        profile_name: saved.profile_name.clone(),
        profile_dir: saved.profile_dir.clone(),
        sources,
        destinations: destinations(&targets, password_of)?,
        compression: saved.compression,
        skip_online_only: saved.skip_online_only,
        verify: saved.verify,
        password,
        incremental: match (saved.incremental, state_path(saved.id)) {
            (true, Some(state_file)) => Some(Incremental { state_file, full_every: saved.full_every.max(2) }),
            _ => None,
        },
    })
}

/// Datei, in der sich ein Auftrag den Stand seiner letzten Sicherung merkt (für Teilsicherungen).
pub fn state_path(job_id: u64) -> Option<PathBuf> {
    Some(Config::data_dir()?.join("staende").join(format!("auftrag-{job_id}.json")))
}

/// Der E-Mail-Bericht, falls einer eingerichtet ist: wann er gesendet wird und wie.
pub type MailReport = Option<(ReportMode, Mail)>;

/// Liest den E-Mail-Bericht aus den Einstellungen; das Passwort kommt aus der
/// Windows-Anmeldeinformationsverwaltung.
pub fn mail_report(cfg: &Config) -> MailReport {
    let settings = &cfg.mail;
    if settings.mode == ReportMode::Never || settings.server.trim().is_empty() {
        return None;
    }
    let password = settings.password_key().and_then(|key| config::load_password(&key)).unwrap_or_default();
    Some((settings.mode, mail_from(settings, password)))
}

pub fn mail_from(settings: &config::MailSettings, password: String) -> Mail {
    Mail {
        server: settings.server.trim().to_string(),
        port: settings.port,
        starttls: settings.starttls,
        user: settings.user.trim().to_string(),
        password,
        from: settings.from.trim().to_string(),
        to: settings.to.trim().to_string(),
    }
}

/// Betreff und Text des Berichts über einen Lauf.
/// `overdue` nennt andere Aufträge, die schon zu lange nicht mehr gesichert haben.
pub fn report_text(job_name: &str, ok: bool, text: &str, saved: &[String], overdue: &[Overdue]) -> (String, String) {
    let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
    let subject = tr!(
        "ZEBack: Sicherung „{job_name}“ {} ({computer})",
        "ZEBack: backup “{job_name}” {} ({computer})",
        if ok { t!("gelungen", "succeeded") } else { t!("FEHLGESCHLAGEN", "FAILED") }
    );
    let mut body = tr!(
        "Auftrag: {job_name}\nComputer: {computer}\nZeit: {}\nErgebnis: {}\n\n{text}\n",
        "Job: {job_name}\nComputer: {computer}\nTime: {}\nResult: {}\n\n{text}\n",
        Local::now().format("%d.%m.%Y %H:%M"),
        if ok { t!("gelungen", "succeeded") } else { t!("fehlgeschlagen", "failed") }
    );
    if !saved.is_empty() {
        body.push_str(t!("\nGespeichert:\n", "\nSaved to:\n"));
        for place in saved {
            body.push_str(&format!("- {place}\n"));
        }
    }
    if !overdue.is_empty() {
        body.push_str(t!("\nAchtung, überfällig:\n", "\nAttention, overdue:\n"));
        for job in overdue {
            body.push_str(&format!("- {}\n", job.text()));
        }
    }
    body.push_str(t!(
        "\nDiese Nachricht hat ZEBack automatisch gesendet.\n",
        "\nThis message was sent automatically by ZEBack.\n"
    ));
    (subject, body)
}

/// Führt den Auftrag aus: sichern, danach aufräumen, Ergebnis im Verlauf festhalten und –
/// falls eingerichtet – per E-Mail berichten.
pub fn execute(saved: &SavedJob, job: &BackupJob, mail: &MailReport, rep: &Reporter) -> Result<BackupSummary> {
    let result = backup::run(job, rep);
    if result.is_ok() && saved.keep_last > 0 {
        rep.status(t!("Alte Sicherungen werden aufgeräumt …", "Cleaning up old backups …"));
        let removed = prune(job, saved.keep_last, rep);
        if removed > 0 {
            rep.log(tr!(
                "Aufgeräumt: {removed} alte Sicherung(en) gelöscht, die letzten {} bleiben.",
                "Cleaned up: {removed} old backup(s) deleted, the last {} are kept.",
                saved.keep_last
            ));
        }
    }
    let text = match &result {
        Ok(s) if s.kind == BackupKind::Unchanged => {
            t!("Keine Änderungen seit der letzten Sicherung", "No changes since the last backup").to_string()
        }
        Ok(s) if s.zip_size == 0 && s.to_server => tr!(
            "{} Dateien ({}) an ZEBack Server, {} übertragen, in {}",
            "{} files ({}) to ZEBack Server, {} transferred, in {}",
            s.files,
            fmt_bytes(s.bytes),
            fmt_bytes(s.uploaded),
            fmt_duration(s.duration)
        ),
        Ok(s) => tr!(
            "{}{} Dateien ({}) als ZIP mit {} in {}",
            "{}{} files ({}) as a {} ZIP in {}",
            if s.kind == BackupKind::Partial { t!("Teilsicherung: ", "Partial backup: ") } else { "" },
            s.files,
            fmt_bytes(s.bytes),
            fmt_bytes(s.zip_size),
            fmt_duration(s.duration)
        ),
        Err(e) => format!("{e:#}"),
    };
    // Ein abgebrochener Lauf ist kein Fehler, über den berichtet werden müsste.
    let cancelled = result.as_ref().is_err_and(|e| e.is::<crate::job::Cancelled>());
    if let Some((mode, mail)) = mail
        && mode.applies(result.is_ok())
        && !cancelled
    {
        rep.status(t!("Bericht wird per E-Mail gesendet …", "Sending report by e-mail …"));
        let places = result.as_ref().map(|s| s.saved.clone()).unwrap_or_default();
        let (subject, body) = report_text(&saved.name, result.is_ok(), &text, &places, &other_overdue(saved.id));
        match crate::mail::send(mail, &subject, &body) {
            Ok(()) => rep.log(tr!("Bericht per E-Mail gesendet an {}.", "Report sent by e-mail to {}.", mail.to)),
            Err(e) => rep.warn(tr!(
                "Der E-Mail-Bericht wurde nicht gesendet: {e:#}",
                "The e-mail report was not sent: {e:#}"
            )),
        }
    }
    record(RunRecord {
        job_id: saved.id,
        job_name: saved.name.clone(),
        finished: Local::now().format("%d.%m.%Y %H:%M").to_string(),
        ok: result.is_ok(),
        text,
    });
    result
}

/// Löscht an jedem Ziel alle Sicherungen dieses Profils bis auf die `keep` neuesten.
/// Angefasst werden nur Dateien, deren Name genau dem Muster der Sicherungen entspricht.
/// Fehler beim Aufräumen werden gemeldet, lassen die Sicherung aber nicht scheitern.
pub fn prune(job: &BackupJob, keep: u32, rep: &Reporter) -> u32 {
    let prefix = backup::archive_prefix(&job.profile_name);
    let keep = keep.max(1) as usize;
    // Gezählt werden Vollsicherungen. Alles, was älter ist als die `keep`-te Vollsicherung,
    // wird gelöscht – auch Teilsicherungen, die ohne ihre Vollsicherung wertlos wären.
    let surplus = |names: Vec<String>| -> Vec<String> {
        let mut found: Vec<(String, bool, String)> = names
            .into_iter()
            .filter_map(|name| {
                let (stamp, partial) = backup::archive_stamp(&name, &prefix)?;
                Some((stamp.to_string(), partial, name))
            })
            .collect();
        // Der Zeitstempel sortiert sich von selbst: absteigend = neueste zuerst.
        found.sort_by(|a, b| b.0.cmp(&a.0));
        let Some(limit) = found.iter().filter(|(_, partial, _)| !partial).nth(keep - 1).map(|(stamp, _, _)| stamp.clone())
        else {
            return Vec::new();
        };
        found.into_iter().filter(|(stamp, _, _)| *stamp < limit).map(|(_, _, name)| name).collect()
    };
    let mut removed = 0;
    for destination in &job.destinations {
        match destination {
            Destination::Server { name, login } => {
                removed += crate::server::prune(login, name, &job.profile_name, keep as u32, rep);
            }
            Destination::Folder { name, path, .. } => {
                let names = match fs::read_dir(path) {
                    Ok(entries) => entries
                        .flatten()
                        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect(),
                    Err(e) => {
                        rep.warn(tr!("Aufräumen auf „{name}“ nicht möglich: {e}", "Cannot clean up on “{name}”: {e}"));
                        continue;
                    }
                };
                for old in surplus(names) {
                    match fs::remove_file(path.join(&old)) {
                        Ok(()) => {
                            rep.log(tr!("Alte Sicherung gelöscht („{name}“): {old}", "Old backup deleted (“{name}”): {old}"));
                            removed += 1;
                        }
                        Err(e) => rep.warn(tr!(
                            "Alte Sicherung {old} auf „{name}“ nicht gelöscht: {e}",
                            "Old backup {old} on “{name}” was not deleted: {e}"
                        )),
                    }
                }
            }
            Destination::Cloud { name, settings } => {
                let listed = settings.connect().and_then(|client| Ok((client.list()?, client)));
                let (files, client) = match listed {
                    Ok(listed) => listed,
                    Err(e) => {
                        rep.warn(tr!("Aufräumen auf „{name}“ nicht möglich: {e:#}", "Cannot clean up on “{name}”: {e:#}"));
                        continue;
                    }
                };
                for old in surplus(files.into_iter().map(|f| f.name).collect()) {
                    match client.delete(&old) {
                        Ok(()) => {
                            rep.log(tr!("Alte Sicherung gelöscht („{name}“): {old}", "Old backup deleted (“{name}”): {old}"));
                            removed += 1;
                        }
                        Err(e) => rep.warn(tr!(
                            "Alte Sicherung {old} auf „{name}“ nicht gelöscht: {e:#}",
                            "Old backup {old} on “{name}” was not deleted: {e:#}"
                        )),
                    }
                }
            }
        }
    }
    removed
}

// ---------------------------------------------------------------------------- Verlauf

/// Ergebnis eines Auftragslaufs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RunRecord {
    pub job_id: u64,
    pub job_name: String,
    /// Zeitpunkt als Text, z. B. `10.11.2026 14:30`
    pub finished: String,
    pub ok: bool,
    pub text: String,
}

/// Form der Zeitangaben im Verlauf und am Auftrag, z. B. `10.11.2026 14:30`.
const STAMP: &str = "%d.%m.%Y %H:%M";

/// Die Zeit jetzt, so wie sie im Verlauf steht.
pub fn now_stamp() -> String {
    Local::now().format(STAMP).to_string()
}

// ---------------------------------------------------------------------------- Überfällig

/// Ein Auftrag, dessen letzte gelungene Sicherung zu lange her ist.
#[derive(Clone, Debug, PartialEq)]
pub struct Overdue {
    pub job_id: u64,
    pub job_name: String,
    /// Volle Tage seit der letzten gelungenen Sicherung – oder, wenn es noch keine gab, seit
    /// der Auftrag angelegt wurde.
    pub days: i64,
    /// Der Auftrag hat noch nie erfolgreich gesichert.
    pub never: bool,
}

impl Overdue {
    /// Der Hinweis als ganzer Satz, mit dem Namen des Auftrags.
    pub fn text(&self) -> String {
        if self.never {
            tr!(
                "„{}“ hat noch nie gesichert – angelegt vor {} Tagen.",
                "“{}” has never backed up – created {} days ago.",
                self.job_name,
                self.days
            )
        } else {
            tr!(
                "„{}“: letzte gelungene Sicherung vor {} Tagen.",
                "“{}”: last successful backup {} days ago.",
                self.job_name,
                self.days
            )
        }
    }

    /// Kurzform für die Liste der Aufträge.
    pub fn short_text(&self) -> String {
        if self.never {
            t!("noch nie gesichert", "never backed up").to_string()
        } else {
            tr!("seit {} Tagen nicht gesichert", "not backed up for {} days", self.days)
        }
    }
}

/// Nach so vielen Tagen ohne gelungene Sicherung gilt ein Auftrag als überfällig: der Abstand
/// des Zeitplans plus zwei Tage Luft (Wochenende, PC aus). Ohne Zeitplan sind es 30 Tage.
pub fn overdue_after_days(schedule: config::ScheduleKind) -> i64 {
    match schedule {
        config::ScheduleKind::Daily => 3,
        config::ScheduleKind::Weekly => 9,
        // Beim Anstecken gibt es keinen festen Abstand: nach zwei Wochen ohne Sicherung erinnern.
        config::ScheduleKind::Plugged => 14,
        config::ScheduleKind::Off => 30,
    }
}

/// Ist der Auftrag überfällig? Maßgeblich ist der letzte gelungene Lauf im Verlauf; gab es
/// noch keinen, zählt die Zeit seit dem Anlegen. Ohne beides lässt sich nichts sagen.
pub fn overdue(job: &SavedJob, history: &[RunRecord], now: NaiveDateTime) -> Option<Overdue> {
    let parse = |text: &str| NaiveDateTime::parse_from_str(text, STAMP).ok();
    let last = history.iter().rev().filter(|r| r.job_id == job.id && r.ok).find_map(|r| parse(&r.finished));
    let (since, never) = match last {
        Some(time) => (time, false),
        None => (parse(&job.created)?, true),
    };
    let days = (now - since).num_days();
    (days >= overdue_after_days(job.schedule))
        .then(|| Overdue { job_id: job.id, job_name: job.name.clone(), days, never })
}

/// Überfällige Aufträge außer dem, der gerade läuft – für den Bericht per E-Mail. So fällt ein
/// Auftrag, der gar nicht mehr startet, wenigstens im Bericht eines anderen auf.
fn other_overdue(running: u64) -> Vec<Overdue> {
    if cfg!(test) {
        return Vec::new();
    }
    let jobs = Config::load().jobs;
    let mut found = overdue_jobs(&jobs, &load_history(), Local::now().naive_local());
    found.retain(|job| job.job_id != running);
    found
}

/// Alle überfälligen Aufträge, in der Reihenfolge der Aufträge.
pub fn overdue_jobs(jobs: &[SavedJob], history: &[RunRecord], now: NaiveDateTime) -> Vec<Overdue> {
    jobs.iter().filter_map(|job| overdue(job, history, now)).collect()
}

fn history_path() -> Option<PathBuf> {
    Some(Config::data_dir()?.join("verlauf.json"))
}

/// Protokoll des letzten Laufs eines Auftrags.
pub fn log_path(job_id: u64) -> Option<PathBuf> {
    Some(Config::data_dir()?.join("protokolle").join(format!("auftrag-{job_id}.log")))
}

/// Bisherige Läufe, ältester zuerst.
pub fn load_history() -> Vec<RunRecord> {
    history_path()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn record(entry: RunRecord) {
    // Testläufe in Entwicklungs-Builds sollen den echten Verlauf nicht verändern.
    #[cfg(debug_assertions)]
    if std::env::var_os("ZEBACK_NO_SAVE").is_some() {
        return;
    }
    if cfg!(test) {
        return;
    }
    let Some(path) = history_path() else { return };
    let mut history = load_history();
    history.push(entry);
    let start = history.len().saturating_sub(MAX_HISTORY);
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(text) = serde_json::to_string_pretty(&history[start..]) {
        let _ = fs::write(path, text);
    }
}

// ---------------------------------------------------------------------------- Lauf ohne Oberfläche

/// Führt den Auftrag mit dieser Kennung ohne Fenster aus (für den Zeitplan und für Skripte).
/// Rückgabe ist der Beendigungscode des Programms: 0 = gelungen.
pub fn run_headless(job_id: u64) -> i32 {
    run_headless_with(Config::load(), job_id)
}

// ---------------------------------------------------------------------------- Beim Anstecken

/// Was sich ein Auftrag mit dem Zeitplan "Beim Anstecken" zwischen zwei Prüfungen merkt.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
struct PlugState {
    /// War das Ziel bei der letzten Prüfung da?
    present: bool,
    /// Wann zuletzt deswegen gesichert wurde, z. B. `10.11.2026 14:30`
    last_run: String,
}

fn plug_state_path(job_id: u64) -> Option<PathBuf> {
    Some(Config::data_dir()?.join("staende").join(format!("anstecken-{job_id}.json")))
}

/// Entfernt, was sich der Auftrag zum Anstecken gemerkt hat (beim Löschen des Auftrags).
pub fn forget_plug_state(job_id: u64) {
    if let Some(path) = plug_state_path(job_id) {
        let _ = fs::remove_file(path);
    }
}

/// Die Ziele eines Auftrags, auf deren Anstecken er wartet – so wie sie jetzt gerade erreichbar
/// sind. `Err` nennt, was fehlt. Dient beim Speichern dazu, die Laufwerke kennenzulernen.
pub fn plug_targets_now(job: &SavedJob, cfg: &Config) -> Result<Vec<config::PlugTarget>, String> {
    let mut found = Vec::new();
    for target in cfg.targets.iter().filter(|t| job.target_ids.contains(&t.id) && t.kind == TargetKind::Local) {
        let serial = crate::disk::split_drive(target.path.trim()).and_then(|(root, _)| crate::disk::volume_serial(&root));
        match serial {
            Some(serial) => found.push(config::PlugTarget { target_id: target.id, serial }),
            None => {
                return Err(tr!(
                    "„{}“ ist nicht angesteckt\nStecke das Ziel jetzt an und speichere noch einmal. So lernt ZEBack das Laufwerk kennen und erkennt es später wieder.",
                    "“{}” is not plugged in\nPlug the target in now and save again. That is how ZEBack gets to know the drive and recognises it later.",
                    target.name
                ));
            }
        }
    }
    if found.is_empty() {
        return Err(t!(
            "Kein Ziel zum Anstecken\nDieser Auftrag sichert auf kein Ziel der Art „Ordner / USB“. Nur so ein Ziel kann angesteckt werden.",
            "No target to plug in\nThis job does not back up to a target of the kind “Folder / USB”. Only such a target can be plugged in."
        )
        .to_string());
    }
    Ok(found)
}

/// Sind alle Ziele da, auf die der Auftrag wartet? Dann die Ordner, unter denen sie jetzt
/// erreichbar sind (Kennung des Ziels → Pfad). Hat Windows dem Laufwerk einen anderen Buchstaben
/// gegeben, zählt es nur, wenn der Zielordner dort schon liegt – sonst würde auf einem fremden
/// Datenträger ein neuer Ordner entstehen.
fn plugged_paths(job: &SavedJob, cfg: &Config) -> Option<Vec<(u64, String)>> {
    if job.plug_targets.is_empty() {
        return None;
    }
    let mut paths = Vec::new();
    for wanted in &job.plug_targets {
        let target = cfg.targets.iter().find(|t| t.id == wanted.target_id && t.kind == TargetKind::Local)?;
        let path = target.path.trim();
        let (root, rest) = crate::disk::split_drive(path)?;
        if crate::disk::volume_serial(&root) == Some(wanted.serial) {
            paths.push((target.id, path.to_string()));
            continue;
        }
        let moved = crate::disk::roots_with_serial(wanted.serial)
            .into_iter()
            .map(|other| format!("{other}{rest}"))
            .find(|candidate| !rest.is_empty() && std::path::Path::new(candidate).is_dir())?;
        paths.push((target.id, moved));
    }
    Some(paths)
}

/// Soll jetzt gesichert werden? Ja, wenn das Ziel gerade erst angesteckt wurde – oder wenn es
/// dran geblieben ist und die letzte Sicherung deswegen mindestens einen Tag her ist.
fn plug_due(state: &PlugState, now: NaiveDateTime) -> bool {
    if !state.present {
        return true;
    }
    match NaiveDateTime::parse_from_str(&state.last_run, STAMP) {
        Ok(last) => (now - last).num_hours() >= 24,
        Err(_) => true,
    }
}

/// Zeitplan "Beim Anstecken": Die Aufgabenplanung ruft das alle paar Minuten auf. Ist das Ziel
/// nicht da, passiert nichts (kein Protokoll, kein Eintrag im Verlauf). Rückgabe wie bei
/// [`run_headless`].
pub fn run_if_plugged(job_id: u64) -> i32 {
    let mut cfg = Config::load();
    // Den Auftrag gibt es nicht mehr: still beenden, sonst käme die Meldung alle paar Minuten.
    let Some(saved) = cfg.jobs.iter().find(|j| j.id == job_id).cloned() else { return 2 };
    let Some(state_file) = plug_state_path(job_id) else { return 2 };
    let state: PlugState =
        fs::read_to_string(&state_file).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default();
    let remember = |state: &PlugState| {
        if let Some(dir) = state_file.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(&state_file, serde_json::to_string(state).unwrap_or_default());
    };

    let Some(paths) = plugged_paths(&saved, &cfg) else {
        if state.present {
            remember(&PlugState { present: false, last_run: state.last_run });
        }
        return 0;
    };
    if !plug_due(&state, Local::now().naive_local()) {
        return 0;
    }
    // Vor dem Lauf merken: Schlägt er fehl, soll er nicht alle paar Minuten neu starten, sondern
    // erst beim nächsten Anstecken oder am nächsten Tag.
    remember(&PlugState { present: true, last_run: now_stamp() });
    // Steckt das Laufwerk unter einem anderen Buchstaben, gilt für diesen Lauf der neue Pfad.
    for (target_id, path) in paths {
        if let Some(target) = cfg.targets.iter_mut().find(|t| t.id == target_id) {
            target.path = path;
        }
    }
    run_headless_with(cfg, job_id)
}

fn run_headless_with(cfg: Config, job_id: u64) -> i32 {
    let log_file = log_path(job_id);
    if let Some(dir) = log_file.as_ref().and_then(|p| p.parent()) {
        let _ = fs::create_dir_all(dir);
    }
    let mut log = log_file.as_ref().and_then(|path| fs::File::create(path).ok());
    let mut write = move |line: &str| {
        if let Some(file) = log.as_mut() {
            let _ = writeln!(file, "{} {line}", Local::now().format("%d.%m.%Y %H:%M:%S"));
        }
    };

    let Some(saved) = cfg.jobs.iter().find(|j| j.id == job_id).cloned() else {
        write(&tr!("Auftrag {job_id} gibt es nicht.", "Job {job_id} does not exist."));
        if cfg.notify.applies(false) {
            notify_failure(
                &tr!("Auftrag {job_id}", "Job {job_id}"),
                t!(
                    "Diesen Auftrag gibt es nicht mehr. Bitte den Zeitplan in ZEBack neu speichern.",
                    "This job no longer exists. Please save the schedule in ZEBack again."
                ),
            );
        }
        return 2;
    };
    write(&tr!(
        "Auftrag „{}“ startet (ZEBack {}).",
        "Job “{}” is starting (ZEBack {}).",
        saved.name,
        env!("CARGO_PKG_VERSION")
    ));

    // Passwörter kommen aus der Windows-Anmeldeinformationsverwaltung.
    let password_of = |target: &Target| target.password_key().and_then(|key| config::load_password(&key)).unwrap_or_default();
    let job_password = saved.encrypt.then(|| config::load_password(&saved.password_key())).flatten();
    let job = match build(&saved, &cfg, &password_of, job_password) {
        Ok(job) => job,
        Err(message) => {
            write(&message.replace('\n', " – "));
            record(RunRecord {
                job_id,
                job_name: saved.name.clone(),
                finished: Local::now().format("%d.%m.%Y %H:%M").to_string(),
                ok: false,
                text: message.replace('\n', " – "),
            });
            // Auch ein Auftrag, der gar nicht erst starten konnte, wird gemeldet.
            if let Some((mode, mail)) = mail_report(&cfg)
                && mode.applies(false)
            {
                let (subject, body) = report_text(&saved.name, false, &message, &[], &other_overdue(saved.id));
                if let Err(e) = crate::mail::send(&mail, &subject, &body) {
                    write(&tr!(
                        "WARNUNG: Der E-Mail-Bericht wurde nicht gesendet: {e:#}",
                        "WARNING: The e-mail report was not sent: {e:#}"
                    ));
                }
            }
            if cfg.notify.applies(false) {
                notify_failure(&saved.name, &message);
            }
            return 1;
        }
    };

    let _awake = crate::sysimage::KeepAwake::new();
    let (rep, rx, _cancel) = Reporter::new(|| {});
    // Meldungen der Sicherung landen im Protokoll des Auftrags.
    let logger = std::thread::spawn(move || {
        for msg in rx {
            match msg {
                Msg::Log(text) => write(&text),
                Msg::Warn(text) => write(&tr!("WARNUNG: {text}", "WARNING: {text}")),
                Msg::Status(_) | Msg::Progress { .. } => {}
            }
        }
        write
    });
    let result = execute(&saved, &job, &mail_report(&cfg), &rep);
    drop(rep);
    let mut write = logger.join().expect("Protokoll-Thread");
    match result {
        Ok(summary) => {
            write(&tr!("Fertig: {} Dateien, {}.", "Done: {} files, {}.", summary.files, summary.saved.join("; ")));
            if cfg.notify.applies(true) {
                let text = tr!(
                    "{} Dateien ({}) gesichert.",
                    "{} files ({}) backed up.",
                    summary.files,
                    fmt_bytes(summary.bytes)
                );
                crate::notify::show_blocking(
                    &tr!("Sicherung „{}“ gelungen", "Backup “{}” succeeded", saved.name),
                    &text,
                    false,
                );
            }
            0
        }
        Err(e) => {
            write(&tr!("FEHLER: {e:#}", "ERROR: {e:#}"));
            if cfg.notify.applies(false) {
                notify_failure(&saved.name, &format!("{e:#}"));
            }
            1
        }
    }
}

/// Meldet einen gescheiterten Lauf mit einem Hinweisfenster – sonst bliebe er unbemerkt.
fn notify_failure(job_name: &str, message: &str) {
    #[cfg(all(windows, not(test)))]
    {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn MessageBoxW(window: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
        }
        const MB_ICONERROR: u32 = 0x10;
        const MB_SETFOREGROUND: u32 = 0x0001_0000;
        const MB_TOPMOST: u32 = 0x0004_0000;
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
        let text = wide(&tr!(
            "Die Sicherung „{job_name}“ ist fehlgeschlagen.\n\n{message}\n\nEinzelheiten stehen in ZEBack unter „Aufträge“.",
            "The backup “{job_name}” failed.\n\n{message}\n\nYou can find the details in ZEBack under “Jobs”."
        ));
        let caption = wide("ZEBack");
        // SAFETY: Beide Zeichenketten sind nullterminiert und leben bis zum Ende des Aufrufs.
        unsafe { MessageBoxW(0, text.as_ptr(), caption.as_ptr(), MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST) };
    }
    #[cfg(not(all(windows, not(test))))]
    let _ = (job_name, message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::Source;
    use crate::config::Compression;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zeback-test-jobs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn folder_target(id: u64, path: &std::path::Path) -> Target {
        Target { id, name: format!("Ziel {id}"), kind: TargetKind::Local, path: path.display().to_string(), ..Target::default() }
    }

    #[test]
    fn saved_job_runs_and_keeps_only_the_newest_backups() {
        let base = temp_dir("run");
        let source = base.join("quelle");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("brief.txt"), "Hallo").unwrap();
        let (first, second) = (base.join("ziel-a"), base.join("ziel-b"));
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();

        // Im ersten Ziel liegen schon drei ältere Sicherungen dieses Profils und Fremdes.
        let prefix = backup::archive_prefix("anna");
        let old: Vec<String> = ["2020-01-01_120000", "2020-01-02_120000", "2020-01-03_120000"]
            .iter()
            .map(|stamp| format!("{prefix}{stamp}.zip"))
            .collect();
        for name in &old {
            fs::write(first.join(name), "alt").unwrap();
        }
        let foreign = [format!("{prefix}Urlaub.zip"), "Backup_PC_berta_2020-01-01_120000.zip".to_string(), "notizen.txt".to_string()];
        for name in &foreign {
            fs::write(first.join(name), "fremd").unwrap();
        }

        let cfg = Config { targets: vec![folder_target(1, &first), folder_target(2, &second)], ..Config::default() };
        let saved = SavedJob {
            id: 7,
            name: "Täglich".into(),
            profile_name: "anna".into(),
            profile_dir: base.clone(),
            sources: vec![Source::plain(source, None)],
            target_ids: vec![1, 2],
            compression: Compression::Fast,
            keep_last: 2,
            ..SavedJob::default()
        };
        let job = build(&saved, &cfg, &|_| String::new(), None).unwrap();
        assert_eq!(job.destinations.len(), 2);
        let (rep, _rx, _cancel) = Reporter::new(|| {});
        let summary = execute(&saved, &job, &None, &rep).unwrap();
        assert_eq!((summary.files, summary.saved.len()), (1, 2));

        // Geblieben sind die neue und die jüngste alte Sicherung – und alles Fremde.
        let mut left: Vec<String> =
            fs::read_dir(&first).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        let new_name = summary.local_path.unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let mut expected = vec![old[2].clone(), new_name, foreign[0].clone(), foreign[1].clone(), foreign[2].clone()];
        expected.sort();
        assert_eq!(left, expected);
        assert_eq!(fs::read_dir(&second).unwrap().count(), 1);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn jobs_without_a_recent_successful_backup_are_overdue() {
        use crate::config::ScheduleKind;
        let at = |text: &str| NaiveDateTime::parse_from_str(text, STAMP).unwrap();
        let run = |job_id: u64, finished: &str, ok: bool| RunRecord {
            job_id,
            job_name: String::new(),
            finished: finished.into(),
            ok,
            text: String::new(),
        };
        let job = |id: u64, schedule: ScheduleKind, created: &str| SavedJob {
            id,
            name: format!("Auftrag {id}"),
            schedule,
            created: created.into(),
            ..SavedJob::default()
        };
        let daily = job(1, ScheduleKind::Daily, "01.11.2026 08:00");
        let history = [
            run(1, "10.11.2026 12:00", true),
            // Ein anderer Auftrag und ein fehlgeschlagener Lauf zählen nicht.
            run(2, "16.11.2026 12:00", true),
            run(1, "16.11.2026 12:00", false),
        ];

        // Täglich: zwei Tage Luft, ab dem dritten Tag überfällig.
        assert_eq!(overdue(&daily, &history, at("13.11.2026 11:59")), None);
        let late = overdue(&daily, &history, at("17.11.2026 09:00")).unwrap();
        assert_eq!((late.days, late.never), (6, false));
        assert_eq!(late.text(), "„Auftrag 1“: letzte gelungene Sicherung vor 6 Tagen.");
        assert_eq!(late.short_text(), "seit 6 Tagen nicht gesichert");

        // Wöchentlich und von Hand haben mehr Zeit.
        let weekly = job(1, ScheduleKind::Weekly, "");
        assert_eq!(overdue(&weekly, &history, at("19.11.2026 11:00")), None);
        assert!(overdue(&weekly, &history, at("19.11.2026 12:00")).is_some());
        let manual = job(1, ScheduleKind::Off, "");
        assert_eq!(overdue(&manual, &history, at("09.12.2026 12:00")), None);
        assert!(overdue(&manual, &history, at("10.12.2026 12:00")).is_some());

        // Noch nie gelungen: Es zählt die Zeit seit dem Anlegen.
        let never = job(3, ScheduleKind::Daily, "14.11.2026 08:00");
        assert_eq!(overdue(&never, &history, at("16.11.2026 08:00")), None);
        let late = overdue(&never, &history, at("17.11.2026 08:00")).unwrap();
        assert_eq!((late.days, late.never), (3, true));
        assert_eq!(late.text(), "„Auftrag 3“ hat noch nie gesichert – angelegt vor 3 Tagen.");
        // Ohne Anlegedatum (Auftrag aus einer älteren Version) lässt sich nichts sagen.
        assert_eq!(overdue(&job(3, ScheduleKind::Daily, ""), &history, at("17.12.2026 08:00")), None);

        let all = overdue_jobs(&[daily, job(2, ScheduleKind::Daily, ""), never], &history, at("17.11.2026 09:00"));
        assert_eq!(all.iter().map(|o| o.job_id).collect::<Vec<_>>(), [1, 3]);

        // Im Bericht eines anderen Auftrags stehen die überfälligen mit drin.
        let (_, body) = report_text("Auftrag 2", true, "ok", &[], &all);
        assert!(body.contains("Achtung, überfällig:\n- „Auftrag 1“: letzte gelungene Sicherung vor 6 Tagen.\n"), "{body}");
        assert!(!report_text("Auftrag 2", true, "ok", &[], &[]).1.contains("überfällig"));
    }

    #[test]
    fn plugged_in_jobs_run_once_per_plug_in_and_once_a_day() {
        let at = |text: &str| NaiveDateTime::parse_from_str(text, STAMP).unwrap();
        let state = |present: bool, last_run: &str| PlugState { present, last_run: last_run.into() };
        // Gerade angesteckt (vorher nicht da): sichern, auch wenn heute schon gesichert wurde.
        assert!(plug_due(&state(false, ""), at("17.11.2026 10:00")));
        assert!(plug_due(&state(false, "17.11.2026 09:00"), at("17.11.2026 10:00")));
        // Bleibt es dran: erst nach einem Tag wieder.
        assert!(!plug_due(&state(true, "17.11.2026 09:00"), at("17.11.2026 10:00")));
        assert!(!plug_due(&state(true, "17.11.2026 09:00"), at("18.11.2026 08:59")));
        assert!(plug_due(&state(true, "17.11.2026 09:00"), at("18.11.2026 09:00")));
        assert!(plug_due(&state(true, "unlesbar"), at("17.11.2026 10:00")));

        assert_eq!(crate::disk::split_drive("e:\\Backups\\PC"), Some(("E:\\".to_string(), "Backups\\PC")));
        assert_eq!(crate::disk::split_drive("E:"), Some(("E:\\".to_string(), "")));
        assert_eq!(crate::disk::split_drive("\\\\nas\\backup"), None);
    }

    /// Mit den echten Laufwerken dieses PCs: Das Ziel wird an der Seriennummer seines Laufwerks
    /// erkannt; ein Auftrag ohne Ordner-Ziel oder mit fehlendem Laufwerk wartet auf nichts.
    #[cfg(windows)]
    #[test]
    fn recognises_the_target_drive_by_its_serial_number() {
        let base = temp_dir("anstecken");
        let folder = base.join("ziel");
        fs::create_dir_all(&folder).unwrap();
        let path = folder.to_string_lossy().into_owned();
        let (root, rest) = crate::disk::split_drive(&path).unwrap();
        let serial = crate::disk::volume_serial(&root).expect("Seriennummer des Laufwerks");
        assert!(crate::disk::roots_with_serial(serial).contains(&root));

        let mut cfg = Config::default();
        cfg.targets.push(Target { id: 1, name: "USB".into(), kind: TargetKind::Local, path: path.clone(), ..Target::default() });
        cfg.targets.push(Target { id: 2, name: "Wolke".into(), kind: TargetKind::Nextcloud, ..Target::default() });
        let mut job = SavedJob { id: 5, target_ids: vec![1, 2], ..SavedJob::default() };

        // Beim Speichern lernt der Auftrag das Laufwerk kennen – nur Ordner-Ziele zählen.
        let known = plug_targets_now(&job, &cfg).unwrap();
        assert_eq!(known, [config::PlugTarget { target_id: 1, serial }]);
        assert_eq!(plugged_paths(&job, &cfg), None, "ohne gemerkte Laufwerke wartet der Auftrag auf nichts");
        job.plug_targets = known;
        assert_eq!(plugged_paths(&job, &cfg), Some(vec![(1, path.clone())]));

        // Anderer Buchstabe, den es nicht gibt: Das Laufwerk wird über die Seriennummer gefunden,
        // weil der Zielordner dort liegt.
        let free = ('D'..='Z').rev().map(|c| format!("{c}:\\")).find(|r| crate::disk::volume_serial(r).is_none()).unwrap();
        cfg.targets[0].path = format!("{free}{rest}");
        assert_eq!(plugged_paths(&job, &cfg), Some(vec![(1, format!("{root}{rest}"))]));
        // Fehlt dort der Ordner, gilt das Ziel als nicht angesteckt …
        cfg.targets[0].path = format!("{free}gibt-es-nicht-{}", std::process::id());
        assert_eq!(plugged_paths(&job, &cfg), None);
        // … genauso bei einer fremden Seriennummer.
        cfg.targets[0].path = path;
        job.plug_targets[0].serial = serial.wrapping_add(1);
        assert_eq!(plugged_paths(&job, &cfg), None);

        // Ohne Ordner-Ziel oder mit fehlendem Laufwerk lässt sich so ein Auftrag nicht speichern.
        let only_cloud = SavedJob { target_ids: vec![2], ..SavedJob::default() };
        assert!(plug_targets_now(&only_cloud, &cfg).unwrap_err().starts_with("Kein Ziel zum Anstecken"));
        cfg.targets[0].path = format!("{free}Backups");
        assert!(plug_targets_now(&job, &cfg).unwrap_err().starts_with("„USB“ ist nicht angesteckt"));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn job_without_its_target_or_password_is_refused() {
        let base = temp_dir("refuse");
        let cfg = Config { targets: vec![folder_target(1, &base)], ..Config::default() };
        let mut saved = SavedJob {
            name: "Test".into(),
            sources: vec![Source::plain(base.clone(), None)],
            target_ids: vec![1, 9],
            ..SavedJob::default()
        };
        assert!(build(&saved, &cfg, &|_| String::new(), None).err().unwrap().contains("kein gültiges Ziel"));
        saved.target_ids = vec![1];
        assert!(build(&saved, &cfg, &|_| String::new(), None).is_ok());
        saved.encrypt = true;
        assert!(build(&saved, &cfg, &|_| String::new(), None).err().unwrap().contains("Passwort"));
        assert_eq!(build(&saved, &cfg, &|_| String::new(), Some("geheim123".into())).unwrap().password.as_deref(), Some("geheim123"));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn finds_backups_on_folder_targets_and_skips_unreachable_ones() {
        let base = temp_dir("find");
        fs::write(base.join("Backup_PC_anna_2026-11-10_143005.zip"), "zip").unwrap();
        fs::write(base.join("Urlaub.ZIP"), "noch eins").unwrap();
        fs::write(base.join("notizen.txt"), "kein Archiv").unwrap();
        fs::create_dir_all(base.join("ordner.zip")).unwrap();
        let missing = Target { id: 2, name: "Stick".into(), kind: TargetKind::Local, path: base.join("fehlt").display().to_string(), ..Target::default() };
        let targets = [(folder_target(1, &base), String::new()), (missing, String::new())];

        let (rep, rx, _cancel) = Reporter::new(|| {});
        let found = find_backups(&targets, &rep);
        let mut names: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["Backup_PC_anna_2026-11-10_143005.zip", "Urlaub.ZIP"]);
        assert!(found.iter().all(|f| f.target_id == 1 && matches!(&f.place, Place::File(path) if path.is_file())));
        // Das fehlende Ziel wird gemeldet, lässt die Suche aber nicht scheitern.
        assert!(rx.try_iter().any(|m| matches!(m, Msg::Warn(text) if text.contains("Stick"))));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn recognises_only_exact_backup_names() {
        assert!(backup::is_archive_of("Backup_PC_anna_2026-11-10_143005.zip", "Backup_PC_anna_"));
        assert!(!backup::is_archive_of("Backup_PC_anna_2_2026-11-10_143005.zip", "Backup_PC_anna_"));
        assert!(!backup::is_archive_of("Backup_PC_anna_2026-11-10_143005.zip.part", "Backup_PC_anna_"));
        assert!(!backup::is_archive_of("Backup_PC_anna_2026-11-10.zip", "Backup_PC_anna_"));
        assert!(!backup::is_archive_of("Backup_PC_anna_Urlaub-2026_abcdef.zip", "Backup_PC_anna_"));
    }
}
