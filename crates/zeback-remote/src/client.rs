//! Die Aufrufe der Geräte-Schnittstelle von ZEBack Server (`/api/v1`).

use serde::{Deserialize, Serialize};
use ureq::http::Response;
use ureq::{Agent, Body};
use zeback_format::snapshot::SnapshotSummary;
use zeback_format::{ChunkId, FORMAT_VERSION, KeyFile, wire};

use crate::error::{Error, Result};

/// Größte Antwort mit JSON, die angenommen wird.
const MAX_JSON: u64 = 64 * 1024 * 1024;
/// Größte Antwort mit Blobs: das, was der Server höchstens schickt, plus ein Blob Reserve.
const MAX_FETCH: u64 = (wire::FETCH_BUDGET_BYTES + wire::MAX_BLOB_LEN + wire::RECORD_HEADER_LEN) as u64;

const JSON: &str = "application/json";
const BINARY: &str = "application/octet-stream";

#[derive(Clone, Debug, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    /// Version des Blockformats, die der Server versteht
    pub format: u8,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RepoInfo {
    pub name: String,
    pub encrypted: bool,
    pub format: u8,
    /// Schlüsseldatei; fehlt, bis das erste Gerät sie angelegt hat
    pub key: Option<KeyFile>,
    /// Sperrfrist neuer Sicherungen in Tagen (0 = keine)
    pub worm_days: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SnapshotInfo {
    pub id: i64,
    /// Kennung des Blocks mit dem Kopf der Sicherung
    pub header: ChunkId,
    pub created: String,
    pub computer: String,
    pub user: String,
    pub files: u64,
    pub bytes: u64,
    pub chunks: u64,
    /// Eingang auf dem Server, Sekunden seit 1970
    pub received_at: i64,
    /// WORM: bis dahin nicht löschbar (0 = keine Sperre)
    pub retain_until: i64,
    pub locked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct Uploaded {
    pub stored: u32,
    pub duplicates: u32,
}

#[derive(Deserialize)]
struct Paired {
    token: String,
    repository: RepoInfo,
}

#[derive(Deserialize)]
struct ServerError {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// Macht aus einer Eingabe wie `backup.example.de/` eine Adresse ohne Schrägstrich am Ende.
/// Ohne Angabe gilt `https://`.
pub fn normalize_url(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.contains("://") { trimmed.to_string() } else { format!("https://{trimmed}") }
}

/// Liest die Antwort. Lehnt der Server ab, wird daraus ein [`Error::Server`] mit seinem Text.
fn read(response: std::result::Result<Response<Body>, ureq::Error>, limit: u64) -> Result<Vec<u8>> {
    let mut response = match response {
        Ok(response) => response,
        // Tritt nur auf, wenn die Verbindung Statuscodes als Fehler meldet.
        Err(ureq::Error::StatusCode(status)) => {
            return Err(Error::Server { status, code: String::new(), message: format!("Der Server meldet einen Fehler ({status}).") });
        }
        Err(error) => return Err(error.into()),
    };
    let status = response.status().as_u16();
    let body = response.body_mut().with_config().limit(limit).read_to_vec()?;
    if status < 400 {
        return Ok(body);
    }
    let parsed: ServerError = serde_json::from_slice(&body).unwrap_or(ServerError { error: String::new(), message: String::new() });
    let message = if parsed.message.is_empty() { format!("Der Server meldet einen Fehler ({status}).") } else { parsed.message };
    Err(Error::Server { status, code: parsed.error, message })
}

fn json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|error| Error::Protocol(error.to_string()))
}

fn check_format(format: u8) -> Result<()> {
    if format == FORMAT_VERSION {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "Der Server arbeitet mit Blockformat {format}, dieses Programm mit {FORMAT_VERSION}. Bitte beide auf denselben Stand bringen."
        )))
    }
}

/// Verbindung eines gekoppelten Geräts zu seinem Repository.
#[derive(Clone)]
pub struct ServerClient {
    agent: Agent,
    base: String,
    token: String,
}

impl std::fmt::Debug for ServerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Das Token soll in keiner Fehlermeldung und keinem Protokoll auftauchen.
        write!(f, "ServerClient {{ base: {:?}, token: *** }}", self.base)
    }
}

impl ServerClient {
    /// Lebenszeichen: Läuft unter dieser Adresse ein ZEBack Server?
    pub fn health(agent: &Agent, url: &str) -> Result<Health> {
        let body = read(agent.get(format!("{}/api/v1/health", normalize_url(url))).call(), MAX_JSON)?;
        let health: Health = json(&body)?;
        check_format(health.format)?;
        Ok(health)
    }

    /// Koppelt dieses Gerät mit dem Code aus dem Dashboard. Das Token in der Rückgabe
    /// ([`ServerClient::token`]) gehört sicher verwahrt; der Code gilt danach nicht mehr.
    pub fn pair(agent: Agent, url: &str, code: &str, device_name: &str) -> Result<(Self, RepoInfo)> {
        let base = normalize_url(url);
        #[derive(Serialize)]
        struct Request<'a> {
            code: &'a str,
            name: &'a str,
        }
        let request = serde_json::to_vec(&Request { code, name: device_name }).expect("JSON aus Text");
        let body = read(agent.post(format!("{base}/api/v1/pair")).content_type(JSON).send(&request[..]), MAX_JSON)?;
        let paired: Paired = json(&body)?;
        check_format(paired.repository.format)?;
        Ok((Self { agent, base, token: paired.token }, paired.repository))
    }

    /// Verbindung mit einem Token aus einer früheren Kopplung.
    pub fn new(agent: Agent, url: &str, token: impl Into<String>) -> Self {
        Self { agent, base: normalize_url(url), token: token.into() }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.base)
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn get(&self, path: &str) -> Result<Vec<u8>> {
        read(self.agent.get(self.url(path)).header("Authorization", self.auth()).call(), MAX_JSON)
    }

    fn post(&self, path: &str, content_type: &str, body: &[u8], limit: u64) -> Result<Vec<u8>> {
        read(self.agent.post(self.url(path)).header("Authorization", self.auth()).content_type(content_type).send(body), limit)
    }

    /// Einstellungen des Repositorys. Prüft dabei Token und Formatversion.
    pub fn repo(&self) -> Result<RepoInfo> {
        let repo: RepoInfo = json(&self.get("/repo")?)?;
        check_format(repo.format)?;
        Ok(repo)
    }

    /// Legt die Schlüsseldatei ab. Gibt es schon eine, lehnt der Server mit `key_exists` ab.
    pub fn put_key(&self, key: &KeyFile) -> Result<()> {
        let body = serde_json::to_vec(key).expect("Schlüsseldatei als JSON");
        read(self.agent.put(self.url("/repo/key")).header("Authorization", self.auth()).content_type(JSON).send(&body[..]), MAX_JSON)?;
        Ok(())
    }

    /// Welche dieser Blöcke hat der Server noch nicht?
    pub fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>> {
        let mut missing = Vec::new();
        for part in ids.chunks(wire::MAX_IDS_PER_QUERY) {
            let body = self.post("/repo/chunks/missing", BINARY, &wire::join_ids(part), MAX_JSON)?;
            missing.extend(wire::split_ids(&body)?);
        }
        Ok(missing)
    }

    /// Lädt Blobs hoch. `records` sind Datensätze nach [`wire::push_record`]; der Server
    /// legt sie als ein Pack ab.
    pub fn upload(&self, records: &[u8]) -> Result<Uploaded> {
        json(&self.post("/repo/chunks", BINARY, records, MAX_JSON)?)
    }

    /// Holt Blobs. Die Antwort enthält die ersten der angefragten Blöcke in der angefragten
    /// Reihenfolge – wie viele, entscheidet der Server nach Größe. Den Rest erneut anfragen.
    pub fn fetch_some(&self, ids: &[ChunkId]) -> Result<Vec<(ChunkId, Vec<u8>)>> {
        let ids = &ids[..ids.len().min(wire::MAX_IDS_PER_FETCH)];
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let body = self.post("/repo/chunks/fetch", BINARY, &wire::join_ids(ids), MAX_FETCH)?;
        let records = wire::read_records(&body)?;
        if records.is_empty() || records.len() > ids.len() {
            return Err(Error::Protocol("Die Antwort enthält nicht die angefragten Blöcke.".into()));
        }
        for ((got, _), wanted) in records.iter().zip(ids) {
            if got != wanted {
                return Err(Error::Protocol(format!("Block {wanted} angefragt, Block {got} erhalten.")));
            }
        }
        Ok(records.into_iter().map(|(id, blob)| (id, blob.to_vec())).collect())
    }

    /// Schließt eine Sicherung ab. `refs` sind alle Blöcke, die sie braucht.
    pub fn commit(&self, summary: &SnapshotSummary, refs: &[ChunkId]) -> Result<SnapshotInfo> {
        let summary = serde_json::to_vec(summary).expect("Zusammenfassung als JSON");
        json(&self.post("/repo/snapshots", BINARY, &wire::encode_commit(&summary, refs), MAX_JSON)?)
    }

    /// Sicherungen des Repositorys, neueste zuerst.
    pub fn snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        json(&self.get("/repo/snapshots")?)
    }

    /// Löscht eine Sicherung. Ist sie noch gesperrt, schlägt das mit einem Fehler fehl, für
    /// den [`Error::is_locked`] gilt.
    pub fn delete_snapshot(&self, id: i64) -> Result<()> {
        read(self.agent.delete(self.url(&format!("/repo/snapshots/{id}"))).header("Authorization", self.auth()).call(), MAX_JSON)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_normalized() {
        assert_eq!(normalize_url("backup.example.de"), "https://backup.example.de");
        assert_eq!(normalize_url("  https://backup.example.de/// "), "https://backup.example.de");
        assert_eq!(normalize_url("http://192.168.1.5:8484/"), "http://192.168.1.5:8484");
    }

    #[test]
    fn the_token_stays_out_of_debug_output() {
        let agent: Agent = Agent::config_builder().build().into();
        let client = ServerClient::new(agent, "backup.example.de", "streng-geheim");
        let text = format!("{client:?}");
        assert!(text.contains("backup.example.de"));
        assert!(!text.contains("streng-geheim"));
    }

    #[test]
    fn other_format_versions_are_refused() {
        assert!(check_format(FORMAT_VERSION).is_ok());
        assert!(matches!(check_format(FORMAT_VERSION + 1), Err(Error::Protocol(_))));
    }
}
