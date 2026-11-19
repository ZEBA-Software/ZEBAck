//! Übertragung zwischen Client und Server.
//!
//! Blobs und Kennungen gehen binär über die Leitung, nicht als JSON: Bei Millionen Blöcken
//! zählt jedes Byte und jede gesparte Umwandlung.
//!
//! * Liste von Kennungen: je 32 Bytes, direkt hintereinander.
//! * Blobs: je Datensatz Kennung (32 Bytes), Länge des Blobs (u32, Little Endian), Blob.
//! * Abschluss einer Sicherung: Länge der Zusammenfassung (u32, Little Endian), die
//!   Zusammenfassung als JSON, danach die Kennungen aller Blöcke der Sicherung.

use std::ops::Range;

use crate::blob::{HEADER_LEN, MAX_PLAIN_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::id::ChunkId;

pub const ID_LEN: usize = 32;
pub const RECORD_HEADER_LEN: usize = ID_LEN + 4;

/// Größter Blob, den es geben kann: Komprimierte Daten sind nie länger als der Klartext.
pub const MAX_BLOB_LEN: usize = HEADER_LEN + NONCE_LEN + MAX_PLAIN_LEN + TAG_LEN;

/// So viele Blob-Bytes packt der Client höchstens in eine Anfrage. Der Server legt jede
/// Anfrage als ein Pack ab.
pub const UPLOAD_BATCH_BYTES: usize = 64 * 1024 * 1024;
/// Obergrenze des Servers für eine Upload-Anfrage.
pub const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// So viele Kennungen dürfen in einer Frage nach fehlenden Blöcken stehen.
pub const MAX_IDS_PER_QUERY: usize = 16 * 1024;
/// So viele Blöcke dürfen in einer Anfrage zum Herunterladen stehen.
pub const MAX_IDS_PER_FETCH: usize = 1024;
/// Der Server beendet eine Antwort mit Blobs, sobald sie diese Größe erreicht. Was fehlt,
/// fragt der Client erneut an.
pub const FETCH_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Hängt einen Blob-Datensatz an.
pub fn push_record(out: &mut Vec<u8>, id: &ChunkId, blob: &[u8]) {
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    out.extend_from_slice(blob);
}

/// Sieht nach, ob am Anfang von `buf` ein vollständiger Datensatz liegt. Liefert die Kennung
/// und die Lage des Blobs in `buf`; der Datensatz endet am Ende dieses Bereichs. `None`
/// heißt: Es fehlen noch Bytes.
pub fn peek_record(buf: &[u8]) -> Result<Option<(ChunkId, Range<usize>)>> {
    let Some(header) = buf.get(..RECORD_HEADER_LEN) else {
        return Ok(None);
    };
    let len = u32::from_le_bytes([header[32], header[33], header[34], header[35]]) as usize;
    if len > MAX_BLOB_LEN {
        return Err(Error::TooLarge(len));
    }
    let end = RECORD_HEADER_LEN + len;
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some((ChunkId::from_slice(&header[..ID_LEN])?, RECORD_HEADER_LEN..end)))
}

/// Liest alle Datensätze aus einem vollständigen Puffer.
pub fn read_records(mut buf: &[u8]) -> Result<Vec<(ChunkId, &[u8])>> {
    let mut records = Vec::new();
    while !buf.is_empty() {
        let (id, range) = peek_record(buf)?.ok_or(Error::Truncated)?;
        records.push((id, &buf[range.clone()]));
        buf = &buf[range.end..];
    }
    Ok(records)
}

pub fn join_ids(ids: &[ChunkId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ids.len() * ID_LEN);
    for id in ids {
        out.extend_from_slice(id.as_bytes());
    }
    out
}

pub fn split_ids(bytes: &[u8]) -> Result<Vec<ChunkId>> {
    if bytes.len() % ID_LEN != 0 {
        return Err(Error::Truncated);
    }
    bytes.chunks_exact(ID_LEN).map(ChunkId::from_slice).collect()
}

/// Baut die Anfrage zum Abschluss einer Sicherung.
pub fn encode_commit(summary_json: &[u8], refs: &[ChunkId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + summary_json.len() + refs.len() * ID_LEN);
    out.extend_from_slice(&(summary_json.len() as u32).to_le_bytes());
    out.extend_from_slice(summary_json);
    out.extend_from_slice(&join_ids(refs));
    out
}

/// Zerlegt die Anfrage zum Abschluss einer Sicherung in Zusammenfassung (JSON) und Kennungen.
pub fn decode_commit(body: &[u8]) -> Result<(&[u8], Vec<ChunkId>)> {
    let len = body.get(..4).ok_or(Error::Truncated)?;
    let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
    let rest = &body[4..];
    if rest.len() < len {
        return Err(Error::Truncated);
    }
    let (json, refs) = rest.split_at(len);
    Ok((json, split_ids(refs)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        let mut buf = Vec::new();
        push_record(&mut buf, &ChunkId([1; 32]), b"eins");
        push_record(&mut buf, &ChunkId([2; 32]), b"");
        push_record(&mut buf, &ChunkId([3; 32]), b"drei!");
        let records = read_records(&buf).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], (ChunkId([1; 32]), &b"eins"[..]));
        assert_eq!(records[1].1, b"");
        assert_eq!(records[2].1, b"drei!");
    }

    #[test]
    fn peek_waits_for_missing_bytes() {
        let mut buf = Vec::new();
        push_record(&mut buf, &ChunkId([9; 32]), b"Inhalt");
        for cut in 0..buf.len() {
            assert!(peek_record(&buf[..cut]).unwrap().is_none(), "bei {cut} Bytes");
        }
        let (id, range) = peek_record(&buf).unwrap().unwrap();
        assert_eq!(id, ChunkId([9; 32]));
        assert_eq!(&buf[range], b"Inhalt");
        assert!(matches!(read_records(&buf[..buf.len() - 1]), Err(Error::Truncated)));
    }

    #[test]
    fn rejects_oversized_records() {
        let mut buf = vec![0u8; ID_LEN];
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(peek_record(&buf), Err(Error::TooLarge(_))));
    }

    #[test]
    fn ids_and_commit_round_trip() {
        let ids = vec![ChunkId([5; 32]), ChunkId([6; 32])];
        assert_eq!(split_ids(&join_ids(&ids)).unwrap(), ids);
        assert!(split_ids(&[0u8; 33]).is_err());

        let body = encode_commit(b"{\"a\":1}", &ids);
        let (json, refs) = decode_commit(&body).unwrap();
        assert_eq!(json, b"{\"a\":1}");
        assert_eq!(refs, ids);
        assert!(decode_commit(&body[..body.len() - 1]).is_err());
        assert!(decode_commit(&[9, 0, 0, 0, 1]).is_err());
        assert!(decode_commit(&[1]).is_err());
    }
}
