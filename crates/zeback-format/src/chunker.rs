//! Blöcke schneiden: FastCDC (Variante 2020) mit inhaltsabhängigen Grenzen.
//!
//! Die Grenzen hängen vom Inhalt ab, nicht von der Position. Wird am Anfang einer großen
//! Datei etwas eingefügt, ändern sich nur die ersten Blöcke; der Rest bleibt gleich und muss
//! nicht noch einmal übertragen werden.
//!
//! Die Größen und die Normalisierungsstufe gehören zum Format. Wer sie ändert, bekommt andere
//! Grenzen und damit keine Deduplizierung mehr gegen bestehende Sicherungen.

use std::io::{self, Read};

use fastcdc::v2020::{Error as CdcError, Normalization, StreamCDC};

pub const MIN_CHUNK: usize = 512 * 1024;
pub const AVG_CHUNK: usize = 1024 * 1024;
pub const MAX_CHUNK: usize = 8 * 1024 * 1024;

/// Liefert die Blöcke einer Datei der Reihe nach.
pub struct Chunker<R: Read>(StreamCDC<R>);

impl<R: Read> Chunker<R> {
    /// `seed` kommt aus [`crate::Sealer::chunker_seed`]. Bei verschlüsselten Repositories
    /// verschiebt er die Grenzen, damit sich aus den Blockgrößen nicht auf bekannte Dateien
    /// schließen lässt.
    pub fn new(reader: R, seed: u64) -> Self {
        Self(StreamCDC::with_level_and_seed(reader, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK, Normalization::Level1, seed))
    }
}

impl<R: Read> Iterator for Chunker<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(match self.0.next()? {
            Ok(chunk) => Ok(chunk.data),
            Err(CdcError::IoError(error)) => Err(error),
            Err(other) => Err(io::Error::other(other.to_string())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Immer dieselben, nicht komprimierbaren Testdaten.
    fn noise(label: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new().update(label).finalize_xof().fill(&mut out);
        out
    }

    fn cut(data: &[u8], seed: u64) -> Vec<Vec<u8>> {
        Chunker::new(data, seed).collect::<io::Result<_>>().unwrap()
    }

    fn ids(chunks: &[Vec<u8>]) -> Vec<blake3::Hash> {
        chunks.iter().map(|chunk| blake3::hash(chunk)).collect()
    }

    #[test]
    fn chunks_join_back_to_the_input() {
        let data = noise(b"a", 20 * 1024 * 1024 + 12345);
        let chunks = cut(&data, 0);
        assert!(chunks.len() > 5);
        assert_eq!(chunks.concat(), data);
        for chunk in &chunks[..chunks.len() - 1] {
            assert!(chunk.len() >= MIN_CHUNK && chunk.len() <= MAX_CHUNK, "Blockgröße {}", chunk.len());
        }
    }

    #[test]
    fn small_and_empty_inputs() {
        assert!(cut(&[], 0).is_empty());
        let small = noise(b"b", 1000);
        assert_eq!(cut(&small, 0), vec![small]);
    }

    #[test]
    fn an_insert_at_the_front_keeps_later_chunks() {
        let data = noise(b"c", 24 * 1024 * 1024);
        let mut changed = b"ein paar eingefuegte Bytes".to_vec();
        changed.extend_from_slice(&data);

        let before = ids(&cut(&data, 0));
        let after = ids(&cut(&changed, 0));
        let kept = after.iter().filter(|id| before.contains(id)).count();
        assert!(kept * 10 >= before.len() * 8, "nur {kept} von {} Blöcken blieben gleich", before.len());
    }

    /// Fingerabdruck der Blockgrenzen: BLAKE3 über alle Blocklängen.
    fn boundaries(data: &[u8], seed: u64) -> String {
        let mut hasher = blake3::Hasher::new();
        for chunk in cut(data, seed) {
            hasher.update(&(chunk.len() as u64).to_le_bytes());
        }
        hasher.finalize().to_hex()[..16].to_string()
    }

    /// Feste Prüfwerte. Schlägt dieser Test nach einem Update von `fastcdc` fehl, schneidet
    /// die neue Version anders: Dann das Update zurücknehmen oder die Formatversion erhöhen.
    #[test]
    fn boundaries_are_part_of_the_format() {
        let data = noise(b"format", 32 * 1024 * 1024);
        assert_eq!(boundaries(&data, 0), "532abd97ac78ec76");
        assert_eq!(boundaries(&data, 0x0123_4567_89ab_cdef), "a3363262e9ff4e52");
    }

    #[test]
    fn the_seed_moves_the_boundaries() {
        let data = noise(b"d", 16 * 1024 * 1024);
        let plain: Vec<usize> = cut(&data, 0).iter().map(Vec::len).collect();
        let seeded: Vec<usize> = cut(&data, 0x1234_5678_9abc_def1).iter().map(Vec::len).collect();
        assert_ne!(plain, seeded);
        assert_eq!(seeded, cut(&data, 0x1234_5678_9abc_def1).iter().map(Vec::len).collect::<Vec<_>>());
    }
}
