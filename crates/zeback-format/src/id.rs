//! Kennung eines Blocks: 32 Bytes, als 64 Hex-Zeichen geschrieben.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Error;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(pub [u8; 32]);

impl ChunkId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into().map(ChunkId).map_err(|_| Error::InvalidId)
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({self})")
    }
}

impl FromStr for ChunkId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| Error::InvalidId)?;
        Ok(ChunkId(bytes))
    }
}

impl Serialize for ChunkId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ChunkId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let id = ChunkId([0xab; 32]);
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<ChunkId>().unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<ChunkId>(&json).unwrap(), id);
    }

    #[test]
    fn rejects_bad_input() {
        assert!("abc".parse::<ChunkId>().is_err());
        assert!("zz".repeat(32).parse::<ChunkId>().is_err());
        assert!(ChunkId::from_slice(&[0u8; 31]).is_err());
    }
}
