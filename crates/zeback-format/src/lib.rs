//! Gemeinsames Blockformat von ZEBack (Windows-Client) und ZEBack Server.
//!
//! Beide Seiten binden dieses Crate ein. So schneiden sie Blöcke an denselben Stellen,
//! berechnen dieselben Kennungen und lesen dieselben Blobs. Die Festlegungen stehen in
//! `docs/ARCHITEKTUR.md`, Abschnitt „Blockformat“.

pub mod blob;
pub mod chunker;
pub mod crypto;
pub mod error;
pub mod id;
pub mod keyfile;
pub mod snapshot;
pub mod wire;

pub use blob::{BlobInfo, Sealer};
pub use chunker::Chunker;
pub use crypto::{MasterKey, RepoKeys};
pub use error::{Error, Result};
pub use id::ChunkId;
pub use keyfile::KeyFile;

/// Version des Blockformats. Steht im ersten Byte jedes Blobs.
pub const FORMAT_VERSION: u8 = 1;
