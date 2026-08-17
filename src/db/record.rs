//! Framing for the version 1 database log.
//!
//! Replay and compaction intentionally share this reader so they cannot
//! disagree about where a record ends.

use super::{SIGNATURE, VERSION};
use std::convert::TryInto;
use std::io::{BufReader, Read, Seek, SeekFrom};

pub(super) const DATABASE_HEADER_SIZE: u64 = 8;
pub(super) const PATH_RECORD_HEADER_SIZE: u64 = 2;
pub(super) const PATH_ID_SIZE: usize = 3;
const BUILD_MARK: u16 = 0x8000;

#[derive(Debug)]
pub(super) enum Error {
    Io(std::io::Error),
    Allocation,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::Allocation => write!(f, "database allocation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Allocation => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Kind {
    Path(PathLayout),
    Build(BuildLayout),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PathLayout {
    name_start: usize,
    pub(super) name_len: usize,
}

impl PathLayout {
    pub(super) fn name<'a>(self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.name_start..self.name_start + self.name_len]
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct BuildLayout {
    outputs_start: usize,
    pub(super) outputs_len: usize,
    deps_start: usize,
    deps_len: usize,
    hash_start: usize,
}

impl BuildLayout {
    pub(super) fn outputs<'a>(self, bytes: &'a [u8]) -> impl Iterator<Item = u32> + 'a {
        let range = self.outputs_start..self.outputs_start + self.outputs_len * PATH_ID_SIZE;
        bytes[range].chunks_exact(PATH_ID_SIZE).map(read_u24)
    }

    pub(super) fn dependencies<'a>(self, bytes: &'a [u8]) -> impl Iterator<Item = u32> + 'a {
        let range = self.deps_start..self.deps_start + self.deps_len * PATH_ID_SIZE;
        bytes[range].chunks_exact(PATH_ID_SIZE).map(read_u24)
    }

    pub(super) fn hash(self, bytes: &[u8]) -> u64 {
        u64::from_le_bytes(
            bytes[self.hash_start..self.hash_start + 8]
                .try_into()
                .unwrap(),
        )
    }

    pub(super) fn remap_ids(
        self,
        bytes: &mut [u8],
        mut remap: impl FnMut(u32) -> Option<u32>,
    ) -> Option<()> {
        for range in [
            self.outputs_start..self.outputs_start + self.outputs_len * PATH_ID_SIZE,
            self.deps_start..self.deps_start + self.deps_len * PATH_ID_SIZE,
        ] {
            for encoded in bytes[range].chunks_exact_mut(PATH_ID_SIZE) {
                let old = read_u24(encoded);
                write_u24(encoded, remap(old)?);
            }
        }
        Some(())
    }
}

fn read_u24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

fn write_u24(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_le_bytes()[..PATH_ID_SIZE]);
}

/// Sequentially reads complete records and reuses one record-sized buffer.
pub(super) struct Records<R> {
    reader: BufReader<R>,
    offset: u64,
    end: u64,
    bytes: Vec<u8>,
    kind: Option<Kind>,
}

impl<R: Read + Seek> Records<R> {
    pub(super) fn new(mut source: R, end: u64) -> anyhow::Result<Self> {
        source.seek(SeekFrom::Start(0))?;
        let mut header = [0; 4];
        source.read_exact(&mut header)?;
        if &header != SIGNATURE {
            anyhow::bail!("invalid db signature");
        }
        source.read_exact(&mut header)?;
        let version = u32::from_le_bytes(header);
        if version != VERSION {
            anyhow::bail!(
                "db version mismatch: got {version}, expected {VERSION}; TODO: db upgrades etc"
            );
        }

        Ok(Self {
            reader: BufReader::new(source),
            offset: DATABASE_HEADER_SIZE,
            end,
            bytes: Vec::new(),
            kind: None,
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(super) fn kind(&self) -> Kind {
        self.kind.expect("next() must produce a record first")
    }

    pub(super) fn ended_at_record_boundary(&self) -> bool {
        self.offset == self.end
    }

    fn resize(&mut self, len: usize) -> Result<(), Error> {
        if len > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(len - self.bytes.len())
                .map_err(|_| Error::Allocation)?;
        }
        self.bytes.resize(len, 0);
        Ok(())
    }

    pub(super) fn next(&mut self) -> Result<bool, Error> {
        self.bytes.clear();
        self.kind = None;
        if self.offset == self.end || self.end - self.offset < 2 {
            return Ok(false);
        }

        self.resize(2)?;
        self.reader.read_exact(&mut self.bytes)?;
        let mark = u16::from_le_bytes(self.bytes[..2].try_into().unwrap());
        let (len, kind) = if mark & BUILD_MARK == 0 {
            let name_len = usize::from(mark);
            (
                2 + name_len,
                Kind::Path(PathLayout {
                    name_start: 2,
                    name_len,
                }),
            )
        } else {
            let outputs_len = usize::from(mark & !BUILD_MARK);
            let outputs_start = 2;
            let deps_count_start = outputs_start + outputs_len * PATH_ID_SIZE;
            let deps_start = deps_count_start + 2;
            if deps_start as u64 > self.end - self.offset {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete database build record",
                )
                .into());
            }
            self.resize(deps_start)?;
            self.reader.read_exact(&mut self.bytes[2..])?;
            let deps_len = usize::from(u16::from_le_bytes(
                self.bytes[deps_count_start..deps_start].try_into().unwrap(),
            ));
            let hash_start = deps_start + deps_len * PATH_ID_SIZE;
            (
                hash_start + 8,
                Kind::Build(BuildLayout {
                    outputs_start,
                    outputs_len,
                    deps_start,
                    deps_len,
                    hash_start,
                }),
            )
        };

        if len as u64 > self.end - self.offset {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete database record",
            )
            .into());
        }
        let prefix_len = self.bytes.len();
        self.resize(len)?;
        self.reader.read_exact(&mut self.bytes[prefix_len..])?;
        self.offset += len as u64;
        self.kind = Some(kind);
        Ok(true)
    }
}
