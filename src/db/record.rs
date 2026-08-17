//! Framing for the version 1 database log.

use super::{SIGNATURE, VERSION};
use std::convert::TryInto;
use std::io::{BufReader, Read};

const PATH_ID_SIZE: usize = 3;
const BUILD_MARK: u16 = 0x8000;

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
}

fn read_u24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

/// Sequentially reads complete records and reuses one record-sized buffer.
pub(super) struct Records<R> {
    reader: BufReader<R>,
    bytes: Vec<u8>,
    kind: Option<Kind>,
}

impl<R: Read> Records<R> {
    pub(super) fn new(mut source: R) -> anyhow::Result<Self> {
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
            bytes: Vec::new(),
            kind: None,
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn kind(&self) -> Kind {
        self.kind.expect("next() must produce a record first")
    }

    fn resize(&mut self, len: usize) {
        self.bytes.resize(len, 0);
    }

    pub(super) fn next(&mut self) -> std::io::Result<bool> {
        self.bytes.clear();
        self.kind = None;
        self.resize(2);
        match self.reader.read_exact(&mut self.bytes) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(err) => return Err(err),
        }
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
            self.resize(deps_start);
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

        let prefix_len = self.bytes.len();
        self.resize(len);
        self.reader.read_exact(&mut self.bytes[prefix_len..])?;
        self.kind = Some(kind);
        Ok(true)
    }
}
