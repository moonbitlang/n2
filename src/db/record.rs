//! Encoding and decoding for version 1 database records.

use super::Id;
use std::io::{Read, Write};
use std::mem::size_of;

const SIGNATURE: &[u8] = b"n2db";
const VERSION: u32 = 1;
const BUILD_MARK: u16 = 0x8000;
const PATH_ID_SIZE: usize = 3;

#[derive(Debug)]
pub(super) enum Record<'a, R> {
    Path(PathRecord),
    Build(BuildRecord<'a, R>),
}

#[derive(Debug)]
pub(super) struct PathRecord {
    name: String,
}

pub(super) struct BuildRecord<'a, R> {
    reader: &'a mut Reader<R>,
    outputs_len: usize,
    outputs_remaining: usize,
    dependencies_remaining: Option<usize>,
}

impl PathRecord {
    pub(super) fn into_name(self) -> String {
        self.name
    }
}

impl<R> std::fmt::Debug for BuildRecord<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildRecord")
            .field("outputs_len", &self.outputs_len)
            .field("outputs_remaining", &self.outputs_remaining)
            .field("dependencies_remaining", &self.dependencies_remaining)
            .finish()
    }
}

impl<R: Read> BuildRecord<'_, R> {
    pub(super) fn outputs_len(&self) -> usize {
        self.outputs_len
    }

    pub(super) fn outputs(&mut self) -> impl ExactSizeIterator<Item = std::io::Result<Id>> + '_ {
        assert!(
            self.dependencies_remaining.is_none(),
            "outputs read after dependencies"
        );
        Ids {
            reader: &mut *self.reader,
            remaining: &mut self.outputs_remaining,
        }
    }

    pub(super) fn dependencies(
        &mut self,
    ) -> std::io::Result<impl ExactSizeIterator<Item = std::io::Result<Id>> + '_> {
        assert_eq!(self.outputs_remaining, 0, "dependencies before outputs");
        assert!(
            self.dependencies_remaining.is_none(),
            "dependencies read more than once"
        );
        self.dependencies_remaining = Some(usize::from(self.reader.read_u16()?));
        Ok(Ids {
            reader: &mut *self.reader,
            remaining: self.dependencies_remaining.as_mut().unwrap(),
        })
    }

    pub(super) fn hash(self) -> std::io::Result<u64> {
        assert_eq!(self.outputs_remaining, 0, "hash before outputs");
        assert_eq!(
            self.dependencies_remaining,
            Some(0),
            "hash before dependencies"
        );
        self.reader.read_u64()
    }
}

struct Ids<'a, R> {
    reader: &'a mut Reader<R>,
    remaining: &'a mut usize,
}

impl<R: Read> Iterator for Ids<'_, R> {
    type Item = std::io::Result<Id>;

    fn next(&mut self) -> Option<Self::Item> {
        if *self.remaining == 0 {
            return None;
        }
        Some(self.reader.read_id().map(|id| {
            *self.remaining -= 1;
            id
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (*self.remaining, Some(*self.remaining))
    }
}

impl<R: Read> ExactSizeIterator for Ids<'_, R> {}

/// Streams version 1 database records from an existing byte source.
///
/// Transport buffering remains the caller's choice. Path names retain their
/// existing owned representation; build IDs are decoded as the caller consumes
/// them, without materializing a complete build record.
pub(super) struct Reader<R> {
    source: R,
}

impl<R: Read> Reader<R> {
    pub(super) fn new(source: R) -> Self {
        Self { source }
    }

    pub(super) fn read_signature(&mut self) -> anyhow::Result<()> {
        let mut signature = [0; SIGNATURE.len()];
        self.source.read_exact(&mut signature)?;
        if &signature != SIGNATURE {
            anyhow::bail!("invalid db signature");
        }

        let mut version = [0; size_of::<u32>()];
        self.source.read_exact(&mut version)?;
        let version = u32::from_le_bytes(version);
        if version != VERSION {
            anyhow::bail!(
                "db version mismatch: got {version}, expected {VERSION}; TODO: db upgrades etc"
            );
        }
        Ok(())
    }

    /// Reads the next record. A returned build record borrows this reader and
    /// must be consumed in output, dependency, then hash order.
    pub(super) fn read_record(&mut self) -> std::io::Result<Option<Record<'_, R>>> {
        let mut header = [0; size_of::<u16>()];
        match self.source.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                // TODO: `read_exact` does not distinguish a clean end from a
                // one-byte partial record header. Replay historically accepts
                // both as the end of the append-only log.
                return Ok(None);
            }
            Err(err) => return Err(err),
        }

        let mark = u16::from_le_bytes(header);
        if mark & BUILD_MARK == 0 {
            let name_len = usize::from(mark);
            let mut name = vec![0; name_len];
            self.source.read_exact(&mut name)?;
            // The graph represents canonical paths as `String`; the database
            // persists that existing UTF-8 representation without translating it.
            let name = unsafe { String::from_utf8_unchecked(name) };
            Ok(Some(Record::Path(PathRecord { name })))
        } else {
            let outputs_len = usize::from(mark & !BUILD_MARK);
            Ok(Some(Record::Build(BuildRecord {
                reader: self,
                outputs_len,
                outputs_remaining: outputs_len,
                dependencies_remaining: None,
            })))
        }
    }

    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut encoded = [0; size_of::<u16>()];
        self.source.read_exact(&mut encoded)?;
        Ok(u16::from_le_bytes(encoded))
    }

    fn read_id(&mut self) -> std::io::Result<Id> {
        let mut encoded = [0; size_of::<u32>()];
        self.source.read_exact(&mut encoded[..PATH_ID_SIZE])?;
        Ok(Id(u32::from_le_bytes(encoded)))
    }

    fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut encoded = [0; size_of::<u64>()];
        self.source.read_exact(&mut encoded)?;
        Ok(u64::from_le_bytes(encoded))
    }
}

pub(super) fn write_signature(target: &mut impl Write) -> std::io::Result<()> {
    target.write_all(SIGNATURE)?;
    target.write_all(&VERSION.to_le_bytes())
}

pub(super) fn write_path(target: &mut impl Write, name: &str) -> std::io::Result<()> {
    if name.len() >= usize::from(BUILD_MARK) {
        panic!("filename too long");
    }
    let mut record = Vec::new();
    write_u16(&mut record, name.len() as u16);
    record.extend_from_slice(name.as_bytes());
    target.write_all(&record)
}

/// Buffers one build record so it reaches the underlying file in one write,
/// matching the existing protection against partial records.
pub(super) struct BuildWriter {
    bytes: Vec<u8>,
    outputs_remaining: usize,
    dependencies_len: usize,
    dependencies_remaining: usize,
    dependencies_started: bool,
}

impl BuildWriter {
    pub(super) fn new(outputs_len: usize, dependencies_len: usize) -> Self {
        let mut bytes = Vec::new();
        write_u16(&mut bytes, (outputs_len as u16) | BUILD_MARK);
        Self {
            bytes,
            outputs_remaining: outputs_len,
            dependencies_len,
            dependencies_remaining: dependencies_len,
            dependencies_started: false,
        }
    }

    pub(super) fn write_output(&mut self, id: Id) {
        assert!(!self.dependencies_started, "output after dependency");
        assert!(self.outputs_remaining > 0, "too many build outputs");
        write_id(&mut self.bytes, id);
        self.outputs_remaining -= 1;
    }

    pub(super) fn write_dependency(&mut self, id: Id) {
        self.start_dependencies();
        assert!(
            self.dependencies_remaining > 0,
            "too many build dependencies"
        );
        write_id(&mut self.bytes, id);
        self.dependencies_remaining -= 1;
    }

    pub(super) fn finish(mut self, hash: u64, target: &mut impl Write) -> std::io::Result<()> {
        self.start_dependencies();
        assert_eq!(self.dependencies_remaining, 0, "too few build dependencies");
        self.bytes.extend_from_slice(&hash.to_le_bytes());
        target.write_all(&self.bytes)
    }

    fn start_dependencies(&mut self) {
        if self.dependencies_started {
            return;
        }
        assert_eq!(self.outputs_remaining, 0, "too few build outputs");
        write_u16(&mut self.bytes, self.dependencies_len as u16);
        self.dependencies_started = true;
    }
}

fn write_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn write_id(target: &mut Vec<u8>, id: Id) {
    if id.0 > (1 << (PATH_ID_SIZE * u8::BITS as usize)) {
        panic!("too many fileids");
    }
    target.extend_from_slice(&id.0.to_le_bytes()[..PATH_ID_SIZE]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn version_one_records_keep_the_existing_encoding() -> anyhow::Result<()> {
        let mut bytes = Vec::new();
        write_signature(&mut bytes)?;
        write_path(&mut bytes, "out")?;
        write_path(&mut bytes, "dep")?;
        let mut build = BuildWriter::new(1, 1);
        build.write_output(Id(0));
        build.write_dependency(Id(1));
        build.finish(42, &mut bytes)?;

        assert_eq!(
            bytes,
            [
                b'n', b'2', b'd', b'b', 1, 0, 0, 0, // File header.
                3, 0, b'o', b'u', b't', // Path record.
                3, 0, b'd', b'e', b'p', // Path record.
                1, 128, 0, 0, 0, // Build marker and output ID.
                1, 0, 1, 0, 0, // Dependency count and ID.
                42, 0, 0, 0, 0, 0, 0, 0, // Hash.
            ]
        );

        let mut reader = Reader::new(Cursor::new(bytes));
        reader.read_signature()?;
        let Some(record) = reader.read_record()? else {
            panic!("expected record");
        };
        let Record::Path(path) = record else {
            panic!("expected path record");
        };
        assert_eq!(path.into_name(), "out");
        let Some(Record::Path(path)) = reader.read_record()? else {
            panic!("expected path record");
        };
        assert_eq!(path.into_name(), "dep");
        let Some(record) = reader.read_record()? else {
            panic!("expected record");
        };
        let Record::Build(mut build) = record else {
            panic!("expected build record");
        };
        assert_eq!(build.outputs_len(), 1);
        assert_eq!(
            build
                .outputs()
                .map(|id| id.map(|id| id.0))
                .collect::<std::io::Result<Vec<_>>>()?,
            [0]
        );
        assert_eq!(
            build
                .dependencies()?
                .map(|id| id.map(|id| id.0))
                .collect::<std::io::Result<Vec<_>>>()?,
            [1]
        );
        assert_eq!(build.hash()?, 42);
        assert!(reader.read_record()?.is_none());
        Ok(())
    }

    #[test]
    fn truncated_record_header_remains_an_incomplete_tail() -> anyhow::Result<()> {
        let mut bytes = Vec::new();
        write_signature(&mut bytes)?;
        bytes.push(1);

        let mut reader = Reader::new(Cursor::new(bytes));
        reader.read_signature()?;
        assert!(reader.read_record()?.is_none());
        Ok(())
    }

    #[test]
    fn truncated_record_payload_remains_an_error() -> anyhow::Result<()> {
        let mut bytes = Vec::new();
        write_signature(&mut bytes)?;
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.push(b'o');

        let mut reader = Reader::new(Cursor::new(bytes));
        reader.read_signature()?;
        let err = reader.read_record().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        Ok(())
    }

    #[test]
    fn malformed_file_header_keeps_existing_errors() {
        let mut reader = Reader::new(Cursor::new(b"bad!\x01\0\0\0"));
        let invalid_signature = reader.read_signature().unwrap_err();
        assert_eq!(invalid_signature.to_string(), "invalid db signature");

        let mut reader = Reader::new(Cursor::new(b"n2db\x02\0\0\0"));
        let version_mismatch = reader.read_signature().unwrap_err();
        assert_eq!(
            version_mismatch.to_string(),
            "db version mismatch: got 2, expected 1; TODO: db upgrades etc"
        );
    }
}
