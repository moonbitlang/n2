//! The n2 database stores information about previous builds for determining
//! which files are up to date.

use crate::{
    densemap, densemap::DenseMap, graph::BuildId, graph::FileId, graph::Graph, graph::Hashes,
    hash::BuildHash,
};
use anyhow::bail;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

const VERSION: u32 = 1;
const SIGNATURE: &[u8; 4] = b"n2db";
// Keep the policy internal to the database: callers should not need to
// coordinate maintenance beyond providing exclusive access to the file.
const MIN_COMPACTION_SIZE: u64 = 2 * 1024 * 1024;
const COMPACTION_RATIO: u64 = 3;

// These sizes mirror the wire format written below. A database starts with a
// 4-byte signature and u32 version. A path record has a u16 length; a build
// record has u16 output/dependency counts and a u64 hash. All path references
// are packed into three bytes.
const DATABASE_HEADER_SIZE: u64 = 8;
const PATH_RECORD_HEADER_SIZE: u64 = 2;
const BUILD_RECORD_FIXED_SIZE: u64 = 12;
const PATH_ID_SIZE: usize = 3;

/// Files are identified by integers that are stable across n2 executions.
#[derive(Debug, Clone, Copy)]
pub struct Id(u32);
impl densemap::Index for Id {
    fn index(&self) -> usize {
        self.0 as usize
    }
}
impl From<usize> for Id {
    fn from(u: usize) -> Id {
        Id(u as u32)
    }
}

/// The loaded state of a database, as needed to make updates to the stored
/// state.  Other state is directly loaded into the build graph.
#[derive(Debug, Default)]
pub struct IdMap {
    /// Maps db::Id to FileId.
    fileids: DenseMap<Id, FileId>,
    /// Maps FileId to db::Id.
    db_ids: HashMap<FileId, Id>,
}

/// RecordWriter buffers writes into a Vec<u8>.
/// We attempt to write a full record per underlying finish() to lessen the chance of writing partial records.
#[derive(Default)]
struct RecordWriter(Vec<u8>);

impl RecordWriter {
    fn write(&mut self, buf: &[u8]) {
        self.0.extend_from_slice(buf);
    }

    fn write_u16(&mut self, n: u16) {
        self.write(&n.to_le_bytes());
    }

    fn write_u24(&mut self, n: u32) {
        self.write(&n.to_le_bytes()[..PATH_ID_SIZE]);
    }

    fn write_u64(&mut self, n: u64) {
        self.write(&n.to_le_bytes());
    }

    fn write_str(&mut self, s: &str) {
        self.write_u16(s.len() as u16);
        self.write(s.as_bytes());
    }

    fn write_id(&mut self, id: Id) {
        if id.0 > (1 << 24) {
            panic!("too many fileids");
        }
        self.write_u24(id.0);
    }

    fn finish(&self, w: &mut impl Write) -> std::io::Result<()> {
        w.write_all(&self.0)
    }
}

/// An opened database, ready for writes.
#[derive(Debug)]
pub struct Writer {
    ids: IdMap,
    w: File,
}

impl Writer {
    fn create(path: &Path) -> std::io::Result<Self> {
        let f = std::fs::File::create(path)?;
        let mut w = Self::from_opened(IdMap::default(), f);
        w.write_signature()?;
        Ok(w)
    }

    fn from_opened(ids: IdMap, w: File) -> Self {
        Writer { ids, w }
    }

    fn write_signature(&mut self) -> std::io::Result<()> {
        self.w.write_all(SIGNATURE)?;
        self.w.write_all(&u32::to_le_bytes(VERSION))
    }

    fn write_path(&mut self, name: &str) -> std::io::Result<()> {
        if name.len() >= 0b1000_0000_0000_0000 {
            panic!("filename too long");
        }
        let mut w = RecordWriter::default();
        w.write_str(&name);
        w.finish(&mut self.w)
    }

    fn ensure_id(&mut self, graph: &Graph, fileid: FileId) -> std::io::Result<Id> {
        let id = match self.ids.db_ids.get(&fileid) {
            Some(&id) => id,
            None => {
                let id = self.ids.fileids.push(fileid);
                self.ids.db_ids.insert(fileid, id);
                self.write_path(&graph.file(fileid).name)?;
                id
            }
        };
        Ok(id)
    }

    pub fn write_build(
        &mut self,
        graph: &Graph,
        id: BuildId,
        hash: BuildHash,
    ) -> std::io::Result<()> {
        let build = &graph.builds[id];

        // Span to capture DB write details; parent load/work spans carry context.
        let db_span = tracing::info_span!(
            "db.write_build",
            outs_len = build.outs().len(),
            deps_len = build.discovered_ins().len()
        );
        let _enter = db_span.enter();

        let mut w = RecordWriter::default();
        let outs = build.outs();
        let mark = (outs.len() as u16) | 0b1000_0000_0000_0000;
        w.write_u16(mark);
        for &out in outs {
            let id = self.ensure_id(graph, out)?;
            w.write_id(id);
        }

        let deps = build.discovered_ins();
        w.write_u16(deps.len() as u16);
        for &dep in deps {
            let id = self.ensure_id(graph, dep)?;
            w.write_id(id);
        }

        w.write_u64(hash.0);
        w.finish(&mut self.w)
    }

    fn rewrite_compacted(
        mut file: File,
        graph: &Graph,
        plan: &CompactionPlan,
    ) -> std::io::Result<Self> {
        // Make the empty valid log durable before writing records. If the
        // process stops during the rewrite, the next open can discard the
        // incomplete final record and keep the preceding complete prefix.
        file.set_len(DATABASE_HEADER_SIZE)?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(DATABASE_HEADER_SIZE))?;

        let mut writer = Self::from_opened(IdMap::default(), file);
        let result = plan
            .builds
            .iter()
            .try_for_each(|&(id, hash)| writer.write_build(graph, id, hash))
            .and_then(|()| writer.w.sync_all());
        if let Err(err) = result {
            if let Err(cleanup_err) = writer
                .w
                .set_len(DATABASE_HEADER_SIZE)
                .and_then(|()| writer.w.sync_all())
            {
                tracing::warn!(
                    error = %cleanup_err,
                    "failed to restore database header after compaction error"
                );
            }
            return Err(err);
        }
        Ok(writer)
    }
}

struct CompactionPlan {
    builds: Vec<(BuildId, BuildHash)>,
    encoded_size: u64,
}

impl CompactionPlan {
    /// Capture the exact persistent state and encoded size to rewrite.
    ///
    /// GraphFiles also contains paths read from obsolete database records, so
    /// paths are reachable from live builds rather than every graph file. A
    /// stored hash, including BuildHash(0), is what makes a current build live.
    fn new(graph: &Graph, hashes: &Hashes) -> Self {
        let mut builds = Vec::new();
        let mut paths: HashSet<FileId> = HashSet::new();
        let mut encoded_size = DATABASE_HEADER_SIZE;

        for (index, build) in graph.builds.iter().enumerate() {
            let id = BuildId::from(index);
            let Some(hash) = hashes.get(id) else {
                continue;
            };

            builds.push((id, hash));
            encoded_size += BUILD_RECORD_FIXED_SIZE
                + PATH_ID_SIZE as u64 * (build.outs().len() + build.discovered_ins().len()) as u64;
            paths.extend(build.outs().iter().copied());
            paths.extend(build.discovered_ins().iter().copied());
        }

        for id in paths {
            encoded_size += PATH_RECORD_HEADER_SIZE + graph.file(id).name.len() as u64;
        }

        Self {
            builds,
            encoded_size,
        }
    }
}

fn should_compact(old_size: u64, compacted_size: u64) -> bool {
    old_size >= MIN_COMPACTION_SIZE && compacted_size <= old_size / COMPACTION_RATIO
}

fn compact_if_needed(
    path: &Path,
    mut file: File,
    old_ids: IdMap,
    graph: &Graph,
    hashes: &Hashes,
    valid_size: u64,
) -> std::io::Result<Writer> {
    let old_size = file.seek(SeekFrom::End(0))?;
    if valid_size < old_size {
        file.set_len(valid_size)?;
        tracing::warn!(
            path = %path.display(),
            discarded_bytes = old_size - valid_size,
            "discarded incomplete database record"
        );
    }
    file.seek(SeekFrom::Start(valid_size))?;

    if valid_size < MIN_COMPACTION_SIZE {
        return Ok(Writer::from_opened(old_ids, file));
    }
    let plan = CompactionPlan::new(graph, hashes);
    tracing::debug!(
        path = %path.display(),
        old_size = valid_size,
        compacted_size = plan.encoded_size,
        "evaluated database compaction"
    );
    if !should_compact(valid_size, plan.encoded_size) {
        return Ok(Writer::from_opened(old_ids, file));
    }

    let writer = Writer::rewrite_compacted(file, graph, &plan)?;
    tracing::info!(
        path = %path.display(),
        old_size = valid_size,
        new_size = plan.encoded_size,
        "database compacted successfully"
    );
    Ok(writer)
}

struct Reader<'a> {
    r: BufReader<&'a mut File>,
    ids: IdMap,
    graph: &'a mut Graph,
    hashes: &'a mut Hashes,
}

impl<'a> Reader<'a> {
    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf: [u8; 2] = [0; 2];
        self.r.read_exact(&mut buf[..])?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u24(&mut self) -> std::io::Result<u32> {
        let mut buf: [u8; 4] = [0; 4];
        self.r.read_exact(&mut buf[..PATH_ID_SIZE])?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut buf: [u8; 8] = [0; 8];
        self.r.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_id(&mut self) -> std::io::Result<Id> {
        self.read_u24().map(Id)
    }

    fn read_str(&mut self, len: usize) -> std::io::Result<String> {
        let mut buf = vec![0; len];
        self.r.read_exact(buf.as_mut_slice())?;
        Ok(unsafe { String::from_utf8_unchecked(buf) })
    }

    fn read_path(&mut self, len: usize) -> std::io::Result<()> {
        let name = self.read_str(len)?;
        // No canonicalization needed, paths were written canonicalized.
        let fileid = self.graph.files.id_from_canonical(name);
        let dbid = self.ids.fileids.push(fileid);
        self.ids.db_ids.insert(fileid, dbid);
        Ok(())
    }

    fn read_build(&mut self, len: usize) -> std::io::Result<()> {
        // This record logs a build.  We expect all the outputs to be
        // outputs of the same build id; if not, that means the graph has
        // changed since this log, in which case we just ignore it.
        //
        // It's possible we log a build that generates files A B, then
        // change the build file such that it only generates file A; this
        // logic will still attach the old dependencies to A, but it
        // shouldn't matter because the changed command line will cause us
        // to rebuild A regardless, and these dependencies are only used
        // to affect dirty checking, not build order.

        let mut unique_bid = None;
        let mut obsolete = false;
        for _ in 0..len {
            let fileid = self.read_id()?;
            if obsolete {
                // Even though we know we don't want this record, we must
                // keep reading to parse through it.
                continue;
            }
            match self.graph.file(self.ids.fileids[fileid]).input {
                None => {
                    obsolete = true;
                }
                Some(bid) => {
                    match unique_bid {
                        None => unique_bid = Some(bid),
                        Some(unique_bid) if unique_bid == bid => {
                            // Ok, matches the existing id.
                        }
                        Some(_) => {
                            // Mismatch.
                            unique_bid = None;
                            obsolete = true;
                        }
                    }
                }
            }
        }

        let len = self.read_u16()?;
        let mut deps = Vec::new();
        for _ in 0..len {
            let id = self.read_id()?;
            deps.push(self.ids.fileids[id]);
        }

        let hash = BuildHash(self.read_u64()?);

        // unique_bid is set here if this record is valid.
        if let Some(id) = unique_bid {
            // Common case: only one associated build.
            self.graph.builds[id].set_discovered_ins(deps);
            self.hashes.set(id, hash);
        }
        Ok(())
    }

    fn read_signature(&mut self) -> anyhow::Result<()> {
        let mut buf: [u8; 4] = [0; 4];
        self.r.read_exact(&mut buf[..])?;
        if buf.as_slice() != SIGNATURE {
            bail!("invalid db signature");
        }
        self.r.read_exact(&mut buf[..])?;
        let version = u32::from_le_bytes(buf);
        if version != VERSION {
            bail!("db version mismatch: got {version}, expected {VERSION}; TODO: db upgrades etc");
        }
        Ok(())
    }

    fn read_file(&mut self) -> anyhow::Result<u64> {
        let span = tracing::info_span!("db.read_file");
        let _enter = span.enter();

        self.read_signature()?;
        loop {
            let record_start = self.r.stream_position()?;
            let mut len = match self.read_u16() {
                Ok(r) => r,
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(record_start);
                }
                Err(err) => bail!(err),
            };
            let mask = 0b1000_0000_0000_0000;
            let result = if len & mask == 0 {
                let _path_span =
                    tracing::info_span!("db.read_path_record", name_len = (len as usize)).entered();
                self.read_path(len as usize)
            } else {
                let outs_len = (len & !mask) as usize;
                let _build_span =
                    tracing::info_span!("db.read_build_record", outs_len = outs_len).entered();
                len &= !mask;
                self.read_build(len as usize)
            };
            match result {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(record_start);
                }
                Err(err) => bail!(err),
            }
        }
    }

    /// Reads an on-disk database, loading its state into the provided Graph/Hashes.
    fn read(f: &mut File, graph: &mut Graph, hashes: &mut Hashes) -> anyhow::Result<(IdMap, u64)> {
        let mut r = Reader {
            r: std::io::BufReader::new(f),
            ids: IdMap::default(),
            graph,
            hashes,
        };
        let valid_size = r.read_file()?;

        Ok((r.ids, valid_size))
    }
}

#[derive(Debug)]
pub struct OpenError {
    path: PathBuf,
    source: OpenErrorKind,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to open {}", self.path.display())
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug)]
enum OpenErrorKind {
    OpenDB(std::io::Error),
    ReadDB(anyhow::Error),
    CreateDB(std::io::Error),
}

impl std::fmt::Display for OpenErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenErrorKind::OpenDB(_) => write!(f, "failed to open"),
            OpenErrorKind::ReadDB(_) => write!(f, "failed to read"),
            OpenErrorKind::CreateDB(_) => write!(f, "failed to create"),
        }
    }
}

impl std::error::Error for OpenErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenErrorKind::OpenDB(err) => Some(err),
            OpenErrorKind::ReadDB(err) => Some(err.as_ref()),
            OpenErrorKind::CreateDB(err) => Some(err),
        }
    }
}

/// Opens or creates an on-disk database, loading its state into the provided Graph.
///
/// Existing databases are automatically compacted after replay when they are
/// at least 2 MiB and at least three times the encoded size of their live state.
/// Incomplete trailing records are discarded on open, and compaction rewrites
/// the existing file in place so its identity and metadata are preserved. The
/// caller must provide exclusive access to `path` for the lifetime of the
/// returned Writer.
pub fn open(path: &Path, graph: &mut Graph, hashes: &mut Hashes) -> Result<Writer, OpenError> {
    let span = tracing::info_span!("db.open", path = %path.display());
    let _enter = span.enter();

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(mut f) => {
            let _branch = tracing::info_span!("db.open_existing").entered();
            tracing::info!(path = %path.display(), "opening existing database");
            let (ids, valid_size) = {
                let _read = tracing::info_span!("db.read").entered();
                Reader::read(&mut f, graph, hashes).map_err(|err| OpenError {
                    path: path.to_path_buf(),
                    source: OpenErrorKind::ReadDB(err),
                })?
            };
            tracing::info!(path = %path.display(), "database loaded successfully");
            compact_if_needed(path, f, ids, graph, hashes, valid_size).map_err(|err| OpenError {
                path: path.to_path_buf(),
                source: OpenErrorKind::OpenDB(err),
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _create = tracing::info_span!("db.create").entered();
            tracing::info!(path = %path.display(), "creating new database");
            let w = Writer::create(path).map_err(|err| OpenError {
                path: path.to_path_buf(),
                source: OpenErrorKind::CreateDB(err),
            })?;
            Ok(w)
        }
        Err(err) => Err(OpenError {
            path: path.to_path_buf(),
            source: OpenErrorKind::OpenDB(err),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_with_discovered_deps(
        dep_count: usize,
        include_dead_build: bool,
    ) -> anyhow::Result<(Graph, BuildId)> {
        let manifest = if include_dead_build {
            b"build out: phony\nbuild dead-out: phony\n".to_vec()
        } else {
            b"build out: phony\n".to_vec()
        };
        let mut graph = crate::load::parse("build.ninja", manifest)?;
        let id = graph
            .file(graph.files.lookup("out").unwrap())
            .input
            .unwrap();
        let deps = (0..dep_count)
            .map(|i| graph.files.id_from_canonical(format!("dep-{i}")))
            .collect();
        graph.builds[id].set_discovered_ins(deps);
        Ok((graph, id))
    }

    fn open_current(path: &Path) -> anyhow::Result<(Graph, BuildId, Hashes, Writer)> {
        let (mut graph, id) = graph_with_discovered_deps(0, false)?;
        let mut hashes = Hashes::default();
        let writer = open(path, &mut graph, &mut hashes)?;
        Ok((graph, id, hashes, writer))
    }

    fn write_oversized_database(path: &Path) -> anyhow::Result<u64> {
        let (mut graph, id) = graph_with_discovered_deps(16, true)?;
        let dead_id = graph
            .file(graph.files.lookup("dead-out").unwrap())
            .input
            .unwrap();
        let mut writer = open(path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, dead_id, BuildHash(123))?;
        for hash in 1..=40_000 {
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        writer.write_build(&graph, id, BuildHash(0))?;
        drop(writer);
        Ok(std::fs::metadata(path)?.len())
    }

    #[test]
    fn open_compacts_obsolete_build_records() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let old_size = write_oversized_database(&path)?;
        assert!(old_size >= 2 * 1024 * 1024);
        let link_path = dir.path().join(".n2_db.link");
        std::fs::hard_link(&path, &link_path)?;
        let neighboring_path = dir.path().join(".n2_db.recompact");
        std::fs::write(&neighboring_path, b"unrelated")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        let (graph, id, hashes, mut writer) = open_current(&path)?;

        let new_size = std::fs::metadata(&path)?.len();
        assert!(new_size < old_size / 3);
        assert_eq!(std::fs::metadata(link_path)?.len(), new_size);
        assert_eq!(std::fs::read(neighboring_path)?, b"unrelated");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(hashes.get(id), Some(BuildHash(0)));
        assert_eq!(graph.builds[id].discovered_ins().len(), 16);

        let appended_hash = BuildHash(42);
        writer.write_build(&graph, id, appended_hash)?;
        drop(writer);

        let (mut graph, id) = graph_with_discovered_deps(0, true)?;
        let dead_id = graph
            .file(graph.files.lookup("dead-out").unwrap())
            .input
            .unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;

        assert_eq!(hashes.get(id), Some(appended_hash));
        assert_eq!(hashes.get(dead_id), None);
        assert_eq!(graph.builds[id].discovered_ins().len(), 16);
        drop(writer);
        Ok(())
    }

    #[test]
    fn compaction_thresholds() {
        assert!(!should_compact(MIN_COMPACTION_SIZE - 1, 1));
        assert!(!should_compact(
            MIN_COMPACTION_SIZE,
            MIN_COMPACTION_SIZE / 2
        ));
        assert!(should_compact(
            MIN_COMPACTION_SIZE,
            MIN_COMPACTION_SIZE / COMPACTION_RATIO
        ));
    }

    #[test]
    fn open_discards_incomplete_record_tail() -> anyhow::Result<()> {
        let mut record = RecordWriter::default();
        record.write_u16(0b1000_0000_0000_0001);
        record.write_u24(0);
        record.write_u16(0);
        record.write_u64(42);

        for tail_len in [1, record.0.len() - 1] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join(".n2_db");
            let (graph, id, _, mut writer) = open_current(&path)?;
            writer.write_build(&graph, id, BuildHash(7))?;
            drop(writer);
            let valid_size = std::fs::metadata(&path)?.len();

            let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(&record.0[..tail_len])?;
            drop(file);

            let (graph, id, hashes, mut writer) = open_current(&path)?;
            assert_eq!(hashes.get(id), Some(BuildHash(7)));
            assert_eq!(std::fs::metadata(&path)?.len(), valid_size);

            writer.write_build(&graph, id, BuildHash(42))?;
            drop(writer);
            let (_, id, hashes, writer) = open_current(&path)?;
            assert_eq!(hashes.get(id), Some(BuildHash(42)));
            drop(writer);
        }
        Ok(())
    }
}
