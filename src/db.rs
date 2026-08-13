//! The n2 database stores information about previous builds for determining
//! which files are up to date.

use crate::{
    densemap, densemap::DenseMap, graph::BuildId, graph::FileId, graph::Graph, graph::Hashes,
    hash::BuildHash,
};
use anyhow::bail;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

const VERSION: u32 = 1;
const SIGNATURE: &[u8; 4] = b"n2db";
// Keep the policy internal to the database: callers should not need to
// coordinate maintenance beyond providing exclusive access to the file.
const MIN_COMPACTION_SIZE: u64 = 2 * 1024 * 1024;
const COMPACTION_RATIO: u64 = 3;

// A database starts with a 4-byte signature and u32 version. All path
// references are packed into three bytes.
const DATABASE_HEADER_SIZE: u64 = 8;
const BUILD_RECORD_FIXED_SIZE: u64 = 12;
const PATH_ID_SIZE: usize = 3;

/// Files are identified by integers that are stable across n2 executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        ids: IdMap,
        graph: &Graph,
        plan: &CompactionPlan,
    ) -> std::io::Result<Self> {
        if plan.encoded_size > usize::MAX as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "compacted database does not fit in memory",
            ));
        }

        // Preserve database path IDs, then copy the latest raw build records
        // in their original order. Read everything before truncating so an I/O
        // error leaves the old database untouched.
        let mut compacted = Vec::with_capacity(plan.encoded_size as usize);
        compacted.extend_from_slice(SIGNATURE);
        compacted.extend_from_slice(&VERSION.to_le_bytes());
        for &fileid in ids.fileids.iter() {
            let name = &graph.file(fileid).name;
            compacted.extend_from_slice(&(name.len() as u16).to_le_bytes());
            compacted.extend_from_slice(name.as_bytes());
        }
        for range in &plan.build_ranges {
            file.seek(SeekFrom::Start(range.start))?;
            let start = compacted.len();
            compacted.resize(start + range.len() as usize, 0);
            file.read_exact(&mut compacted[start..])?;
        }
        debug_assert_eq!(compacted.len() as u64, plan.encoded_size);

        // Make the empty valid log durable before writing records. If the
        // process stops during the rewrite, the next open can discard the
        // incomplete final record and keep the preceding complete prefix.
        file.set_len(DATABASE_HEADER_SIZE)?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(DATABASE_HEADER_SIZE))?;

        let mut writer = Self::from_opened(ids, file);
        let result = writer
            .w
            .write_all(&compacted[DATABASE_HEADER_SIZE as usize..])
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordRange {
    start: u64,
    end: u64,
}

impl RecordRange {
    fn len(self) -> u64 {
        self.end - self.start
    }
}

struct LiveRecord {
    outs: Rc<[Id]>,
    range: RecordRange,
}

/// Tracks the latest persistent records independently of the current graph.
///
/// During replay, `slot_by_outputs` maps each exact database output list to its
/// live slot in `records`. Seeing the same outputs again turns the old slot into
/// a tombstone and appends the new record range, so flattening `records` yields
/// the retained records in last-occurrence order without sorting. When
/// tombstones outnumber live records, a stable retain and reindex bounds memory;
/// its cost is amortized over the overwritten records that created them.
///
/// The tracker also maintains a monotonic lower bound for the compacted size:
/// all path bytes plus the smallest possible record for each distinct output
/// list. Once that exceeds the compaction ratio, tracking stops because no
/// future replacement can make compaction eligible again.
///
/// Compaction keeps the path table in database-ID order and copies these raw
/// build ranges. Graph membership therefore affects replay projection only,
/// never which persistent records survive.
struct CompactionTracker {
    /// Exact output lists locate their current slots; ordering comes only from
    /// the append-ordered slots, never from HashMap iteration.
    slot_by_outputs: HashMap<Rc<[Id]>, usize>,
    records: Vec<Option<LiveRecord>>,
    // Keep every path record so raw build record IDs remain valid after rewrite.
    path_bytes: u64,
    build_bytes: u64,
    minimum_build_bytes: u64,
    maximum_encoded_size: u64,
}

impl CompactionTracker {
    fn new(database_size: u64) -> Self {
        Self {
            slot_by_outputs: HashMap::new(),
            records: Vec::new(),
            path_bytes: 0,
            build_bytes: 0,
            minimum_build_bytes: 0,
            maximum_encoded_size: database_size / COMPACTION_RATIO,
        }
    }

    /// Returns whether compaction can still meet the configured ratio.
    fn record_path(&mut self, range: RecordRange) -> bool {
        self.path_bytes += range.len();
        self.minimum_encoded_size() <= self.maximum_encoded_size
    }

    /// Returns whether compaction can still meet the configured ratio.
    fn record_build(&mut self, outs: Vec<Id>, range: RecordRange) -> bool {
        let outs: Rc<[Id]> = outs.into();
        let index = self.records.len();
        if let Some(old_index) = self.slot_by_outputs.insert(outs.clone(), index) {
            let old = self.records[old_index]
                .take()
                .expect("latest output list must point to a live record");
            self.build_bytes -= old.range.len();
        } else {
            self.minimum_build_bytes +=
                BUILD_RECORD_FIXED_SIZE + PATH_ID_SIZE as u64 * outs.len() as u64;
        }

        self.build_bytes += range.len();
        self.records.push(Some(LiveRecord { outs, range }));

        // Stable packing bounds tombstones to the number of live records. Its
        // cost is amortized over the overwritten records that created them.
        if self.records.len() > self.slot_by_outputs.len().saturating_mul(2) {
            self.records.retain(Option::is_some);
            for (index, record) in self.records.iter().enumerate() {
                let record = record.as_ref().unwrap();
                *self
                    .slot_by_outputs
                    .get_mut(record.outs.as_ref())
                    .expect("live record must have an output-list index") = index;
            }
        }

        self.minimum_encoded_size() <= self.maximum_encoded_size
    }

    fn minimum_encoded_size(&self) -> u64 {
        DATABASE_HEADER_SIZE + self.path_bytes + self.minimum_build_bytes
    }

    fn into_plan(self) -> CompactionPlan {
        CompactionPlan {
            build_ranges: self
                .records
                .into_iter()
                .flatten()
                .map(|record| record.range)
                .collect(),
            encoded_size: DATABASE_HEADER_SIZE + self.path_bytes + self.build_bytes,
        }
    }
}

struct CompactionPlan {
    build_ranges: Vec<RecordRange>,
    encoded_size: u64,
}

fn should_compact(old_size: u64, compacted_size: u64) -> bool {
    old_size >= MIN_COMPACTION_SIZE && compacted_size <= old_size / COMPACTION_RATIO
}

fn compact_if_needed(
    path: &Path,
    mut file: File,
    old_ids: IdMap,
    tracker: Option<CompactionTracker>,
    graph: &Graph,
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
    let Some(tracker) = tracker else {
        tracing::debug!(
            path = %path.display(),
            old_size = valid_size,
            "skipped database compaction after its minimum size exceeded the ratio"
        );
        return Ok(Writer::from_opened(old_ids, file));
    };
    let plan = tracker.into_plan();
    tracing::debug!(
        path = %path.display(),
        old_size = valid_size,
        compacted_size = plan.encoded_size,
        "evaluated database compaction"
    );
    if !should_compact(valid_size, plan.encoded_size) {
        return Ok(Writer::from_opened(old_ids, file));
    }

    let writer = Writer::rewrite_compacted(file, old_ids, graph, &plan)?;
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
    tracker: Option<CompactionTracker>,
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

    fn read_path(&mut self, len: usize, record_start: u64) -> std::io::Result<()> {
        let name = self.read_str(len)?;
        // No canonicalization needed, paths were written canonicalized.
        let fileid = self.graph.files.id_from_canonical(name);
        let dbid = self.ids.fileids.push(fileid);
        self.ids.db_ids.insert(fileid, dbid);
        if self.tracker.is_some() {
            let record_end = self.r.stream_position()?;
            let tracker = self.tracker.as_mut().unwrap();
            let still_candidate = tracker.record_path(RecordRange {
                start: record_start,
                end: record_end,
            });
            if !still_candidate {
                self.tracker = None;
            }
        }
        Ok(())
    }

    fn read_build(&mut self, len: usize, record_start: u64) -> std::io::Result<()> {
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

        let mut outs = self.tracker.as_ref().map(|_| Vec::with_capacity(len));
        let mut unique_bid = None;
        let mut obsolete = false;
        for _ in 0..len {
            let id = self.read_id()?;
            let fileid = self.ids.fileids[id];
            if let Some(outs) = &mut outs {
                outs.push(id);
            }
            if obsolete {
                // Even though we know this record does not match the current
                // graph, retain its outputs for graph-independent compaction.
                continue;
            }
            match self.graph.file(fileid).input {
                None => obsolete = true,
                Some(bid) => match unique_bid {
                    None => unique_bid = Some(bid),
                    Some(unique_bid) if unique_bid == bid => {}
                    Some(_) => {
                        unique_bid = None;
                        obsolete = true;
                    }
                },
            }
        }

        let len = self.read_u16()?;
        let mut deps = Vec::new();
        for _ in 0..len {
            let id = self.read_id()?;
            deps.push(self.ids.fileids[id]);
        }

        let hash = BuildHash(self.read_u64()?);

        if let Some(id) = unique_bid {
            // Common case: only one associated build.
            self.graph.builds[id].set_discovered_ins(deps);
            self.hashes.set(id, hash);
        }
        if let Some(outs) = outs {
            let record_end = self.r.stream_position()?;
            let tracker = self.tracker.as_mut().unwrap();
            let still_candidate = tracker.record_build(
                outs,
                RecordRange {
                    start: record_start,
                    end: record_end,
                },
            );
            if !still_candidate {
                self.tracker = None;
            }
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
                self.read_path(len as usize, record_start)
            } else {
                let outs_len = (len & !mask) as usize;
                let _build_span =
                    tracing::info_span!("db.read_build_record", outs_len = outs_len).entered();
                len &= !mask;
                self.read_build(len as usize, record_start)
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
    fn read(
        f: &mut File,
        graph: &mut Graph,
        hashes: &mut Hashes,
        database_size: u64,
    ) -> anyhow::Result<(IdMap, Option<CompactionTracker>, u64)> {
        let mut r = Reader {
            r: std::io::BufReader::new(f),
            ids: IdMap::default(),
            tracker: (database_size >= MIN_COMPACTION_SIZE)
                .then(|| CompactionTracker::new(database_size)),
            graph,
            hashes,
        };
        let valid_size = r.read_file()?;

        Ok((r.ids, r.tracker, valid_size))
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
/// at least 2 MiB and at least three times the encoded size of their path table
/// and the latest build record for each exact output list. Records outside the
/// current graph are preserved.
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
            let database_size = f
                .metadata()
                .map_err(|err| OpenError {
                    path: path.to_path_buf(),
                    source: OpenErrorKind::OpenDB(err),
                })?
                .len();
            let (ids, tracker, valid_size) = {
                let _read = tracing::info_span!("db.read").entered();
                Reader::read(&mut f, graph, hashes, database_size).map_err(|err| OpenError {
                    path: path.to_path_buf(),
                    source: OpenErrorKind::ReadDB(err),
                })?
            };
            tracing::info!(path = %path.display(), "database loaded successfully");
            compact_if_needed(path, f, ids, tracker, graph, valid_size).map_err(|err| OpenError {
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

    const OUT_ONLY_MANIFEST: &[u8] = b"build out: phony\n";
    const OUT_AND_OTHER_MANIFEST: &[u8] = b"build out: phony\nbuild other-out: phony\n";

    fn graph_with_discovered_deps(
        manifest: &[u8],
        dep_count: usize,
    ) -> anyhow::Result<(Graph, BuildId)> {
        let mut graph = crate::load::parse("build.ninja", manifest.to_vec())?;
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

    fn open_out_only(path: &Path) -> anyhow::Result<(Graph, BuildId, Hashes, Writer)> {
        let (mut graph, id) = graph_with_discovered_deps(OUT_ONLY_MANIFEST, 0)?;
        let mut hashes = Hashes::default();
        let writer = open(path, &mut graph, &mut hashes)?;
        Ok((graph, id, hashes, writer))
    }

    fn write_oversized_database(path: &Path) -> anyhow::Result<u64> {
        let (mut graph, id) = graph_with_discovered_deps(OUT_AND_OTHER_MANIFEST, 16)?;
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let other_dep = graph.files.id_from_canonical("other-dep".to_owned());
        graph.builds[other_id].set_discovered_ins(vec![other_dep]);
        let mut writer = open(path, &mut graph, &mut Hashes::default())?;
        // This record is written only once. It is absent from the partial graph
        // that triggers compaction, but it has never been superseded.
        writer.write_build(&graph, other_id, BuildHash(123))?;
        for hash in 1..=40_000 {
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        writer.write_build(&graph, id, BuildHash(0))?;
        drop(writer);
        Ok(std::fs::metadata(path)?.len())
    }

    #[test]
    fn open_compaction_preserves_records_outside_current_graph() -> anyhow::Result<()> {
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

        let (graph, id, hashes, mut writer) = open_out_only(&path)?;

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

        let (mut graph, id) = graph_with_discovered_deps(OUT_AND_OTHER_MANIFEST, 0)?;
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;

        assert_eq!(hashes.get(id), Some(appended_hash));
        assert_eq!(hashes.get(other_id), Some(BuildHash(123)));
        assert_eq!(graph.builds[id].discovered_ins().len(), 16);
        let other_deps = graph.builds[other_id].discovered_ins();
        assert_eq!(other_deps.len(), 1);
        assert_eq!(graph.file(other_deps[0]).name, "other-dep");
        drop(writer);
        Ok(())
    }

    #[test]
    fn compaction_plan_preserves_latest_record_order() {
        let a = Id(1);
        let b = Id(2);
        let mut tracker = CompactionTracker::new(u64::MAX);
        tracker.record_build(vec![a], RecordRange { start: 10, end: 15 });
        tracker.record_build(vec![b], RecordRange { start: 15, end: 20 });
        tracker.record_build(vec![a], RecordRange { start: 20, end: 25 });
        tracker.record_build(vec![a], RecordRange { start: 25, end: 30 });
        // This record crosses the packing threshold. Stable packing must leave
        // B followed by the last A rather than HashMap iteration order.
        tracker.record_build(vec![a], RecordRange { start: 30, end: 35 });

        let plan = tracker.into_plan();
        assert_eq!(
            plan.build_ranges,
            vec![
                RecordRange { start: 15, end: 20 },
                RecordRange { start: 30, end: 35 }
            ]
        );
        assert_eq!(plan.encoded_size, DATABASE_HEADER_SIZE + 10);
    }

    #[test]
    fn compaction_tracker_stops_when_minimum_cannot_meet_ratio() {
        let one_build_size = DATABASE_HEADER_SIZE + BUILD_RECORD_FIXED_SIZE + PATH_ID_SIZE as u64;
        let mut tracker = CompactionTracker::new(one_build_size * COMPACTION_RATIO);

        assert!(tracker.record_build(vec![Id(1)], RecordRange { start: 10, end: 20 }));
        // Replacing the same output list can still shrink the exact compacted
        // size, so it does not increase the lower bound.
        assert!(tracker.record_build(vec![Id(1)], RecordRange { start: 20, end: 30 }));
        // A distinct output list must survive forever and makes the theoretical
        // minimum larger than one third of the database.
        assert!(!tracker.record_build(vec![Id(2)], RecordRange { start: 30, end: 40 }));
    }

    #[test]
    fn replay_accepts_removed_trailing_output() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let mut graph = crate::load::parse("build.ninja", b"build a b: phony\n".to_vec())?;
        let id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, id, BuildHash(7))?;
        drop(writer);

        let mut graph = crate::load::parse("build.ninja", b"build a: phony\n".to_vec())?;
        let id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;

        assert_eq!(hashes.get(id), Some(BuildHash(7)));
        drop(writer);
        Ok(())
    }

    #[test]
    fn compaction_preserves_order_of_overlapping_output_lists() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");

        let mut graph = crate::load::parse("build.ninja", b"build a b: phony\n".to_vec())?;
        let id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, id, BuildHash(1))?;
        drop(writer);

        let mut graph = crate::load::parse("build.ninja", b"build a: phony\n".to_vec())?;
        let id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let deps = (0..16)
            .map(|i| graph.files.id_from_canonical(format!("dep-{i}")))
            .collect();
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        graph.builds[id].set_discovered_ins(deps);
        for hash in 2..=40_001 {
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        drop(writer);
        assert!(std::fs::metadata(&path)?.len() >= MIN_COMPACTION_SIZE);

        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(id), Some(BuildHash(40_001)));
        drop(writer);

        // Both [a, b] and [a] match this graph under the existing replay
        // compatibility rule. Reopening after compaction verifies that the
        // later [a] record remains authoritative.
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(id), Some(BuildHash(40_001)));
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
            let (graph, id, _, mut writer) = open_out_only(&path)?;
            writer.write_build(&graph, id, BuildHash(7))?;
            drop(writer);
            let valid_size = std::fs::metadata(&path)?.len();

            let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(&record.0[..tail_len])?;
            drop(file);

            let (graph, id, hashes, mut writer) = open_out_only(&path)?;
            assert_eq!(hashes.get(id), Some(BuildHash(7)));
            assert_eq!(std::fs::metadata(&path)?.len(), valid_size);

            writer.write_build(&graph, id, BuildHash(42))?;
            drop(writer);
            let (_, id, hashes, writer) = open_out_only(&path)?;
            assert_eq!(hashes.get(id), Some(BuildHash(42)));
            drop(writer);
        }
        Ok(())
    }
}
