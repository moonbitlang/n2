//! The n2 database stores information about previous builds for determining
//! which files are up to date.

mod compaction;
mod history;
mod record;

use crate::{
    densemap, densemap::DenseMap, graph::BuildId, graph::FileId, graph::Graph, graph::Hashes,
    hash::BuildHash,
};
use history::{BuildHistory, RecordId};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

const VERSION: u32 = 1;
const SIGNATURE: &[u8; 4] = b"n2db";

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
        self.write(&n.to_le_bytes()[..3]);
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
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(path)?;
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
}

struct Reader<'a> {
    records: record::Records<&'a mut File>,
    ids: IdMap,
    history: BuildHistory,
    pending: DenseMap<BuildId, Option<PendingBuild>>,
    graph: &'a mut Graph,
}

#[derive(Clone)]
struct PendingBuild {
    record: RecordId,
    deps: Vec<FileId>,
    hash: BuildHash,
}

struct Replay {
    ids: IdMap,
    history: BuildHistory,
    pending: DenseMap<BuildId, Option<PendingBuild>>,
    ended_at_record_boundary: bool,
}

impl Replay {
    fn commit(
        mut self,
        replacement_ids: Option<IdMap>,
        graph: &mut Graph,
        hashes: &mut Hashes,
    ) -> IdMap {
        for index in 0..graph.builds.iter().len() {
            let id = BuildId::from(index);
            let Some(pending) = self.pending[id].take() else {
                continue;
            };
            if self.history.is_live(pending.record) {
                graph.builds[id].set_discovered_ins(pending.deps);
                hashes.set(id, pending.hash);
            }
        }
        replacement_ids.unwrap_or(self.ids)
    }
}

impl<'a> Reader<'a> {
    fn lookup_file(&self, raw_id: u32) -> FileId {
        self.ids.fileids[Id(raw_id)]
    }

    fn matching_build(&self, build: record::BuildLayout) -> Option<BuildId> {
        let bytes = self.records.bytes();
        let Some(first) = build.outputs(bytes).next() else {
            return None;
        };
        let Some(id) = self.graph.file(self.lookup_file(first)).input else {
            return None;
        };
        let current_outputs = self.graph.builds[id].outs();
        if current_outputs.len() != build.outputs_len {
            return None;
        }
        for (raw_id, &current) in build.outputs(bytes).zip(current_outputs) {
            if self.lookup_file(raw_id) != current {
                return None;
            }
        }
        Some(id)
    }

    fn read_build(&mut self, build: record::BuildLayout) {
        let record = self.history.record_build(build, self.records.bytes());
        let mut deps = Vec::new();
        for raw_id in build.dependencies(self.records.bytes()) {
            deps.push(self.lookup_file(raw_id));
        }
        let Some(id) = self.matching_build(build) else {
            return;
        };

        let hash = BuildHash(build.hash(self.records.bytes()));
        self.pending[id] = Some(PendingBuild { record, deps, hash });
    }

    fn read_file(&mut self) -> anyhow::Result<()> {
        let span = tracing::info_span!("db.read_file");
        let _enter = span.enter();

        loop {
            if !self.records.next()? {
                break;
            }
            let kind = self.records.kind();
            match kind {
                record::Kind::Path(path) => {
                    let _path_span =
                        tracing::info_span!("db.read_path_record", name_len = path.name_len)
                            .entered();
                    let name = path.name(self.records.bytes()).to_vec();
                    let name = unsafe { String::from_utf8_unchecked(name) };
                    // No canonicalization needed; paths were canonicalized
                    // before they were written.
                    let fileid = self.graph.files.id_from_canonical(name);
                    let dbid = self.ids.fileids.push(fileid);
                    self.ids.db_ids.insert(fileid, dbid);
                    self.history.record_path();
                }
                record::Kind::Build(build) => {
                    let _build_span =
                        tracing::info_span!("db.read_build_record", outs_len = build.outputs_len)
                            .entered();
                    self.read_build(build);
                }
            }
        }
        Ok(())
    }

    /// Replays an on-disk database without committing matched build state.
    fn read(f: &mut File, graph: &mut Graph) -> anyhow::Result<Replay> {
        let end = f.metadata()?.len();
        let records = record::Records::new(f, end)?;
        let pending = DenseMap::new_sized(graph.builds.next_id(), None);
        let mut r = Reader {
            records,
            ids: IdMap::default(),
            history: BuildHistory::default(),
            pending,
            graph,
        };
        r.read_file()?;
        Ok(Replay {
            ids: r.ids,
            history: r.history,
            pending: r.pending,
            ended_at_record_boundary: r.records.ended_at_record_boundary(),
        })
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
/// Ordinary replay also gathers database-global output ownership: a later
/// build record invalidates every earlier record sharing any output. If a
/// database is at least 2 MiB and the remaining records and paths fit in one
/// third of the current log, opening performs best-effort mechanical
/// compaction before opening the append handle. The current graph is never
/// used to decide which persistent records are live. Compaction streams the
/// retained state to a temporary file and replaces the cache only after the
/// staged file contents have been synchronized. A log that does not end at a
/// complete record boundary is left unchanged; recovery is a separate policy.
/// The database is a reconstructible cache: replacement does not preserve its
/// inode, hard links, custom permissions, ACLs, or extended attributes. The
/// containing directory is not synchronized, so a system crash may lose the
/// cache entry.
///
/// Graphs sharing `path` must be disjoint portions of one logical graph. Each
/// Build must appear with its complete output list, and an output must not have
/// multiple producers across those portions.
///
/// Before calling this function, the caller must acquire the same interprocess
/// exclusive lock used by every consumer of `path`, and hold it until the
/// returned [`Writer`] is dropped.
pub fn open(path: &Path, graph: &mut Graph, hashes: &mut Hashes) -> Result<Writer, OpenError> {
    let span = tracing::info_span!("db.open", path = %path.display());
    let _enter = span.enter();

    // A library process may change its process-wide working directory from a
    // different thread. Resolve a relative database name once so compaction,
    // replay, and append all select the file protected by the caller's lock.
    let stable_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|current_dir| current_dir.join(path))
            .map_err(|err| OpenError {
                path: path.to_path_buf(),
                source: OpenErrorKind::OpenDB(err),
            })?
    };
    let mut source = match File::open(&stable_path) {
        Ok(source) => source,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _create = tracing::info_span!("db.create").entered();
            tracing::info!(path = %path.display(), "creating new database");
            return Writer::create(&stable_path).map_err(|err| OpenError {
                path: path.to_path_buf(),
                source: OpenErrorKind::CreateDB(err),
            });
        }
        Err(err) => {
            return Err(OpenError {
                path: path.to_path_buf(),
                source: OpenErrorKind::OpenDB(err),
            })
        }
    };

    let _branch = tracing::info_span!("db.open_existing").entered();
    tracing::info!(path = %path.display(), "opening existing database");
    let old_size = source
        .metadata()
        .map_err(|err| OpenError {
            path: path.to_path_buf(),
            source: OpenErrorKind::OpenDB(err),
        })?
        .len();
    let replay = {
        let _read = tracing::info_span!("db.read").entered();
        Reader::read(&mut source, graph).map_err(|err| OpenError {
            path: path.to_path_buf(),
            source: OpenErrorKind::ReadDB(err),
        })?
    };
    drop(source);

    let replacement_ids = compaction::compact_if_needed(
        &stable_path,
        graph,
        &replay.ids,
        &replay.history,
        replay.ended_at_record_boundary,
        old_size,
    );
    let w = std::fs::OpenOptions::new()
        .append(true)
        .open(&stable_path)
        .map_err(|err| OpenError {
            path: path.to_path_buf(),
            source: OpenErrorKind::OpenDB(err),
        })?;
    // Do not mutate the caller's build state unless opening for append also
    // succeeded: a successful return is the transaction boundary of open().
    let ids = replay.commit(replacement_ids, graph, hashes);
    tracing::info!(path = %path.display(), "database loaded successfully");
    Ok(Writer::from_opened(ids, w))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT_ONLY: &[u8] = b"build out: phony\n";
    const OUT_AND_OTHER: &[u8] = b"build out: phony\nbuild other-out: phony\n";
    const A_ONLY: &[u8] = b"build a: phony\n";
    const B_ONLY: &[u8] = b"build b: phony\n";
    const A_AND_B: &[u8] = b"build a b: phony\n";

    fn build_graph(manifest: &[u8], dep_count: usize) -> anyhow::Result<(Graph, BuildId)> {
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

    fn append_build_record(path: &Path, outputs: &[u32], hash: u64) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
        file.write_all(&(0x8000 | outputs.len() as u16).to_le_bytes())?;
        for output in outputs {
            file.write_all(&output.to_le_bytes()[..3])?;
        }
        file.write_all(&0u16.to_le_bytes())?;
        file.write_all(&hash.to_le_bytes())
    }

    #[test]
    fn opening_with_a_partial_graph_preserves_other_records() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let (mut graph, id) = build_graph(OUT_AND_OTHER, 16)?;
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, other_id, BuildHash(123))?;
        for hash in 1..=40_000 {
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        drop(writer);
        // Keep the fixture above the threshold used by the reverted automatic
        // compaction so reintroducing it unsafely makes this test fail.
        assert!(std::fs::metadata(&path)?.len() >= 2 * 1024 * 1024);

        // Opening a shared database with one invocation's partial graph must
        // not erase records owned by another invocation.
        let (mut partial_graph, _) = build_graph(OUT_ONLY, 0)?;
        let writer = open(&path, &mut partial_graph, &mut Hashes::default())?;
        drop(writer);

        let (mut graph, _) = build_graph(OUT_AND_OTHER, 0)?;
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;

        assert_eq!(hashes.get(other_id), Some(BuildHash(123)));
        drop(writer);
        Ok(())
    }

    #[test]
    fn overlapping_output_invalidates_the_whole_prior_record() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let mut graph = crate::load::parse("build.ninja", A_AND_B.to_vec())?;
        let joint_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, joint_id, BuildHash(1))?;
        drop(writer);

        // Path ID 0 is `a`. Its newer ownership invalidates the complete
        // earlier [a, b] record, even though b is not mentioned again.
        append_build_record(&path, &[0], 2)?;

        let mut graph = crate::load::parse("build.ninja", A_AND_B.to_vec())?;
        let joint_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(joint_id), None);
        drop(writer);

        let mut graph = crate::load::parse("build.ninja", A_ONLY.to_vec())?;
        let a_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(a_id), Some(BuildHash(2)));
        drop(writer);
        Ok(())
    }

    #[test]
    fn split_outputs_acquire_independent_latest_records() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let mut graph = crate::load::parse("build.ninja", A_AND_B.to_vec())?;
        let joint_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, joint_id, BuildHash(1))?;
        drop(writer);

        append_build_record(&path, &[0], 2)?;
        append_build_record(&path, &[1], 3)?;

        let mut graph = crate::load::parse("build.ninja", A_ONLY.to_vec())?;
        let a_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(a_id), Some(BuildHash(2)));
        drop(writer);

        let mut graph = crate::load::parse("build.ninja", B_ONLY.to_vec())?;
        let b_id = graph.file(graph.files.lookup("b").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(b_id), Some(BuildHash(3)));
        drop(writer);
        Ok(())
    }
}
