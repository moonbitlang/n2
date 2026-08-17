//! The n2 database stores information about previous builds for determining
//! which files are up to date.

mod record;

use crate::{
    densemap, densemap::DenseMap, graph::BuildId, graph::FileId, graph::Graph, graph::Hashes,
    hash::BuildHash,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::path::PathBuf;

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
        record::write_signature(&mut w.w)?;
        Ok(w)
    }

    fn from_opened(ids: IdMap, w: File) -> Self {
        Writer { ids, w }
    }

    fn write_path(&mut self, name: &str) -> std::io::Result<()> {
        record::write_path(&mut self.w, name)
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

        let outs = build.outs();
        let deps = build.discovered_ins();
        let mut record = record::BuildWriter::new(outs.len(), deps.len());
        for &out in outs {
            let id = self.ensure_id(graph, out)?;
            record.write_output(id);
        }

        for &dep in deps {
            let id = self.ensure_id(graph, dep)?;
            record.write_dependency(id);
        }

        record.finish(hash.0, &mut self.w)
    }
}

struct Reader<'a> {
    r: record::Reader<BufReader<&'a mut File>>,
    ids: IdMap,
    graph: &'a mut Graph,
    hashes: &'a mut Hashes,
}

impl<'a> Reader<'a> {
    fn replay_build<R: Read>(
        ids: &IdMap,
        graph: &mut Graph,
        hashes: &mut Hashes,
        mut build: record::BuildRecord<'_, R>,
    ) -> std::io::Result<()> {
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
        for fileid in build.outputs() {
            let fileid = fileid?;
            if obsolete {
                continue;
            }
            match graph.file(ids.fileids[fileid]).input {
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

        let mut deps = Vec::new();
        for id in build.dependencies()? {
            deps.push(ids.fileids[id?]);
        }
        let hash = BuildHash(build.hash()?);

        // unique_bid is set here if this record is valid.
        if let Some(id) = unique_bid {
            // Common case: only one associated build.
            graph.builds[id].set_discovered_ins(deps);
            hashes.set(id, hash);
        }
        Ok(())
    }

    fn read_file(&mut self) -> anyhow::Result<()> {
        let span = tracing::info_span!("db.read_file");
        let _enter = span.enter();

        self.r.read_signature()?;
        loop {
            let Some(record) = self.r.read_record()? else {
                break;
            };
            match record {
                record::Record::Path(path) => {
                    let name = path.into_name();
                    let _path_span =
                        tracing::info_span!("db.read_path_record", name_len = name.len()).entered();
                    // No canonicalization needed, paths were written canonicalized.
                    let fileid = self.graph.files.id_from_canonical(name);
                    let dbid = self.ids.fileids.push(fileid);
                    self.ids.db_ids.insert(fileid, dbid);
                }
                record::Record::Build(build) => {
                    let _build_span =
                        tracing::info_span!("db.read_build_record", outs_len = build.outputs_len())
                            .entered();
                    Self::replay_build(&self.ids, &mut *self.graph, &mut *self.hashes, build)?;
                }
            }
        }
        Ok(())
    }

    /// Reads an on-disk database, loading its state into the provided Graph/Hashes.
    fn read(f: &mut File, graph: &mut Graph, hashes: &mut Hashes) -> anyhow::Result<IdMap> {
        let mut r = Reader {
            r: record::Reader::new(BufReader::new(f)),
            ids: IdMap::default(),
            graph,
            hashes,
        };
        r.read_file()?;

        Ok(r.ids)
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
pub fn open(path: &Path, graph: &mut Graph, hashes: &mut Hashes) -> Result<Writer, OpenError> {
    let span = tracing::info_span!("db.open", path = %path.display());
    let _enter = span.enter();

    match std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
    {
        Ok(mut f) => {
            let _branch = tracing::info_span!("db.open_existing").entered();
            tracing::info!(path = %path.display(), "opening existing database");
            let ids = {
                let _read = tracing::info_span!("db.read").entered();
                Reader::read(&mut f, graph, hashes).map_err(|err| OpenError {
                    path: path.to_path_buf(),
                    source: OpenErrorKind::ReadDB(err),
                })?
            };
            tracing::info!(path = %path.display(), "database loaded successfully");
            Ok(Writer::from_opened(ids, f))
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

    const OUT_ONLY: &[u8] = b"build out: phony\n";
    const OUT_AND_OTHER: &[u8] = b"build out: phony\nbuild other-out: phony\n";

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
}
