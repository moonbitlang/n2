//! Graph-independent compaction of the append-only database log.

use super::record::{self, Kind, Records, DATABASE_HEADER_SIZE, PATH_RECORD_HEADER_SIZE};
use super::{history::BuildHistory, history::RecordId, IdMap, SIGNATURE, VERSION};
use crate::graph::Graph;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const MIN_COMPACTION_SIZE: u64 = 2 * 1024 * 1024;
const COMPACTION_RATIO: u64 = 3;

/// Best-effort maintenance after ordinary replay and before append is opened.
///
/// Ordinary replay has already identified the live database-global build
/// records. This module marks their paths, densely remaps path IDs, streams a
/// replacement, and returns the replacement's IdMap. It never consults graph
/// membership to decide persistent liveness.
pub(super) fn compact_if_needed(
    path: &Path,
    graph: &Graph,
    ids: &IdMap,
    history: &BuildHistory,
    ended_at_record_boundary: bool,
    old_size: u64,
) -> Option<IdMap> {
    if old_size < MIN_COMPACTION_SIZE
        || DATABASE_HEADER_SIZE + history.live_build_bytes() > old_size / COMPACTION_RATIO
    {
        return None;
    }
    if !ended_at_record_boundary {
        // Tail recovery is a separate policy. Mechanical compaction must not
        // silently turn the currently tolerated one-byte suffix into a repair.
        tracing::warn!("skipped database compaction with an incomplete tail");
        return None;
    }
    // Replacement must target the file selected by a final-component symlink,
    // not replace that symlink itself.
    let path = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(error = %err, "skipped database compaction path resolution");
            return None;
        }
    };
    match compact(&path, graph, ids, history, old_size) {
        Ok(Some((ids, new_size))) => {
            tracing::info!(old_size, new_size, "database compacted");
            Some(ids)
        }
        Ok(None) => None,
        Err(record::Error::Io(err)) => {
            tracing::warn!(error = %err, "skipped database compaction");
            None
        }
        Err(record::Error::Allocation) => {
            tracing::warn!("skipped database compaction after an allocation failed");
            None
        }
    }
}

fn compact(
    path: &Path,
    graph: &Graph,
    ids: &IdMap,
    history: &BuildHistory,
    old_size: u64,
) -> Result<Option<(IdMap, u64)>, record::Error> {
    let source = File::open(path)?;
    let mut records = open_records(source, old_size)?;
    let live_paths = collect_live_paths(&mut records, history)?;
    let encoded_size = ids
        .fileids
        .iter()
        .enumerate()
        .filter(|(id, _)| live_paths.contains(*id))
        .try_fold(
            DATABASE_HEADER_SIZE + history.live_build_bytes(),
            |size, (_, &fileid)| {
                size.checked_add(PATH_RECORD_HEADER_SIZE + graph.file(fileid).name.len() as u64)
            },
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "compacted database size overflow",
            )
        })?;
    if encoded_size > old_size / COMPACTION_RATIO {
        return Ok(None);
    }

    drop(records);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let (staged, new_ids) = stage(path, graph, ids, history, &live_paths, parent)?;
    // No source or append handle remains when replacement happens.
    match staged.persist(path) {
        Ok(file) => drop(file),
        Err(err) => return Err(err.error.into()),
    }
    Ok(Some((new_ids, encoded_size)))
}

fn open_records(source: File, end: u64) -> Result<Records<File>, record::Error> {
    Records::new(source, end).map_err(|err| match err.downcast::<std::io::Error>() {
        Ok(err) => err.into(),
        Err(err) => std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()).into(),
    })
}

fn collect_live_paths(
    records: &mut Records<File>,
    history: &BuildHistory,
) -> Result<LivePaths, record::Error> {
    let mut live = LivePaths::new(history.path_count())?;
    let mut build_count = 0usize;
    while records.next()? {
        let Kind::Build(build) = records.kind() else {
            continue;
        };
        let record = RecordId::next(build_count);
        build_count += 1;
        if !history.is_live(record) {
            continue;
        }
        for id in build
            .outputs(records.bytes())
            .chain(build.dependencies(records.bytes()))
        {
            live.mark(id as usize);
        }
    }
    debug_assert_eq!(build_count, history.record_count());
    live.finish()?;
    Ok(live)
}

fn stage(
    path: &Path,
    graph: &Graph,
    ids: &IdMap,
    history: &BuildHistory,
    live_paths: &LivePaths,
    parent: &Path,
) -> Result<(tempfile::NamedTempFile, IdMap), record::Error> {
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.as_file_mut().write_all(SIGNATURE)?;
    staged.as_file_mut().write_all(&VERSION.to_le_bytes())?;

    let mut new_ids = IdMap::default();
    let live_path_count = live_paths.len();
    new_ids
        .fileids
        .try_reserve(live_path_count)
        .map_err(|_| record::Error::Allocation)?;
    new_ids
        .db_ids
        .try_reserve(live_path_count)
        .map_err(|_| record::Error::Allocation)?;
    for (old_id, &fileid) in ids.fileids.iter().enumerate() {
        if !live_paths.contains(old_id) {
            continue;
        }
        let name = &graph.file(fileid).name;
        staged
            .as_file_mut()
            .write_all(&(name.len() as u16).to_le_bytes())?;
        staged.as_file_mut().write_all(name.as_bytes())?;
        let new_id = new_ids.fileids.push(fileid);
        new_ids.db_ids.insert(fileid, new_id);
    }

    let source = File::open(path)?;
    let end = source.metadata()?.len();
    let mut records = open_records(source, end)?;
    let mut build_count = 0usize;
    while records.next()? {
        let Kind::Build(build) = records.kind() else {
            continue;
        };
        let record = RecordId::next(build_count);
        build_count += 1;
        if !history.is_live(record) {
            continue;
        }
        if build
            .remap_ids(records.bytes_mut(), |id| live_paths.remap(id as usize))
            .is_none()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "retained build references a path that was not marked live",
            )
            .into());
        }
        staged.as_file_mut().write_all(records.bytes())?;
    }
    debug_assert_eq!(build_count, history.record_count());
    drop(records);
    staged.as_file().sync_all()?;
    Ok((staged, new_ids))
}

/// A fixed-domain bitmap keeps path tracking below 3 MiB even when every
/// possible 24-bit path ID is present. `ranks[word]` stores the number of live
/// IDs in preceding words, making old-to-new ID remapping constant time.
struct LivePaths {
    bits: Vec<u64>,
    ranks: Vec<u32>,
}

impl LivePaths {
    fn new(path_count: usize) -> Result<Self, record::Error> {
        let word_count = path_count.div_ceil(u64::BITS as usize);
        let mut bits = Vec::new();
        bits.try_reserve_exact(word_count)
            .map_err(|_| record::Error::Allocation)?;
        bits.resize(word_count, 0);
        Ok(Self {
            bits,
            ranks: Vec::new(),
        })
    }

    fn mark(&mut self, id: usize) {
        self.bits[id / u64::BITS as usize] |= 1 << (id % u64::BITS as usize);
    }

    fn finish(&mut self) -> Result<(), record::Error> {
        self.ranks
            .try_reserve_exact(self.bits.len())
            .map_err(|_| record::Error::Allocation)?;
        let mut rank = 0u32;
        for &word in &self.bits {
            self.ranks.push(rank);
            rank += word.count_ones();
        }
        Ok(())
    }

    fn contains(&self, id: usize) -> bool {
        self.bits[id / u64::BITS as usize] & (1 << (id % u64::BITS as usize)) != 0
    }

    fn len(&self) -> usize {
        self.bits
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    fn remap(&self, id: usize) -> Option<u32> {
        if !self.contains(id) {
            return None;
        }
        let word_index = id / u64::BITS as usize;
        let bit_index = id % u64::BITS as usize;
        let preceding_mask = if bit_index == 0 {
            0
        } else {
            (1u64 << bit_index) - 1
        };
        Some(self.ranks[word_index] + (self.bits[word_index] & preceding_mask).count_ones())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open;
    use crate::graph::{BuildId, Graph, Hashes};
    use crate::hash::BuildHash;

    const OUT_ONLY: &[u8] = b"build out: phony\n";
    const OUT_AND_OTHER: &[u8] = b"build out: phony\nbuild other-out: phony\n";
    const THREE_OUTPUTS: &[u8] =
        b"build out: phony\nbuild other-out: phony\nbuild after-out: phony\n";
    const A_ONLY: &[u8] = b"build a: phony\n";
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

    fn write_oversized_database(path: &Path) -> anyhow::Result<u64> {
        let (mut graph, id) = build_graph(OUT_AND_OTHER, 16)?;
        let fixed_deps = graph.builds[id].discovered_ins().to_vec();
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let other_dep = graph.files.id_from_canonical("other-dep".to_owned());
        graph.builds[other_id].set_discovered_ins(vec![other_dep]);
        let mut writer = open(path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, other_id, BuildHash(123))?;
        for hash in 1..=40_000 {
            let mut deps = fixed_deps.clone();
            deps.push(
                graph
                    .files
                    .id_from_canonical(format!("obsolete-dep-{hash}")),
            );
            graph.builds[id].set_discovered_ins(deps);
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        drop(writer);
        Ok(std::fs::metadata(path)?.len())
    }

    fn record_counts(path: &Path) -> anyhow::Result<(usize, usize)> {
        let file = File::open(path)?;
        let end = file.metadata()?.len();
        let mut records = Records::new(file, end)?;
        let mut paths = 0;
        let mut builds = 0;
        while records.next()? {
            match records.kind() {
                Kind::Path(_) => paths += 1,
                Kind::Build(_) => builds += 1,
            }
        }
        Ok((paths, builds))
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

    fn write_distinct_database(path: &Path) -> std::io::Result<u64> {
        let mut file = File::create(path)?;
        file.write_all(SIGNATURE)?;
        file.write_all(&VERSION.to_le_bytes())?;
        for id in 0u32..40_000 {
            let name = format!("unique-output-{id:030}");
            file.write_all(&(name.len() as u16).to_le_bytes())?;
            file.write_all(name.as_bytes())?;
            file.write_all(&0x8001u16.to_le_bytes())?;
            file.write_all(&id.to_le_bytes()[..3])?;
            file.write_all(&0u16.to_le_bytes())?;
            file.write_all(&(id as u64).to_le_bytes())?;
        }
        drop(file);
        Ok(std::fs::metadata(path)?.len())
    }

    #[test]
    fn open_mechanically_compacts_builds_and_paths() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let old_size = write_oversized_database(&path)?;
        assert!(old_size >= MIN_COMPACTION_SIZE);

        // A partial graph may trigger maintenance, but it never defines which
        // persistent records or paths are retained.
        let (mut partial_graph, id) = build_graph(OUT_ONLY, 0)?;
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut partial_graph, &mut hashes)?;
        assert_eq!(hashes.get(id), Some(BuildHash(40_000)));
        let dep_names: Vec<&str> = partial_graph.builds[id]
            .discovered_ins()
            .iter()
            .map(|&id| partial_graph.file(id).name.as_str())
            .collect();
        let mut expected: Vec<String> = (0..16).map(|i| format!("dep-{i}")).collect();
        expected.push("obsolete-dep-40000".to_owned());
        assert_eq!(dep_names, expected);
        drop(writer);

        assert!(std::fs::metadata(&path)?.len() < old_size / COMPACTION_RATIO);
        // Two latest build records reference 20 distinct paths. All 39,999
        // superseded per-build dependencies are gone.
        assert_eq!(record_counts(&path)?, (20, 2));

        let (mut graph, _) = build_graph(OUT_AND_OTHER, 0)?;
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(other_id), Some(BuildHash(123)));
        assert_eq!(graph.builds[other_id].discovered_ins().len(), 1);
        assert_eq!(
            graph.file(graph.builds[other_id].discovered_ins()[0]).name,
            "other-dep"
        );
        drop(writer);
        Ok(())
    }

    #[test]
    fn small_database_is_not_compacted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let (mut graph, id) = build_graph(OUT_ONLY, 1)?;
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        for hash in 1..=10 {
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        drop(writer);
        let old_size = std::fs::metadata(&path)?.len();

        let (mut graph, _) = build_graph(OUT_ONLY, 0)?;
        let writer = open(&path, &mut graph, &mut Hashes::default())?;
        drop(writer);
        assert_eq!(std::fs::metadata(&path)?.len(), old_size);
        Ok(())
    }

    #[test]
    fn database_that_cannot_shrink_enough_is_unchanged() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let old_size = write_distinct_database(&path)?;
        assert!(old_size >= MIN_COMPACTION_SIZE);

        let (mut graph, _) = build_graph(OUT_ONLY, 0)?;
        let writer = open(&path, &mut graph, &mut Hashes::default())?;
        drop(writer);

        assert_eq!(std::fs::metadata(&path)?.len(), old_size);
        assert_eq!(record_counts(&path)?, (40_000, 40_000));
        Ok(())
    }

    #[test]
    fn incomplete_tail_is_not_silently_repaired() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        write_oversized_database(&path)?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(&[0])?;
        let old_size = std::fs::metadata(&path)?.len();

        let (mut graph, id) = build_graph(OUT_ONLY, 0)?;
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(id), Some(BuildHash(40_000)));
        drop(writer);

        assert_eq!(std::fs::metadata(&path)?.len(), old_size);
        Ok(())
    }

    #[test]
    fn writer_can_append_after_compaction() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let old_size = write_oversized_database(&path)?;
        let (mut graph, _) = build_graph(THREE_OUTPUTS, 0)?;
        let mut hashes = Hashes::default();
        let mut writer = open(&path, &mut graph, &mut hashes)?;
        assert!(std::fs::metadata(&path)?.len() < old_size / COMPACTION_RATIO);

        let after_id = graph
            .file(graph.files.lookup("after-out").unwrap())
            .input
            .unwrap();
        writer.write_build(&graph, after_id, BuildHash(777))?;
        drop(writer);

        let (mut graph, _) = build_graph(THREE_OUTPUTS, 0)?;
        let after_id = graph
            .file(graph.files.lookup("after-out").unwrap())
            .input
            .unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(after_id), Some(BuildHash(777)));
        drop(writer);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn compaction_follows_the_database_symlink() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("database");
        let old_size = write_oversized_database(&target)?;
        let path = dir.path().join("database-link");
        std::os::unix::fs::symlink(&target, &path)?;

        let (mut graph, _) = build_graph(OUT_ONLY, 0)?;
        let writer = open(&path, &mut graph, &mut Hashes::default())?;
        drop(writer);

        assert!(std::fs::symlink_metadata(&path)?.file_type().is_symlink());
        assert!(std::fs::metadata(&target)?.len() < old_size / COMPACTION_RATIO);
        Ok(())
    }

    #[test]
    fn compaction_drops_record_invalidated_by_overlapping_output() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let mut graph = crate::load::parse("build.ninja", A_AND_B.to_vec())?;
        let joint_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let deps = (0..16)
            .map(|i| graph.files.id_from_canonical(format!("joint-dep-{i}")))
            .collect();
        graph.builds[joint_id].set_discovered_ins(deps);
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
        for hash in 1..=40_000 {
            writer.write_build(&graph, joint_id, BuildHash(hash))?;
        }
        drop(writer);

        // Path ID 0 is `a`. The later [a] record invalidates the last [a, b]
        // record and every older version of it.
        append_build_record(&path, &[0], 41_000)?;

        let mut graph = crate::load::parse("build.ninja", A_AND_B.to_vec())?;
        let joint_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(joint_id), None);
        drop(writer);

        assert_eq!(record_counts(&path)?, (1, 1));
        let mut graph = crate::load::parse("build.ninja", A_ONLY.to_vec())?;
        let a_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(a_id), Some(BuildHash(41_000)));
        drop(writer);
        Ok(())
    }
}
