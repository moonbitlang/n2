//! Compaction of superseded build records in the append-only database log.

use super::{history::BuildHistory, history::RecordId, record};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

pub(super) const MIN_COMPACTION_SIZE: u64 = 2 * 1024 * 1024;
const COMPACTION_RATIO: u64 = 3;

/// Best-effort maintenance after replay, returning a usable append handle.
/// Replacement addresses `path` itself; callers should not use a symlink when
/// preserving that directory entry matters.
pub(super) fn compact_if_needed(path: &Path, file: File, old_size: u64) -> std::io::Result<File> {
    if old_size < MIN_COMPACTION_SIZE {
        return Ok(file);
    }
    drop(file);

    match compact(path, old_size) {
        Ok(Some(new_size)) => tracing::info!(old_size, new_size, "database compacted"),
        Ok(None) => {}
        Err(err) => tracing::warn!(error = %err, "skipped database compaction"),
    }
    std::fs::OpenOptions::new().append(true).open(path)
}

fn compact(path: &Path, old_size: u64) -> std::io::Result<Option<u64>> {
    let scan = scan(path)?;
    let compacted_size = record::DATABASE_HEADER_SIZE
        .checked_add(scan.path_bytes)
        .and_then(|size| size.checked_add(scan.history.live_build_bytes()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "compacted database size overflow",
            )
        })?;
    if compacted_size > old_size / COMPACTION_RATIO {
        return Ok(None);
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged
        .as_file()
        .set_permissions(std::fs::metadata(path)?.permissions())?;
    rewrite(path, &scan.history, staged.as_file_mut())?;
    staged.as_file().sync_all()?;
    match staged.persist(path) {
        Ok(file) => drop(file),
        Err(err) => return Err(err.error),
    }
    Ok(Some(compacted_size))
}

struct Scan {
    history: BuildHistory,
    path_bytes: u64,
}

fn scan(path: &Path) -> std::io::Result<Scan> {
    let mut records = open_records(File::open(path)?)?;
    let mut history = BuildHistory::default();
    let mut path_bytes = 0u64;
    while let Some(record) = records.read_record()? {
        match record {
            record::Record::Path(path) => {
                history.record_path();
                path_bytes = path_bytes
                    .checked_add(path.encoded_len() as u64)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "database path record size overflow",
                        )
                    })?;
            }
            record::Record::Build(mut build) => {
                let id = history.start_build();
                for output in build.outputs() {
                    let output = output?;
                    if output.0 as usize >= history.path_count() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "build record references an unknown output path",
                        ));
                    }
                    history.record_output(id, output);
                }
                for dependency in build.dependencies()? {
                    dependency?;
                }
                let encoded_len = build.encoded_len();
                build.hash()?;
                history.finish_build(id, encoded_len);
            }
        }
    }
    Ok(Scan {
        history,
        path_bytes,
    })
}

fn rewrite(path: &Path, history: &BuildHistory, target: &mut File) -> std::io::Result<()> {
    let mut records = open_records(File::open(path)?)?;
    let mut target = BufWriter::new(target);
    record::write_signature(&mut target)?;

    let mut build_count = 0usize;
    while let Some(record) = records.read_record()? {
        match record {
            record::Record::Path(path) => record::write_path(&mut target, &path.into_name())?,
            record::Record::Build(build) => {
                if build_count == history.record_count() {
                    return Err(database_changed());
                }
                let id = RecordId::next(build_count);
                build_count += 1;
                if history.is_live(id) {
                    build.write_to(&mut target)?;
                } else {
                    build.skip()?;
                }
            }
        }
    }
    if build_count != history.record_count() {
        return Err(database_changed());
    }
    target.flush()
}

fn open_records(source: File) -> std::io::Result<record::Reader<BufReader<File>>> {
    let mut records = record::Reader::new(BufReader::new(source));
    records
        .read_signature()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    Ok(records)
}

fn database_changed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "database changed during compaction",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open, Id};
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
        let other_id = graph
            .file(graph.files.lookup("other-out").unwrap())
            .input
            .unwrap();
        let other_dep = graph.files.id_from_canonical("other-dep".to_owned());
        graph.builds[other_id].set_discovered_ins(vec![other_dep]);
        let mut writer = open(path, &mut graph, &mut Hashes::default())?;
        writer.write_build(&graph, other_id, BuildHash(123))?;
        for hash in 1..=40_000 {
            writer.write_build(&graph, id, BuildHash(hash))?;
        }
        drop(writer);
        Ok(std::fs::metadata(path)?.len())
    }

    fn record_counts(path: &Path) -> anyhow::Result<(usize, usize)> {
        let mut records = open_records(File::open(path)?)?;
        let mut paths = 0;
        let mut builds = 0;
        while let Some(record) = records.read_record()? {
            match record {
                record::Record::Path(_) => paths += 1,
                record::Record::Build(build) => {
                    builds += 1;
                    build.skip()?;
                }
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
        record::write_signature(&mut file)?;
        for id in 0u32..40_000 {
            let name = format!("unique-output-{id:030}");
            record::write_path(&mut file, &name)?;
            let mut build = record::BuildWriter::new(1, 0);
            build.write_output(Id(id));
            build.finish(id as u64, &mut file)?;
        }
        drop(file);
        Ok(std::fs::metadata(path)?.len())
    }

    #[test]
    fn open_compacts_superseded_builds_but_keeps_paths() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let old_size = write_oversized_database(&path)?;
        assert!(old_size >= MIN_COMPACTION_SIZE);

        // A partial graph may trigger maintenance, but it never determines
        // which persistent records are retained.
        let (mut partial_graph, id) = build_graph(OUT_ONLY, 0)?;
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut partial_graph, &mut hashes)?;
        assert_eq!(hashes.get(id), Some(BuildHash(40_000)));
        assert_eq!(partial_graph.builds[id].discovered_ins().len(), 16);
        drop(writer);

        assert!(std::fs::metadata(&path)?.len() < old_size / COMPACTION_RATIO);
        assert_eq!(record_counts(&path)?, (19, 2));

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
    fn compaction_discards_an_incomplete_record_header() -> anyhow::Result<()> {
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

        assert!(std::fs::metadata(&path)?.len() < old_size / COMPACTION_RATIO);
        Ok(())
    }

    #[test]
    fn writer_can_append_after_compaction() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".n2_db");
        let old_size = write_oversized_database(&path)?;
        let (mut graph, _) = build_graph(THREE_OUTPUTS, 0)?;
        let mut writer = open(&path, &mut graph, &mut Hashes::default())?;
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

    #[test]
    fn overlapping_output_invalidates_the_whole_prior_record() -> anyhow::Result<()> {
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

        append_build_record(&path, &[0], 41_000)?;

        let mut graph = crate::load::parse("build.ninja", A_AND_B.to_vec())?;
        let joint_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(joint_id), Some(BuildHash(41_000)));
        drop(writer);

        assert_eq!(record_counts(&path)?, (18, 1));
        let mut graph = crate::load::parse("build.ninja", A_ONLY.to_vec())?;
        let a_id = graph.file(graph.files.lookup("a").unwrap()).input.unwrap();
        let mut hashes = Hashes::default();
        let writer = open(&path, &mut graph, &mut hashes)?;
        assert_eq!(hashes.get(a_id), Some(BuildHash(41_000)));
        drop(writer);
        Ok(())
    }
}
