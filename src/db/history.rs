//! Database-global ownership for records in the append-only build log.

use super::Id;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordId(usize);

impl RecordId {
    pub(super) fn next(record_count: usize) -> Self {
        Self(record_count)
    }

    fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug)]
struct BuildState {
    live: bool,
    has_outputs: bool,
    encoded_len: u32,
}

/// Tracks the latest complete record owning each output path.
///
/// A later record invalidates every earlier record sharing any output. Stale
/// pointers for the earlier record's other outputs are harmless because the
/// per-record `live` flag is authoritative.
#[derive(Debug, Default)]
pub(super) struct BuildHistory {
    latest_by_output: Vec<Option<RecordId>>,
    builds: Vec<BuildState>,
    live_build_bytes: u64,
}

impl BuildHistory {
    pub(super) fn record_path(&mut self) {
        self.latest_by_output.push(None);
    }

    pub(super) fn start_build(&mut self) -> RecordId {
        let record = RecordId::next(self.builds.len());
        self.builds.push(BuildState {
            live: true,
            has_outputs: false,
            encoded_len: 0,
        });
        record
    }

    pub(super) fn record_output(&mut self, record: RecordId, output: Id) {
        let output = output.0 as usize;
        self.builds[record.index()].has_outputs = true;
        if let Some(old) = self.latest_by_output[output] {
            if old != record && self.builds[old.index()].live {
                self.builds[old.index()].live = false;
                self.live_build_bytes -= u64::from(self.builds[old.index()].encoded_len);
            }
        }
        self.latest_by_output[output] = Some(record);
    }

    pub(super) fn finish_build(&mut self, record: RecordId, encoded_len: usize) {
        let build = &mut self.builds[record.index()];
        build.encoded_len = u32::try_from(encoded_len).expect("database record length fits in u32");
        if build.has_outputs {
            self.live_build_bytes += u64::from(build.encoded_len);
        } else {
            build.live = false;
        }
    }

    pub(super) fn is_live(&self, record: RecordId) -> bool {
        self.builds[record.index()].live
    }

    pub(super) fn path_count(&self) -> usize {
        self.latest_by_output.len()
    }

    pub(super) fn record_count(&self) -> usize {
        self.builds.len()
    }

    pub(super) fn live_build_bytes(&self) -> u64 {
        self.live_build_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish(history: &mut BuildHistory, outputs: &[u32], encoded_len: usize) -> RecordId {
        let record = history.start_build();
        for &output in outputs {
            history.record_output(record, Id(output));
        }
        history.finish_build(record, encoded_len);
        record
    }

    #[test]
    fn overlapping_output_invalidates_the_whole_prior_record() {
        let mut history = BuildHistory::default();
        history.record_path();
        history.record_path();
        let joint = finish(&mut history, &[0, 1], 20);
        let split = finish(&mut history, &[0], 10);

        assert!(!history.is_live(joint));
        assert!(history.is_live(split));
        assert_eq!(history.live_build_bytes(), 10);
    }

    #[test]
    fn outputs_can_acquire_independent_latest_records() {
        let mut history = BuildHistory::default();
        history.record_path();
        history.record_path();
        let joint = finish(&mut history, &[0, 1], 20);
        let first = finish(&mut history, &[0], 10);
        let second = finish(&mut history, &[1], 11);

        assert!(!history.is_live(joint));
        assert!(history.is_live(first));
        assert!(history.is_live(second));
        assert_eq!(history.live_build_bytes(), 21);
    }

    #[test]
    fn record_without_outputs_is_not_live() {
        let mut history = BuildHistory::default();
        let record = finish(&mut history, &[], 12);

        assert!(!history.is_live(record));
        assert_eq!(history.live_build_bytes(), 0);
    }
}
