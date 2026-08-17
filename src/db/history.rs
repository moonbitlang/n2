//! Database-global latest-output ownership for the append-only build log.

use super::record;

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

/// Path IDs are dense, so each output directly names its latest build record.
/// A later record invalidates every earlier record sharing any output. Stale
/// pointers left behind for other outputs are harmless because `live_records`
/// is authoritative. Consequently all live records have pairwise-disjoint
/// output sets when replay finishes.
#[derive(Debug, Default)]
pub(super) struct BuildHistory {
    latest_by_output: Vec<Option<RecordId>>,
    live_records: Vec<bool>,
}

impl BuildHistory {
    pub(super) fn record_path(&mut self) {
        self.latest_by_output.push(None);
    }

    pub(super) fn record_build(&mut self, build: record::BuildLayout, bytes: &[u8]) -> RecordId {
        let record = RecordId::next(self.live_records.len());
        if build.outputs_len == 0 {
            self.live_records.push(false);
            return record;
        }

        self.live_records.push(true);
        for output in build.outputs(bytes) {
            if let Some(old) = self.latest_by_output[output as usize] {
                if self.live_records[old.index()] {
                    self.live_records[old.index()] = false;
                }
            }
        }

        for output in build.outputs(bytes) {
            self.latest_by_output[output as usize] = Some(record);
        }
        record
    }

    pub(super) fn is_live(&self, record: RecordId) -> bool {
        self.live_records[record.index()]
    }
}
