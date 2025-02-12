use crate::parser::{CallStatus, RawData};
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};

use bstr::ByteSlice;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct FileData<'a> {
    pub pid: Pid,
    pub time: &'a [u8],
    pub file: &'a [u8],
    pub error: Option<&'a [u8]>,
    pub duration: f32,
}

impl<'a> FileData<'a> {
    fn new(
        pid: Pid,
        time: &'a [u8],
        file_opt: Option<&'a [u8]>,
        error: Option<&'a [u8]>,
        duration_opt: Option<f32>,
    ) -> FileData<'a> {
        FileData {
            pid,
            time,
            file: file_opt.unwrap_or_default(),
            error,
            duration: duration_opt.map_or(0.0, |dur| dur * 1000.0),
        }
    }
}

impl<'a, 'b> From<&'b RawData<'a>> for FileData<'a> {
    fn from(raw_data: &RawData<'a>) -> FileData<'a> {
        FileData {
            pid: raw_data.pid,
            time: raw_data.time,
            file: raw_data.file().unwrap_or_default(),
            error: raw_data.error,
            duration: raw_data.duration.map_or(0.0, |dur| dur * 1000.0),
        }
    }
}

impl<'a> fmt::Display for FileData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let error = self.error.unwrap_or(b"-");

        write!(
            f,
            "{: >10.3}    {: ^15}    {: ^15}    {: <30}",
            self.duration,
            self.time.to_str_lossy(),
            error.to_str_lossy(),
            self.file.to_str_lossy()
        )
    }
}

pub enum SortFilesBy {
    Duration,
    Time,
}

pub fn files_opened<'a>(
    pids: &[Pid],
    raw_data: &HashMap<Pid, PidData<'a>>,
    sort_by: SortFilesBy,
) -> BTreeMap<Pid, Vec<FileData<'a>>> {
    pids.par_iter()
        .map(|pid| {
            let mut open_events = raw_data[pid].open_events.clone();
            open_events.par_sort_unstable_by(|x, y| (x.time).cmp(&y.time));

            let mut coalesced_data: Vec<_> = coalesce_file_data(open_events.as_slice());

            match sort_by {
                SortFilesBy::Duration => coalesced_data.par_sort_by(|x, y| {
                    (&y.duration)
                        .partial_cmp(&x.duration)
                        .expect("Invalid comparison when sorting file open times")
                }),
                SortFilesBy::Time => coalesced_data.par_sort_by(|x, y| (x.time).cmp(&y.time)),
            }
            (*pid, coalesced_data)
        })
        .collect()
}

fn coalesce_file_data<'a>(file_data: &[RawData<'a>]) -> Vec<FileData<'a>> {
    let mut complete_entries = Vec::new();
    let mut iter = file_data.iter();

    while let Some(entry) = iter.next() {
        match entry.call_status {
            CallStatus::Complete => {
                complete_entries.push(FileData::new(
                    entry.pid,
                    entry.time,
                    entry.file(),
                    entry.error,
                    entry.duration,
                ));
            }
            CallStatus::Started => {
                if let Some(next_entry) = iter.next() {
                    complete_entries.push(FileData::new(
                        entry.pid,
                        entry.time,
                        entry.file(),
                        next_entry.error,
                        next_entry.duration,
                    ));
                }
            }
            CallStatus::Resumed => {}
        }
    }

    complete_entries
}
