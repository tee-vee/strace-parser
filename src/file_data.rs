use crate::parser::{CallStatus, RawData};
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};
use rayon::prelude::*;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct FileData<'a> {
    time: &'a str,
    file: &'a str,
    error: Option<&'a str>,
    duration: f32,
}

impl<'a> FileData<'a> {
    fn new(
        time: &'a str,
        file_opt: Option<&'a str>,
        error: Option<&'a str>,
        duration_opt: Option<f32>,
    ) -> FileData<'a> {
        FileData {
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
            time: raw_data.time,
            file: raw_data.file.unwrap_or_default(),
            error: raw_data.error,
            duration: raw_data.duration.map_or(0.0, |dur| dur * 1000.0),
        }
    }
}

impl<'a> fmt::Display for FileData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let error = &self.error.unwrap_or("-");

        write!(
            f,
            "  {0: >10.3}\t{1: ^17}\t   {2: ^15}\t   {3: <30}",
            self.duration, self.time, error, self.file
        )
    }
}

pub enum SortFilesBy {
    Length,
    Time,
}

pub fn files_opened<'a>(
    pids: &[Pid],
    raw_data: &HashMap<Pid, PidData<'a>>,
    sort_by: SortFilesBy,
) -> HashMap<Pid, Vec<FileData<'a>>> {
    let pid_data: HashMap<_, _> = pids
        .par_iter()
        .map(|pid| {
            let mut open_events = raw_data[pid].open_events.clone();
            open_events.par_sort_unstable_by(|x, y| (x.time).cmp(&y.time));

            let mut coalesced_data: Vec<_> = coalesce_file_data(open_events.as_slice());

            match sort_by {
                SortFilesBy::Length => coalesced_data.par_sort_by(|x, y| {
                    (&y.duration)
                        .partial_cmp(&x.duration)
                        .expect("Invalid comparison when sorting file open times")
                }),
                SortFilesBy::Time => coalesced_data.par_sort_by(|x, y| (x.time).cmp(&y.time)),
            }
            (*pid, coalesced_data)
        })
        .collect();

    pid_data
}

fn coalesce_file_data<'a>(file_data: &[RawData<'a>]) -> Vec<FileData<'a>> {
    let mut complete_entries = Vec::new();
    let mut iter = file_data.iter();

    while let Some(entry) = iter.next() {
        match entry.call_status {
            CallStatus::Complete => {
                complete_entries.push(FileData::new(
                    entry.time,
                    entry.file,
                    entry.error,
                    entry.duration,
                ));
            }
            CallStatus::Started => {
                if let Some(next_entry) = iter.next() {
                    complete_entries.push(FileData::new(
                        entry.time,
                        entry.file,
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
