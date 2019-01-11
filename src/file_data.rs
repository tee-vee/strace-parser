use crate::parser::RawData;
use crate::syscall_data::PidData;
use crate::HashMap;
use crate::Pid;
use rayon::prelude::*;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct FileData<'a> {
    time: &'a str,
    file: Option<&'a str>,
    error: Option<&'a str>,
    length: Option<f32>,
}

impl<'a, 'b> From<&'b RawData<'a>> for FileData<'a> {
    fn from(raw_data: &RawData<'a>) -> FileData<'a> {
        FileData {
            time: raw_data.time,
            file: raw_data.file,
            error: raw_data.error,
            length: raw_data.length,
        }
    }
}

impl<'a> fmt::Display for FileData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = &self.file.unwrap_or_default();
        let length = self.length.map_or(0.0, |l| l * 1000.0);
        let error = &self.error.unwrap_or("-");

        write!(
            f,
            "  {0: >10.3}\t{1: ^17}\t   {2: ^15}\t   {3: <30}",
            length, self.time, error, name
        )
    }
}

pub enum SortFilesBy {
    Length,
    Time,
}

pub fn files_opened<'a>(
    raw_data: &HashMap<Pid, PidData<'a>>,
    pids: &[Pid],
    sort_by: SortFilesBy,
) -> HashMap<Pid, Vec<FileData<'a>>> {
    let pid_data: HashMap<_, _> = pids
        .iter()
        .map(|pid| {
            let mut open_events = raw_data[pid].open_events.clone();
            open_events.par_sort_unstable_by(|x, y| (x.time).cmp(&y.time));

            let mut coalesced_data: Vec<_> = coalesce_file_data(open_events.as_slice());

            match sort_by {
                SortFilesBy::Length => coalesced_data.par_sort_by(|x, y| {
                    (&y.length)
                        .partial_cmp(&x.length)
                        .expect("Invalid comparison when sorting file access times")
                }),
                SortFilesBy::Time => coalesced_data.par_sort_by(|x, y| (x.time).cmp(&y.time)),
            }
            (*pid, coalesced_data)
        })
        .collect();

    pid_data
}

fn coalesce_file_data<'a>(file_data: &[RawData<'a>]) -> Vec<FileData<'a>> {
    let mut iter = file_data.iter().peekable();

    let mut complete_entries = Vec::new();

    while let Some(entry) = iter.next() {
        match (&entry.file, entry.length) {
            (Some(_), Some(_)) => complete_entries.push(FileData::from(entry)),
            (Some(f), None) => {
                if let Some(next) = iter.peek() {
                    complete_entries.push(FileData {
                        time: entry.time,
                        file: Some(f),
                        length: next.length,
                        error: next.error,
                    });
                    iter.next();
                } else {
                    complete_entries.push(FileData::from(entry));
                }
            }
            _ => {}
        }
    }

    complete_entries
}
