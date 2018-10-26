use chrono::NaiveTime;
use crate::parser::RawData;
use crate::Pid;
use fnv::FnvHashMap;
use rayon::prelude::*;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct FileData<'a> {
    time: NaiveTime,
    file: Option<&'a str>,
    error: Option<&'a str>,
    length: Option<f32>,
}

impl<'a> FileData<'a> {
    pub fn from_raw_data(raw_data: &RawData<'a>) -> FileData<'a> {
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
        let name = match &self.file {
            Some(n) => n,
            None => "",
        };
        let length = match self.length {
            Some(l) => l * 1000.0,
            None => 0.0,
        };
        let error = match &self.error {
            Some(e) => e,
            None => "",
        };

        write!(
            f,
            "  {0: >10.3}\t{1: >15}\t   {2: >15}\t   {3: <30}",
            length, self.time, error, name
        )
    }
}

pub fn files_opened<'a>(
    raw_data: FnvHashMap<Pid, Vec<RawData<'a>>>,
    pids: &[Pid],
) -> FnvHashMap<Pid, Vec<FileData<'a>>> {
    let pid_data: FnvHashMap<_, _> = pids
        .iter()
        .map(|pid| {
            let pid_data = raw_data[pid].clone();
            let mut data: Vec<_> = pid_data
                .into_par_iter()
                .filter(|d| d.pid == *pid)
                .filter(|d| d.syscall == "open" || d.syscall == "openat")
                .collect();
            data.par_sort_unstable_by(|x, y| (x.time).cmp(&y.time));

            let mut coalesced_data: Vec<_> = coalesce_file_data(data.as_slice());
            coalesced_data.par_sort_by(|x, y| {
                (&y.length)
                    .partial_cmp(&x.length)
                    .expect("Invalid comparison wben sorting file access times")
            });
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
            (Some(_), Some(_)) => complete_entries.push(FileData::from_raw_data(entry)),
            (Some(f), None) => {
                if let Some(next) = iter.peek() {
                    complete_entries.push(FileData {
                        time: entry.time,
                        file: Some(f),
                        length: next.length,
                        error: next.error.clone(),
                    });
                    iter.next();
                } else {
                    complete_entries.push(FileData::from_raw_data(entry));
                }
            }
            _ => {}
        }
    }

    complete_entries
}
