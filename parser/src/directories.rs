use crate::file_data;
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryData<'a> {
    pub pid: Pid,
    pub time: &'a str,
    pub duration: f32,
}

impl<'a> DirectoryData<'a> {
    fn new(
        pid: Pid,
        time: &'a str,
        duration: f32,
    ) -> DirectoryData<'a> {
        DirectoryData {
            pid,
            time,
            duration
        }
    }
}

impl<'a> fmt::Display for DirectoryData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{: >10.3}    {: ^15}",
            self.duration, self.time
        )
    }
}

pub enum SortDirectoriesBy {
    Duration,
    Time,
}

pub fn directories_opened<'a>(
    pids: &[Pid],
    raw_data: &HashMap<Pid, PidData<'a>>,
    _sort_by: SortDirectoriesBy,
) -> HashMap<Pid, BTreeMap<String, DirectoryData<'a>>> {
    let file_calls = file_data::files_opened(&pids, raw_data, file_data::SortFilesBy::Time);

    pids.par_iter()
        .map(|pid| {
            let mut directory_data = BTreeMap::new();

            file_calls.get(pid).map(|files| {
                for file in files {
                    // We split the full path into a vector of directory names
                    let mut directories: Vec<&str> = file.file.split("/").collect();

                    // Then remove the last segment which is the filename
                    directories.pop();

                    // Now loop through the directories, reconstructing the hierarchy
                    for (index, _directory) in directories.iter().enumerate() {
                        let mut path = directories[0..index].join("/");

                        if path.is_empty() {
                            path.push('/');
                        }

                        // Store a map based on the full path to this directory
                        // .time is set to the latest file to read from it
                        // .duration is accumulative from all files read from inside it
                        directory_data.entry(path)
                            .and_modify(|entry: &mut DirectoryData| {
                                entry.time = file.time;
                                entry.duration += file.duration;
                            })
                            .or_insert(DirectoryData::new(
                                file.pid,
                                file.time,
                                file.duration,
                            ));
                    }
                }
            });

            (*pid, directory_data)
        })
        .collect()
}
