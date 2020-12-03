use crate::file_data;
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};

use bstr::ByteSlice;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryData<'a> {
    pub pid: Pid,
    pub time: &'a [u8],
    pub duration: f32,
}

impl<'a> DirectoryData<'a> {
    fn new(pid: Pid, time: &'a [u8], duration: f32) -> DirectoryData<'a> {
        DirectoryData {
            pid,
            time,
            duration,
        }
    }
}

impl<'a> fmt::Display for DirectoryData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{: >10.3}    {: ^15}",
            self.duration,
            self.time.to_str_lossy()
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
) -> HashMap<Pid, BTreeMap<&'a Path, DirectoryData<'a>>> {
    let file_calls = file_data::files_opened(&pids, raw_data, file_data::SortFilesBy::Time);

    pids.par_iter()
        .map(|pid| {
            let mut directory_data = BTreeMap::new();

            file_calls.get(pid).map(|files| {
                for file_entry in files {
                    if let Some(p) = file_entry
                        .file
                        .to_os_str()
                        .ok()
                        .map(|s| Path::new(s))
                        .and_then(|p| p.parent())
                    {
                        for path in p.ancestors() {
                            directory_data
                                .entry(path)
                                .and_modify(|entry: &mut DirectoryData| {
                                    entry.time = file_entry.time;
                                    entry.duration += file_entry.duration;
                                })
                                .or_insert(DirectoryData::new(
                                    file_entry.pid,
                                    file_entry.time,
                                    file_entry.duration,
                                ));
                        }
                    }
                }
            });

            (*pid, directory_data)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_data::build_syscall_data;
    use SortDirectoriesBy::*;

    use approx::assert_ulps_eq;

    #[test]
    fn dirs_captures_pid() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map, Duration);
        assert_eq!(vec![&1070690], dir_data.keys().collect::<Vec<_>>());
    }

    #[test]
    fn dirs_captures_path_ancestors() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map, Duration);
        assert_eq!(
            vec![&Path::new("/"), &Path::new("/etc")],
            dir_data[&1070690].keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn dirs_sums_times() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>
1070690 02:39:58.429716 openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.429788 openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3</usr/share/locale/locale.alias> <0.000020>
1070690 02:39:58.430142 openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.430197 openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3</usr/lib/locale/en_US.utf8/LC_IDENTIFICATION> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map, Duration);
        assert_ulps_eq!(
            (0.00002 * 1000.0) * 5.0,
            dir_data[&1070690][&Path::new("/")].duration
        );
        assert_ulps_eq!(
            (0.00002 * 1000.0) * 4.0,
            dir_data[&1070690][&Path::new("/usr")].duration
        );
        assert_ulps_eq!(
            (0.00002 * 1000.0) * 3.0,
            dir_data[&1070690][&Path::new("/usr/lib")].duration
        );
    }
}
