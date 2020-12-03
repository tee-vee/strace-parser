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
    pub start_time: &'a [u8],
    pub end_time: &'a [u8],
    pub duration: f32,
    pub ct: usize,
}

impl<'a> DirectoryData<'a> {
    fn new(pid: Pid, start_time: &'a [u8], end_time: &'a [u8], duration: f32) -> DirectoryData<'a> {
        DirectoryData {
            pid,
            start_time,
            end_time,
            duration,
            ct: 1,
        }
    }
}

impl<'a> fmt::Display for DirectoryData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{: >10.3}    {: ^15}    {: ^15}    {: >10}",
            self.duration,
            self.start_time.to_str_lossy(),
            self.end_time.to_str_lossy(),
            self.ct,
        )
    }
}

pub enum SortDirectoriesBy {
    Count,
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
                for event in files {
                    if let Some(parent) = event
                        .file
                        .to_os_str()
                        .ok()
                        .map(|s| Path::new(s))
                        .and_then(|p| p.parent())
                    {
                        for path in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
                            directory_data
                                .entry(path)
                                .and_modify(|entry: &mut DirectoryData| {
                                    if event.time < entry.start_time {
                                        entry.start_time = event.time;
                                    }

                                    if event.time > entry.end_time {
                                        entry.end_time = event.time;
                                    }

                                    entry.duration += event.duration;
                                    entry.ct += 1;
                                })
                                .or_insert(DirectoryData::new(
                                    event.pid,
                                    event.time,
                                    event.time,
                                    event.duration,
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

    #[test]
    fn dirs_captures_start_end_time() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>
1070690 02:39:58.429716 openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.429788 openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3</usr/share/locale/locale.alias> <0.000020>
1070690 02:39:58.430142 openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.430197 openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3</usr/lib/locale/en_US.utf8/LC_IDENTIFICATION> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map, Duration);
        assert_eq!(
            b"02:39:58.426334".as_bstr(),
            dir_data[&1070690][&Path::new("/")].start_time.as_bstr(),
            "Start time"
        );
        assert_eq!(
            b"02:39:58.430197".as_ref().as_bstr(),
            dir_data[&1070690][&Path::new("/")].end_time.as_bstr(),
            "End time"
        );
    }
}
