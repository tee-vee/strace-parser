use crate::Pid;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};

lazy_static! {
    static ref ALL_RE: Regex = Regex::new(
        r##"(?x)
        ^(?P<pid>\d+)[^a-zA-Z]+
        (?P<syscall>\w+)(:?\((:?[A-Z_]+,\s)?"(?P<file>[^"]+)")?
        ([^)]+<unfinished\s[.]{3}>$|.+\)\s+=\s+(?P<return_code>(-)?[\d?]+)(:?<[^>]+>)?
        \s+(:?(?P<error_code>E[A-Z]+)\s\([^)]+\)\s+)?
        <(?P<length>\d+\.\d+)?>$)
    "##
    )
    .unwrap();
}

#[derive(Debug, PartialEq)]
pub struct RawData<'a> {
    pid: Pid,
    syscall: &'a str,
    length: Option<f32>,
    error: Option<&'a str>,
    file: Option<&'a str>,
    child_pid: Option<Pid>,
}

impl<'a> RawData<'a> {
    pub fn from_strs(
        pid_str: &'a str,
        syscall: &'a str,
        length_str: Option<&'a str>,
        error: Option<&'a str>,
        file: Option<&'a str>,
        child_pid_str: Option<&'a str>,
    ) -> Option<RawData<'a>> {
        match (length_str, child_pid_str) {
            (Some(length), Some(child_pid)) => match (
                pid_str.parse::<Pid>(),
                length.parse::<f32>(),
                child_pid.parse::<Pid>(),
            ) {
                (Ok(pid), Ok(length), Ok(child_pid)) => Some(RawData {
                    pid,
                    syscall,
                    length: Some(length),
                    error,
                    file,
                    child_pid: Some(child_pid),
                }),
                _ => None,
            },
            (Some(length), None) => match (pid_str.parse::<Pid>(), length.parse::<f32>()) {
                (Ok(pid), Ok(length)) => Some(RawData {
                    pid,
                    syscall,
                    length: Some(length),
                    error,
                    file,
                    child_pid: None,
                }),
                _ => None,
            },
            (None, None) => match pid_str.parse::<Pid>() {
                (Ok(pid)) => Some(RawData {
                    pid,
                    syscall,
                    length: None,
                    error,
                    file,
                    child_pid: None,
                }),
                _ => None,
            },
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct SyscallData<'a> {
    pub lengths: Vec<f32>,
    pub errors: BTreeMap<&'a str, Pid>,
}

impl<'a> SyscallData<'a> {
    pub fn new() -> SyscallData<'a> {
        SyscallData {
            lengths: Vec::new(),
            errors: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct PidData<'a> {
    pub syscall_data: HashMap<&'a str, SyscallData<'a>>,
    pub files: BTreeSet<&'a str>,
    pub child_pids: Vec<Pid>,
}

impl<'a> PidData<'a> {
    pub fn new() -> PidData<'a> {
        PidData {
            syscall_data: HashMap::new(),
            files: BTreeSet::new(),
            child_pids: Vec::new(),
        }
    }
}

pub fn parse_syscall_data<'a>(buffer: &'a str) -> HashMap<Pid, PidData<'a>> {
    let parsed_raw_data = extract_raw_data(buffer);
    let collected_data = build_syscall_data(parsed_raw_data);

    collected_data
}

fn build_syscall_data<'a>(parsed_data: Vec<Option<RawData<'a>>>) -> HashMap<Pid, PidData<'a>> {
    let mut syscall_data = HashMap::new();
    for event_data in parsed_data {
        if let Some(data) = event_data {
            let pid_entry = syscall_data.entry(data.pid).or_insert(PidData::new());
            let syscall_entry = pid_entry
                .syscall_data
                .entry(data.syscall)
                .or_insert(SyscallData::new());

            if let Some(length) = data.length {
                syscall_entry.lengths.push(length);
            }

            if let Some(error) = data.error {
                let error_entry = syscall_entry.errors.entry(error).or_insert(0);
                *error_entry += 1;
            }

            if let Some(file) = data.file {
                pid_entry.files.insert(file);
            }

            if let Some(child_pid) = data.child_pid {
                pid_entry.child_pids.push(child_pid);
            }
        }
    }

    syscall_data
}

fn extract_raw_data<'a>(buffer: &'a str) -> Vec<Option<RawData<'a>>> {
    let parsed_data: Vec<_> = buffer
        .par_lines()
        .filter_map(|line| ALL_RE.captures(line))
        .map(|caps| match caps.name("syscall") {
            Some(s) => {
                let syscall = s.as_str();
                if syscall == "open" || syscall == "openat" {
                    match (
                        caps.name("pid"),
                        caps.name("length"),
                        caps.name("error_code"),
                        caps.name("file"),
                    ) {
                        (Some(pid), Some(length), Some(error), Some(file)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            Some(error.as_str()),
                            Some(file.as_str()),
                            None,
                        ),
                        (Some(pid), Some(length), None, Some(file)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            Some(file.as_str()),
                            None,
                        ),
                        (Some(pid), Some(length), None, None) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            None,
                            None,
                        ),
                        (Some(pid), None, None, Some(file)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            None,
                            None,
                            Some(file.as_str()),
                            None,
                        ),
                        _ => None,
                    }
                } else if syscall == "clone" {
                    match (
                        caps.name("pid"),
                        caps.name("length"),
                        caps.name("error_code"),
                        caps.name("return_code"),
                    ) {
                        (Some(pid), Some(length), None, Some(return_code)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            None,
                            Some(return_code.as_str()),
                        ),
                        (Some(pid), Some(length), Some(error), None) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            Some(error.as_str()),
                            None,
                            None,
                        ),
                        (Some(pid), Some(length), None, None) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            None,
                            None,
                        ),
                        _ => None,
                    }
                } else {
                    match (
                        caps.name("pid"),
                        caps.name("length"),
                        caps.name("error_code"),
                    ) {
                        (Some(pid), Some(length), Some(error)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            Some(error.as_str()),
                            None,
                            None,
                        ),
                        (Some(pid), Some(length), None) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            None,
                            None,
                        ),
                        _ => None,
                    }
                }
            }
            None => None,
        })
        .collect();

    parsed_data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_data_returns_none_invalid_pid() {
        assert_eq!(
            RawData::from_strs("123aaa", "test", None, None, None, None),
            None
        );
    }

    #[test]
    fn raw_data_returns_none_invalid_length() {
        assert_eq!(
            RawData::from_strs("123", "test", Some("1.00000aaa"), None, None, None),
            None
        );
    }

    #[test]
    fn raw_data_returns_none_invalid_child_pid() {
        assert_eq!(
            RawData::from_strs("123", "test", None, None, None, Some("123aaa"),),
            None
        );
    }

    #[test]
    fn raw_data_constructed_pid_length_child_pid() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "test",
                Some("1.000000"),
                Some("EWAT"),
                Some("/dev/null"),
                Some("456")
            ),
            Some(RawData {
                pid: 123,
                syscall: "test",
                length: Some(1.000000),
                error: Some("EWAT"),
                file: Some("/dev/null"),
                child_pid: Some(456),
            })
        );
    }

    #[test]
    fn raw_data_constructed_pid_length() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "test",
                Some("1.000000"),
                Some("EWAT"),
                Some("/dev/null"),
                None,
            ),
            Some(RawData {
                pid: 123,
                syscall: "test",
                length: Some(1.000000),
                error: Some("EWAT"),
                file: Some("/dev/null"),
                child_pid: None,
            })
        );
    }
    #[test]
    fn raw_data_constructed_pid() {
        assert_eq!(
            RawData::from_strs("123", "test", None, Some("EWAT"), Some("/dev/null"), None,),
            Some(RawData {
                pid: 123,
                syscall: "test",
                length: None,
                error: Some("EWAT"),
                file: Some("/dev/null"),
                child_pid: None,
            })
        );
    }

    #[test]
    fn syscall_data_captures_lengths() {
        let input = r##"567   00:09:47.836504 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 221</proc/495/fd> <0.000027>
567   00:10:56.303348 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 228</proc/495/status> <0.000028>
567   00:10:56.360699 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 228</proc/495/fd> <0.000484>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        assert_eq!(
            pid_data_map[&567].syscall_data["open"].lengths,
            vec![0.000027, 0.000028, 0.000484]
        );
    }

    #[test]
    fn syscall_data_captures_errors() {
        let input = r##"823   00:09:51.247794 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:58.635714 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        assert_eq!(
            pid_data_map[&823].syscall_data["ioctl"]
                .errors
                .clone()
                .into_iter()
                .collect::<Vec<(&str, i32)>>(),
            vec![("ENOTTY", 2)]
        );
    }

    #[test]
    fn syscall_data_captures_child_pid() {
        let input = r##"477   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000134>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        assert!(pid_data_map[&477].child_pids.contains(&7390));
    }

    #[test]
    fn syscall_data_unfinished_events_ignored() {
        let input = r##"826   00:09:47.789757 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
2690  00:09:47.790444 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        assert_eq!(pid_data_map.contains_key(&826), false)
    }

    #[test]
    fn syscall_data_unfinished_open_file_captured() {
        let input = r##"817   00:09:58.951745 open("/opt/gitlab/embedded/service/gitlab-rails/vendor/active_record/associations/preloader/belongs_to.rb", O_RDONLY|O_NONBLOCK|O_CLOEXEC <unfinished ...>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        assert!(pid_data_map[&817].files.contains("/opt/gitlab/embedded/service/gitlab-rails/vendor/active_record/associations/preloader/belongs_to.rb"));
    }
}
