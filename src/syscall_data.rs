use crate::parser::RawData;
use crate::Pid;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

pub fn build_syscall_data<'a>(
    parsed_data: &HashMap<Pid, Vec<RawData<'a>>>,
) -> HashMap<Pid, PidData<'a>> {
    let mut syscall_data = HashMap::new();
    for (pid, data_vec) in parsed_data {
        for data in data_vec {
            let pid_entry = syscall_data.entry(*pid).or_insert(PidData::new());
            let syscall_entry = pid_entry
                .syscall_data
                .entry(data.syscall)
                .or_insert(SyscallData::new());

            if let Some(length) = data.length {
                syscall_entry.lengths.push(length);
            }

            if let Some(file) = data.file {
                pid_entry.files.insert(file);
            }

            if let Some(error) = data.error {
                let error_entry = syscall_entry.errors.entry(error).or_insert(0);
                *error_entry += 1;
            }

            if let Some(child_pid) = data.child_pid {
                pid_entry.child_pids.push(child_pid);
            }
        }
    }
    syscall_data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn syscall_data_captures_lengths() {
        let input = r##"567   00:09:47.836504 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 221</proc/495/fd> <0.000027>
567   00:10:56.303348 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 228</proc/495/status> <0.000028>
567   00:10:56.360699 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 228</proc/495/fd> <0.000484>"##.to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        assert_eq!(
            pid_data_map[&567].syscall_data["open"].lengths,
            vec![0.000027, 0.000028, 0.000484]
        );
    }

    #[test]
    fn syscall_data_captures_errors() {
        let input = r##"823   00:09:51.247794 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:58.635714 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>"##.to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
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
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        assert!(pid_data_map[&477].child_pids.contains(&7390));
    }

    #[test]
    fn syscall_data_unfinished_events_captured() {
        let input = r##"826   00:09:47.789757 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
2690  00:09:47.790444 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>"##.to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        assert_eq!(pid_data_map.contains_key(&826), true)
    }

    #[test]
    fn syscall_data_unfinished_open_file_captured() {
        let input = r##"817   00:09:58.951745 open("/opt/gitlab/embedded/service/gitlab-rails/vendor/active_record/associations/preloader/belongs_to.rb", O_RDONLY|O_NONBLOCK|O_CLOEXEC <unfinished ...>"##.to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        assert!(pid_data_map[&817].files.contains("/opt/gitlab/embedded/service/gitlab-rails/vendor/active_record/associations/preloader/belongs_to.rb"));
    }
}
