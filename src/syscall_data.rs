use crate::parser;
use crate::parser::RawData;
use crate::HashMap;
use crate::Pid;
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct SyscallData<'a> {
    pub lengths: Vec<f32>,
    pub errors: HashMap<&'a str, Pid>,
}

impl<'a> SyscallData<'a> {
    pub fn new() -> SyscallData<'a> {
        SyscallData {
            lengths: Vec::new(),
            errors: HashMap::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PidData<'a> {
    pub syscall_data: HashMap<&'a str, SyscallData<'a>>,
    pub child_pids: Vec<Pid>,
    pub open_events: Vec<RawData<'a>>,
    pub execve: Option<Vec<&'a str>>,
}

impl<'a> PidData<'a> {
    pub fn new() -> PidData<'a> {
        PidData {
            syscall_data: HashMap::default(),
            child_pids: Vec::new(),
            open_events: Vec::new(),
            execve: None,
        }
    }
}

pub fn build_syscall_data<'a>(buffer: &'a str) -> HashMap<Pid, PidData<'a>> {
    buffer
        .par_lines()
        .fold(HashMap::default, |mut pid_data_map, line| {
            if let Some(raw_data) = parser::parse_line(line) {
                add_syscall_data(&mut pid_data_map, raw_data);
            }
            pid_data_map
        })
        .reduce(HashMap::default, |mut pid_data_map, temp_map| {
            coalesce_pid_data(&mut pid_data_map, temp_map);
            pid_data_map
        })
}

fn add_syscall_data<'a>(pid_data_map: &mut HashMap<Pid, PidData<'a>>, raw_data: RawData<'a>) {
    let pid_entry = pid_data_map
        .entry(raw_data.pid)
        .or_insert_with(PidData::new);

    let syscall_entry = pid_entry
        .syscall_data
        .entry(raw_data.syscall)
        .or_insert_with(SyscallData::new);

    if let Some(length) = raw_data.length {
        syscall_entry.lengths.push(length);
    }

    if let Some(error) = raw_data.error {
        let error_entry = syscall_entry.errors.entry(error).or_insert(0);
        *error_entry += 1;
    }

    if let Some(child_pid) = raw_data.child_pid {
        pid_entry.child_pids.push(child_pid);
    }

    if raw_data.syscall == "execve" {
        if let Some(ref e) = raw_data.execve {
            pid_entry.execve = Some(e.clone());
        }
    }

    if raw_data.syscall == "open" || raw_data.syscall == "openat" {
        pid_entry.open_events.push(raw_data);
    }
}

fn coalesce_pid_data<'a>(
    pid_data_map: &mut HashMap<Pid, PidData<'a>>,
    temp_map: HashMap<Pid, PidData<'a>>,
) {
    for (pid, temp_pid_data) in temp_map.into_iter() {
        let pid_entry = pid_data_map.entry(pid).or_insert_with(PidData::new);

        for (syscall, temp_syscall_data) in temp_pid_data.syscall_data {
            let syscall_entry = pid_entry
                .syscall_data
                .entry(syscall)
                .or_insert_with(SyscallData::new);

            syscall_entry
                .lengths
                .extend(temp_syscall_data.lengths.into_iter());

            for (error, count) in temp_syscall_data.errors.iter() {
                let error_entry = syscall_entry.errors.entry(error).or_insert(0);
                *error_entry += count;
            }
        }

        pid_entry
            .child_pids
            .extend(temp_pid_data.child_pids.into_iter());

        pid_entry
            .open_events
            .extend(temp_pid_data.open_events.into_iter());

        if let Some(temp_execve) = temp_pid_data.execve {
            pid_entry.execve = Some(temp_execve);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_data_captures_lengths() {
        let input = r##"567   00:09:47.836504 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 221</proc/495/fd> <0.000027>
567   00:10:56.303348 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 228</proc/495/status> <0.000028>
567   00:10:56.360699 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 228</proc/495/fd> <0.000484>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
        assert_eq!(
            pid_data_map[&567].syscall_data["open"].lengths,
            vec![0.000027, 0.000028, 0.000484]
        );
    }

    #[test]
    fn syscall_data_captures_errors() {
        let input = r##"823   00:09:51.247794 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:58.635714 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
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
        let pid_data_map = build_syscall_data(&input);
        assert!(pid_data_map[&477].child_pids.contains(&7390));
    }

    #[test]
    fn syscall_data_unfinished_events_captured() {
        let input = r##"826   00:09:47.789757 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
2690  00:09:47.790444 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
        assert!(pid_data_map.contains_key(&826))
    }

    #[test]
    fn syscall_data_captures_execve() {
        let input = r##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(&input);
        assert!(pid_data_map[&13656].execve.is_some());
    }
}
