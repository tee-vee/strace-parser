use crate::parser;
use crate::parser::{ExitType, LineData, OtherFields, ProcType, RawData};
use crate::Pid;
use crate::{HashMap, HashSet};

use rayon::prelude::*;
use std::convert::TryFrom;

#[derive(Clone, Default, Debug)]
pub struct SyscallData<'a> {
    pub lengths: Vec<f32>,
    pub errors: HashMap<&'a [u8], Pid>,
}

impl<'a> SyscallData<'a> {
    pub fn new() -> SyscallData<'a> {
        SyscallData {
            lengths: Vec::new(),
            errors: HashMap::default(),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct PidData<'a> {
    pub syscall_data: HashMap<&'a [u8], SyscallData<'a>>,
    pub start_time: &'a [u8],
    pub end_time: &'a [u8],
    pub pvt_futex: HashSet<&'a [u8]>,
    pub split_clones: Vec<RawData<'a>>,
    pub threads: Vec<Pid>,
    pub child_pids: Vec<Pid>,
    pub open_events: Vec<RawData<'a>>,
    pub io_events: Vec<RawData<'a>>,
    pub execve: Option<Vec<RawExec<'a>>>,
    pub exit: Option<ExitType<'a>>,
}

impl<'a> PidData<'a> {
    pub fn new() -> PidData<'a> {
        PidData {
            syscall_data: HashMap::default(),
            start_time: b"zzzzz", // greater than any valid time str
            end_time: b"00000",   // less than any valid time str
            pvt_futex: HashSet::new(),
            split_clones: Vec::new(),
            threads: Vec::new(),
            child_pids: Vec::new(),
            open_events: Vec::new(),
            io_events: Vec::new(),
            execve: None,
            exit: None,
        }
    }

    fn coalesce_split_clones(&mut self) {
        self.split_clones.sort_by(|a, b| a.time.cmp(&b.time));

        let mut pairs = self.split_clones.chunks_exact(2);
        while let Some([start, end]) = pairs.next() {
            match (&start.other, &end.rtn_cd) {
                (Some(OtherFields::Clone(ProcType::Process)), Some(child_pid)) => {
                    self.child_pids.push(*child_pid);
                }
                (Some(OtherFields::Clone(ProcType::Thread)), Some(thread_pid)) => {
                    self.threads.push(*thread_pid);
                    self.child_pids.push(*thread_pid);
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct RawExec<'a> {
    pub exec: Vec<&'a [u8]>,
    pub time: &'a [u8],
}

impl<'a> RawExec<'a> {
    pub fn new(exec: Vec<&'a [u8]>, time: &'a [u8]) -> RawExec<'a> {
        RawExec { exec, time }
    }
}

impl<'a> TryFrom<RawData<'a>> for RawExec<'a> {
    type Error = &'static str;

    fn try_from(data: RawData<'a>) -> Result<Self, Self::Error> {
        let t = data.time;
        if let Some(OtherFields::Execve(v)) = data.other {
            Ok(RawExec::new(v, t))
        } else {
            Err("No exec")
        }
    }
}

pub fn build_syscall_data<'a>(buffer: &'a [u8]) -> HashMap<Pid, PidData<'a>> {
    let mut data_map = buffer
        .par_split(|c| *c == b'\n')
        .fold(HashMap::default, |mut pid_data_map, line| {
            if let Some(raw_data) = parser::parse_line(line) {
                add_syscall_data(&mut pid_data_map, raw_data);
            }
            pid_data_map
        })
        .reduce(HashMap::default, |mut pid_data_map, temp_map| {
            coalesce_pid_data(&mut pid_data_map, temp_map);
            pid_data_map
        });

    data_map.par_iter_mut().for_each(|(_, pid_data)| {
        pid_data.coalesce_split_clones();
    });

    data_map
}

fn add_syscall_data<'a>(pid_data_map: &mut HashMap<Pid, PidData<'a>>, line_data: LineData<'a>) {
    let pid_entry = pid_data_map
        .entry(line_data.pid())
        .or_insert_with(PidData::new);

    match line_data {
        LineData::Syscall(raw_data) => {
            let syscall_entry = pid_entry
                .syscall_data
                .entry(raw_data.syscall)
                .or_insert_with(SyscallData::new);

            if let Some(duration) = raw_data.duration {
                syscall_entry.lengths.push(duration);
            }

            if let Some(error) = raw_data.error {
                let error_entry = syscall_entry.errors.entry(error).or_insert(0);
                *error_entry += 1;
            }

            if raw_data.time < pid_entry.start_time {
                pid_entry.start_time = raw_data.time;
            }

            if raw_data.time > pid_entry.end_time {
                pid_entry.end_time = raw_data.time;
            }

            match raw_data.syscall {
                b"clone" | b"fork" | b"vfork" => match (raw_data.rtn_cd, &raw_data.other) {
                    (Some(child_pid), Some(OtherFields::Clone(ProcType::Process))) => {
                        pid_entry.child_pids.push(child_pid as Pid)
                    }
                    (Some(child_pid), Some(OtherFields::Clone(ProcType::Thread))) => {
                        pid_entry.threads.push(child_pid as Pid);
                        pid_entry.child_pids.push(child_pid as Pid);
                    }
                    (None, Some(_)) | (Some(_), None) => {
                        pid_entry.split_clones.push(raw_data);
                    }
                    _ => {}
                },
                b"execve" => {
                    if let Ok(e) = RawExec::try_from(raw_data) {
                        if let Some(execs) = &mut pid_entry.execve {
                            execs.push(e);
                        } else {
                            pid_entry.execve = Some(vec![e]);
                        }
                    }
                }
                b"futex" => {
                    if let Some(OtherFields::Futex(addr)) = raw_data.other {
                        pid_entry.pvt_futex.insert(addr);
                    }
                }
                b"open" | b"openat" => {
                    pid_entry.open_events.push(raw_data);
                }
                b"pread64" | b"pwrite64" | b"preadv" | b"preadv2" | b"pwritev" | b"pwritev2"
                | b"read" | b"recv" | b"recvfrom" | b"recvmsg" | b"send" | b"sendmsg"
                | b"sendto" | b"write" | b"writev" => {
                    pid_entry.io_events.push(raw_data);
                }
                _ => {}
            }
        }
        LineData::Exit(exit_data) => {
            pid_entry.exit = Some(exit_data.exit);
        }
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

        if temp_pid_data.start_time < pid_entry.start_time {
            pid_entry.start_time = temp_pid_data.start_time;
        }

        if temp_pid_data.end_time > pid_entry.end_time {
            pid_entry.end_time = temp_pid_data.end_time;
        }

        pid_entry.pvt_futex.extend(temp_pid_data.pvt_futex);

        pid_entry.split_clones.extend(temp_pid_data.split_clones);

        pid_entry.threads.extend(temp_pid_data.threads);

        pid_entry.child_pids.extend(temp_pid_data.child_pids);

        pid_entry.open_events.extend(temp_pid_data.open_events);

        pid_entry.io_events.extend(temp_pid_data.io_events);

        match (pid_entry.execve.as_mut(), temp_pid_data.execve) {
            (Some(pid_exec), Some(temp_exec)) => {
                for exec in temp_exec.into_iter() {
                    pid_exec.push(exec);
                }
            }
            (None, Some(temp_exec)) => pid_entry.execve = Some(temp_exec),
            _ => {}
        }

        if temp_pid_data.exit.is_some() {
            pid_entry.exit = temp_pid_data.exit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_data_captures_lengths() {
        let input = br##"567   00:09:47.836504 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 221</proc/495/fd> <0.000027>
567   00:10:56.303348 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 228</proc/495/status> <0.000028>
567   00:10:56.360699 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 228</proc/495/fd> <0.000484>"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(
            pid_data_map[&567].syscall_data[b"open".as_ref()].lengths,
            vec![0.000027, 0.000028, 0.000484]
        );
    }

    #[test]
    fn syscall_data_captures_errors() {
        let input = br##"823   00:09:51.247794 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:58.635714 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(
            pid_data_map[&823].syscall_data[b"ioctl".as_ref()]
                .errors
                .clone()
                .into_iter()
                .collect::<Vec<(&[u8], i32)>>(),
            vec![(b"ENOTTY".as_ref(), 2)]
        );
    }

    #[test]
    fn syscall_data_captures_thread() {
        let input = br##"28898 21:16:52.387464 clone(child_stack=0x7f03e0beeff0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f03e0bef9d0, tls=0x7f03e0bef700, child_tidptr=0x7f03e0bef9d0) = 28899 <0.000081>"##;
        let pid_data_map = build_syscall_data(input);
        assert!(pid_data_map[&28898].threads.contains(&28899));
    }

    #[test]
    fn syscall_data_captures_child_pid() {
        let input = br##"477   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000134>"##;
        let pid_data_map = build_syscall_data(input);
        assert!(pid_data_map[&477].child_pids.contains(&7390));
    }

    #[test]
    fn syscall_data_captures_split_clone_proc() {
        let input = br##"17826 13:43:48.980451 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
17826 13:43:48.993404 <... clone resumed>) = 17906 <0.012945>"##;
        let pid_data_map = build_syscall_data(input);
        assert!(pid_data_map[&17826].child_pids.contains(&17906));
    }

    #[test]
    fn syscall_data_captures_split_clone_thread() {
        let input = br##"17839 13:43:43.960050 clone(child_stack=0x7f1afced1ff0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID <unfinished ...>
17839 13:43:43.960137 <... clone resumed>, parent_tid=[17857], tls=0x7f1afced2700, child_tidptr=0x7f1afced29d0) = 17857 <0.000076>"##;
        let pid_data_map = build_syscall_data(input);
        assert!(pid_data_map[&17839].threads.contains(&17857));
    }

    #[test]
    fn syscall_data_unfinished_events_captured() {
        let input = br##"826   00:09:47.789757 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
2690  00:09:47.790444 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>"##;
        let pid_data_map = build_syscall_data(input);
        assert!(pid_data_map.contains_key(&826))
    }

    #[test]
    fn syscall_data_captures_execve() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        assert!(pid_data_map[&13656].execve.is_some());
    }

    #[test]
    fn syscall_data_captures_multiple_execve() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>
13656 10:54:02.442246 execve("/bin/ls", ["ls", "/usr"], [/* 12 vars */]) = 0 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(2, pid_data_map[&13656].execve.as_ref().unwrap().len());
    }

    #[test]
    fn pid_data_captures_start_time() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(b"10:53:02.442246", pid_data_map[&13656].start_time,);
    }

    #[test]
    fn pid_data_captures_end_time() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(b"10:53:02.442246", pid_data_map[&13656].end_time,);
    }

    #[test]
    fn pid_data_updates_end_time() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>
13656 12:00:00.000000 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...> "##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(b"12:00:00.000000", pid_data_map[&13656].end_time,);
    }

    #[test]
    fn pid_data_captures_exit_code() {
        let input = br##"203 01:58:06.988634 +++ exited with 1 +++"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(Some(ExitType::Exit(1)), pid_data_map[&203].exit);
    }

    #[test]
    fn pid_data_captures_futex_addrs() {
        let input = br##"11616 11:34:25.556786 futex(0x7ffa5001fa54, FUTEX_WAIT_PRIVATE, 29, NULL <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(
            &[b"0x7ffa5001fa54"],
            &pid_data_map[&11616]
                .pvt_futex
                .iter()
                .cloned()
                .collect::<Vec<_>>()[..1]
        );
    }

    #[test]
    fn pid_data_handles_windows_newlines() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...>\r
13656 12:00:00.000000 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <unfinished ...> "##;
        let pid_data_map = build_syscall_data(input);
        assert_eq!(b"12:00:00.000000", pid_data_map[&13656].end_time,);
    }
}
