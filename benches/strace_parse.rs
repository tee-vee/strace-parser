#[macro_use]
extern crate criterion;
extern crate rayon;

use chrono::NaiveTime;
use criterion::Criterion;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet, HashMap};

type Pid = i32;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: NaiveTime,
    pub syscall: &'a str,
    pub length: Option<f32>,
    pub file: Option<&'a str>,
    pub error: Option<&'a str>,
    pub child_pid: Option<Pid>,
}

impl<'a> RawData<'a> {
    pub fn from_strs(
        pid_str: &'a str,
        time_str: &'a str,
        syscall: &'a str,
        length_str: Option<&'a str>,
        file: Option<&'a str>,
        error: Option<&'a str>,
        child_pid_str: Option<&'a str>,
    ) -> Option<RawData<'a>> {
        let pid = match pid_str.parse() {
            Ok(pid) => pid,
            Err(_) => return None,
        };

        let time = match NaiveTime::parse_from_str(time_str, "%H:%M:%S%.6f") {
            Ok(time) => time,
            Err(_) => return None,
        };

        let length = match length_str {
            Some(length) => match length.parse() {
                Ok(len) => Some(len),
                Err(_) => None,
            },
            None => None,
        };

        let child_pid = match child_pid_str {
            Some(child_pid) => match child_pid.parse() {
                Ok(c_pid) => Some(c_pid),
                Err(_) => None,
            },
            None => None,
        };

        Some(RawData {
            pid,
            time,
            syscall,
            length,
            file,
            error,
            child_pid,
        })
    }
}

enum CallStatus {
    Resumed,
    Started,
}

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

pub fn parse<'a>(buffer: &'a str) -> HashMap<Pid, Vec<RawData<'a>>> {
    let data = buffer.par_lines().filter_map(|l| parse_line(l)).collect();
    let sorted_data = sort_parsed_data(data);

    sorted_data
}

fn parse_line<'a>(line: &'a str) -> Option<RawData<'a>> {
    let tokens: SmallVec<[&str; 20]> = line.split_whitespace().collect();

    if tokens.len() < 5 {
        return None;
    }

    let pid = tokens[0];
    let time = tokens[1];

    let call_status = if tokens[2].starts_with('<') {
        CallStatus::Resumed
    } else {
        CallStatus::Started
    };

    let syscall;
    let mut file = None;

    match call_status {
        CallStatus::Started => {
            let split: SmallVec<[&str; 5]> = tokens[2].split('(').collect();

            if split.len() < 2 {
                return None;
            }

            syscall = split[0];
            if syscall == "open" {
                let file_quoted = split[1];
                file = Some(&file_quoted[1..file_quoted.len() - 2]);
            } else if syscall == "openat" {
                let file_quoted = tokens[3];
                file = Some(&file_quoted[1..file_quoted.len() - 2]);
            }
        }
        CallStatus::Resumed => {
            syscall = tokens[3];
        }
    }

    let length = match tokens.last() {
        Some(token) => {
            if token.starts_with('<') {
                Some(&token[1..token.len() - 1])
            } else {
                None
            }
        }
        None => None,
    };

    let mut child_pid = None;
    let mut error = None;

    let eq_pos = tokens.iter().rposition(|&t| t == "=");
    if let Some(pos) = eq_pos {
        if syscall == "clone" {
            if let Some(child_pid_str) = tokens.get(pos + 1).map(|t| *t) {
                child_pid = Some(child_pid_str);
            }
        }

        let err_pos = tokens.iter().skip(pos).position(|t| (*t).starts_with("E"));
        if let Some(e_pos) = err_pos {
            error = tokens.get(pos + e_pos).map(|t| *t);
        }
    }

    RawData::from_strs(pid, time, syscall, length, file, error, child_pid)
}

fn sort_parsed_data<'a>(parsed_data: Vec<RawData<'a>>) -> HashMap<Pid, Vec<RawData<'a>>> {
    let mut sorted_data = HashMap::new();

    for data in parsed_data.into_iter() {
        let pid_entry = sorted_data.entry(data.pid).or_insert(Vec::new());
        pid_entry.push(data);
    }

    sorted_data
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

fn parse_strace(buffer: &str) {
    let _syscall_data = parse(buffer);
}

fn parse_benchmark(c: &mut Criterion) {
    c.bench_function("parse strace", move |b| b.iter(|| parse_strace(DATA)));
}

fn build_data(raw_data: &HashMap<Pid, Vec<RawData>>) {
    let _data = build_syscall_data(raw_data);
}

fn data_benchmark(c: &mut Criterion) {
    let raw_data = parse(DATA);
    c.bench_function("build data", move |b| {
        b.iter(|| build_data(&(raw_data.clone())))
    });
}

criterion_group!(benches, parse_benchmark, data_benchmark);
criterion_main!(benches);

static DATA: &'static str = r##"
7387  00:09:47.789648 wait4(-1,  <unfinished ...>
826   00:09:47.789757 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
7112  00:09:47.789777 epoll_wait(39<anon_inode:[eventpoll]>,  <unfinished ...>
1093  00:09:47.789807 restart_syscall(<... resuming interrupted nanosleep ...> <unfinished ...>
7111  00:09:47.789817 futex(0x7f5ef33fa77c, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>
922   00:09:47.789829 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
7113  00:09:47.789841 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 88, NULL <unfinished ...>
7110  00:09:47.789853 restart_syscall(<... resuming interrupted futex ...> <unfinished ...>
7113  00:09:47.789865 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000017>
7109  00:09:47.789878 futex(0x7f5ee1a30cac, FUTEX_WAIT_PRIVATE, 5, NULL <unfinished ...>
7113  00:09:47.789889 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 94, NULL <unfinished ...>
823   00:09:47.789901 select(26, [14<pipe:[3579145]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {24, 602754} <unfinished ...>
819   00:09:47.790185 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
817   00:09:47.790200 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {3, 852656} <unfinished ...>
2690  00:09:47.790412 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 3986, NULL <unfinished ...>
2688  00:09:47.790426 epoll_wait(38<anon_inode:[eventpoll]>,  <unfinished ...>
2690  00:09:47.790444 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
2690  00:09:47.790465 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 3990, NULL <unfinished ...>
2687  00:09:47.790477 futex(0x7f5ef33fa77c, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>
2686  00:09:47.790503 restart_syscall(<... resuming interrupted futex ...> <unfinished ...>
2685  00:09:47.790515 futex(0x7f5ee669bf2c, FUTEX_WAIT_PRIVATE, 7, NULL <unfinished ...>
815   00:09:47.790541 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
813   00:09:47.790553 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {24, 610462} <unfinished ...>
824   00:09:47.790763 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
568   00:09:47.790777 restart_syscall(<... resuming interrupted futex ...> <unfinished ...>
566   00:09:47.790847 restart_syscall(<... resuming interrupted futex ...> <unfinished ...>
495   00:09:47.790861 ppoll([{fd=10<pipe:[3577543]>, events=POLLIN}], 1, {32, 734575908}, NULL, 8 <unfinished ...>
477   00:09:47.790910 wait4(-1,  <unfinished ...>
475   00:09:47.790924 restart_syscall(<... resuming interrupted poll ...> <unfinished ...>
567   00:09:47.836504 open("/proc/self/fd", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 221</proc/495/fd> <0.000027>
567   00:09:47.836618 fstat(221</proc/495/fd>, {st_mode=S_IFDIR|0500, st_size=0, ...}) = 0 <0.000063>
567   00:09:47.836797 getdents(221</proc/495/fd>, /* 224 entries */, 32768) = 5376 <0.000143>
567   00:09:47.837002 lstat("/proc/self/fd/0", {st_mode=S_IFLNK|0500, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.837058 lstat("/proc/self/fd/1", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.837101 lstat("/proc/self/fd/2", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000024>
567   00:09:47.837149 lstat("/proc/self/fd/3", {st_mode=S_IFLNK|0500, st_size=64, ...}) = 0 <0.000013>
567   00:09:47.837184 lstat("/proc/self/fd/4", {st_mode=S_IFLNK|0500, st_size=64, ...}) = 0 <0.000013>
567   00:09:47.837260 lstat("/proc/self/fd/5", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.837315 lstat("/proc/self/fd/6", {st_mode=S_IFLNK|0500, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.837354 lstat("/proc/self/fd/7", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.837396 lstat("/proc/self/fd/8", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.837444 lstat("/proc/self/fd/9", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000025>
567   00:09:47.837498 lstat("/proc/self/fd/10", {st_mode=S_IFLNK|0500, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.837550 lstat("/proc/self/fd/11", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.837599 lstat("/proc/self/fd/12", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000028>
567   00:09:47.837655 lstat("/proc/self/fd/13", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.837710 lstat("/proc/self/fd/14", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.837752 lstat("/proc/self/fd/15", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.837802 lstat("/proc/self/fd/16", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.837849 lstat("/proc/self/fd/17", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000023>
567   00:09:47.837901 lstat("/proc/self/fd/18", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.837956 lstat("/proc/self/fd/19", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.837998 lstat("/proc/self/fd/20", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.838051 lstat("/proc/self/fd/21", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.838099 lstat("/proc/self/fd/22", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.838147 lstat("/proc/self/fd/23", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.838201 lstat("/proc/self/fd/24", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.838244 lstat("/proc/self/fd/25", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.838293 lstat("/proc/self/fd/26", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.838341 lstat("/proc/self/fd/27", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000023>
567   00:09:47.838393 lstat("/proc/self/fd/28", {st_mode=S_IFLNK|0300, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.838448 lstat("/proc/self/fd/29", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.838490 lstat("/proc/self/fd/30", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.838540 lstat("/proc/self/fd/31", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.838587 lstat("/proc/self/fd/32", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000039>
567   00:09:47.838655 lstat("/proc/self/fd/33", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.838708 lstat("/proc/self/fd/34", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.838748 lstat("/proc/self/fd/35", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.838792 lstat("/proc/self/fd/36", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.838835 lstat("/proc/self/fd/37", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000025>
567   00:09:47.838888 lstat("/proc/self/fd/38", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.838942 lstat("/proc/self/fd/39", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000019>
567   00:09:47.838992 lstat("/proc/self/fd/40", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.839041 lstat("/proc/self/fd/41", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.839081 lstat("/proc/self/fd/42", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000029>
567   00:09:47.839137 lstat("/proc/self/fd/43", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.839195 lstat("/proc/self/fd/44", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.839240 lstat("/proc/self/fd/45", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.839294 lstat("/proc/self/fd/46", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.839334 lstat("/proc/self/fd/47", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.839381 lstat("/proc/self/fd/48", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.839426 lstat("/proc/self/fd/49", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000029>
567   00:09:47.839481 lstat("/proc/self/fd/50", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.839521 lstat("/proc/self/fd/51", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.839574 lstat("/proc/self/fd/52", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.839624 lstat("/proc/self/fd/53", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.839672 lstat("/proc/self/fd/54", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000023>
567   00:09:47.839725 lstat("/proc/self/fd/55", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.839777 lstat("/proc/self/fd/56", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.839820 lstat("/proc/self/fd/57", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.839870 lstat("/proc/self/fd/58", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.839917 lstat("/proc/self/fd/59", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000023>
567   00:09:47.839969 lstat("/proc/self/fd/60", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.840024 lstat("/proc/self/fd/61", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.840066 lstat("/proc/self/fd/62", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.840116 lstat("/proc/self/fd/63", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.840163 lstat("/proc/self/fd/64", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000023>
567   00:09:47.840214 lstat("/proc/self/fd/65", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.840269 lstat("/proc/self/fd/66", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.840311 lstat("/proc/self/fd/67", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.840365 lstat("/proc/self/fd/68", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.840412 lstat("/proc/self/fd/69", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000023>
567   00:09:47.840462 lstat("/proc/self/fd/70", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.840517 lstat("/proc/self/fd/71", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.840559 lstat("/proc/self/fd/72", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.840612 lstat("/proc/self/fd/73", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.840659 lstat("/proc/self/fd/74", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.840709 lstat("/proc/self/fd/75", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.840763 lstat("/proc/self/fd/76", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.840805 lstat("/proc/self/fd/77", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000026>
567   00:09:47.840856 lstat("/proc/self/fd/78", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.840904 lstat("/proc/self/fd/79", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.840943 lstat("/proc/self/fd/80", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.840982 lstat("/proc/self/fd/81", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000016>
567   00:09:47.841025 lstat("/proc/self/fd/82", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.841071 lstat("/proc/self/fd/83", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841111 lstat("/proc/self/fd/84", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841149 lstat("/proc/self/fd/85", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841189 lstat("/proc/self/fd/86", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841238 lstat("/proc/self/fd/87", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.841288 lstat("/proc/self/fd/88", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.841333 lstat("/proc/self/fd/89", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.841378 lstat("/proc/self/fd/90", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.841423 lstat("/proc/self/fd/91", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.841468 lstat("/proc/self/fd/92", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.841513 lstat("/proc/self/fd/93", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.841558 lstat("/proc/self/fd/94", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.841614 lstat("/proc/self/fd/95", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000019>
567   00:09:47.841659 lstat("/proc/self/fd/96", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841698 lstat("/proc/self/fd/97", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841737 lstat("/proc/self/fd/98", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.841776 lstat("/proc/self/fd/99", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.841815 lstat("/proc/self/fd/100", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.841853 lstat("/proc/self/fd/101", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841892 lstat("/proc/self/fd/102", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841935 lstat("/proc/self/fd/103", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.841974 lstat("/proc/self/fd/104", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842013 lstat("/proc/self/fd/105", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842052 lstat("/proc/self/fd/106", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842091 lstat("/proc/self/fd/107", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.842129 lstat("/proc/self/fd/108", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842168 lstat("/proc/self/fd/109", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842207 lstat("/proc/self/fd/110", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000014>
567   00:09:47.842245 lstat("/proc/self/fd/111", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842284 lstat("/proc/self/fd/112", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.842331 lstat("/proc/self/fd/113", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.842381 lstat("/proc/self/fd/114", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.842431 lstat("/proc/self/fd/115", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842480 lstat("/proc/self/fd/116", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842530 lstat("/proc/self/fd/117", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.842579 lstat("/proc/self/fd/118", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842628 lstat("/proc/self/fd/119", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842678 lstat("/proc/self/fd/120", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.842727 lstat("/proc/self/fd/121", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842776 lstat("/proc/self/fd/122", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842830 lstat("/proc/self/fd/123", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.842881 lstat("/proc/self/fd/124", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842930 lstat("/proc/self/fd/125", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.842979 lstat("/proc/self/fd/126", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843032 lstat("/proc/self/fd/127", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.843082 lstat("/proc/self/fd/128", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843132 lstat("/proc/self/fd/129", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843182 lstat("/proc/self/fd/130", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843231 lstat("/proc/self/fd/131", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843281 lstat("/proc/self/fd/132", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843331 lstat("/proc/self/fd/133", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843380 lstat("/proc/self/fd/134", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.843429 lstat("/proc/self/fd/135", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843479 lstat("/proc/self/fd/136", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.843528 lstat("/proc/self/fd/137", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000029>
567   00:09:47.843582 lstat("/proc/self/fd/138", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.843620 lstat("/proc/self/fd/139", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000015>
567   00:09:47.843668 lstat("/proc/self/fd/140", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.843715 lstat("/proc/self/fd/141", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.843759 lstat("/proc/self/fd/142", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.843803 lstat("/proc/self/fd/143", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.843846 lstat("/proc/self/fd/144", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.843890 lstat("/proc/self/fd/145", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.843933 lstat("/proc/self/fd/146", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.843976 lstat("/proc/self/fd/147", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844019 lstat("/proc/self/fd/148", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844063 lstat("/proc/self/fd/149", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844106 lstat("/proc/self/fd/150", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844150 lstat("/proc/self/fd/151", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844194 lstat("/proc/self/fd/152", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844239 lstat("/proc/self/fd/153", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844283 lstat("/proc/self/fd/154", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844327 lstat("/proc/self/fd/155", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.844370 lstat("/proc/self/fd/156", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844414 lstat("/proc/self/fd/157", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.844459 lstat("/proc/self/fd/158", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844503 lstat("/proc/self/fd/159", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844547 lstat("/proc/self/fd/160", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.844591 lstat("/proc/self/fd/161", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844634 lstat("/proc/self/fd/162", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844678 lstat("/proc/self/fd/163", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844722 lstat("/proc/self/fd/164", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844766 lstat("/proc/self/fd/165", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844813 lstat("/proc/self/fd/166", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844857 lstat("/proc/self/fd/167", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844900 lstat("/proc/self/fd/168", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844943 lstat("/proc/self/fd/169", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.844987 lstat("/proc/self/fd/170", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845031 lstat("/proc/self/fd/171", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845075 lstat("/proc/self/fd/172", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.845119 lstat("/proc/self/fd/173", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845162 lstat("/proc/self/fd/174", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845213 lstat("/proc/self/fd/175", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845259 lstat("/proc/self/fd/176", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845304 lstat("/proc/self/fd/177", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.845348 lstat("/proc/self/fd/178", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.845396 lstat("/proc/self/fd/179", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845441 lstat("/proc/self/fd/180", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845485 lstat("/proc/self/fd/181", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.845530 lstat("/proc/self/fd/182", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845575 lstat("/proc/self/fd/183", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845620 lstat("/proc/self/fd/184", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845665 lstat("/proc/self/fd/185", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845709 lstat("/proc/self/fd/186", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.845754 lstat("/proc/self/fd/187", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845799 lstat("/proc/self/fd/188", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845843 lstat("/proc/self/fd/189", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.845888 lstat("/proc/self/fd/190", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845933 lstat("/proc/self/fd/191", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.845977 lstat("/proc/self/fd/192", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.846022 lstat("/proc/self/fd/193", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.846068 lstat("/proc/self/fd/194", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000018>
567   00:09:47.846113 lstat("/proc/self/fd/195", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.846158 lstat("/proc/self/fd/196", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.846203 lstat("/proc/self/fd/197", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000017>
567   00:09:47.846247 lstat("/proc/self/fd/198", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000028>
567   00:09:47.846308 lstat("/proc/self/fd/199", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846358 lstat("/proc/self/fd/200", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846408 lstat("/proc/self/fd/201", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.846457 lstat("/proc/self/fd/202", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.846506 lstat("/proc/self/fd/203", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846556 lstat("/proc/self/fd/204", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846608 lstat("/proc/self/fd/205", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846658 lstat("/proc/self/fd/206", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846709 lstat("/proc/self/fd/207", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846758 lstat("/proc/self/fd/208", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.846808 lstat("/proc/self/fd/209", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846857 lstat("/proc/self/fd/210", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.846906 lstat("/proc/self/fd/211", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.846956 lstat("/proc/self/fd/212", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.847005 lstat("/proc/self/fd/213", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.847056 lstat("/proc/self/fd/214", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.847105 lstat("/proc/self/fd/215", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.847154 lstat("/proc/self/fd/216", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.847203 lstat("/proc/self/fd/217", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.847253 lstat("/proc/self/fd/218", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000021>
567   00:09:47.847302 lstat("/proc/self/fd/219", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.847351 lstat("/proc/self/fd/220", {st_mode=S_IFLNK|0700, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.847400 lstat("/proc/self/fd/221", {st_mode=S_IFLNK|0500, st_size=64, ...}) = 0 <0.000020>
567   00:09:47.847449 getdents(221</proc/495/fd>, /* 0 entries */, 32768) = 0 <0.000016>
567   00:09:47.847500 close(221</proc/495/fd>) = 0 <0.000019>
567   00:09:47.847741 futex(0x7f5efe9dd8b4, FUTEX_WAIT_BITSET_PRIVATE, 67, {282562, 332181810}, ffffffff <unfinished ...>
477   00:09:47.913636 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7383 <0.122712>
477   00:09:47.913694 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
477   00:09:47.913745 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000012>
477   00:09:47.913781 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7383, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:47.913804 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000013>
477   00:09:47.913838 rt_sigreturn({mask=[]}) = 0 <0.000012>
477   00:09:47.913873 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000013>
477   00:09:47.913907 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:47.913988 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000020>
477   00:09:47.914047 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000012>
477   00:09:47.914085 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000013>
477   00:09:47.914125 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:47.914159 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:47.914198 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000013>
477   00:09:47.914237 close(3</dev/null>) = 0 <0.000012>
477   00:09:47.914271 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:47.914306 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000012>
477   00:09:47.914344 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:47.914378 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:47.914412 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000012>
477   00:09:47.914450 fcntl(1</dev/null>, F_GETFD) = 0 <0.000012>
477   00:09:47.914486 kill(495, SIG_0)  = 0 <0.000013>
477   00:09:47.914519 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000013>
477   00:09:47.914557 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000013>
477   00:09:47.914600 close(11<pipe:[3578440]>) = 0 <0.000012>
477   00:09:47.914634 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000014>
477   00:09:47.914673 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000013>
477   00:09:47.914707 close(10<pipe:[3578440]>) = 0 <0.000013>
477   00:09:47.914761 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000013>
477   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000134>
477   00:09:47.915036 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000009>
477   00:09:47.915111 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000007>
477   00:09:47.915147 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000008>
477   00:09:47.915173 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000007>
477   00:09:47.915207 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000008>
477   00:09:47.915236 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7390  00:09:47.915252 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:47.915277 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000032>
7390  00:09:47.915315 <... close resumed> ) = 0 <0.000045>
477   00:09:47.915328 wait4(-1,  <unfinished ...>
7390  00:09:47.915342 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000012>
7390  00:09:47.915376 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_DFL, [], 0}, 8) = 0 <0.000017>
7390  00:09:47.915417 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_DFL, [], 0}, 8) = 0 <0.000013>
7390  00:09:47.915450 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_DFL, [], 0}, 8) = 0 <0.000022>
7390  00:09:47.915501 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7390  00:09:47.915540 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7390  00:09:47.915603 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7390  00:09:47.915644 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7390  00:09:47.915683 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7390  00:09:47.915719 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000011>
7390  00:09:47.915756 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7390  00:09:47.915791 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7390  00:09:47.915839 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7390  00:09:47.915875 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000016>
7390  00:09:47.915950 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000186>
7390  00:09:47.916193 brk(NULL)         = 0x666000 <0.000011>
7390  00:09:47.916254 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7390  00:09:47.916308 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000013>
7390  00:09:47.916347 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000022>
7390  00:09:47.916402 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000013>
7390  00:09:47.916439 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f68bf86d000 <0.000065>
7390  00:09:47.916549 close(3</etc/ld.so.cache>) = 0 <0.000013>
7390  00:09:47.916600 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000013>
7390  00:09:47.916638 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000016>
7390  00:09:47.916678 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000022>
7390  00:09:47.916732 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000012>
7390  00:09:47.916781 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f68bf86c000 <0.000014>
7390  00:09:47.916821 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f68bf281000 <0.000014>
7390  00:09:47.916868 mprotect(0x7f68bf441000, 2097152, PROT_NONE) = 0 <0.000019>
7390  00:09:47.916908 mmap(0x7f68bf641000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f68bf641000 <0.000026>
7390  00:09:47.916963 mmap(0x7f68bf647000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f68bf647000 <0.000015>
7390  00:09:47.917004 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000022>
7390  00:09:47.917060 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f68bf86b000 <0.000013>
7390  00:09:47.917097 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f68bf86a000 <0.000012>
7390  00:09:47.917133 arch_prctl(ARCH_SET_FS, 0x7f68bf86b700) = 0 <0.000013>
7390  00:09:47.917234 mprotect(0x7f68bf641000, 16384, PROT_READ) = 0 <0.000025>
7390  00:09:47.917285 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000015>
7390  00:09:47.917320 mprotect(0x7f68bf870000, 4096, PROT_READ) = 0 <0.000019>
7390  00:09:47.917357 munmap(0x7f68bf86d000, 10600) = 0 <0.000017>
7390  00:09:47.917480 brk(NULL)         = 0x666000 <0.000019>
7390  00:09:47.917522 brk(0x687000)     = 0x687000 <0.000013>
7390  00:09:47.917576 nanosleep({1, 0},  <unfinished ...>
1093  00:09:47.959607 <... restart_syscall resumed> ) = 0 <0.169794>
1093  00:09:47.959638 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000014>
1093  00:09:47.959686 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:47.959727 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54110, ...}) = 0 <0.000009>
1093  00:09:47.959762 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000009>
1093  00:09:47.959794 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000012>
1093  00:09:47.959829 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000013>
1093  00:09:47.959865 open("/var/log/gitlab/gitlab-rails/api_json.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/api_json.log> <0.000020>
1093  00:09:47.959910 fstat(33</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000013>
1093  00:09:47.959944 close(33</var/log/gitlab/gitlab-rails/api_json.log>) = 0 <0.000013>
1093  00:09:47.959978 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000013>
1093  00:09:47.960014 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000009>
1093  00:09:47.960045 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:47.960082 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000008>
1093  00:09:47.960113 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000013>
1093  00:09:47.960149 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000012>
1093  00:09:47.960184 open("/var/log/gitlab/alertmanager/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/alertmanager/current> <0.000016>
1093  00:09:47.960218 fstat(33</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000008>
1093  00:09:47.960247 close(33</var/log/gitlab/alertmanager/current>) = 0 <0.000016>
1093  00:09:47.960283 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000009>
1093  00:09:47.960318 read(15</var/log/gitlab/registry/current>, "2018-09-25_00:09:47.36101 time=\"2018-09-25T00:09:47.360956532Z\" level=debug msg=\"s3aws.Stat(\\\"/\\\")\" environment=production go.version=go1.10.3 instance.id=e8df01bb-477a-4ea2-9667-91aa4b6682d9 service=registry trace.duration=51.736506ms trace.file=\"/var/cache/omnibus/src/registry/src/github.com/docker/distribution/registry/storage/driver/base/base.go\" trace.func=\"github.com/docker/distribution/registry/storage/driver/base.(*Base).Stat\" trace.id=a5309f00-ee38-4671-a538-ae5f78604c1f trace.line=137 version=v2.6.2-2-g91c17ef \n", 8192) = 527 <0.000024>
1093  00:09:47.960368 read(15</var/log/gitlab/registry/current>, "", 8192) = 0 <0.000010>
1093  00:09:47.960402 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000009>
1093  00:09:47.960437 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000009>
1093  00:09:47.960473 open("/var/log/gitlab/gitlab-shell/gitlab-shell.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-shell/gitlab-shell.log> <0.000015>
1093  00:09:47.960508 fstat(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000009>
1093  00:09:47.960542 close(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>) = 0 <0.000009>
1093  00:09:47.960574 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:47.960610 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:47.960645 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960680 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000010>
1093  00:09:47.960715 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960750 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960786 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960820 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960856 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960891 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.960926 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:47.960966 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.961001 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000011>
1093  00:09:47.961042 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:47.961077 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:47.961112 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000009>
1093  00:09:47.961146 open("/var/log/gitlab/gitaly/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitaly/current> <0.000015>
1093  00:09:47.961181 fstat(33</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000010>
1093  00:09:47.961216 close(33</var/log/gitlab/gitaly/current>) = 0 <0.000010>
1093  00:09:47.961248 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:47.961282 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54110, ...}) = 0 <0.000009>
1093  00:09:47.961316 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000009>
1093  00:09:47.961350 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000010>
1093  00:09:47.961384 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000010>
1093  00:09:47.961418 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000009>
1093  00:09:47.961452 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000010>
1093  00:09:47.961486 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:47.961521 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:47.961555 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000010>
1093  00:09:47.961589 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:47.961623 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000010>
1093  00:09:47.961657 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000010>
1093  00:09:47.961691 open("/var/log/gitlab/gitlab-workhorse/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-workhorse/current> <0.000014>
1093  00:09:47.961726 fstat(33</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000010>
1093  00:09:47.961759 close(33</var/log/gitlab/gitlab-workhorse/current>) = 0 <0.000009>
1093  00:09:47.961792 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000010>
1093  00:09:47.961825 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.961858 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.961892 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:47.961926 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000010>
1093  00:09:47.961960 open("/var/log/gitlab/nginx/gitlab_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_access.log> <0.000015>
1093  00:09:47.961995 fstat(33</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000009>
1093  00:09:47.962029 close(33</var/log/gitlab/nginx/gitlab_access.log>) = 0 <0.000010>
1093  00:09:47.962061 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:47.962095 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962129 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962163 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962197 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962231 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962265 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962299 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:47.962333 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000010>
1093  00:09:47.962367 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:47.962401 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:47.962435 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/registry/current <==\n2018-09-25_00:09:47.36101 time=\"2018-09-25T00:09:47.360956532Z\" level=debug msg=\"s3aws.Stat(\\\"/\\\")\" environment=production go.version=go1.10.3 instance.id=e8df01bb-477a-4ea2-9667-91aa4b6682d9 service=registry trace.duration=51.736506ms trace.file=\"/var/cache/omnibus/src/registry/src/github.com/docker/distribution/registry/storage/driver/base/base.go\" trace.func=\"github.com/docker/distribution/registry/storage/driver/base.(*Base).Stat\" trace.id=a5309f00-ee38-4671-a538-ae5f78604c1f trace.line=137 version=v2.6.2-2-g91c17ef \n", 569) = 569 <0.000058>
1093  00:09:47.962595 nanosleep({1, 0},  <unfinished ...>
7110  00:09:48.111957 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.322095>
7110  00:09:48.112006 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000012>
7110  00:09:48.112041 clock_gettime(CLOCK_MONOTONIC, {282494, 196521136}) = 0 <0.000029>
7110  00:09:48.112101 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 96, {282495, 197328885}, ffffffff <unfinished ...>
566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.354208>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000016>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <0.000024>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <0.000015>
566   00:09:48.145327 sendmsg(221<NETLINK:[3604353]>, {msg_name(12)={sa_family=AF_NETLINK, pid=0, groups=00000000}, msg_iov(3)=[{"\334\0\0\0\22\0\1\3\303\0\0\0\357\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\2\4\0\0\0\0\0\0", 76}, {"\220\0\1\0", 4}, {"\7\214\220\0\2 \1\1\220\37\0\0\177\0\0\1\3401\344\23_\177\0\0\0\311\275\7\324\367z\314\1\0\0\0\0\0\0\0\211\274X\23_\177\0\0\3\0\0\0\0\0\0\0\270\274L\17_\177\0\0\260\233X\23_\177\0\0\1\0\0\0\0\0\0\0 \376\35\22\1\0\0\0\3006\344\23_\177\0\0@\201\17\344^\177\0\0\331\274\vt\36wxJ\30{\r\344^\177\0\0@\201\17\344^\177\0\0\370w\210\0_\177\0\0h-]\23", 140}], msg_controllen=0, msg_flags=0}, 0) = 220 <0.000215>
566   00:09:48.145595 recvmsg(221<NETLINK:[3604353]>, {msg_name(12)={sa_family=AF_NETLINK, pid=0, groups=00000000}, msg_iov(1)=[{"`\0\0\0\22\0\2\0\303\0\0\0F\247u\276\2\n\0\0\37\220\0\0\177\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\4\0\0\346\3\0\0\265\2336\0\5\0\10\0\0\0\0\0", 4096}], msg_controllen=0, msg_flags=0}, 0) = 96 <0.000018>
566   00:09:48.145657 recvmsg(221<NETLINK:[3604353]>, {msg_name(12)={sa_family=AF_NETLINK, pid=0, groups=00000000}, msg_iov(1)=[{"\24\0\0\0\3\0\2\0\303\0\0\0F\247u\276\0\0\0\0", 4096}], msg_controllen=0, msg_flags=0}, 0) = 20 <0.000014>
566   00:09:48.145797 lstat("/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket", {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <0.000021>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <0.000032>
566   00:09:48.145996 ioctl(222</proc/495/net/unix>, TCGETS, 0x7f5f13e44050) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
566   00:09:48.146032 fstat(222</proc/495/net/unix>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000010>
566   00:09:48.146066 lseek(222</proc/495/net/unix>, 0, SEEK_CUR) = 0 <0.000013>
566   00:09:48.146104 read(222</proc/495/net/unix>, "Num       RefCount Protocol Flags    Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 3579347 /var/opt/gitlab/gitlab-workhorse/socket\n0000000000000000: 00000002 00000000 00010000 0001 01 3578806 /var/opt/gitlab/gitlab-rails/sockets/gitlab.socket\n0000000000000000: 00000002 00000000 00010000 0001 01 3579521 /tmp/gitaly-ruby945344659/socket.0\n0000000000000000: 00000002 00000000 00010000 0001 01 3579393 /var/opt/gitlab/gitaly/gitaly.socket\n0000000000000000: 00000002 00000000 00010000 0001 01 3579524 /tmp/gitaly-ruby945344659/socket.1\n0000000000000000: 00000003 00000000 00000000 0001 03 3585351\n0000000000000000: 00000003 00000000 00000000 0001 03 3603813\n0000000000000000: 00000003 00000000 00000000 0001 03 3584822 /tmp/gitaly-ruby945344659/socket.1\n0000000000000000: 00000003 00000000 00000000 0001 03 3603201 /var/opt/gitlab/gitaly/gitaly.socket\n0000000000000000: 00000003 00000000 00000000 0001 03 3586321 /var/opt/gitlab/gitaly/gitaly.socket\n0000000000000000: 00000003 00000000 00000000 0001 0"..., 8192) = 1559 <0.000046>
566   00:09:48.146178 read(222</proc/495/net/unix>, "", 6633) = 0 <0.000010>
566   00:09:48.146213 close(222</proc/495/net/unix>) = 0 <0.000014>
566   00:09:48.146344 futex(0x7f5efea4bcb4, FUTEX_WAIT_BITSET_PRIVATE, 391, {282508, 730790992}, ffffffff <unfinished ...>
2686  00:09:48.183457 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.392947>
2686  00:09:48.183496 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000016>
2686  00:09:48.183539 clock_gettime(CLOCK_MONOTONIC, {282494, 268006995}) = 0 <0.000014>
2686  00:09:48.183585 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 3992, {282495, 268834003}, ffffffff <unfinished ...>
7390  00:09:48.917683 <... nanosleep resumed> NULL) = 0 <1.000090>
7390  00:09:48.917759 close(1<pipe:[3578440]>) = 0 <0.000018>
7390  00:09:48.917824 close(2<pipe:[3578440]>) = 0 <0.000016>
7390  00:09:48.917874 exit_group(0)     = ?
7390  00:09:48.917985 +++ exited with 0 +++
477   00:09:48.918023 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7390 <1.002689>
477   00:09:48.918057 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
477   00:09:48.918106 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:48.918141 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7390, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:48.918173 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000012>
477   00:09:48.918207 rt_sigreturn({mask=[]}) = 0 <0.000013>
477   00:09:48.918243 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000013>
477   00:09:48.918277 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000012>
477   00:09:48.918354 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000020>
477   00:09:48.918407 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:48.918444 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000013>
477   00:09:48.918482 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000012>
477   00:09:48.918516 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:48.918555 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000013>
477   00:09:48.918595 close(3</dev/null>) = 0 <0.000013>
477   00:09:48.918628 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000012>
477   00:09:48.918663 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000013>
477   00:09:48.918700 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:48.918735 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:48.918769 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000013>
477   00:09:48.918807 fcntl(1</dev/null>, F_GETFD) = 0 <0.000013>
477   00:09:48.918842 kill(495, SIG_0)  = 0 <0.000013>
477   00:09:48.918876 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000013>
477   00:09:48.918914 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000012>
477   00:09:48.918949 close(11<pipe:[3578440]>) = 0 <0.000012>
477   00:09:48.918983 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000013>
477   00:09:48.919022 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000013>
477   00:09:48.919056 close(10<pipe:[3578440]>) = 0 <0.000013>
477   00:09:48.919110 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000013>
477   00:09:48.919145 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7393 <0.000287>
7393  00:09:48.919453 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:48.919592 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7393  00:09:48.919610 <... close resumed> ) = 0 <0.000029>
477   00:09:48.919622 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000019>
7393  00:09:48.919655 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
477   00:09:48.919670 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7393  00:09:48.919683 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
477   00:09:48.919695 <... rt_sigprocmask resumed> [], 8) = 0 <0.000018>
7393  00:09:48.919707 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:48.919731 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7393  00:09:48.919745 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000018>
477   00:09:48.919758 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7393  00:09:48.919769 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:48.919782 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7393  00:09:48.919794 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000018>
477   00:09:48.919807 <... rt_sigprocmask resumed> [], 8) = 0 <0.000019>
7393  00:09:48.919823 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:48.919836 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7393  00:09:48.919848 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000019>
477   00:09:48.919861 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7393  00:09:48.919875 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:48.919890 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7393  00:09:48.919910 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000028>
477   00:09:48.919924 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000021>
7393  00:09:48.919938 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:48.919951 wait4(-1,  <unfinished ...>
7393  00:09:48.919962 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7393  00:09:48.919987 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7393  00:09:48.920021 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7393  00:09:48.920069 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7393  00:09:48.920106 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7393  00:09:48.920151 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7393  00:09:48.920189 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7393  00:09:48.920229 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7393  00:09:48.920264 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000012>
7393  00:09:48.920344 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000194>
7393  00:09:48.920594 brk(NULL)         = 0x23ed000 <0.000015>
7393  00:09:48.920652 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7393  00:09:48.920694 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000015>
7393  00:09:48.920736 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000015>
7393  00:09:48.920787 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000013>
7393  00:09:48.920828 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f9af3323000 <0.000014>
7393  00:09:48.920876 close(3</etc/ld.so.cache>) = 0 <0.000011>
7393  00:09:48.920912 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000013>
7393  00:09:48.920955 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000015>
7393  00:09:48.920992 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000013>
7393  00:09:48.921053 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000009>
7393  00:09:48.921089 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f9af3322000 <0.000023>
7393  00:09:48.921137 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f9af2d37000 <0.000015>
7393  00:09:48.921175 mprotect(0x7f9af2ef7000, 2097152, PROT_NONE) = 0 <0.000016>
7393  00:09:48.921220 mmap(0x7f9af30f7000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f9af30f7000 <0.000057>
7393  00:09:48.921307 mmap(0x7f9af30fd000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f9af30fd000 <0.000024>
7393  00:09:48.921362 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000010>
7393  00:09:48.921414 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f9af3321000 <0.000014>
7393  00:09:48.921452 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f9af3320000 <0.000012>
7393  00:09:48.921487 arch_prctl(ARCH_SET_FS, 0x7f9af3321700) = 0 <0.000011>
7393  00:09:48.921585 mprotect(0x7f9af30f7000, 16384, PROT_READ) = 0 <0.000016>
7393  00:09:48.921624 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000023>
7393  00:09:48.921672 mprotect(0x7f9af3326000, 4096, PROT_READ) = 0 <0.000015>
7393  00:09:48.921705 munmap(0x7f9af3323000, 10600) = 0 <0.000022>
7393  00:09:48.921837 brk(NULL)         = 0x23ed000 <0.000014>
7393  00:09:48.921871 brk(0x240e000)    = 0x240e000 <0.000020>
7393  00:09:48.921932 nanosleep({1, 0},  <unfinished ...>
1093  00:09:48.962686 <... nanosleep resumed> NULL) = 0 <1.000080>
1093  00:09:48.962719 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000017>
1093  00:09:48.962773 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000016>
1093  00:09:48.962817 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54251, ...}) = 0 <0.000016>
1093  00:09:48.962863 read(5</var/log/gitlab/gitlab-monitor/current>, "2018-09-25_00:09:48.11473 127.0.0.1 - - [25/Sep/2018:00:09:48 UTC] \"GET /database HTTP/1.1\" 200 679\n2018-09-25_00:09:48.11480 - -> /database\n", 8192) = 141 <0.000029>
1093  00:09:48.962922 read(5</var/log/gitlab/gitlab-monitor/current>, "", 8192) = 0 <0.000018>
1093  00:09:48.962969 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000019>
1093  00:09:48.963017 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000019>
1093  00:09:48.963066 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000018>
1093  00:09:48.963114 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000019>
1093  00:09:48.963163 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000018>
1093  00:09:48.963211 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000019>
1093  00:09:48.963261 open("/var/log/gitlab/gitlab-rails/sidekiq.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sidekiq/current> <0.000024>
1093  00:09:48.963317 fstat(33</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000018>
1093  00:09:48.963365 close(33</var/log/gitlab/sidekiq/current>) = 0 <0.000018>
1093  00:09:48.963415 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000014>
1093  00:09:48.963454 open("/var/log/gitlab/sidekiq/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sidekiq/current> <0.000014>
1093  00:09:48.963493 fstat(33</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000014>
1093  00:09:48.963531 close(33</var/log/gitlab/sidekiq/current>) = 0 <0.000022>
1093  00:09:48.963577 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000014>
1093  00:09:48.963616 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000014>
1093  00:09:48.963655 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000013>
1093  00:09:48.963693 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000014>
1093  00:09:48.963732 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000014>
1093  00:09:48.963770 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.963808 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.963846 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.963884 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000013>
1093  00:09:48.963921 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.963959 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.963997 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.964035 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.964072 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.964110 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.964148 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.964187 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.964225 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000014>
1093  00:09:48.964263 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000014>
1093  00:09:48.964301 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000013>
1093  00:09:48.964339 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000013>
1093  00:09:48.964376 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.964414 open("/var/log/gitlab/logrotate/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/logrotate/current> <0.000014>
1093  00:09:48.964452 fstat(33</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.964489 close(33</var/log/gitlab/logrotate/current>) = 0 <0.000014>
1093  00:09:48.964525 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54251, ...}) = 0 <0.000014>
1093  00:09:48.964562 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000013>
1093  00:09:48.964599 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000013>
1093  00:09:48.964637 open("/var/log/gitlab/gitlab-rails/grpc.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/grpc.log> <0.000015>
1093  00:09:48.964678 fstat(33</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000014>
1093  00:09:48.964716 close(33</var/log/gitlab/gitlab-rails/grpc.log>) = 0 <0.000014>
1093  00:09:48.964752 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000014>
1093  00:09:48.964789 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000013>
1093  00:09:48.964827 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000014>
1093  00:09:48.964864 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000014>
1093  00:09:48.964901 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:48.964938 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000013>
1093  00:09:48.964975 open("/var/log/gitlab/prometheus/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/prometheus/current> <0.000014>
1093  00:09:48.965014 fstat(33</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000014>
1093  00:09:48.965051 close(33</var/log/gitlab/prometheus/current>) = 0 <0.000013>
1093  00:09:48.965086 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000013>
1093  00:09:48.965123 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000013>
1093  00:09:48.965160 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000014>
1093  00:09:48.965204 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000014>
1093  00:09:48.965243 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965281 open("/var/log/gitlab/nginx/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/current> <0.000014>
1093  00:09:48.965320 fstat(33</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965358 close(33</var/log/gitlab/nginx/current>) = 0 <0.000014>
1093  00:09:48.965394 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965431 open("/var/log/gitlab/nginx/access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/access.log> <0.000014>
1093  00:09:48.965470 fstat(33</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965508 close(33</var/log/gitlab/nginx/access.log>) = 0 <0.000014>
1093  00:09:48.965544 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000015>
1093  00:09:48.965582 open("/var/log/gitlab/nginx/error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/error.log> <0.000014>
1093  00:09:48.965621 fstat(33</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965659 close(33</var/log/gitlab/nginx/error.log>) = 0 <0.000014>
1093  00:09:48.965695 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000014>
1093  00:09:48.965733 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965772 open("/var/log/gitlab/nginx/gitlab_pages_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_pages_error.log> <0.000014>
1093  00:09:48.965810 fstat(33</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965848 close(33</var/log/gitlab/nginx/gitlab_pages_error.log>) = 0 <0.000014>
1093  00:09:48.965885 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.965922 open("/var/log/gitlab/nginx/gitlab_registry_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_registry_error.log> <0.000014>
1093  00:09:48.965964 fstat(33</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966002 close(33</var/log/gitlab/nginx/gitlab_registry_error.log>) = 0 <0.000014>
1093  00:09:48.966038 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966076 open("/var/log/gitlab/nginx/gitlab_pages_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_pages_access.log> <0.000014>
1093  00:09:48.966115 fstat(33</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.966153 close(33</var/log/gitlab/nginx/gitlab_pages_access.log>) = 0 <0.000014>
1093  00:09:48.966189 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966227 open("/var/log/gitlab/nginx/gitlab_registry_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_registry_access.log> <0.000014>
1093  00:09:48.966266 fstat(33</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966304 close(33</var/log/gitlab/nginx/gitlab_registry_access.log>) = 0 <0.000014>
1093  00:09:48.966340 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966378 open("/var/log/gitlab/nginx/gitlab_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_error.log> <0.000014>
1093  00:09:48.966416 fstat(33</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966454 close(33</var/log/gitlab/nginx/gitlab_error.log>) = 0 <0.000014>
1093  00:09:48.966490 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966528 open("/var/log/gitlab/gitlab-pages/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-pages/current> <0.000015>
1093  00:09:48.966567 fstat(33</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:48.966605 close(33</var/log/gitlab/gitlab-pages/current>) = 0 <0.000014>
1093  00:09:48.966641 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966679 open("/var/log/gitlab/node-exporter/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/node-exporter/current> <0.000014>
1093  00:09:48.966717 fstat(33</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966755 close(33</var/log/gitlab/node-exporter/current>) = 0 <0.000014>
1093  00:09:48.966792 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966830 open("/var/log/gitlab/unicorn/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/current> <0.000014>
1093  00:09:48.966868 fstat(33</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:48.966906 close(33</var/log/gitlab/unicorn/current>) = 0 <0.000014>
1093  00:09:48.966942 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000014>
1093  00:09:48.966980 open("/var/log/gitlab/unicorn/unicorn_stderr.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/unicorn_stderr.log> <0.000015>
1093  00:09:48.967019 fstat(33</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000014>
1093  00:09:48.967057 close(33</var/log/gitlab/unicorn/unicorn_stderr.log>) = 0 <0.000014>
1093  00:09:48.967094 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000014>
1093  00:09:48.967132 open("/var/log/gitlab/unicorn/unicorn_stdout.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/unicorn_stdout.log> <0.000015>
1093  00:09:48.967173 fstat(33</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000014>
1093  00:09:48.967211 close(33</var/log/gitlab/unicorn/unicorn_stdout.log>) = 0 <0.000014>
1093  00:09:48.967247 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000014>
1093  00:09:48.967285 open("/var/log/gitlab/sshd/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sshd/current> <0.000014>
1093  00:09:48.967324 fstat(33</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000014>
1093  00:09:48.967362 close(33</var/log/gitlab/sshd/current>) = 0 <0.000014>
1093  00:09:48.967398 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/gitlab-monitor/current <==\n2018-09-25_00:09:48.11473 127.0.0.1 - - [25/Sep/2018:00:09:48 UTC] \"GET /database HTTP/1.1\" 200 679\n2018-09-25_00:09:48.11480 - -> /database\n", 189) = 189 <0.000072>
1093  00:09:48.967541 nanosleep({1, 0},  <unfinished ...>
7110  00:09:49.112963 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000850>
7110  00:09:49.113018 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000014>
7110  00:09:49.113058 clock_gettime(CLOCK_MONOTONIC, {282495, 197524750}) = 0 <0.000013>
7110  00:09:49.113104 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 98, {282496, 167328885}, ffffffff <unfinished ...>
2686  00:09:49.184466 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000871>
2686  00:09:49.184521 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000014>
2686  00:09:49.184561 clock_gettime(CLOCK_MONOTONIC, {282495, 269027735}) = 0 <0.000014>
2686  00:09:49.184608 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 3994, {282496, 269834003}, ffffffff <unfinished ...>
7393  00:09:49.922033 <... nanosleep resumed> NULL) = 0 <1.000088>
7393  00:09:49.922104 close(1<pipe:[3578440]>) = 0 <0.000014>
7393  00:09:49.922156 close(2<pipe:[3578440]>) = 0 <0.000012>
7393  00:09:49.922195 exit_group(0)     = ?
7393  00:09:49.922295 +++ exited with 0 +++
477   00:09:49.922331 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7393 <1.002374>
477   00:09:49.922361 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
477   00:09:49.922410 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:49.922445 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7393, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:49.922467 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000012>
477   00:09:49.922502 rt_sigreturn({mask=[]}) = 0 <0.000013>
477   00:09:49.922537 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000012>
477   00:09:49.922571 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:49.922648 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000019>
477   00:09:49.922700 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000012>
477   00:09:49.922736 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000013>
477   00:09:49.922774 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:49.922808 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:49.922847 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000012>
477   00:09:49.922886 close(3</dev/null>) = 0 <0.000012>
477   00:09:49.922919 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:49.922953 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000013>
477   00:09:49.922990 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:49.923025 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:49.923059 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000013>
477   00:09:49.923097 fcntl(1</dev/null>, F_GETFD) = 0 <0.000013>
477   00:09:49.923132 kill(495, SIG_0)  = 0 <0.000013>
477   00:09:49.923165 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000012>
477   00:09:49.923204 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000013>
477   00:09:49.923248 close(11<pipe:[3578440]>) = 0 <0.000013>
477   00:09:49.923282 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000013>
477   00:09:49.923321 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000012>
477   00:09:49.923355 close(10<pipe:[3578440]>) = 0 <0.000013>
477   00:09:49.923408 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000013>
477   00:09:49.923444 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7395 <0.000144>
477   00:09:49.923658 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7395  00:09:49.923848 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:49.923879 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000042>
7395  00:09:49.923891 <... close resumed> ) = 0 <0.000022>
477   00:09:49.923931 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7395  00:09:49.923946 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
477   00:09:49.923960 <... rt_sigprocmask resumed> [], 8) = 0 <0.000021>
7395  00:09:49.923972 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000019>
477   00:09:49.924001 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7395  00:09:49.924015 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:49.924029 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000021>
7395  00:09:49.924041 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000018>
477   00:09:49.924054 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7395  00:09:49.924383 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:49.924406 <... rt_sigprocmask resumed> [], 8) = 0 <0.000033>
7395  00:09:49.924419 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000023>
477   00:09:49.924433 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7395  00:09:49.924446 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:49.924459 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7395  00:09:49.924474 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000021>
477   00:09:49.924488 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7395  00:09:49.924502 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:49.924515 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7395  00:09:49.924527 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
477   00:09:49.924541 wait4(-1,  <unfinished ...>
7395  00:09:49.924568 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7395  00:09:49.924604 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7395  00:09:49.924648 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7395  00:09:49.924686 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7395  00:09:49.924730 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7395  00:09:49.924766 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7395  00:09:49.924814 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7395  00:09:49.924852 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7395  00:09:49.924899 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000012>
7395  00:09:49.924985 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000167>
7395  00:09:49.925219 brk(NULL)         = 0xe01000 <0.000014>
7395  00:09:49.925269 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000013>
7395  00:09:49.925321 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000013>
7395  00:09:49.925358 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000015>
7395  00:09:49.925402 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000010>
7395  00:09:49.925437 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f6519c36000 <0.000014>
7395  00:09:49.925477 close(3</etc/ld.so.cache>) = 0 <0.000010>
7395  00:09:49.925511 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000022>
7395  00:09:49.925557 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000015>
7395  00:09:49.925594 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000014>
7395  00:09:49.925649 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000009>
7395  00:09:49.925686 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6519c35000 <0.000014>
7395  00:09:49.925728 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f651964a000 <0.000015>
7395  00:09:49.925767 mprotect(0x7f651980a000, 2097152, PROT_NONE) = 0 <0.000017>
7395  00:09:49.925804 mmap(0x7f6519a0a000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f6519a0a000 <0.000016>
7395  00:09:49.925852 mmap(0x7f6519a10000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f6519a10000 <0.000015>
7395  00:09:49.925895 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000010>
7395  00:09:49.925948 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6519c34000 <0.000013>
7395  00:09:49.925986 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6519c33000 <0.000021>
7395  00:09:49.926032 arch_prctl(ARCH_SET_FS, 0x7f6519c34700) = 0 <0.000012>
7395  00:09:49.926123 mprotect(0x7f6519a0a000, 16384, PROT_READ) = 0 <0.000016>
7395  00:09:49.926176 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000014>
7395  00:09:49.926214 mprotect(0x7f6519c39000, 4096, PROT_READ) = 0 <0.000014>
7395  00:09:49.926249 munmap(0x7f6519c36000, 10600) = 0 <0.000015>
7395  00:09:49.926392 brk(NULL)         = 0xe01000 <0.000054>
7395  00:09:49.926470 brk(0xe22000)     = 0xe22000 <0.000020>
7395  00:09:49.926534 nanosleep({1, 0},  <unfinished ...>
1093  00:09:49.967658 <... nanosleep resumed> NULL) = 0 <1.000079>
1093  00:09:49.967685 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000014>
1093  00:09:49.967732 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:49.967764 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54251, ...}) = 0 <0.000013>
1093  00:09:49.967799 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000013>
1093  00:09:49.967834 open("/var/log/gitlab/gitlab-rails/sidekiq_exporter.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/sidekiq_exporter.log> <0.000019>
1093  00:09:49.967880 fstat(33</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000009>
1093  00:09:49.967910 close(33</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>) = 0 <0.000013>
1093  00:09:49.967943 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000012>
1093  00:09:49.967978 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000009>
1093  00:09:49.968009 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000008>
1093  00:09:49.968039 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000012>
1093  00:09:49.968074 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:49.968104 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:49.968134 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000012>
1093  00:09:49.968169 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000009>
1093  00:09:49.968199 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000008>
1093  00:09:49.968230 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000009>
1093  00:09:49.968260 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000008>
1093  00:09:49.968290 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:49.968320 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:49.968355 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:49.968385 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000009>
1093  00:09:49.968415 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:49.968449 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:49.968490 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:49.968525 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:49.968555 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:49.968585 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:49.968618 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:49.968649 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:49.968680 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000009>
1093  00:09:49.968710 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000013>
1093  00:09:49.968744 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000012>
1093  00:09:49.968779 nanosleep({1, 0},  <unfinished ...>
7110  00:09:50.082963 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.969847>
7110  00:09:50.083019 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000017>
7110  00:09:50.083063 clock_gettime(CLOCK_MONOTONIC, {282496, 167530773}) = 0 <0.000016>
7110  00:09:50.083114 futex(0x7f5ef33fb464, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7f5ef33fb460, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1} <unfinished ...>
7113  00:09:50.083155 <... futex resumed> ) = 0 <2.293260>
7110  00:09:50.083168 <... futex resumed> ) = 1 <0.000049>
7113  00:09:50.083179 futex(0x7f5ef33fb4a0, FUTEX_WAIT_PRIVATE, 2, NULL <unfinished ...>
7110  00:09:50.083192 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
7113  00:09:50.083205 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
7110  00:09:50.083219 <... futex resumed> ) = 0 <0.000020>
7113  00:09:50.083231 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
7110  00:09:50.083242 epoll_wait(33<anon_inode:[eventpoll]>,  <unfinished ...>
7113  00:09:50.083274 <... futex resumed> ) = 0 <0.000037>
7110  00:09:50.083288 <... epoll_wait resumed> [], 100, 0) = 0 <0.000019>
7113  00:09:50.083301 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
7110  00:09:50.083311 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
7113  00:09:50.083321 <... clock_gettime resumed> {282496, 167770318}) = 0 <0.000014>
7110  00:09:50.083336 <... clock_gettime resumed> {282496, 167779147}) = 0 <0.000019>
7113  00:09:50.083348 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 101, {282496, 198328885}, ffffffff <unfinished ...>
7110  00:09:50.083363 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 102, NULL <unfinished ...>
7113  00:09:50.083376 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
7113  00:09:50.083401 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 102, {282496, 198328885}, ffffffff) = -1 ETIMEDOUT (Connection timed out) <0.030539>
7113  00:09:50.113989 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000013>
7113  00:09:50.114029 clock_gettime(CLOCK_MONOTONIC, {282496, 198494103}) = 0 <0.000012>
7113  00:09:50.114070 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 104, {282497, 199328885}, ffffffff <unfinished ...>
2686  00:09:50.185470 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000852>
2686  00:09:50.185526 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000022>
2686  00:09:50.185578 clock_gettime(CLOCK_MONOTONIC, {282496, 270048254}) = 0 <0.000021>
2686  00:09:50.185639 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 3996, {282496, 841834003}, ffffffff) = -1 ETIMEDOUT (Connection timed out) <0.571821>
2686  00:09:50.757526 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000019>
2686  00:09:50.757590 clock_gettime(CLOCK_MONOTONIC, {282496, 842059573}) = 0 <0.000018>
2686  00:09:50.757648 futex(0x7f5ef33fb464, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7f5ef33fb460, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1} <unfinished ...>
2690  00:09:50.757680 <... futex resumed> ) = 0 <2.967209>
2686  00:09:50.757693 <... futex resumed> ) = 1 <0.000038>
2690  00:09:50.757703 futex(0x7f5ef33fb4a0, FUTEX_WAIT_PRIVATE, 2, NULL <unfinished ...>
2686  00:09:50.757717 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
2690  00:09:50.757730 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
2686  00:09:50.757754 <... futex resumed> ) = 0 <0.000031>
2690  00:09:50.757768 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
2686  00:09:50.757778 epoll_wait(36<anon_inode:[eventpoll]>,  <unfinished ...>
2690  00:09:50.757811 <... futex resumed> ) = 0 <0.000037>
2686  00:09:50.757824 <... epoll_wait resumed> [], 100, 0) = 0 <0.000020>
2690  00:09:50.757838 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
2686  00:09:50.757848 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
2690  00:09:50.757858 <... clock_gettime resumed> {282496, 842306680}) = 0 <0.000014>
2686  00:09:50.757873 <... clock_gettime resumed> {282496, 842315647}) = 0 <0.000020>
2690  00:09:50.757885 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 3999, {282497, 270834003}, ffffffff <unfinished ...>
2686  00:09:50.757900 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 4000, NULL <unfinished ...>
2690  00:09:50.757913 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
2690  00:09:50.757937 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4000, {282497, 270834003}, ffffffff <unfinished ...>
7395  00:09:50.926636 <... nanosleep resumed> NULL) = 0 <1.000089>
7395  00:09:50.926719 close(1<pipe:[3578440]>) = 0 <0.000019>
7395  00:09:50.926784 close(2<pipe:[3578440]>) = 0 <0.000015>
7395  00:09:50.926831 exit_group(0)     = ?
7395  00:09:50.926938 +++ exited with 0 +++
477   00:09:50.926976 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7395 <1.002428>
477   00:09:50.927011 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
477   00:09:50.927063 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:50.927097 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7395, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:50.927120 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000013>
477   00:09:50.927154 rt_sigreturn({mask=[]}) = 0 <0.000012>
477   00:09:50.927189 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000013>
477   00:09:50.927223 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000012>
477   00:09:50.927301 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000020>
477   00:09:50.927353 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:50.927387 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000010>
477   00:09:50.927418 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:50.927450 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000011>
477   00:09:50.927486 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000010>
477   00:09:50.927522 close(3</dev/null>) = 0 <0.000009>
477   00:09:50.927576 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:50.927609 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000010>
477   00:09:50.927641 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:50.927672 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000010>
477   00:09:50.927703 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000010>
477   00:09:50.927736 fcntl(1</dev/null>, F_GETFD) = 0 <0.000010>
477   00:09:50.927768 kill(495, SIG_0)  = 0 <0.000013>
477   00:09:50.927801 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000009>
477   00:09:50.927834 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000010>
477   00:09:50.927866 close(11<pipe:[3578440]>) = 0 <0.000009>
477   00:09:50.927897 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000014>
477   00:09:50.927933 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000010>
477   00:09:50.927964 close(10<pipe:[3578440]>) = 0 <0.000010>
477   00:09:50.928014 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000013>
477   00:09:50.928050 clone( <unfinished ...>
7404  00:09:50.928263 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper>) = 0 <0.000012>
7404  00:09:50.928319 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000009>
7404  00:09:50.928352 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928458 <... clone resumed> child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7404 <0.000404>
7404  00:09:50.928479 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000026>
7404  00:09:50.928498 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928513 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7404  00:09:50.928525 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000021>
477   00:09:50.928538 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7404  00:09:50.928551 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928597 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7404  00:09:50.928610 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000052>
477   00:09:50.928623 <... rt_sigprocmask resumed> [], 8) = 0 <0.000020>
7404  00:09:50.928652 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928666 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7404  00:09:50.928678 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
477   00:09:50.928692 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7404  00:09:50.928704 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928718 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7404  00:09:50.928736 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000024>
477   00:09:50.928748 <... rt_sigprocmask resumed> [], 8) = 0 <0.000023>
7404  00:09:50.928761 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928774 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7404  00:09:50.928787 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
477   00:09:50.928800 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7404  00:09:50.928818 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928830 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7404  00:09:50.928843 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
477   00:09:50.928856 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7404  00:09:50.928870 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:50.928885 wait4(-1,  <unfinished ...>
7404  00:09:50.928899 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000022>
7404  00:09:50.928920 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7404  00:09:50.928956 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000017>
7404  00:09:50.929000 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7404  00:09:50.929035 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000021>
7404  00:09:50.929079 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000013>
7404  00:09:50.929160 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000167>
7404  00:09:50.929384 brk(NULL)         = 0x1273000 <0.000014>
7404  00:09:50.929437 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000025>
7404  00:09:50.929491 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000013>
7404  00:09:50.929529 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000013>
7404  00:09:50.929580 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000013>
7404  00:09:50.929627 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7fdfbf767000 <0.000014>
7404  00:09:50.929667 close(3</etc/ld.so.cache>) = 0 <0.000013>
7404  00:09:50.929709 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7404  00:09:50.929746 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000015>
7404  00:09:50.929795 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000013>
7404  00:09:50.929839 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000018>
7404  00:09:50.929883 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fdfbf766000 <0.000013>
7404  00:09:50.929921 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7fdfbf17b000 <0.000024>
7404  00:09:50.929970 mprotect(0x7fdfbf33b000, 2097152, PROT_NONE) = 0 <0.000018>
7404  00:09:50.930008 mmap(0x7fdfbf53b000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7fdfbf53b000 <0.000016>
7404  00:09:50.930060 mmap(0x7fdfbf541000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fdfbf541000 <0.000014>
7404  00:09:50.930106 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000013>
7404  00:09:50.930153 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fdfbf765000 <0.000013>
7404  00:09:50.930197 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fdfbf764000 <0.000014>
7404  00:09:50.930234 arch_prctl(ARCH_SET_FS, 0x7fdfbf765700) = 0 <0.000012>
7404  00:09:50.930319 mprotect(0x7fdfbf53b000, 16384, PROT_READ) = 0 <0.000024>
7404  00:09:50.930369 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000014>
7404  00:09:50.930404 mprotect(0x7fdfbf76a000, 4096, PROT_READ) = 0 <0.000020>
7404  00:09:50.930443 munmap(0x7fdfbf767000, 10600) = 0 <0.000016>
7404  00:09:50.930566 brk(NULL)         = 0x1273000 <0.000023>
7404  00:09:50.930612 brk(0x1294000)    = 0x1294000 <0.000013>
7404  00:09:50.930661 nanosleep({1, 0},  <unfinished ...>
1093  00:09:50.968879 <... nanosleep resumed> NULL) = 0 <1.000090>
1093  00:09:50.968935 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000012>
1093  00:09:50.968981 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:50.969014 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000011>
1093  00:09:50.969047 read(5</var/log/gitlab/gitlab-monitor/current>, "2018-09-25_00:09:50.35654 127.0.0.1 - - [25/Sep/2018:00:09:50 UTC] \"GET /process HTTP/1.1\" 200 1514\n2018-09-25_00:09:50.35656 - -> /process\n", 8192) = 140 <0.000012>
1093  00:09:50.969081 read(5</var/log/gitlab/gitlab-monitor/current>, "", 8192) = 0 <0.000011>
1093  00:09:50.969111 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000011>
1093  00:09:50.969142 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000011>
1093  00:09:50.969174 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000011>
1093  00:09:50.969206 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000011>
1093  00:09:50.969238 open("/var/log/gitlab/gitlab-rails/production_json.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/production_json.log> <0.000016>
1093  00:09:50.969277 fstat(33</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000011>
1093  00:09:50.969309 close(33</var/log/gitlab/gitlab-rails/production_json.log>) = 0 <0.000011>
1093  00:09:50.969339 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000011>
1093  00:09:50.969371 open("/var/log/gitlab/gitlab-rails/production.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/production.log> <0.000012>
1093  00:09:50.969403 fstat(33</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000011>
1093  00:09:50.969434 close(33</var/log/gitlab/gitlab-rails/production.log>) = 0 <0.000011>
1093  00:09:50.969463 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000011>
1093  00:09:50.969495 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000011>
1093  00:09:50.969526 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000012>
1093  00:09:50.969558 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000011>
1093  00:09:50.969590 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000011>
1093  00:09:50.969622 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000012>
1093  00:09:50.969654 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000011>
1093  00:09:50.969686 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969717 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969748 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969779 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000011>
1093  00:09:50.969811 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969842 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969873 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969904 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969938 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.969970 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.970001 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.970033 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.970064 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000011>
1093  00:09:50.970095 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000011>
1093  00:09:50.970126 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000011>
1093  00:09:50.970158 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000011>
1093  00:09:50.970189 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.970219 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000011>
1093  00:09:50.970250 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000011>
1093  00:09:50.970280 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000011>
1093  00:09:50.970311 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000011>
1093  00:09:50.970341 open("/var/log/gitlab/gitlab-rails/api_json.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/api_json.log> <0.000013>
1093  00:09:50.970374 fstat(33</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000011>
1093  00:09:50.970404 close(33</var/log/gitlab/gitlab-rails/api_json.log>) = 0 <0.000011>
1093  00:09:50.970433 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120221, ...}) = 0 <0.000011>
1093  00:09:50.970464 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=116903, ...}) = 0 <0.000010>
1093  00:09:50.970495 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000011>
1093  00:09:50.970525 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:50.970556 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000011>
1093  00:09:50.970586 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:50.970617 open("/var/log/gitlab/alertmanager/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/alertmanager/current> <0.000013>
1093  00:09:50.970649 fstat(33</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:50.970680 close(33</var/log/gitlab/alertmanager/current>) = 0 <0.000011>
1093  00:09:50.970709 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000011>
1093  00:09:50.970739 open("/var/log/gitlab/registry/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/registry/current> <0.000012>
1093  00:09:50.970772 fstat(33</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000011>
1093  00:09:50.970802 close(33</var/log/gitlab/registry/current>) = 0 <0.000011>
1093  00:09:50.970831 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56121, ...}) = 0 <0.000011>
1093  00:09:50.970862 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000011>
1093  00:09:50.970892 open("/var/log/gitlab/gitlab-shell/gitlab-shell.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-shell/gitlab-shell.log> <0.000013>
1093  00:09:50.970927 fstat(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000011>
1093  00:09:50.970958 close(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>) = 0 <0.000011>
1093  00:09:50.970987 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:50.971018 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971048 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:50.971079 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42324, ...}) = 0 <0.000011>
1093  00:09:50.971109 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971140 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971170 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971201 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971231 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971262 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971292 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971323 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:50.971353 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000011>
1093  00:09:50.971384 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000011>
1093  00:09:50.971414 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000011>
1093  00:09:50.971445 write(1<pipe:[3576493]>, "2018-09-25_00:09:50.35654 127.0.0.1 - - [25/Sep/2018:00:09:50 UTC] \"GET /process HTTP/1.1\" 200 1514\n2018-09-25_00:09:50.35656 - -> /process\n", 140) = 140 <0.000051>
1093  00:09:50.971591 nanosleep({1, 0},  <unfinished ...>
7113  00:09:51.114959 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000879>
7113  00:09:51.115012 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000016>
7113  00:09:51.115055 clock_gettime(CLOCK_MONOTONIC, {282497, 199522323}) = 0 <0.000016>
7113  00:09:51.115105 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 106, {282498, 200328885}, ffffffff <unfinished ...>
2690  00:09:51.186469 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.428523>
2690  00:09:51.186521 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000014>
2690  00:09:51.186560 clock_gettime(CLOCK_MONOTONIC, {282497, 271027604}) = 0 <0.000013>
2690  00:09:51.186607 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4002, {282498, 271834003}, ffffffff <unfinished ...>
813   00:09:51.241172 <... select resumed> ) = 1 (in [25], left {21, 160064}) <3.450431>
823   00:09:51.241275 <... select resumed> ) = 1 (in [25], left {21, 151694}) <3.451100>
817   00:09:51.241312 <... select resumed> ) = 1 (in [25], left {0, 401829}) <3.450908>
813   00:09:51.241331 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:51.241411 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
817   00:09:51.241447 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:51.241478 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000039>
817   00:09:51.241492 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000021>
823   00:09:51.241504 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:51.241543 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:51.241574 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = 26<UNIX:[3605141->3605140,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> <0.000038>
817   00:09:51.241611 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000044>
813   00:09:51.241624 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000221>
823   00:09:51.241641 recvfrom(26<UNIX:[3605141->3605140,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:51.241675 getppid( <unfinished ...>
823   00:09:51.241686 <... recvfrom resumed> "GET /-/liveness?token=wCN2tgfx9JTzXz_sC6EN HTTP/1.1\r\nHost: 10.7.7.42\r\nUser-Agent: ELB-HealthChecker/1.0\r\nAccept: */*\r\nGitlab-Workhorse: v6.1.0-20180921.115425\r\nGitlab-Workhorse-Proxy-Start: 1537834191241050209\r\nX-Forwarded-For: 10.7.7.46\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Ssl: on\r\nX-Real-Ip: 10.7.7.46\r\nX-Sendfile-Type: X-Sendfile\r\nAccept-Encoding: gzip\r\n\r\n", 16384, MSG_DONTWAIT, NULL, NULL) = 362 <0.000018>
817   00:09:51.241702 <... getppid resumed> ) = 495 <0.000022>
813   00:09:51.241712 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:51.242174 write(8</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/-/liveness?token=[FILTERED]\" for 10.7.7.46 at 2018-09-25 00:09:51 +0000\n", 86 <unfinished ...>
817   00:09:51.242215 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:51.242472 <... write resumed> ) = 86 <0.000267>
813   00:09:51.242487 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000745>
823   00:09:51.242623 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0&\242\206H\362]D\355YP\227KPJ\301\264\203\332\20\20\233\270\230\\\351v<\7\343\360\17\266\260#]\33\257\266\224", 43, MSG_NOSIGNAL, NULL, 0 <unfinished ...>
813   00:09:51.242952 getppid( <unfinished ...>
823   00:09:51.242983 <... sendto resumed> ) = 43 <0.000043>
813   00:09:51.242997 <... getppid resumed> ) = 495 <0.000037>
823   00:09:51.243010 poll([{fd=32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, events=POLLIN|POLLERR}], 1, -1 <unfinished ...>
813   00:09:51.243314 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:51.243678 <... poll resumed> ) = 1 ([{fd=32, revents=POLLIN}]) <0.000376>
823   00:09:51.243714 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0Z", 5, 0, NULL, NULL) = 5 <0.000014>
823   00:09:51.244006 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30F\fWks\320I\24\17\35\377)I\361\221\302*\301n{\214l\213\250\340a\343\260\23\30\220<\372Ls\237\366\256Rlg\357p\241\2751\203\35\20\243\216_\231i\330x\316+:\315\353\266\242\341\315\344\303\222\270:o\227\354\317VR\370\306\252!\251\304\251", 90, 0, NULL, NULL) = 90 <0.000014>
823   00:09:51.244585 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
823   00:09:51.244883 write(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$48\r\ncache:gitlab:ApplicationSetting:11.3.0-ee:4.2.10\r\n", 68) = 68 <0.000035>
823   00:09:51.245214 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
823   00:09:51.245504 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "$13765\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\27ApplicationSetting\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\1\246I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\33default_projects_limit\6;\fT@\vI\"\23signup_enabled\6;\fTo: ActiveRecord::Type::Boolean\10;\0160;\0170;\0200I\"\25gravatar_enabled\6;\fT@\21I\"\21sign_in_text\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\17created_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\17updated_at\6;\fTU;\30[\t;\31[\0[\0@\32I\"\22home_page_url\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\36default_branch_protection\6;\fT@\vI\"\16help_text\6;\fT@\24I\"!restricted_visibility_levels\6;\fTU:#ActiveRecord::Type::Serialized[\t;\31[\7:\r@subtype:\v@coder[\7@\24o:%ActiveRecord::Coders::YAMLColumn\6:\22@object_classc\vObject@\24I\"\32version_check_enabled\6;\fT@\21I\"\30max_attachment_size\6;\fT@\vI\"\37de", 1024) = 1024 <0.000023>
823   00:09:51.245879 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
823   00:09:51.246169 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "fault_project_visibility\6;\fT@\vI\"\37default_snippet_visibility\6;\fT@\vI\"\25domain_whitelist\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; c\nArray@\24I\"\34user_oauth_applications\6;\fT@\21I\"\30after_sign_out_path\6;\fT@!I\"\31session_expire_delay\6;\fT@\vI\"\23import_sources\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; @*@\24I\"\23help_page_text\6;\fT@\24I\"\35admin_notification_email\6;\fT@!I\"\33shared_runners_enabled\6;\fT@\21I\"\27max_artifacts_size\6;\fT@\vI\"\37runners_registration_token\6;\fT@!I\"\23max_pages_size\6;\fT@\vI\"&require_two_factor_authentication\6;\fT@\21I\"\34two_factor_grace_period\6;\fT@\vI\"\24metrics_enabled\6;\fT@\21I\"\21metrics_host\6;\fT@!I\"\26metrics_pool_size\6;\fT@\vI\"\24metrics_timeout\6;\fT@\vI\"\"metrics_method_call_threshold\6;\fT@\vI\"\26recaptcha_enabled\6;\fT@\21I\"\27recaptcha_site_key\6;\fT@!I\"\32recaptcha_private_key\6;\fT@!I\"\21metrics_port\6;\fT@\vI\"\24akismet_enabled\6;\fT@\21I\"\24akismet_api_key\6;\fT@!I\"\34metrics_sample_interval\6;\fT@\vI\"\23sentry_enabled\6;\fT@\21I\"\17sentry_dsn\6;\fT@!I\"\31email_author_in_body\6;\fT@\21I\"\35default_group_visibility\6;\fT@\vI\"\36repository_checks_enabled\6;\fT@\21I\"\30shared_runners_text\6;\fT@\24I\"\30metrics_packet_size\6;\fT@\vI\"#disable"..., 12749) = 12749 <0.000021>
823   00:09:51.246478 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
823   00:09:51.246762 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000018>
823   00:09:51.247727 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000022>
823   00:09:51.247794 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:51.247830 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000010>
823   00:09:51.247866 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000010>
823   00:09:51.247900 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490808 kB\nVmRSS:\t  490808 kB\nRssAnon:\t  476256 kB\nRssFile:\t   14500 kB\nRssShmem:\t      52 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000026>
823   00:09:51.247957 read(44</proc/823/status>, "", 6881) = 0 <0.000010>
823   00:09:51.247991 close(44</proc/823/status>) = 0 <0.000013>
823   00:09:51.250434 write(8</var/log/gitlab/gitlab-rails/production.log>, "Processing by HealthController#liveness as */*\n", 47) = 47 <0.000021>
823   00:09:51.250516 write(8</var/log/gitlab/gitlab-rails/production.log>, "  Parameters: {\"token\"=>\"[FILTERED]\"}\n", 38) = 38 <0.000015>
823   00:09:51.251335 write(8</var/log/gitlab/gitlab-rails/production.log>, "Completed 200 OK in 1ms (Views: 0.2ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\n", 84) = 84 <0.000020>
823   00:09:51.251998 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000016>
823   00:09:51.252302 write(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$14\r\npeek:requests:\r\n$4\r\n1800\r\n$334\r\n{\"context\":{},\"data\":{\"host\":{\"hostname\":\"aabecb3049c7\"},\"pg\":{\"duration\":\"0ms\",\"calls\":0,\"queries\":[]},\"gitaly\":{\"duration\":\"0ms\",\"calls\":0,\"details\":[]},\"redis\":{\"duration\":\"0ms\",\"calls\":0},\"sidekiq\":{\"duration\":\"0ms\",\"calls\":0},\"gc\":{\"invokes\":0,\"invoke_time\":\"0.00\",\"use_size\":0,\"total_size\":0,\"total_object\":0,\"gc_time\":\"0.00\"}}}\r\n", 388) = 388 <0.000037>
823   00:09:51.252625 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
823   00:09:51.252913 read(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000023>
823   00:09:51.253422 write(15</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/-/liveness\",\"format\":\"*/*\",\"controller\":\"HealthController\",\"action\":\"liveness\",\"status\":200,\"duration\":2.64,\"view\":0.2,\"db\":0.0,\"time\":\"2018-09-25T00:09:51.250Z\",\"params\":[{\"key\":\"token\",\"value\":\"[FILTERED]\"}],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n", 294) = 294 <0.000020>
823   00:09:51.253527 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000018>
823   00:09:51.253573 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:51.253608 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000010>
823   00:09:51.253642 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000010>
823   00:09:51.253678 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490808 kB\nVmRSS:\t  490808 kB\nRssAnon:\t  476256 kB\nRssFile:\t   14500 kB\nRssShmem:\t      52 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000025>
823   00:09:51.253730 read(44</proc/823/status>, "", 6881) = 0 <0.000010>
823   00:09:51.253764 close(44</proc/823/status>) = 0 <0.000014>
823   00:09:51.254089 write(26<UNIX:[3605141->3605140,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "HTTP/1.1 200 OK\r\nDate: Tue, 25 Sep 2018 00:09:51 GMT\r\nConnection: close\r\nX-Frame-Options: SAMEORIGIN\r\nX-XSS-Protection: 1; mode=block\r\nX-Content-Type-Options: nosniff\r\nContent-Type: application/json; charset=utf-8\r\nETag: W/\"f5ab4c0705f158802dbe472f370ea765\"\r\nCache-Control: max-age=0, private, must-revalidate\r\nX-Request-Id: aebdcccf-bdf3-4f64-b2b0-269f61359819\r\nX-Runtime: 0.012094\r\n\r\n", 386) = 386 <0.000127>
823   00:09:51.254304 write(26<UNIX:[3605141->3605140,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "{\"db_check\":{\"status\":\"ok\"},\"redis_check\":{\"status\":\"ok\"},\"cache_check\":{\"status\":\"ok\"},\"queues_check\":{\"status\":\"ok\"},\"shared_state_check\":{\"status\":\"ok\"},\"gitaly_check\":{\"status\":\"ok\"}}", 187) = 187 <0.000037>
823   00:09:51.254523 shutdown(26<UNIX:[3605141->3605140,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, SHUT_RDWR) = 0 <0.000271>
823   00:09:51.254859 close(26<UNIX:[3605141,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>) = 0 <0.000017>
823   00:09:51.254944 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000010>
823   00:09:51.254997 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:51.255054 getppid()         = 495 <0.000012>
823   00:09:51.255094 select(26, [14<pipe:[3579145]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0}) = 1 (in [25], left {29, 613894}) <0.386136>
813   00:09:51.641532 <... select resumed> ) = 1 (in [25], left {29, 601992}) <0.398022>
817   00:09:51.641578 <... select resumed> ) = 1 (in [25], left {29, 600937}) <0.399117>
823   00:09:51.641625 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
817   00:09:51.641700 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:51.641735 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000044>
817   00:09:51.641749 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000021>
823   00:09:51.641761 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:51.641793 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:51.641824 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = 26<UNIX:[3605148->3605147,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> <0.000037>
817   00:09:51.641856 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000039>
813   00:09:51.641872 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:51.641907 recvfrom(26<UNIX:[3605148->3605147,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:51.641938 getppid( <unfinished ...>
823   00:09:51.641949 <... recvfrom resumed> "GET /-/liveness?token=wCN2tgfx9JTzXz_sC6EN HTTP/1.1\r\nHost: 10.7.7.42\r\nUser-Agent: ELB-HealthChecker/1.0\r\nAccept: */*\r\nGitlab-Workhorse: v6.1.0-20180921.115425\r\nGitlab-Workhorse-Proxy-Start: 1537834191641333133\r\nX-Forwarded-For: 10.7.7.5\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Ssl: on\r\nX-Real-Ip: 10.7.7.5\r\nX-Sendfile-Type: X-Sendfile\r\nAccept-Encoding: gzip\r\n\r\n", 16384, MSG_DONTWAIT, NULL, NULL) = 360 <0.000018>
817   00:09:51.641965 <... getppid resumed> ) = 495 <0.000021>
813   00:09:51.641978 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000078>
817   00:09:51.641990 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
813   00:09:51.642314 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
813   00:09:51.642399 getppid()         = 495 <0.000014>
813   00:09:51.642461 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:51.642736 write(8</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/-/liveness?token=[FILTERED]\" for 10.7.7.5 at 2018-09-25 00:09:51 +0000\n", 85) = 85 <0.000059>
823   00:09:51.642946 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0&\242\206H\362]D\355Z\211\221\370\276\17\0A\235H\21\354\356=\251n7@M\336\327\322\222p\322\t\206\265$\232a", 43, MSG_NOSIGNAL, NULL, 0) = 43 <0.000052>
823   00:09:51.643320 poll([{fd=32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, events=POLLIN|POLLERR}], 1, -1) = 1 ([{fd=32, revents=POLLIN}]) <0.000471>
823   00:09:51.644153 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0Z", 5, 0, NULL, NULL) = 5 <0.000019>
823   00:09:51.644464 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30G\35\367kN\317/=\346E\205\310\315(\223\364\200\314\3M0\2518\271a\306*\26\337#\313^{\364\301P\330\n\344\220\21e&\3553\222\353-\351?\360g\224\35\213\322+U\317\f6U\274\226\221_Y\242\364\347\263/\31\341\365H\320\260j\24\350@\27", 90, 0, NULL, NULL) = 90 <0.000018>
823   00:09:51.645036 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000019>
823   00:09:51.645369 write(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$48\r\ncache:gitlab:ApplicationSetting:11.3.0-ee:4.2.10\r\n", 68) = 68 <0.000039>
823   00:09:51.645702 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000059>
823   00:09:51.646041 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "$13765\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\27ApplicationSetting\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\1\246I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\33default_projects_limit\6;\fT@\vI\"\23signup_enabled\6;\fTo: ActiveRecord::Type::Boolean\10;\0160;\0170;\0200I\"\25gravatar_enabled\6;\fT@\21I\"\21sign_in_text\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\17created_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\17updated_at\6;\fTU;\30[\t;\31[\0[\0@\32I\"\22home_page_url\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\36default_branch_protection\6;\fT@\vI\"\16help_text\6;\fT@\24I\"!restricted_visibility_levels\6;\fTU:#ActiveRecord::Type::Serialized[\t;\31[\7:\r@subtype:\v@coder[\7@\24o:%ActiveRecord::Coders::YAMLColumn\6:\22@object_classc\vObject@\24I\"\32version_check_enabled\6;\fT@\21I\"\30max_attachment_size\6;\fT@\vI\"\37de", 1024) = 1024 <0.000020>
823   00:09:51.646473 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000011>
823   00:09:51.646760 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "fault_project_visibility\6;\fT@\vI\"\37default_snippet_visibility\6;\fT@\vI\"\25domain_whitelist\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; c\nArray@\24I\"\34user_oauth_applications\6;\fT@\21I\"\30after_sign_out_path\6;\fT@!I\"\31session_expire_delay\6;\fT@\vI\"\23import_sources\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; @*@\24I\"\23help_page_text\6;\fT@\24I\"\35admin_notification_email\6;\fT@!I\"\33shared_runners_enabled\6;\fT@\21I\"\27max_artifacts_size\6;\fT@\vI\"\37runners_registration_token\6;\fT@!I\"\23max_pages_size\6;\fT@\vI\"&require_two_factor_authentication\6;\fT@\21I\"\34two_factor_grace_period\6;\fT@\vI\"\24metrics_enabled\6;\fT@\21I\"\21metrics_host\6;\fT@!I\"\26metrics_pool_size\6;\fT@\vI\"\24metrics_timeout\6;\fT@\vI\"\"metrics_method_call_threshold\6;\fT@\vI\"\26recaptcha_enabled\6;\fT@\21I\"\27recaptcha_site_key\6;\fT@!I\"\32recaptcha_private_key\6;\fT@!I\"\21metrics_port\6;\fT@\vI\"\24akismet_enabled\6;\fT@\21I\"\24akismet_api_key\6;\fT@!I\"\34metrics_sample_interval\6;\fT@\vI\"\23sentry_enabled\6;\fT@\21I\"\17sentry_dsn\6;\fT@!I\"\31email_author_in_body\6;\fT@\21I\"\35default_group_visibility\6;\fT@\vI\"\36repository_checks_enabled\6;\fT@\21I\"\30shared_runners_text\6;\fT@\24I\"\30metrics_packet_size\6;\fT@\vI\"#disable"..., 12749) = 12749 <0.000021>
823   00:09:51.647076 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000016>
823   00:09:51.647365 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000018>
823   00:09:51.648303 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000023>
823   00:09:51.648368 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>
823   00:09:51.648408 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000013>
823   00:09:51.648447 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000012>
823   00:09:51.648484 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490808 kB\nVmRSS:\t  490808 kB\nRssAnon:\t  476256 kB\nRssFile:\t   14500 kB\nRssShmem:\t      52 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000027>
823   00:09:51.648539 read(44</proc/823/status>, "", 6881) = 0 <0.000012>
823   00:09:51.648575 close(44</proc/823/status>) = 0 <0.000013>
823   00:09:51.650945 write(8</var/log/gitlab/gitlab-rails/production.log>, "Processing by HealthController#liveness as */*\n", 47) = 47 <0.000024>
823   00:09:51.651028 write(8</var/log/gitlab/gitlab-rails/production.log>, "  Parameters: {\"token\"=>\"[FILTERED]\"}\n", 38) = 38 <0.000014>
823   00:09:51.651825 write(8</var/log/gitlab/gitlab-rails/production.log>, "Completed 200 OK in 1ms (Views: 0.2ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\n", 84) = 84 <0.000019>
823   00:09:51.652497 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000016>
823   00:09:51.652804 write(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$14\r\npeek:requests:\r\n$4\r\n1800\r\n$334\r\n{\"context\":{},\"data\":{\"host\":{\"hostname\":\"aabecb3049c7\"},\"pg\":{\"duration\":\"0ms\",\"calls\":0,\"queries\":[]},\"gitaly\":{\"duration\":\"0ms\",\"calls\":0,\"details\":[]},\"redis\":{\"duration\":\"0ms\",\"calls\":0},\"sidekiq\":{\"duration\":\"0ms\",\"calls\":0},\"gc\":{\"invokes\":0,\"invoke_time\":\"0.00\",\"use_size\":0,\"total_size\":0,\"total_object\":0,\"gc_time\":\"0.00\"}}}\r\n", 388) = 388 <0.000039>
823   00:09:51.653137 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000019>
823   00:09:51.653429 read(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000018>
823   00:09:51.653953 write(15</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/-/liveness\",\"format\":\"*/*\",\"controller\":\"HealthController\",\"action\":\"liveness\",\"status\":200,\"duration\":2.69,\"view\":0.21,\"db\":0.0,\"time\":\"2018-09-25T00:09:51.651Z\",\"params\":[{\"key\":\"token\",\"value\":\"[FILTERED]\"}],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n", 295) = 295 <0.000018>
823   00:09:51.654049 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000018>
823   00:09:51.654098 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>
823   00:09:51.654135 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000013>
823   00:09:51.654173 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000013>
823   00:09:51.654210 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490808 kB\nVmRSS:\t  490808 kB\nRssAnon:\t  476256 kB\nRssFile:\t   14500 kB\nRssShmem:\t      52 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000026>
823   00:09:51.654263 read(44</proc/823/status>, "", 6881) = 0 <0.000012>
823   00:09:51.654299 close(44</proc/823/status>) = 0 <0.000013>
823   00:09:51.654642 write(26<UNIX:[3605148->3605147,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "HTTP/1.1 200 OK\r\nDate: Tue, 25 Sep 2018 00:09:51 GMT\r\nConnection: close\r\nX-Frame-Options: SAMEORIGIN\r\nX-XSS-Protection: 1; mode=block\r\nX-Content-Type-Options: nosniff\r\nContent-Type: application/json; charset=utf-8\r\nETag: W/\"f5ab4c0705f158802dbe472f370ea765\"\r\nCache-Control: max-age=0, private, must-revalidate\r\nX-Request-Id: 77aea7fa-331b-485a-abac-08106526fbb7\r\nX-Runtime: 0.012332\r\n\r\n", 386) = 386 <0.000129>
823   00:09:51.654851 write(26<UNIX:[3605148->3605147,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "{\"db_check\":{\"status\":\"ok\"},\"redis_check\":{\"status\":\"ok\"},\"cache_check\":{\"status\":\"ok\"},\"queues_check\":{\"status\":\"ok\"},\"shared_state_check\":{\"status\":\"ok\"},\"gitaly_check\":{\"status\":\"ok\"}}", 187) = 187 <0.000036>
823   00:09:51.655071 shutdown(26<UNIX:[3605148->3605147,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, SHUT_RDWR) = 0 <0.000293>
823   00:09:51.655431 close(26<UNIX:[3605148,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>) = 0 <0.000016>
823   00:09:51.655515 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000052>
823   00:09:51.655611 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000016>
823   00:09:51.655669 getppid()         = 495 <0.000012>
823   00:09:51.655709 select(26, [14<pipe:[3579145]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
7404  00:09:51.930770 <... nanosleep resumed> NULL) = 0 <1.000096>
7404  00:09:51.930850 close(1<pipe:[3578440]>) = 0 <0.000011>
7404  00:09:51.930903 close(2<pipe:[3578440]>) = 0 <0.000009>
7404  00:09:51.930939 exit_group(0)     = ?
7404  00:09:51.931040 +++ exited with 0 +++
477   00:09:51.931074 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7404 <1.002183>
477   00:09:51.931103 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000011>
477   00:09:51.931161 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:51.931196 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7404, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:51.931219 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000010>
477   00:09:51.931251 rt_sigreturn({mask=[]}) = 0 <0.000013>
477   00:09:51.931286 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000013>
477   00:09:51.931321 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:51.931399 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000021>
477   00:09:51.931450 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:51.931480 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000010>
477   00:09:51.931512 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:51.931567 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000084>
477   00:09:51.931686 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000010>
477   00:09:51.931727 close(3</dev/null>) = 0 <0.000010>
477   00:09:51.931759 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:51.931793 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000009>
477   00:09:51.931829 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:51.931862 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000010>
477   00:09:51.931894 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000010>
477   00:09:51.931927 fcntl(1</dev/null>, F_GETFD) = 0 <0.000010>
477   00:09:51.931959 kill(495, SIG_0)  = 0 <0.000014>
477   00:09:51.931995 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000010>
477   00:09:51.932028 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000009>
477   00:09:51.932061 close(11<pipe:[3578440]>) = 0 <0.000010>
477   00:09:51.932094 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000015>
477   00:09:51.932131 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000021>
477   00:09:51.932176 close(10<pipe:[3578440]>) = 0 <0.000010>
477   00:09:51.932235 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000016>
477   00:09:51.932278 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7405 <0.000222>
7405  00:09:51.932620 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:51.932683 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7405  00:09:51.932700 <... close resumed> ) = 0 <0.000027>
477   00:09:51.932712 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7405  00:09:51.932723 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000012>
7405  00:09:51.932758 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_DFL, [], 0}, 8) = 0 <0.000010>
477   00:09:51.932790 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7405  00:09:51.932803 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:51.932816 <... rt_sigprocmask resumed> [], 8) = 0 <0.000019>
477   00:09:51.932851 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7405  00:09:51.932864 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000055>
477   00:09:51.932877 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7405  00:09:51.932889 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:51.932902 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000017>
7405  00:09:51.932936 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000040>
477   00:09:51.932949 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7405  00:09:51.932963 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:51.932976 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7405  00:09:51.932990 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
477   00:09:51.933010 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7405  00:09:51.933024 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:51.933037 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7405  00:09:51.933050 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
477   00:09:51.933064 wait4(-1,  <unfinished ...>
7405  00:09:51.933076 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7405  00:09:51.933114 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000010>
7405  00:09:51.933150 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000015>
7405  00:09:51.933199 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7405  00:09:51.933238 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7405  00:09:51.933279 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7405  00:09:51.933317 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000016>
7405  00:09:51.933357 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000014>
7405  00:09:51.933443 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000173>
7405  00:09:51.933671 brk(NULL)         = 0x16a1000 <0.000010>
7405  00:09:51.933719 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000020>
7405  00:09:51.933769 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000014>
7405  00:09:51.933809 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000018>
7405  00:09:51.933866 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000010>
7405  00:09:51.933910 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7ff46c5bd000 <0.000012>
7405  00:09:51.933944 close(3</etc/ld.so.cache>) = 0 <0.000010>
7405  00:09:51.933989 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7405  00:09:51.934026 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000018>
7405  00:09:51.934081 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000014>
7405  00:09:51.934135 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000020>
7405  00:09:51.934181 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ff46c5bc000 <0.000014>
7405  00:09:51.934223 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7ff46bfd1000 <0.000019>
7405  00:09:51.934268 mprotect(0x7ff46c191000, 2097152, PROT_NONE) = 0 <0.000021>
7405  00:09:51.934318 mmap(0x7ff46c391000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7ff46c391000 <0.000017>
7405  00:09:51.934364 mmap(0x7ff46c397000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ff46c397000 <0.000026>
7405  00:09:51.934420 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000010>
7405  00:09:51.934467 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ff46c5bb000 <0.000015>
7405  00:09:51.934505 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ff46c5ba000 <0.000014>
7405  00:09:51.934541 arch_prctl(ARCH_SET_FS, 0x7ff46c5bb700) = 0 <0.000018>
7405  00:09:51.934648 mprotect(0x7ff46c391000, 16384, PROT_READ) = 0 <0.000016>
7405  00:09:51.934688 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000023>
7405  00:09:51.934738 mprotect(0x7ff46c5c0000, 4096, PROT_READ) = 0 <0.000017>
7405  00:09:51.934776 munmap(0x7ff46c5bd000, 10600) = 0 <0.000023>
7405  00:09:51.934900 brk(NULL)         = 0x16a1000 <0.000011>
7405  00:09:51.934930 brk(0x16c2000)    = 0x16c2000 <0.000013>
7405  00:09:51.934997 nanosleep({1, 0},  <unfinished ...>
1093  00:09:51.971703 <... nanosleep resumed> NULL) = 0 <1.000098>
1093  00:09:51.971754 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000017>
1093  00:09:51.971813 open("/var/log/gitlab/gitaly/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitaly/current> <0.000021>
1093  00:09:51.971866 fstat(33</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000016>
1093  00:09:51.971908 close(33</var/log/gitlab/gitaly/current>) = 0 <0.000015>
1093  00:09:51.971944 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.971974 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000009>
1093  00:09:51.972105 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000010>
1093  00:09:51.972142 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000008>
1093  00:09:51.972171 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000008>
1093  00:09:51.972201 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120810, ...}) = 0 <0.000011>
1093  00:09:51.972235 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/-/liveness\",\"format\":\"*/*\",\"controller\":\"HealthController\",\"action\":\"liveness\",\"status\":200,\"duration\":2.64,\"view\":0.2,\"db\":0.0,\"time\":\"2018-09-25T00:09:51.250Z\",\"params\":[{\"key\":\"token\",\"value\":\"[FILTERED]\"}],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n{\"method\":\"GET\",\"path\":\"/-/liveness\",\"format\":\"*/*\",\"controller\":\"HealthController\",\"action\":\"liveness\",\"status\":200,\"duration\":2.69,\"view\":0.21,\"db\":0.0,\"time\":\"2018-09-25T00:09:51.651Z\",\"params\":[{\"key\":\"token\",\"value\":\"[FILTERED]\"}],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n", 8192) = 589 <0.000023>
1093  00:09:51.972289 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "", 8192) = 0 <0.000009>
1093  00:09:51.972321 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117412, ...}) = 0 <0.000009>
1093  00:09:51.972354 read(10</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/-/liveness?token=[FILTERED]\" for 10.7.7.46 at 2018-09-25 00:09:51 +0000\nProcessing by HealthController#liveness as */*\n  Parameters: {\"token\"=>\"[FILTERED]\"}\nCompleted 200 OK in 1ms (Views: 0.2ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\nStarted GET \"/-/liveness?token=[FILTERED]\" for 10.7.7.5 at 2018-09-25 00:09:51 +0000\nProcessing by HealthController#liveness as */*\n  Parameters: {\"token\"=>\"[FILTERED]\"}\nCompleted 200 OK in 1ms (Views: 0.2ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\n", 8192) = 509 <0.000013>
1093  00:09:51.972391 read(10</var/log/gitlab/gitlab-rails/production.log>, "", 8192) = 0 <0.000009>
1093  00:09:51.972422 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:51.972455 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:51.972487 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000010>
1093  00:09:51.972520 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000009>
1093  00:09:51.972552 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000010>
1093  00:09:51.972585 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56451, ...}) = 0 <0.000009>
1093  00:09:51.972618 read(16</var/log/gitlab/gitlab-workhorse/current>, "2018-09-25_00:09:51.25469 10.7.7.42 @ - - [2018/09/25:00:09:51 +0000] \"GET /-/liveness?token=wCN2tgfx9JTzXz_sC6EN HTTP/1.1\" 200 187 \"\" \"ELB-HealthChecker/1.0\" 0.014\n2018-09-25_00:09:51.65526 10.7.7.42 @ - - [2018/09/25:00:09:51 +0000] \"GET /-/liveness?token=wCN2tgfx9JTzXz_sC6EN HTTP/1.1\" 200 187 \"\" \"ELB-HealthChecker/1.0\" 0.014\n", 8192) = 330 <0.000013>
1093  00:09:51.972654 read(16</var/log/gitlab/gitlab-workhorse/current>, "", 8192) = 0 <0.000010>
1093  00:09:51.972685 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000010>
1093  00:09:51.972717 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.972749 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.972782 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.972814 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42587, ...}) = 0 <0.000009>
1093  00:09:51.972847 read(21</var/log/gitlab/nginx/gitlab_access.log>, "10.7.7.46 - - [25/Sep/2018:00:09:51 +0000] \"GET /-/liveness?token=wCN2tgfx9JTzXz_sC6EN HTTP/1.1\" 200 187 \"\" \"ELB-HealthChecker/1.0\"\n10.7.7.5 - - [25/Sep/2018:00:09:51 +0000] \"GET /-/liveness?token=wCN2tgfx9JTzXz_sC6EN HTTP/1.1\" 200 187 \"\" \"ELB-HealthChecker/1.0\"\n", 8192) = 263 <0.000013>
1093  00:09:51.972883 read(21</var/log/gitlab/nginx/gitlab_access.log>, "", 8192) = 0 <0.000010>
1093  00:09:51.972914 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.972946 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.972978 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.973010 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.973044 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.973077 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.973110 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:51.973146 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.973178 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000010>
1093  00:09:51.973211 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:51.973243 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:51.973276 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000009>
1093  00:09:51.973308 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.973340 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000009>
1093  00:09:51.973372 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15401, ...}) = 0 <0.000009>
1093  00:09:51.973404 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000010>
1093  00:09:51.973436 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000009>
1093  00:09:51.973467 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120810, ...}) = 0 <0.000009>
1093  00:09:51.973499 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117412, ...}) = 0 <0.000010>
1093  00:09:51.973531 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:51.973563 open("/var/log/gitlab/gitlab-rails/sidekiq.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sidekiq/current> <0.000016>
1093  00:09:51.973601 fstat(33</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:51.973632 close(33</var/log/gitlab/sidekiq/current>) = 0 <0.000012>
1093  00:09:51.973666 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:51.973697 open("/var/log/gitlab/sidekiq/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sidekiq/current> <0.000014>
1093  00:09:51.973730 fstat(33</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:51.973762 close(33</var/log/gitlab/sidekiq/current>) = 0 <0.000010>
1093  00:09:51.973792 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000010>
1093  00:09:51.973824 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000009>
1093  00:09:51.973855 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000009>
1093  00:09:51.973887 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56451, ...}) = 0 <0.000010>
1093  00:09:51.973919 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000009>
1093  00:09:51.973951 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.973982 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.974014 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.974045 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42587, ...}) = 0 <0.000010>
1093  00:09:51.974077 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.974112 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.974144 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.974175 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.974207 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.974239 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:51.974271 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.974303 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:51.974334 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000009>
1093  00:09:51.974366 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:51.974398 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:51.974430 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/gitlab-rails/production_json.log <==\n{\"method\":\"GET\",\"path\":\"/-/liveness\",\"format\":\"*/*\",\"controller\":\"HealthController\",\"action\":\"liveness\",\"status\":200,\"duration\":2.64,\"view\":0.2,\"db\":0.0,\"time\":\"2018-09-25T00:09:51.250Z\",\"params\":[{\"key\":\"token\",\"value\":\"[FILTERED]\"}],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n{\"method\":\"GET\",\"path\":\"/-/liveness\",\"format\":\"*/*\",\"controller\":\"HealthController\",\"action\":\"liveness\",\"status\":200,\"duration\":2.69,\"view\":0.21,\"db\":0.0,\"time\":\"2018-09-25T00:09:51.651Z\",\"params\":[{\"key\":\"token\",\"value\":\"[FILTERED]\"}],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n\n==> /var/log/gitlab/gitlab-rails/production.log <==\nStarted GET \"/-/liveness?token=[FILTERED]\" for 10.7.7.46 at 2018-09-25 00:09:51 +0000\nProcessing by HealthController#liveness as */*\n  Parameters: {\"token\"=>\"[FILTERED]\"}\nCompleted 200 OK in 1ms (Views: 0.2ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\nStarted GET \"/-/liveness?token=[FILTERED]\" for 10.7.7.5 at 2018-09-25"..., 1901) = 1901 <0.000059>
1093  00:09:51.974620 nanosleep({1, 0},  <unfinished ...>
7113  00:09:52.115959 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000843>
7113  00:09:52.116013 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000014>
7113  00:09:52.116053 clock_gettime(CLOCK_MONOTONIC, {282498, 200521114}) = 0 <0.000014>
7113  00:09:52.116101 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 108, {282499, 201328885}, ffffffff <unfinished ...>
2690  00:09:52.187468 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000851>
2690  00:09:52.187526 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000023>
2690  00:09:52.187579 clock_gettime(CLOCK_MONOTONIC, {282498, 272047071}) = 0 <0.000016>
2690  00:09:52.187633 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4004, {282499, 272834003}, ffffffff <unfinished ...>
7405  00:09:52.935100 <... nanosleep resumed> NULL) = 0 <1.000090>
7405  00:09:52.935277 close(1<pipe:[3578440]>) = 0 <0.000037>
7405  00:09:52.936245 close(2<pipe:[3578440]>) = 0 <0.000008>
7405  00:09:52.936286 exit_group(0)     = ?
7405  00:09:52.936399 +++ exited with 0 +++
477   00:09:52.936429 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7405 <1.003359>
477   00:09:52.936460 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
477   00:09:52.936512 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000010>
477   00:09:52.936544 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7405, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:52.936575 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000020>
477   00:09:52.936629 rt_sigreturn({mask=[]}) = 0 <0.000013>
477   00:09:52.936665 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000010>
477   00:09:52.936697 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000012>
477   00:09:52.936776 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000021>
477   00:09:52.936830 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000013>
477   00:09:52.936867 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000009>
477   00:09:52.936902 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:52.936952 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000010>
477   00:09:52.936989 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000013>
477   00:09:52.937028 close(3</dev/null>) = 0 <0.000010>
477   00:09:52.937060 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:52.937091 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000010>
477   00:09:52.937127 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:52.937158 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000013>
477   00:09:52.937193 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000013>
477   00:09:52.937231 fcntl(1</dev/null>, F_GETFD) = 0 <0.000009>
477   00:09:52.937264 kill(495, SIG_0)  = 0 <0.000014>
477   00:09:52.937298 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000010>
477   00:09:52.937333 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000010>
477   00:09:52.937366 close(11<pipe:[3578440]>) = 0 <0.000010>
477   00:09:52.937397 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000014>
477   00:09:52.937436 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000009>
477   00:09:52.937468 close(10<pipe:[3578440]>) = 0 <0.000013>
477   00:09:52.937521 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000010>
477   00:09:52.937555 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7407 <0.000108>
477   00:09:52.937834 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7407  00:09:52.937954 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:52.937986 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000135>
7407  00:09:52.937999 <... close resumed> ) = 0 <0.000022>
477   00:09:52.938044 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7407  00:09:52.938061 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
477   00:09:52.938075 <... rt_sigprocmask resumed> [], 8) = 0 <0.000020>
7407  00:09:52.938087 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000018>
477   00:09:52.938098 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7407  00:09:52.938122 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:52.938136 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000021>
7407  00:09:52.938148 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000018>
477   00:09:52.938161 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7407  00:09:52.938173 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:52.938187 <... rt_sigprocmask resumed> [], 8) = 0 <0.000019>
477   00:09:52.938208 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7407  00:09:52.938221 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000041>
477   00:09:52.938233 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7407  00:09:52.938246 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:52.938260 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7407  00:09:52.938273 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000021>
477   00:09:52.938286 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7407  00:09:52.938300 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:52.938319 wait4(-1,  <unfinished ...>
7407  00:09:52.938331 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7407  00:09:52.938365 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000011>
7407  00:09:52.938398 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7407  00:09:52.938442 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7407  00:09:52.938482 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000009>
7407  00:09:52.938533 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000016>
7407  00:09:52.938578 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000015>
7407  00:09:52.938622 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7407  00:09:52.938660 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7407  00:09:52.938704 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000014>
7407  00:09:52.938788 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000183>
7407  00:09:52.939039 brk(NULL)         = 0x10f5000 <0.000013>
7407  00:09:52.939101 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000017>
7407  00:09:52.939148 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000022>
7407  00:09:52.939198 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000015>
7407  00:09:52.939240 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000022>
7407  00:09:52.939288 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7fa18a1f4000 <0.000014>
7407  00:09:52.939324 close(3</etc/ld.so.cache>) = 0 <0.000021>
7407  00:09:52.939370 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000013>
7407  00:09:52.939405 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000026>
7407  00:09:52.939454 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000014>
7407  00:09:52.939509 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000009>
7407  00:09:52.939544 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fa18a1f3000 <0.000012>
7407  00:09:52.939599 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7fa189c08000 <0.000015>
7407  00:09:52.939643 mprotect(0x7fa189dc8000, 2097152, PROT_NONE) = 0 <0.000019>
7407  00:09:52.939682 mmap(0x7fa189fc8000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7fa189fc8000 <0.000017>
7407  00:09:52.939736 mmap(0x7fa189fce000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fa189fce000 <0.000014>
7407  00:09:52.939778 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000019>
7407  00:09:52.939832 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fa18a1f2000 <0.000013>
7407  00:09:52.939867 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fa18a1f1000 <0.000022>
7407  00:09:52.939911 arch_prctl(ARCH_SET_FS, 0x7fa18a1f2700) = 0 <0.000012>
7407  00:09:52.939999 mprotect(0x7fa189fc8000, 16384, PROT_READ) = 0 <0.000016>
7407  00:09:52.940047 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000014>
7407  00:09:52.940085 mprotect(0x7fa18a1f7000, 4096, PROT_READ) = 0 <0.000014>
7407  00:09:52.940118 munmap(0x7fa18a1f4000, 10600) = 0 <0.000020>
7407  00:09:52.940245 brk(NULL)         = 0x10f5000 <0.000013>
7407  00:09:52.940289 brk(0x1116000)    = 0x1116000 <0.000015>
7407  00:09:52.940347 nanosleep({1, 0},  <unfinished ...>
1093  00:09:52.974733 <... nanosleep resumed> NULL) = 0 <1.000097>
1093  00:09:52.974788 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000014>
1093  00:09:52.974844 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.974883 open("/var/log/gitlab/logrotate/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/logrotate/current> <0.000022>
1093  00:09:52.974930 fstat(33</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.974963 close(33</var/log/gitlab/logrotate/current>) = 0 <0.000015>
1093  00:09:52.975000 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000009>
1093  00:09:52.975035 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000010>
1093  00:09:52.975073 read(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, "[2018-09-25 00:09:52] 127.0.0.1 - - [25/Sep/2018:00:09:52 UTC] \"GET /metrics HTTP/1.1\" 200 5535 \"-\" \"Prometheus/1.8.2\"\n", 8192) = 119 <0.000014>
1093  00:09:52.975113 read(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, "", 8192) = 0 <0.000010>
1093  00:09:52.975145 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000010>
1093  00:09:52.975179 open("/var/log/gitlab/gitlab-rails/grpc.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/grpc.log> <0.000035>
1093  00:09:52.975245 fstat(33</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000010>
1093  00:09:52.975280 close(33</var/log/gitlab/gitlab-rails/grpc.log>) = 0 <0.000014>
1093  00:09:52.975317 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000010>
1093  00:09:52.975353 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120810, ...}) = 0 <0.000010>
1093  00:09:52.975388 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117412, ...}) = 0 <0.000010>
1093  00:09:52.975431 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:52.975466 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:52.975501 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000014>
1093  00:09:52.975541 open("/var/log/gitlab/prometheus/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/prometheus/current> <0.000015>
1093  00:09:52.975590 fstat(33</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000010>
1093  00:09:52.975619 close(33</var/log/gitlab/prometheus/current>) = 0 <0.000010>
1093  00:09:52.975646 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:52.975677 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000010>
1093  00:09:52.975708 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56451, ...}) = 0 <0.000010>
1093  00:09:52.975738 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000010>
1093  00:09:52.975769 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.975802 open("/var/log/gitlab/nginx/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/current> <0.000014>
1093  00:09:52.975836 fstat(33</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.975865 close(33</var/log/gitlab/nginx/current>) = 0 <0.000010>
1093  00:09:52.975896 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.975926 open("/var/log/gitlab/nginx/access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/access.log> <0.000014>
1093  00:09:52.975959 fstat(33</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.975988 close(33</var/log/gitlab/nginx/access.log>) = 0 <0.000010>
1093  00:09:52.976015 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976045 open("/var/log/gitlab/nginx/error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/error.log> <0.000014>
1093  00:09:52.976079 fstat(33</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976108 close(33</var/log/gitlab/nginx/error.log>) = 0 <0.000009>
1093  00:09:52.976135 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42587, ...}) = 0 <0.000009>
1093  00:09:52.976164 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976194 open("/var/log/gitlab/nginx/gitlab_pages_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_pages_error.log> <0.000016>
1093  00:09:52.976230 fstat(33</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976262 close(33</var/log/gitlab/nginx/gitlab_pages_error.log>) = 0 <0.000010>
1093  00:09:52.976289 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976319 open("/var/log/gitlab/nginx/gitlab_registry_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_registry_error.log> <0.000014>
1093  00:09:52.976352 fstat(33</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.976381 close(33</var/log/gitlab/nginx/gitlab_registry_error.log>) = 0 <0.000010>
1093  00:09:52.976412 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.976442 open("/var/log/gitlab/nginx/gitlab_pages_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_pages_access.log> <0.000014>
1093  00:09:52.976479 fstat(33</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976508 close(33</var/log/gitlab/nginx/gitlab_pages_access.log>) = 0 <0.000010>
1093  00:09:52.976535 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.976565 open("/var/log/gitlab/nginx/gitlab_registry_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_registry_access.log> <0.000014>
1093  00:09:52.976599 fstat(33</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976631 close(33</var/log/gitlab/nginx/gitlab_registry_access.log>) = 0 <0.000009>
1093  00:09:52.976659 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976688 open("/var/log/gitlab/nginx/gitlab_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_error.log> <0.000014>
1093  00:09:52.976722 fstat(33</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.976751 close(33</var/log/gitlab/nginx/gitlab_error.log>) = 0 <0.000010>
1093  00:09:52.976778 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976808 open("/var/log/gitlab/gitlab-pages/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-pages/current> <0.000014>
1093  00:09:52.976842 fstat(33</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.976870 close(33</var/log/gitlab/gitlab-pages/current>) = 0 <0.000009>
1093  00:09:52.976901 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.976930 open("/var/log/gitlab/node-exporter/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/node-exporter/current> <0.000014>
1093  00:09:52.976964 fstat(33</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.976993 close(33</var/log/gitlab/node-exporter/current>) = 0 <0.000010>
1093  00:09:52.977020 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.977050 open("/var/log/gitlab/unicorn/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/current> <0.000014>
1093  00:09:52.977083 fstat(33</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.977112 close(33</var/log/gitlab/unicorn/current>) = 0 <0.000009>
1093  00:09:52.977139 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000010>
1093  00:09:52.977169 open("/var/log/gitlab/unicorn/unicorn_stderr.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/unicorn_stderr.log> <0.000014>
1093  00:09:52.977203 fstat(33</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000009>
1093  00:09:52.977232 close(33</var/log/gitlab/unicorn/unicorn_stderr.log>) = 0 <0.000009>
1093  00:09:52.977259 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000009>
1093  00:09:52.977288 open("/var/log/gitlab/unicorn/unicorn_stdout.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/unicorn_stdout.log> <0.000014>
1093  00:09:52.977322 fstat(33</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000009>
1093  00:09:52.977351 close(33</var/log/gitlab/unicorn/unicorn_stdout.log>) = 0 <0.000009>
1093  00:09:52.977378 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:52.977408 open("/var/log/gitlab/sshd/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sshd/current> <0.000014>
1093  00:09:52.977442 fstat(33</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:52.977474 close(33</var/log/gitlab/sshd/current>) = 0 <0.000010>
1093  00:09:52.977505 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000011>
1093  00:09:52.977536 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.977566 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000010>
1093  00:09:52.977595 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000009>
1093  00:09:52.977624 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000009>
1093  00:09:52.977653 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000009>
1093  00:09:52.977683 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=120810, ...}) = 0 <0.000010>
1093  00:09:52.977713 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117412, ...}) = 0 <0.000010>
1093  00:09:52.977742 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:52.977771 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:52.977800 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000009>
1093  00:09:52.977830 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000009>
1093  00:09:52.977859 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000010>
1093  00:09:52.977888 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56451, ...}) = 0 <0.000010>
1093  00:09:52.977917 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000009>
1093  00:09:52.977946 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.977975 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.978004 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.978033 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42587, ...}) = 0 <0.000009>
1093  00:09:52.978062 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.978092 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.978121 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:52.978150 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.978179 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.978208 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.978237 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.978266 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:52.978295 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000010>
1093  00:09:52.978324 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:52.978353 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:52.978386 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/gitlab-rails/sidekiq_exporter.log <==\n[2018-09-25 00:09:52] 127.0.0.1 - - [25/Sep/2018:00:09:52 UTC] \"GET /metrics HTTP/1.1\" 200 5535 \"-\" \"Prometheus/1.8.2\"\n", 178) = 178 <0.000079>
1093  00:09:52.978523 nanosleep({1, 0},  <unfinished ...>
823   00:09:53.046640 <... select resumed> ) = 1 (in [25], left {28, 609337}) <1.390735>
817   00:09:53.046731 <... select resumed> ) = 1 (in [25], left {28, 595620}) <1.404435>
813   00:09:53.046754 <... select resumed> ) = 1 (in [25], left {28, 596050}) <1.404032>
823   00:09:53.046786 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
817   00:09:53.046864 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:53.046899 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000042>
817   00:09:53.046913 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
823   00:09:53.046925 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:53.046957 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:53.046988 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = 26<UNIX:[3605184->3605183,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> <0.000038>
817   00:09:53.047022 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000040>
813   00:09:53.047035 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:53.047071 recvfrom(26<UNIX:[3605184->3605183,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:53.047102 getppid( <unfinished ...>
823   00:09:53.047122 <... recvfrom resumed> "GET /ealoc-engineering/loccms/noteable/merge_request/2114/notes HTTP/1.1\r\nHost: gitlabts.ea.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\r\nAccept: application/json, text/plain, */*\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nCookie: _ga=GA1.2.1866266439.1526069804; sidebar_collapsed=false; frequently_used_emojis=alien; auto_devops_settings_dismissed=true; _gid=GA1.2.1802602330.1537799390; _gitlab_session=e3db34af92ce75a754809c69bbc89e42\r\nGitlab-Workhorse: v6.1.0-20180921.115425\r\nGitlab-Workhorse-Proxy-Start: 1537834193046450409\r\nIf-None-Match: W/\"b11cedb8dd8fb4b5a14fd64914004afe\"\r\nReferer: https://gitlabts.ea.com/ealoc-engineering/loccms/merge_requests/102/diffs\r\nX-Csrf-Token: yOdBOutLs5+Cl7BBNfQ2Yl5+S/wQuIBr65GhQdEO31IjnuoFMSExsLRCj8uzCGL4j/+XXsRWtXjnMs4/lWh6iA==\r\nX-Forwarded-For: 10.45.32.103, 10.7.7.46\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Ssl: on\r\nX-Last-Fetched-At: 1537834186\r\nX-Real-Ip: 10.7.7.46\r\nX-Reque"..., 16384, MSG_DONTWAIT, NULL, NULL) = 1082 <0.000026>
817   00:09:53.047140 <... getppid resumed> ) = 495 <0.000025>
813   00:09:53.047150 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000087>
823   00:09:53.047578 write(8</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/ealoc-engineering/loccms/noteable/merge_request/2114/notes\" for 10.7.7.46 at 2018-09-25 00:09:53 +0000\n", 117 <unfinished ...>
817   00:09:53.047622 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:53.047885 <... write resumed> ) = 117 <0.000271>
813   00:09:53.047901 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:53.048047 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0&\242\206H\362]D\355[e\244:\336\273\2201\360\307\7CN\320x\226\352\314\374\235\211s\35\250\350\207\322\6\244\27S", 43, MSG_NOSIGNAL, NULL, 0 <unfinished ...>
813   00:09:53.048387 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000455>
823   00:09:53.048425 <... sendto resumed> ) = 43 <0.000050>
813   00:09:53.048443 getppid( <unfinished ...>
823   00:09:53.048465 poll([{fd=32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, events=POLLIN|POLLERR}], 1, -1 <unfinished ...>
813   00:09:53.048777 <... getppid resumed> ) = 495 <0.000319>
813   00:09:53.048815 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:53.049061 <... poll resumed> ) = 1 ([{fd=32, revents=POLLIN}]) <0.000294>
823   00:09:53.049096 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0Z", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:53.049387 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30H\330\300\333\352,\337i\355\2K\212L\17/\334\27#\303\357cq{B\330bi\262\365\217\264\t\235\320F8E\275\2044\215\257i\232\377\262\327h\v\333\3661T\216\246J\314\265\10rGU\360>\242\267\314gO\203\263\230}\251=\307\375bH\23\322HW", 90, 0, NULL, NULL) = 90 <0.000013>
823   00:09:53.049983 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
823   00:09:53.050279 write(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$48\r\ncache:gitlab:ApplicationSetting:11.3.0-ee:4.2.10\r\n", 68) = 68 <0.000036>
823   00:09:53.050599 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000013>
823   00:09:53.050885 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "$13765\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\27ApplicationSetting\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\1\246I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\33default_projects_limit\6;\fT@\vI\"\23signup_enabled\6;\fTo: ActiveRecord::Type::Boolean\10;\0160;\0170;\0200I\"\25gravatar_enabled\6;\fT@\21I\"\21sign_in_text\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\17created_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\17updated_at\6;\fTU;\30[\t;\31[\0[\0@\32I\"\22home_page_url\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\36default_branch_protection\6;\fT@\vI\"\16help_text\6;\fT@\24I\"!restricted_visibility_levels\6;\fTU:#ActiveRecord::Type::Serialized[\t;\31[\7:\r@subtype:\v@coder[\7@\24o:%ActiveRecord::Coders::YAMLColumn\6:\22@object_classc\vObject@\24I\"\32version_check_enabled\6;\fT@\21I\"\30max_attachment_size\6;\fT@\vI\"\37de", 1024) = 1024 <0.000021>
823   00:09:53.051251 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000013>
823   00:09:53.051561 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "fault_project_visibility\6;\fT@\vI\"\37default_snippet_visibility\6;\fT@\vI\"\25domain_whitelist\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; c\nArray@\24I\"\34user_oauth_applications\6;\fT@\21I\"\30after_sign_out_path\6;\fT@!I\"\31session_expire_delay\6;\fT@\vI\"\23import_sources\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; @*@\24I\"\23help_page_text\6;\fT@\24I\"\35admin_notification_email\6;\fT@!I\"\33shared_runners_enabled\6;\fT@\21I\"\27max_artifacts_size\6;\fT@\vI\"\37runners_registration_token\6;\fT@!I\"\23max_pages_size\6;\fT@\vI\"&require_two_factor_authentication\6;\fT@\21I\"\34two_factor_grace_period\6;\fT@\vI\"\24metrics_enabled\6;\fT@\21I\"\21metrics_host\6;\fT@!I\"\26metrics_pool_size\6;\fT@\vI\"\24metrics_timeout\6;\fT@\vI\"\"metrics_method_call_threshold\6;\fT@\vI\"\26recaptcha_enabled\6;\fT@\21I\"\27recaptcha_site_key\6;\fT@!I\"\32recaptcha_private_key\6;\fT@!I\"\21metrics_port\6;\fT@\vI\"\24akismet_enabled\6;\fT@\21I\"\24akismet_api_key\6;\fT@!I\"\34metrics_sample_interval\6;\fT@\vI\"\23sentry_enabled\6;\fT@\21I\"\17sentry_dsn\6;\fT@!I\"\31email_author_in_body\6;\fT@\21I\"\35default_group_visibility\6;\fT@\vI\"\36repository_checks_enabled\6;\fT@\21I\"\30shared_runners_text\6;\fT@\24I\"\30metrics_packet_size\6;\fT@\vI\"#disable"..., 12749) = 12749 <0.000022>
823   00:09:53.051884 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
823   00:09:53.052167 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000019>
823   00:09:53.053053 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000022>
823   00:09:53.053118 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
823   00:09:53.053155 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000010>
823   00:09:53.053192 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000009>
823   00:09:53.053225 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490808 kB\nVmRSS:\t  490808 kB\nRssAnon:\t  476256 kB\nRssFile:\t   14500 kB\nRssShmem:\t      52 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000027>
823   00:09:53.053280 read(44</proc/823/status>, "", 6881) = 0 <0.000010>
823   00:09:53.053315 close(44</proc/823/status>) = 0 <0.000014>
823   00:09:53.063762 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000017>
823   00:09:53.064114 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\333\242\206H\362]D\355\\\v\t\5\2029`H\223H\354\345\304\277\231M\354\204\26\0\220\276M\312+\265\300\232\275\372\305\253\276\227>p\254\306\375\247\202\246x\375\177\t\307\266w\314\234\236\266V\216znHg\243\t\205\270\20J\261nY\20170]\32l^+`\243O?\301\310\337UC\253\324\221\272\204\336^\17\242,r\1\324\320n\177\37\34W J/r\7/\346\305\340v\33\203\27P\376\212\240\266u\213b#\2411v\\\17q\24\237\215\21\275:\347&Vd\"S\334C\341\244\371\21\340\355G\311}\367\25\254P\3\332\5\267\234\323yWr\264RT\323\20y\373W\357\324S\236@e\3660\257\270\27,)A\34%\303\263\7Q\223\30U\220%\3721\255\241\344\236\316\256\361t\270\224\224\327\252p`\24\314S\340!\367\274\272#\24\17a\200\370\355\222\211\34p\225\365\356T\255\322\364\327M\225\242\371Wq\377\207\331\203K\6\262\250\27\f0Z\312\300d\340QI\177\241_l\336`\276\271\v\304F\17g\r\rW\374\374\370\20\223\235wCZ\334\6\231\314-5\336E1\223g\311%\336I\352|9s\22\313\220\321|\343\243\306&\10{M\36:v\277\242\177\333\1\26d\373\323\200\270\223\252\30\213\2\37\255\372[-\324\0-\277\204]l\202\257Yo\265\375\246\377\337g\375cl\271\10\360\301\347\336\177\317d\226j\271ls\272\236\275\377\240\370V\222\26060\307\203\205\3671\342\261\0\361\231F\307\26+\22\274\224\265\26=#\"\235\34#\244\314\2\333\36\nr\371{\275Z\310tI\237bTg-\335i%]iK\236\303D=\350\320MT\253f,\362M{\267\334K\337\237a7\223%\221", 480, MSG_NOSIGNAL, NULL, 0) = 480 <0.000036>
823   00:09:53.064457 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000016>
823   00:09:53.064759 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.001025>
823   00:09:53.066090 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\4d", 5, 0, NULL, NULL) = 5 <0.000013>
823   00:09:53.066360 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30I\326\377\311\304\16\321\274.U\234\217/\215\\MX\350\327O,,%:y\212i)\4\t\336\203\224\364G\rQ\376\1\200sZD\343^>\241\241\23\301\346\247\305\0e\313\t.\232\f4\232\350\221\326\260\234F\3\277\277\22\256\233\27Y#\204\363O\37\264\231\5!\234\277\320G\4\321\276\211\33\207\214M|4\332\315)UE\254\323\35\252\337\t!\1778\0040;\217\231\261\326a\345B\340J\345\337\216<<\35p\360\257\276\374dP|\r\"K\376iY\337\37W\375\215\327^\223\1770&\252;\323t\310\222\n\334\0104\340\257\310\224\2208\336\301|\35\310\322`\3678\323{\224h\261\300\367\212\rW\332\361G\243G\205\340\372\v;\325\313k\200o\fh\374s1s\1\222:\236y\17;\360\350x:\377\373\325X\304\3[Jo\354,L\235Ta\\\6\7\242\326{p\263y\373t\24\7VG\236C\3\211\227\327@\300KL\367.\373\16\1C\32\257\330\350F\255[a\305\275\377\35\331&~i\231\370\325\353\24\361\0053x\362\22Z\1\302\5\251\324\21\317\221ZS\346\r\355\255\31r\360\16QF\353\3375<:\r\311 \223\2022-U\223I\262f/\334\215\275\4\216\207\6\323\34'\37\357\3658\215\237\267\23{Z\200\v\216b\244z\371\230\27s\4p\216\32u\342la#\324\34161\305O\246\225\224\241\252~#\352\4\27\355\27\346]X\314{\322\230\7\200\272\362Q%]\260\r\313\217J\204\37\323\177y\36&\337;\312\202\363#\227\251T\301K\362\n\377@\305\332X\233\350\17S\271\204\2728\37u\331\365\20\232j\26\211L\344\316LK`\331\177O\376-\306\317\366M\320/~\372w\7\366\360b\272\275\240;\332\t\t\377\7&@\312\207n\230\236\1\371\253YcQb65\340E \"T\213q[2\36\233\266\251\210\t\346Mx\221\344\222\250\307)\360\272[\265\223\371\274\247\243_\314G\333\221'\254\367\202Of\203\27\350a\245B]Ig\2\212\222\373C\2\314YB%\325\2209z\256&\21\213\22Vin\260\n\352\23\244\211$\"z\34\202\332\32\311\214-\352\22\365Y\272\205\2j\322\221\323\312\355\331\305\22o\332\235\327ZL\257\267+$0\354\"\207\376($Y}\256\233t!\2\257\352\302IHU\221\350[\263`]\307\326\30\32Sb\347\350\346\332\r\302\201\316\23\36\225*ynB\317\272\307\204\v\177\330\275UF\30\304\307Fn2h<4\17\31H\312E\325Gv\242\367\362k]QB\20\206p\322\241\5\245\312g\2\275[\30\252\177\325\235\254\237v\210X<\212>\24\241\374_\34\213&\\\366\364}\247M1\320\304\306\337s\0029\263a\340\340ay\330M|\270\264\205\236Vg\352\0359\350!\"d\343\250\217Q[\370MAu(\n\265g)~$\31F\35\267(\211P\226\375\316\312zf\271\227k\0\331\275`\2722~\355\r\10\250O?\243,mu\247#S+\5=\326\223\357\354v\335\251\366\26z\365g8Y\230\220\347L\10^\3039\324\224{h-\376\3249\227\teb9\246\237/\336Q\314\217p\241/\272\316\353\211\256\303;\372kq\227$\371\37\253\315\360&\nz\252\344\352<\261{\317\304\236\200\350\216q\237\177f\4j\277\301\327(\347\273\273v'@q\325\363\371+\1@\6+\v\311U\344\241\rj\264\331\350\255Z\242{\t\325\3279\322;\343\314 \205+\177R-\336\35L\244\361\0209\21\264\300?\224\33\t\241\"\2434\37\200w\2314\2072\216\370\r!\272\336|\33\222\214\2j\362\270_\23\24\322\3071j\275s\360}\354-Uz\16\371\352\372t&\3\252\273\361"..., 1124, 0, NULL, NULL) = 1124 <0.000013>
823   00:09:53.067691 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000016>
823   00:09:53.068020 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\211\242\206H\362]D\355]\303\220'd\335\363c\0079G\265K6R\311G\n\213\372\37zmA\217\337;\302X\304\227\201dh\325?\332\312\22:\225\261\267\272\350\340\31\375\354\335a\v.@\304@9\244\314\370\4\r3B\335\"\32V\274\270\207\253\235\23\274\2407JK\256\\\251wN\321m\342\330\317\23Z\23;m\\\352\245\330\355(\377q87U1\1\350\350d\344;\307\211\300\361a\335\204\356\255\32\317\337\34\357\336\376\300\215\360\5\34i\316\371y\213\3532c\217\212\322I4\f\21^wUh\304q\222F\204\233\351\355;C9f\0242\331_P\36:\244\236\226\367\306\2TU\336\3\v\360],\302\0\326\371\36\261\267\356\371\351S\315\301\21;\250\332F\304n\2(\236\274<\313\2or\232(%\371\0\"5h\242\n\352a!\300\344\260\333\260o\357s \21\34\324\363-\317w\330\363\270\23R\210\256\34`O\242\v\323N\277\243\204\375\363\226\32\23{c\0\312\215\266{\0\5\23\352\326o\372?\0266\257\245$\221%EM7+o\303j\0\362\213\201\337\204\20/\254@\357+\263\"z\220\r\201\222p\214/\363\327\346\31#\3469Z\245\362\327f\253\213)\243\3326y\377d\362_\301\273\262H\0\312!\257\23@\277\265|ZP5\231\264\304\370,\26\36\26P\365\254PGN6\264\6\267\304\377\202\254\351>&\224\26\265\243fd", 398, MSG_NOSIGNAL, NULL, 0) = 398 <0.000036>
823   00:09:53.068354 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:53.068654 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000277>
823   00:09:53.069216 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\4d", 5, 0, NULL, NULL) = 5 <0.000014>
823   00:09:53.069510 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30J\365\37\305\222xY\340\243\16\304\371\332\237PfD\336\6\375b^\33\256\312\35\251\316s\204\331\20\362,\347)\fa\360\370-C|\202\254\200\225\351\274o#\177w\340S\267\0\214\224\364\211\27\3\262'\352\242\220\23G\6/[!\213w\35\334\7\257k\6B\200C\200\202\331/6v\177\315+\346`\254\203\267\373\314\2\243\205\r\222mO\247t12~\0QR\202\203\10\363\237m\223\10\344\26\307\6^s\3465\257\227\345x\213&\7\331\260\17\305\301\301\314\331y\335\371\241\332}\343\r\226\16\250M\220W~\3350wH\377\254\321\351\7\207G\310\202\311\374i\301\316\313\262/\220\344\213\357\25D\311?U=\224E\344\233\17\332\323}\271\210\302!\354\314.\20(/\232\356e\0264\202\355in\5\5\2168'\24W\313we\233-\365\35\0034!D\231K!\36|\201\337\10\257\230\375\4\210\373(m\335F\312\343Pykw\33Fd\202\24\245]\7\347\275\240\30\354\33\244\306Q\256$`\214\215\304\305\267\232\32@V\4\236\316\10~j\24\315\220\17*\227\205w%E\23\342kd\27 \230\372P\16}r\372\314\27]\253c\272\350\203\326\321\260\323\315\10\24I\376o\316\tX\337\377\17\306\321\312g\2511\300&\305o\0\316\334?\250K\227\276\3040\21\304\7}5\236~\304%\26t9\360\25\375<\277\244\216\274\177\3U\261\241y\16\276z\\\313\326\6\322\375\222\217v\v\243a\231b0se\20\207\23\261\235!\231M3\10a\217\253\256$\214`\234J_\3429{\16?P\277\\\265\253~\275\372~\350\335F7XV\225\2\340\322\215\346\231\274\214\317\3\215\316#\31Ig\21}\315v`\216[D.\25\251\3342\352\31\303\361\207\2504b\336m\266\262\374H\214J\3323\3\25\325\323\v\204\205\240\334\346\217n\31{\"\205\213=z\16%\355\255\226\3732\0101\347\202\377g\316\272R$\323\t\202\221~\333\362+\23`<\325\1'0\251p\177\234\223\377\7\312V\244\347\363\351\377B\227Q\212\23\200q\324\303\241.:|a\177\35\323\263(\300\374x\21\230\361[\"\233\223xMT\253\357\0\341gMB\306b\10V\235$\377\274 ~\4\321\356\370\3305\30\370E\243\311f\371\200\373\311\261\265\v\355a\234G\16B\215\315\357D\3m\321:\200m\303]2\202\320]\35\321\17\263+;\345\376\4\372P`\212\305 e\251\374\250\32:\37\226\216\276\345}X\330\24\262\344\10@\214O\324\32C\367\30\325;b1\7l\224O\250\346\327 {Z\217\\\237Ti\270\224\371*4/\257\362D\327\22\213\23\241\225\272\3\273\2\20\367\314\205\236\362\325\237\345\212y\365n\346\307\205\0101\354\260\371\r\265\210\v\330\37\3067'\254\277Z\200\354\303M\360\255\340\207\2\246\10\200TT\2445Axv\25\365X\344.x\20\302\27\267\213a}\212\313\233AY\fM\275\27\23\22\263\230\266h\373\177\377hPB\36\251+jt\305\35`;7s\323\2040\246by+\275\3248r|k\320\334Y\3249\332\236\325fj\317\310\315T\301\362\321\304]\24=K\363~\246\277\342;\307)}7\2729\266\244s\240?\6\31\311(\203&\322\6;\353T\313{\262\377t\312\37\245|\254\233\213\2553\231\344\324l\231R\264l\2\337\20\20\231\"\303wm\31m:\255\247,\32kQ\4\275\326\262\223T\202\203\301)2\362`\200\243#\264PL\340>\223R\177\207\314=\0\362\t\301z\210D\302\n\204i\5\333_\250\3377\365>\307\25p\265z\202\224\351$?\fA\363SZ\331\201e\317\370\1\2544\204c\211\365zF\371+b\273B\277\304\314VX"..., 1124, 0, NULL, NULL) = 1124 <0.000014>
823   00:09:53.070809 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:53.071138 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1j\242\206H\362]D\355^}\367h\357|K\236Ozg\320\351F\272\2721I\32\244\215\343\243A/\366\"mf/\320'\36\2118\1:\307<\4\227\2\214\344\24\225=\31\2632.\252\360\356\250\200\271\237\257\323\24\372eCU\27\244A\227\24?4Q\r\23\264\27\3242\336v\223\310\237\17EE\337b\211\316=\222\222h\5\35x\360|k\210\7\330\331\334\355\220J\271;&\270&\373\315\252\235~\364\212\272\253laq\316\v'gi\201\343@x\"o\0364\204a?\217\345\303k\356IS\256'k\257eQ@\361s\357\253\225\341,w\356\221\t\\\253\327X/\21\311\236\232^(\243\25\314\3\265%\26\234\"!\221\326|\316\206\372\273\346\242\215PL(\243\262=\257\347h`\26f\375\205\340\352\257\370\334\310,\347T\314\274\310[zia\225\316UQ\342X\216\36\315\225\246p\16'Z\243M\324\331\241Sp\216\320C\263\347\331\37*\357Yt\313x4?+\212\26\301d\257i\252i\236\24\326\3\276u@\301\n\370\341\r\3633{\214\227\310\0000\213\320v\205\177\36O\20Y\361}\366:[\326\232\317\264\242\341\364\231\246\21!\345}\16\256\326\177\375\345\266\227' \2769\370\34\223\275 \340\26N#\323\276\257\6\17<}>)\275!BU", 367, MSG_NOSIGNAL, NULL, 0) = 367 <0.000037>
823   00:09:53.071473 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000014>
823   00:09:53.071797 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.001094>
823   00:09:53.073174 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r0", 5, 0, NULL, NULL) = 5 <0.000028>
823   00:09:53.073452 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30K\27\276Q2\303\304K<g\206\374\211\210r9\327yQ\17\7\222\376m\364\261kl\27\202m\221\322\326\230\2\226P\302(\333\364Q\6\270%\266<GG+\261E\346\307\10\230\247\33\250$\314DM\222\332\203\230(\22\2405\205%g\31;\301)\16S\234\365\364\r\23\350\240\203\354\247\220\235Q\302\20)\24\257H?\34\255v\215mm\222o\367\253\304\340\33C[y\235\342\342vx\223E,'\307\370\360\352\1w\223}[\363\27\314\253\301\r\361\375u\312/\201\26\20\371\0V\346\352\277\222\f\320w\30!\304f:3`)r\267\373\3503\336Q$\234\363\vP-|\247+[\242Q\212;\344\315\4\266.\20K\267\3654\275-P\262\325\360\2\266\241_\r\306\271l\337h\f\210m\357\277'\30\204\270Z\n@\177\200\317!\210\22S\266\327\332\240\312\340\313a\227\3648\276Uzja\243XL\262\231\26\373d\214\231F*\213\266\246\230j\3311&YKN\4\32\3227\3\313\31/\205C\215~+f\337\231p\t0|\2\31\314\236\341>I\237\207oi6\200\347cS^;Q \326\265\23,9x\222\267\264OO7+w\327\277\205\276\30Ep\200j\261\243\253\342\27\375\261\203H\330\200\302`?\v\246\234y\363\241</\265\234\356\367\2359f\200\377\354\211q\342\327n\324\6&\r\373\210Wx\30\33`\342\354\334&\272\201zOKk\323\316\345\237-X\37414\354\322\2\247\266\237\25,\223^\356_\0223\34\32=\33C]p\253\240\"<\272d\372\307\351\361\276\2211?h\302\371\270\371\36\f]\2571&^i\310\22\306'\275h\3161J\334\254i\367\341\210\4\16\327\251\16[\326\307\7e}\241\225rp#C]\353\336\235SM\t\203P~U{:\2459\17F(\f/\325\344\210\300%\330\"m&M\320\262\226\272!\331\230\304\3152N$M\v\224?(\301\6E\236(@\35\314\345\375\333\316\3063\366\321(_\25q*\367h \10O\265\373\262r\314j\3\251\261d\202O\356\270g\251\200\257\264_\26\245d\264\7p\373\22Y\254c\331A;\276\245{V\v\263\263\33\252\t\336`\242\3\270\212\341\323X\253\367\364B\322\0036c\245\20\227U\235\2k\222\212.>~k\343\235j\230\10\372\266\215\216\201\231\277\2\345\375\36&\177'z\214\22;S\363\253\364\2673\206\362\0h@\206\332\364\240\24K~Y\370\346\223\26J\314\363+>C\31\227\317^jC\322\263Z\242Nl\371\303<\0\262%9yk\34762KXV-\23\264\267n!+2\206B\222\204T\376\304\374\224 \206\0Jw\232\5\335\211\35\236\237\367_n\t\201\363\201q\321\272aH;\352C\312\257\274\206\251~\234\37\316\26B\373\372\307\313|\321Rw)>C\351\270\34N\201\307X|;\226\364\242\236\272\227\372\216\242TXq\270fze\243\25\306\363I\232Tdi\312\20\217*\2033\270\0247\347\221\301\352\305\0201\357\340.\204\37t\333\363l\370\326\344\373\346\207\322|vah\36\214Kkew/\270@\372)\316\200/\203\364\220\262\2\213\314\275\272roC\243/\230\v\322wd$\272\263oi\224\v\247S\250\203\365k>\351'\365\327\3\337\330]\334\322\5h\22-\214\231\262\25k\367[\377HKO\213VQ\272\234\23D\214\5: i{\37\273\200\376\32c\216W?\326Z\377\233\211\252\322\32\312\5\304W\367(\222\5.\336\203|\371\177Y2\362\201\245\322_ ;\3318<\334'OUB\212\231\33/\313{ \20Y\271\362!4\2\271\336\257O\265\r\247P\2210>~uHN\223\242q\235T\352a|6\353f"..., 3376, 0, NULL, NULL) = 3376 <0.000017>
823   00:09:53.081631 write(8</var/log/gitlab/gitlab-rails/production.log>, "Processing by Projects::NotesController#index as JSON\n", 54) = 54 <0.000026>
823   00:09:53.081739 write(8</var/log/gitlab/gitlab-rails/production.log>, "  Parameters: {\"namespace_id\"=>\"ealoc-engineering\", \"project_id\"=>\"loccms\", \"target_type\"=>\"merge_request\", \"target_id\"=>\"2114\"}\n", 129) = 129 <0.000018>
823   00:09:53.082412 fcntl(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000023>
823   00:09:53.082665 write(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$47\r\nsession:gitlab:e3db34af92ce75a754809c69bbc89e42\r\n", 67) = 67 <0.000047>
823   00:09:53.082925 fcntl(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000017>
823   00:09:53.083127 read(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, "$286\r\n\4\10{\nI\"\rsaml_uid\6:\6ETI\"\24ccraciun@ea.com\6;\0TI\"\27saml_session_index\6;\0TI\"*_9e8f6987-2d37-4694-ac42-e9c53e929094\6;\0TI\"\31warden.user.user.key\6;\0T[\7[\6i\2{\1I\"\"$2a$10$c8YgmOQm12hm4leSpZCqFu\6;\0TI\"\20_csrf_token\6;\0FI\"163mrP9pqgi821T+KhvxUmtGB3KLU7jUTDKNvfkRmpdo=\6;\0FI\" ask_for_usage_stats_consent\6;\0FF\r\n", 1024) = 294 <0.000022>
823   00:09:53.084033 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000017>
823   00:09:53.084409 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\240\242\206H\362]D\355_\314\r'0 x\302P\247\374?\35\343\364\n\310\25\254\7\250Q/i\243\210\271\345\260OY\301\373V\211V\311p\2448F\304\226\351\263\22\205\271LZs\20\3@u<$4\232\367\316\7\347\211NS\24\204\331\346Q\372\330\253\3,3;\206\n\213\357\4@\214\343cC\214\274;\225\220/\37\200\352\315$@\364A\3479\347\270_;\244N\300\"\336ct\265\201\354\357,w\341\241\7\325\364\304\373`.=\246\315l\32\360\33B\274\10dW\201\221\272?\6\361n\fEY\277", 165, MSG_NOSIGNAL, NULL, 0) = 165 <0.000037>
823   00:09:53.084750 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:53.085050 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000263>
823   00:09:53.085612 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r8", 5, 0, NULL, NULL) = 5 <0.000032>
823   00:09:53.085929 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30L\362\225\230\201\352B\277\27$\\\252\4\240$q\210\344\252\222K\nqM\366\212\370\336%\306j&M(\320}\357\264+ygW\345l2\33c\365\272\343[\244\337\367cW\216\227\306\206\334\302pv3U\243\334\27Qt\225P\7L\315\333\375\204\243\0\367><\264\222\335L\32@!XG\224U\201\365\342\177Du\rF\276\275\373\302\212\202\372\35\35245\374\17^\221b\361]sS\236\301\367\257_\1\317d\276>\27\252\25\267X\243\345\v\322\347\270\306cI\344\214\250V\362\275\243Z\226\232\277\273K\321M\357\4\315\362n\215\272\322\1\24\330\267\344\223\271t=\232.\310\274\34\26hg+\3{\35\322\247\307\1\373\0027~_j\234,E\235\306\253\272\3273\236\300\2655\327\242\223\342\3:^\265\304\311\277\215\321B\225 \rH\245O\22\31\305\231m\360\350w\303\263\264\262\34\216\337r\362\360C\325\267\223Ea\372\334\2\335\201\362ic#\35\244\17\222eg\34\301\f\1\342Z%\364\"\n6\274A\272\fk\262\351\347#\25c\242{\376\346bf<gf\26\30X\2268\372^\200\307\205\361\201\234\337\37790\372\335b\10%\264\370n\r\324\323\260\213f$\233\16\217\336\251\31\312\231(O\352r\200n\261\323l_\3\310\233\351\360\0\3\333\266\263\211r-\202g\200\331\240\r\200_:'\0\303\204G\240u\310\210G\356%%\304\255/&Un\201\210\321\250\322\305\375N9\303\235A\267\205n\375m\5\345\230\\\201\241\16\16\25\23\305\270E,3\372\2123;\6x\6I\2\23\211\350?\310\20\276\247\365\235\320\7OHv\331\211F\266\212\341\37\v\363\204\2217u\227\307\243\247\31B\216\22\365.\352\277\215\360\223\1\270G\345\330\271\216V+\343\341\225LCE^\356\2\310\276\200\207B\327\266\220\274o5\324\227\23\305\310g\5\277\236Tg\230\242\245\253E\207\215w\16@u\0229n\2\10\342\n^_30BOF;\224\317h\16\0103\226\236\243\3233\210\27[\351he\3277\365\357\3771~+\333\3453'=2\332\274\v\377\302r\351h\322\3\21\256\341\205e\271\5\321\221D\r\377l\3462m{A\311\255s\3\2425b\244V$\333#\0205\363A\345\27\305\364(\357\342\302\305\5\252q)\351\226\236e\265\273\210\345\23+u\306\202\275\33\334#\352\356\264}\244c\375,\362\213T\247dR\37o~\6\21\0302\230\3758\337ESJ\25$\310.\336:\16w\33\264\232\366\236\r'\17^Z\303\217\371*-\247Z\3721'Q\307\365\341k\215\343\264\322(\3337\2\4=\302%=\333\314\214\217\217Z\25\371\316\305\234\227\27\240x\344\264Nk\216e\337\265C\35\nBmk\n\23\207\340\244F\353\207\352\2-\31K\372\220\204\306\3354\210\303d\271\256\302\260\350\212\264\320Oz_\324\221]\311\207\271\316\263\10\337\340\214\377\354\352\354r\272W\200f\342G\224\323}\360u;\246\343\0319La\374\327:\310\275U\0214\303\vD\22}O\302k_l]\301?~;\331C\336\25\373\310>\364\200P\277*\375\3513\200\331\306c\6\353\17\r~\310\363\347^sSJ{\f~\245\342\345\f\326\322h\17_\370\223*\1\315~\233\336[y\235(\344\34\25]&\345\276\243<\207\307k\22\224@\351\351*\257\26\224\332u\230\366\227\331>m\365\r\36\3703\2459\373/`\24\366\212\367\255\31NBD\345-F.\0259\376\201\243\243\21\371,\310\230\226\33%w\217*\301\316\330\3265p.V\324\271T\v4\326SD\344\6b\271I\217\360\0074\366r\3\222\203 =O\245\2\246 \377\247\307x\16\311\363\332\353e\247n"..., 3384, 0, NULL, NULL) = 3384 <0.000022>
823   00:09:53.087710 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 49070132}) = 0 <0.000019>
823   00:09:53.087788 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 49109073}) = 0 <0.000016>
823   00:09:53.088579 fcntl(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000021>
823   00:09:53.088891 write(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$56\r\nsession:user:gitlab:379:e3db34af92ce75a754809c69bbc89e42\r\n$6\r\n604800\r\n$361\r\n\4\10o:\22ActiveSession\r:\20@ip_address\"\01610.7.7.46:\r@browserI\"\fFirefox\6:\6ET:\10@osI\"\fWindows\6;\10T:\21@device_name0:\21@device_typeI\"\fdesktop\6;\10T:\20@created_atU: ActiveSupport::TimeWithZone[\10Iu:\tTime\r\16\243\35\300\313e\316\246\6:\tzoneI\"\10UTC\6;\10FI\"\10UTC\6;\10T@\r:\20@updated_atU;\r[\10Iu;\16\r \243\35\300[XQ'\t;\17I\"\10UTC\6;\10F:\rnano_numi\0022\2:\rnano_deni\6:\rsubmicro\"\7V @\16@\23:\20@session_idI\"%e3db34af92ce75a754809c69bbc89e42\6;\10T\r\n", 459) = 459 <0.000040>
823   00:09:53.089238 fcntl(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000019>
823   00:09:53.089534 write(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, "*3\r\n$4\r\nsadd\r\n$30\r\nsession:lookup:user:gitlab:379\r\n$32\r\ne3db34af92ce75a754809c69bbc89e42\r\n", 90) = 90 <0.000035>
823   00:09:53.089889 fcntl(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
823   00:09:53.090184 read(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, "+OK\r\n:0\r\n", 1024) = 9 <0.000024>
823   00:09:53.090962 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 50572719}) = 0 <0.000018>
823   00:09:53.091849 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:53.092180 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\312\242\206H\362]D\355`\304\243A\305\177\211\237 O#\274uA\v\324\254b\374\336\35\233\366\22\337\337f\3\253\217\327\361A\330d\3442Pk\320\320\6\10\204\0049\17\26Z\322D-\222\257\3\23\377P}s\277P\357\364\312\301\234\n\357D\6\206`AK\221\217\23\270~\316]\v\332\3137\211\324M\5i\373\212\347\26\33X\356\253ab\372\341v@ \23\312t\3759\26\352\253\312\271\0057\300\\(e\230\7\243F\335)\201\22\335\216\233\324\273\315;C\221\252\202\345\337Wb\0\10\25\252\25h\326\26K\37\231jg\253h\237\275\361b`\363`\277\240\0\3767\213\271\273\2064\374\211\220\321\327\223\216\\k\314_1\211\303\325\301\375\211", 207, MSG_NOSIGNAL, NULL, 0) = 207 <0.000035>
823   00:09:53.092504 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000014>
823   00:09:53.092803 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000018>
823   00:09:53.093127 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0_", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:53.093419 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30MP\217\254(\2646\21\310\357\323M\342\255$\235_gp\352\234FV0\221\264\2153\371\303h\225\0079\223J\206\347\272\304\6\33\"|\355\235\377n3\36\334\362\265\353\227\233m\246U\304\210B\246d\363g\264\355s\0312\206\306\3@L\337\2166\244\214\305A\302\21\202\221\26", 95, 0, NULL, NULL) = 95 <0.000014>
823   00:09:53.093862 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 51730301}) = 0 <0.000012>
823   00:09:53.093936 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 51777757}) = 0 <0.000013>
823   00:09:53.094410 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.094736 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\312\242\206H\362]D\355aD6\337\316_\274$\200\334\33\0311\242\367\17\344\16\246\3009\276\330$Ax\343\4\226b-\217/\234\241\270\344\21\263cy~j\177\341\f\342\26\330\27\224Ko\351O;\1\225\276\325\361L\327U\3506\351\3527\340V\244\270\243I]\372\271,\2270\212\221\260fw1\223\30\35\204\24gf\r\364\262\211\311%\277-\225\363\t\304\275{E\205\\yL_3=7\204v\263\251m\30\10>\212f\236\t\350k\337\nl$*\332)\307\366\rgg\3414l\253\363\370&\211\232\361\265\264A1'\364:t\10\207\322\254\200oU\5\301\245\377\307\221\247\n\300\320\24\0106]\254\325\234\213\203\0303b\240\247\274&\356", 207, MSG_NOSIGNAL, NULL, 0) = 207 <0.000034>
823   00:09:53.095060 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000014>
823   00:09:53.095370 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000022>
823   00:09:53.095743 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0_", 5, 0, NULL, NULL) = 5 <0.000021>
823   00:09:53.096049 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30N\354\23\f\364\267\231\177\217\10\210\347\264<2x\rMp\241\23O!m4\355Q\227Hy\240/r\37x\240`6\360\25\260\36\357D\267\267C@q\272GC\6\22\255\233\372\352\321\243\312\222\242F\214ar\3/\212\375a\261\311`\342\3025\371';\202Q\17\311t\1\365", 95, 0, NULL, NULL) = 95 <0.000021>
823   00:09:53.096481 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 52549470}) = 0 <0.000017>
823   00:09:53.096557 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 52597286}) = 0 <0.000015>
823   00:09:53.096610 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 52630023}) = 0 <0.000015>
823   00:09:53.097054 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000024>
823   00:09:53.097389 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\312\242\206H\362]D\355b\302\323DZ\243\37W\3404\224Ns\261\264\306\260\r\215\27\v)>\343j\365\236#\321o^\34$R\344\20\tR\265\355YC\177\225\262F\354})Ok)\252;in\17\227\352\307\257\325\223X\261W\313\1\375\210\302\32y\2505\26\367\363\224\371?\353\24\30\220s\324DJ\366\23D\201/\267\275X6\314\242\35`\356@9\3`\241\245\3209\24C\245W\241T\313\3w\f\355\367\251\310\16\37F\\o|\267\337l\276\5\217\270\363\230=\300\301\35\10\7\364?\260\270\347\340\212~\324F\201F\242\363\242mH\24\350\253\20F\335\325\317?\266\367\211_ZW\22\220\0022\247\212\362\250\260\234\260\177\32M\326\205p", 207, MSG_NOSIGNAL, NULL, 0) = 207 <0.000038>
823   00:09:53.097722 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.098031 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:53.098364 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0_", 5, 0, NULL, NULL) = 5 <0.000022>
823   00:09:53.098669 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30O\200\316Vm\220\rI\3653\32\v1\255\262\257\310'\277\216\331u\357\"\30o\256wye\4\"\\I\330?\254U\2762p\324\fhfkP#sH\273c5}\23\364&h\274\24\320y\327\2270\315z\360\305A\314\327E,9\302\213'\371\2270,\306\343z\2104J", 95, 0, NULL, NULL) = 95 <0.000021>
823   00:09:53.099093 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 53378144}) = 0 <0.000017>
823   00:09:53.099255 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 53511583}) = 0 <0.000017>
823   00:09:53.099403 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 53628839}) = 0 <0.000017>
823   00:09:53.099463 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 53664926}) = 0 <0.000015>
823   00:09:53.100686 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 54863556}) = 0 <0.000016>
823   00:09:53.100750 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 54892771}) = 0 <0.000013>
823   00:09:53.100895 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 54989565}) = 0 <0.000015>
823   00:09:53.102405 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000022>
823   00:09:53.102736 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\221\242\206H\362]D\355c\17q'\351\346\30;\320\314\34\202E\363=\206\f\34i\r\353l\23RT_\351\254\275\342\356J\313\337\355{?\20\v\22vF\275\252>UN1c\31\342~\352\v\312\371\t\277\221\260\3$e\305\271S;\33\36u!\263\315\205R\262\361s<\3iy\300zLU>\346N\357\371!BS\242\241\277\306s4\375\244\212\332.R\364\220F\315\236\20\216\321\f\252\0\23\257Z4</\341\34\246t\2\241_oI<\277\221^\267\350", 150, MSG_NOSIGNAL, NULL, 0) = 150 <0.000035>
823   00:09:53.103063 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:53.103362 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000015>
823   00:09:53.103704 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\7\217", 5, 0, NULL, NULL) = 5 <0.000030>
823   00:09:53.104021 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30P\33\307\377\354\271]q\316\177\357B\324>\345\203\352k\343>@\253\205\335T\216\256;\271\17D\276D\237\271\0\n\261\3203\312Z>\25\334L\255u\360\236\324X\303\20\311-\207K\275\331U\221\"A^t\307)\237:%\215\220\352K\2639\375ewI\274\221Vi\232i\320\177f\316\240\3\370\\\246a\2578\201\10$\254\34\\]/u\260.&\6\364\256,\204\355\0*M\204\302\310oR5\362i\325Gs\306\371\nj\5D\365\307\310h\240\310\304\277\340\256T\230\327\216\254s\4\321\310j$\216T\261T\331u\2139&\33*\346\203^\327v\345\243\344\214vJ\\\211\315&R\203\245\v\24\234\354!\34w\24`u\314\341W\255\346\t\204\325KGF\26\360\20\314p\352\v\256\2553\275\10\370p\376\5Y\240\4+\224\3644\354\217\270\246\376\371\263\25\25\264\230\351\361H\33\377\264I\2\4EiX\325\v\6c\364\335\25\306\245X:\354)\267\362({\2728Q1\240\231\22\313\250\251\352\342\16\206p_\320Jmn\245\233\326\233t\213\214\247$W\364\352\266\3452E7\364'5\24\254\375\23]\227\217(\223\2708a\356\336[\242\325\216\257\267\v\205\th@s\245W\f\223\0\314\303\0065\376\324IrZ\23\237\347M\33\25idh\301{\203\3432\316\34\357\200\200v\377\362\304?\3660\237'\272\365\252\206I_\246\322\205c\213/M:\2112\213T\347\243\16\312 \216\253\275\216\345\20V\320\226\0362\340\356c\303\361\206\362\365\33*\210\200\355\257\346B\356iWx\333'\371\317=\211\301iC\251k\332y\3213\271\327l\360\351Z\361\330\27\302\24\271\210\317Ff\255\377\31\356\346K\376\361\351F@\275`\352B8\367\200d\340~\242\3625}\23\n\376&!(g\245w[\213\215\331\367\23\320!\r\212;Q\323\256$\314\233nL\331\336M\356\332u\225\0\262\6\332\351\276\274\317\243\343%gZv\3169\t\260\0378\335\3536\343\335\16\207T\24ML\n\277\2566X\262\344\220\376t\235-\206\343?\237\222\370b*\221\333\213\202\360+k\205\345\30T\243\231\224ow\342\22zo\350\31N\f\flg\237\26\213u\377\350\23+\333\342#\330\217\7\2EH\3;\223\23Ti5\361\316~\326\326c\311[\34r#, +\373t\312\264\333;\312\3270A\32\25i\330\32\275O\364(HY\242\257\352\27\264\26\307(\3\351\215\306\227\24\270,\264&3T\267\263h\202P\33Q\253\233\303\276\n\323\315\366B\377\306M\231P\351(\362\6tg\225\6'q\270s1\273\265\360\3154\350\315\323\vU1\326\313b8;\353\365\203\376\r!\262 HX\222\222\315kd\226\24H\246o\344\274\277]\353\242\320\230\334\241N*,\263~\1o#\334\207e-\223t\247x\300\221eF\32cn\355\214\v\355AW\254\4\265\205\351\16\252\223\261:\17\10\364\245\235\363\362yK\267\211\vS\327\236\357B\25\230BS,\247\326\304\370]\276\364i|!\370\373\375\37mgyc\267\200\364\3305F\2015\311?c\216K\300\5\271\300\275\245)8\257$\376c2\304\244d\226\204\350O\374\273Y\36S\241C=\335\314\377$\34\3657\226\225#\245\34&?u\341\37\30\246\34`\266\307\2744\207d\335\213\t\354\272\246\233*\17\301\237\317\16\365/\240A\\\364I\341\246r\310s!\232\334|\260\362Q>\246\27\346p[+'\344\26\3644\322o\235\213\0325\357_\261)6S9\237\213\375\222\235\2263\352|`#)\\)\377\364\335;)\210\36\343\370\230\277\n\332O\236v\301@N\3\311\325\225\322\374\316\26\342\363\346[v.\363\361\237W\254"..., 1935, 0, NULL, NULL) = 1935 <0.000016>
823   00:09:53.105030 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 57351082}) = 0 <0.000015>
823   00:09:53.105504 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.105833 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\266\242\206H\362]D\355dy~\24\22406\2\361\4A$~\213\216\23\36\n\7\211\267n\227\371n\314\236^\241\230\225\345\370~\n\2\325\352\204c\230\305g\353;\203\206\350&_WiK\373\272\214}@8Cs\32\232\266VT]\344\247_\"#\203\361\377i\205\337\2545\275\327u\350\323^\16\262\214#\376\354\205\325\374I\377\263\240\207\230\237\6:\272\331}\257\257\240\205e\256\267\372Z\217\337b\336F\327_R$\32\315\245\326\222\255\322%\307\220W\303\350\257\35\367\271\216|\316\3768K+\260\300\30\5\254\334\251\4P\210\276\301\322a\0\230\262\22s\20\23\273\232Xu\342", 187, MSG_NOSIGNAL, NULL, 0) = 187 <0.000036>
823   00:09:53.106159 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:53.106460 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000017>
823   00:09:53.106783 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\213", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:53.107105 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30Q\373b\201\237\235f3\301\226\256\25\362\261\f\354\31\360{.m\254\7\263\5\232\31\372\356\203\274@p\227\320\32\305H\t\313\v\366\21\334\5Ym\357\211\223\211\247\267p\202\240v\1_+\31\344\354x@\215\243\3529]\222y?N\330\264_\305+\1\355\357?\27|\274\225i\273\263SA\310\271}kH\30\17\2275\371\\\4vc\235B\t@\365Eq\256\16t\npm\377m\206\317@\221\327\232\340\6\303Bf@\230]x\206Mb\260\2\v\203\272\16\357P\252]\313X\241\330v4j\201\227\272\325P\37\305\24=\236:\20$E\324(0v\32\4\300\242\340\364R\301\267\346\210\301\237!L8\214\377|\262Q\372\250\376h4\246=\222\352,\255\33k\354\351\331\323i\5\267\f\212\220\231\36\331<\26\252\310\316\324\337\24q\207;\217\243\306\10\256\246O\22\2125q\264n\370\340\4\5\323\310-\22\232\376\315\267$\207G\6\33\303\327\350\250\205\330H\260Py\206\252xQz9\362(r\27\231\373S\221\225\242\306\324D\22?\0045\30\16\273\312vrp\304d \253\203\206\335W,#E.\3\225\"d,\303\372\210\345\223\21l\272\202\216yS<\236t\330\346\233/\301!\307!P\346\375E\37;\r\1#\267\21ou\372?\261\211\220?`\213\367L!=\361\305\341~\250h\274\247\272E\34w\353\207\r\227\247r\223c\343", 395, 0, NULL, NULL) = 395 <0.000024>
823   00:09:53.107869 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58429971}) = 0 <0.000014>
823   00:09:53.107924 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58452208}) = 0 <0.000012>
823   00:09:53.108122 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58631094}) = 0 <0.000011>
823   00:09:53.108167 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58653498}) = 0 <0.000012>
823   00:09:53.108210 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58679613}) = 0 <0.000012>
823   00:09:53.108284 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58736664}) = 0 <0.000012>
823   00:09:53.108322 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58757032}) = 0 <0.000012>
823   00:09:53.108372 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58790202}) = 0 <0.000012>
823   00:09:53.108411 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58812821}) = 0 <0.000012>
823   00:09:53.108447 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58832589}) = 0 <0.000012>
823   00:09:53.108536 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58905168}) = 0 <0.000012>
823   00:09:53.108577 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58928591}) = 0 <0.000012>
823   00:09:53.108617 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58951268}) = 0 <0.000013>
823   00:09:53.108655 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58973390}) = 0 <0.000011>
823   00:09:53.108697 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 58993639}) = 0 <0.000012>
823   00:09:53.108738 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59018743}) = 0 <0.000012>
823   00:09:53.108773 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59037131}) = 0 <0.000013>
823   00:09:53.108809 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59057131}) = 0 <0.000012>
823   00:09:53.108847 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59079061}) = 0 <0.000012>
823   00:09:53.108884 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59098901}) = 0 <0.000012>
823   00:09:53.108918 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59117191}) = 0 <0.000013>
823   00:09:53.108952 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59134706}) = 0 <0.000012>
823   00:09:53.108986 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59153034}) = 0 <0.000013>
823   00:09:53.109024 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59175214}) = 0 <0.000012>
823   00:09:53.109060 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59194978}) = 0 <0.000012>
823   00:09:53.109094 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 59212451}) = 0 <0.000013>
823   00:09:53.109248 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:53.109568 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\216\242\206H\362]D\355e5V\203\35F\311\215z\246\320?N\34\264\207\376&%2\311\204\326#\331~\316\210$\242\326\22\0046\220nh\344\32!A1\375|\361N\252\2649\240\217\1q\226\273\27\232\244#\336}\347s\2507g\37\5Q\233w\242\236%\6W%\3423\240\"\252\223\235\320\377eNq\323\361\253\341\277\320\235B{k\210\345\217\300\312A\25\243]S\354\342\227\354`\20\315\v\10\344\327\304\273p`\02170\234\306\33\334\231\316\317\10", 147, MSG_NOSIGNAL, NULL, 0) = 147 <0.000034>
823   00:09:53.109891 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000014>
823   00:09:53.110189 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000193>
823   00:09:53.110667 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r0", 5, 0, NULL, NULL) = 5 <0.000029>
823   00:09:53.110979 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30R\360fq\303g\260/\364^\10J\252\345\211Xy&\30\355\363\\\247ZB\257K!{\313\221\17\352\324\313]5\306RcR\333\365\326\215\260\232\267\5\241\311\211\307\224u\221\335\366X\323\n[\262\262\364\231\313Kw\36\354\20Q\32*\242+|7ZYq\373'\254\253\324\241\354KL\220\35\3509}\321\327\356:;H\354\227\274\300\326\313\374\307=l\260J\356\205\342\261?\350tk\207\310%\341\4\224\301\221p|{-\222\306.\32\302\24\303]f\202\223\214\0364\23;\243\261g\233\254\327\ti\227{\373\352\371;\3j\310\273r\351\257\0255\rw\305M\346\326\363\323\245\f_\377\245Q\352\16\2113~JA\317\307:\336\347\302\2058I<\255\307ZG\205\253\377a\307\240\326\236\371\313\232\32\357\3133:\20\2251\242\313\234\17\207\344\7\265n\306t\373\205\373\200RF\0\203\32.\4SK\211\316\24t\5\251d\212~\261\261!\241a.\221\331T_\207\322[\273\17\324Wd\212xAe\352c\337\251\20\3547\36\231\250\304$\326\"\25\211b\231\276K\243M\3769\4U|:\333t\254\213\220\355CN\253\277\307\3563\2166\37:C\323r\215K\351\356!\301\22\350\352\234)\254\366&\242h\260c\242\334\302x\31r\340\273\255=\340\300\\\2\5\324N\360\7\324\7\331\22\264r`\356IkS!\214x\331\277\326\256\210\0200\334>i\236\262\242\5\"\256\2\370\356\311H\320\376\271\364\2025<\335C\246\342\200b\264a\366\311\326\231T\272\37[\307>\277+f\347\220\2533+p`D>\267H\302\370\3644\260\327Q\235p\252\276_\243\251\344\255\220\304lC\32l\267\364M\35R\347+\300wh\207\373\242\310\276\27\342\202\321\256L\345\203.'\"\372\274\2215\267\37\335\265\243ZZ-\374\34\333\331XN]\355\342:Ga\375n\241\342kA\ty\30\23\3108k\312\375\231*3pz\3552%\345\251\347B*\0363`\207\34\245\250}kkQ\242\2\247\262v)\224P\235\22\320\2305\36\346\227\371\265\262\375\271\226n\317\244I\332z\225X.\214\276}\307R\30\217(\3473=]-\310\315M\5\372\272\2\30p\7\357\244e\312\367Q4\203\223\3037Y7\25\257\321\366\264\17r\244\321\334pB\347$\n\336-,0\177\211\365\6\303\237\3123\371\216\350\352}\7\263!\267\6\236\27\367\307_n\222\25\232\3714\3547J\252v\334\3412\343\243E\2443\252\242\241\316\7+\376\352\230\240k%\247\"\342\272`+`g\0\324s]\336\311\326i,\0041\345_\27\313\366\302\304\317\334\326\1\26\6\301^'HJ\247&\t\324\230\2]\256\225\230q\267\270I\322GW.\3514d\365EB\261|G.3\350<\206Ju\211\247\5,B\314n:*\235\347\2312\317D-{s\327\340{\201\371\316\363\355st\226\276\211^+b\22,\374\351\377\354\245\323\243\300\230UuP\334Y\\\214\4\311\311mOxm\221(\20[\316t\343+#[\215\312\345\365\331\255\331\226V\252%Pf\267\206\t\fk|\n\362\356\367\346\310\372v\326\0323\347\277C+Al\370^\303C\215}\233&&\304\r\340\334\376\303&\227\5^a\365\3\277\366\223\245\360\360:\200\1iQ\26\344\350\302\310o_\4h\237\324\255\272\305T_\177\346\333W\317\355\376\230\247\"t:\327\25\217\3>6S\267RV\243!\313p\340\242}\335\272\6\253\25\320\17\301Z\350\265h\304\324\214V\10>\311\t\276\24\4_\362\205'\21\317\341yP'\312\264\3156\306\352\302\213\251\316\250\3\275\234IMS)\244\367A\247\205\340\325oF\215\230\265x\367H\320\315o#2"..., 3376, 0, NULL, NULL) = 3376 <0.000019>
823   00:09:53.112006 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60249952}) = 0 <0.000019>
823   00:09:53.112067 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60275486}) = 0 <0.000015>
823   00:09:53.112114 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60302600}) = 0 <0.000015>
823   00:09:53.112155 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60325809}) = 0 <0.000015>
823   00:09:53.112203 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60355337}) = 0 <0.000015>
823   00:09:53.112248 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60382435}) = 0 <0.000015>
823   00:09:53.112293 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60409829}) = 0 <0.000015>
823   00:09:53.112341 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60439106}) = 0 <0.000015>
823   00:09:53.112399 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 60478949}) = 0 <0.000015>
823   00:09:53.113036 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000024>
823   00:09:53.113373 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\256\242\206H\362]D\355f\364\321\4\6\330\3733\266\6k\247\6\204\353X\21\334\22\276ku\214-@\261\306z\376\375\370gV\341\351\35a\35\203\377s\rBd\260J\335*\205\236\177\214\"\230\205MT\220<\350\25|Wa\4\350\2456\26\267\327\226\234\216pE\225\222\274\314\301\265\16;~\22\333\352y\307\224\266e\210\23\217\213T\227i\16e\262;\262\215\345\324Jug\5\233\0002\272<\26$\374\323c\6>-\325\211\202\335\374\1'\373~\252\304\233\366\344\316\327cD\1\203\210\\@gI\323\277\262\236=\33E\36\333\364\303\3014\10\352]\343", 179, MSG_NOSIGNAL, NULL, 0) = 179 <0.000038>
823   00:09:53.113705 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.114015 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:53.114347 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2\r", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:53.114650 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30SK\232rzI4\337l\270$\307\310\2Js\303\322\370X,y\245\355\f\224\20\327\316\324\364w\5\331\256\323\254\336\262\315C\10T\312z\373^\246\336~\345.G1\331ga\302=$\372\37290K\334(EL\255I\273\362^\262Tf\340\3057)\231\324\24H\253\31\251\206\337\317\376Ga\352\335Q'H\232A*\211`o\244\315\345k\357<ti\17\331\26\230\3448c\253T\214\201h\255\354\270[I\303\316\243\321\247DA,QQ\257\243\200F\2547\210\376\3334\246\321L\t~\230\374\205\262K\20m\356\353U\7]\r\317\215!G\277u\222\v\32\310\311\177\320\312\21(\357a\340[O\215\222\230@\3\310\336z\214\352\225\246\10\217\265\361_\v\5\213\371]\20\24\4%\201\6\204\372|\314M\27\205>\3\343c\241\355\1\342\\h'\225\1P\347\245\n\334\251\"\355+d\255\304D\321\17@\301\360\271\314\312\3464\240&\270\2516H\322F\231\24\247\310!\37\1\364W\t\331w\225h\316I=\251Y\37\254>\2z\232NL\233Q#\245\231\3`5s\322_\310\235\261 \214\374\345a\n\337\20\234ra\207\224q\317\22\277\10\0367\24\304b\210\22_\206\17\355\321:A\4^\247\0\34\316c\254\17Yh\362\260c'5\345M@\337/<U\355\370\335T\332\361\205\205W\2512H)A\267\241\332\276\270\350\37\246D(\36m\323\7\350 s\270f,\3679W\277\231\347[\25\1;\322 W\307ue\t\373O$\322\232\271C\257o\202\205N\f\277\344\264\236\254\354\273\254\5<V\24S\211Y\367L\354%A\212\3\16\370\267\322\362U\210\312\\\240\306\357|A\t\314d\360c\254E\fu\327\354\257\317\204\257\34\271\350+A\326\3109\270\216!u=\251f{\25\207hHN\321\320\202\321^\230\212u\24\251\21\350\240\217\3\370\301@", 525, 0, NULL, NULL) = 525 <0.000020>
823   00:09:53.115724 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62058523}) = 0 <0.000019>
823   00:09:53.115787 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62086036}) = 0 <0.000016>
823   00:09:53.115831 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62109869}) = 0 <0.000016>
823   00:09:53.116086 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62345790}) = 0 <0.000017>
823   00:09:53.116144 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62378431}) = 0 <0.000015>
823   00:09:53.116192 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62407448}) = 0 <0.000015>
823   00:09:53.116236 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62432400}) = 0 <0.000015>
823   00:09:53.116277 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62455227}) = 0 <0.000016>
823   00:09:53.116319 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62478722}) = 0 <0.000016>
823   00:09:53.116361 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62502218}) = 0 <0.000015>
823   00:09:53.116401 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62524174}) = 0 <0.000015>
823   00:09:53.116443 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62547379}) = 0 <0.000015>
823   00:09:53.116485 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62571639}) = 0 <0.000015>
823   00:09:53.116525 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62593426}) = 0 <0.000015>
823   00:09:53.116568 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62617486}) = 0 <0.000015>
823   00:09:53.116608 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62639487}) = 0 <0.000015>
823   00:09:53.116653 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62666907}) = 0 <0.000015>
823   00:09:53.116696 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62690667}) = 0 <0.000015>
823   00:09:53.116736 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62712606}) = 0 <0.000015>
823   00:09:53.116777 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62736067}) = 0 <0.000016>
823   00:09:53.116818 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62758059}) = 0 <0.000015>
823   00:09:53.116858 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62780769}) = 0 <0.000015>
823   00:09:53.116903 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62807747}) = 0 <0.000026>
7113  00:09:53.116945 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000837>
823   00:09:53.116957 clock_gettime(CLOCK_THREAD_CPUTIME_ID,  <unfinished ...>
7113  00:09:53.116968 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
823   00:09:53.116982 <... clock_gettime resumed> {4, 62829031}) = 0 <0.000020>
7113  00:09:53.116997 <... futex resumed> ) = 0 <0.000021>
823   00:09:53.117007 clock_gettime(CLOCK_THREAD_CPUTIME_ID,  <unfinished ...>
7113  00:09:53.117018 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
823   00:09:53.117028 <... clock_gettime resumed> {4, 62846635}) = 0 <0.000015>
7113  00:09:53.117042 <... clock_gettime resumed> {282499, 201486840}) = 0 <0.000019>
823   00:09:53.117056 clock_gettime(CLOCK_THREAD_CPUTIME_ID,  <unfinished ...>
7113  00:09:53.117066 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 110, {282500, 202328885}, ffffffff <unfinished ...>
823   00:09:53.117081 <... clock_gettime resumed> {4, 62861216}) = 0 <0.000020>
823   00:09:53.117111 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62886498}) = 0 <0.000015>
823   00:09:53.117152 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62909364}) = 0 <0.000015>
823   00:09:53.117197 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62935523}) = 0 <0.000015>
823   00:09:53.117241 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62961945}) = 0 <0.000016>
823   00:09:53.117287 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 62989213}) = 0 <0.000015>
823   00:09:53.117329 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63013307}) = 0 <0.000016>
823   00:09:53.117375 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63035461}) = 0 <0.000016>
823   00:09:53.117417 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63058574}) = 0 <0.000015>
823   00:09:53.117461 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63084779}) = 0 <0.000015>
823   00:09:53.117503 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63108084}) = 0 <0.000015>
823   00:09:53.117543 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63130131}) = 0 <0.000015>
823   00:09:53.117584 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63153032}) = 0 <0.000015>
823   00:09:53.117625 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63175941}) = 0 <0.000015>
823   00:09:53.117669 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63201574}) = 0 <0.000015>
823   00:09:53.117710 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63224736}) = 0 <0.000015>
823   00:09:53.117750 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63246752}) = 0 <0.000015>
823   00:09:53.117811 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63289953}) = 0 <0.000015>
823   00:09:53.117852 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63312001}) = 0 <0.000015>
823   00:09:53.117893 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63334716}) = 0 <0.000015>
823   00:09:53.117968 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63361437}) = 0 <0.000016>
823   00:09:53.118011 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63384609}) = 0 <0.000015>
823   00:09:53.118051 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63406382}) = 0 <0.000015>
823   00:09:53.118092 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63429345}) = 0 <0.000015>
823   00:09:53.118134 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63452790}) = 0 <0.000015>
823   00:09:53.118175 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63475745}) = 0 <0.000015>
823   00:09:53.118215 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63497740}) = 0 <0.000015>
823   00:09:53.118256 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63520508}) = 0 <0.000015>
823   00:09:53.118296 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63543214}) = 0 <0.000016>
823   00:09:53.118343 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63571401}) = 0 <0.000015>
823   00:09:53.118390 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63599498}) = 0 <0.000015>
823   00:09:53.118435 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63626547}) = 0 <0.000016>
823   00:09:53.118477 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63649994}) = 0 <0.000015>
823   00:09:53.118517 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63671841}) = 0 <0.000015>
823   00:09:53.118559 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63695068}) = 0 <0.000016>
823   00:09:53.118603 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63721267}) = 0 <0.000015>
823   00:09:53.118645 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63744727}) = 0 <0.000015>
823   00:09:53.118685 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63766584}) = 0 <0.000015>
823   00:09:53.118726 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63789486}) = 0 <0.000015>
823   00:09:53.118767 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63812211}) = 0 <0.000015>
823   00:09:53.118811 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63838384}) = 0 <0.000015>
823   00:09:53.118853 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63861672}) = 0 <0.000016>
823   00:09:53.118893 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63883505}) = 0 <0.000015>
823   00:09:53.118934 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63906997}) = 0 <0.000015>
823   00:09:53.118974 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63928793}) = 0 <0.000015>
823   00:09:53.119015 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63952375}) = 0 <0.000016>
823   00:09:53.119057 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63975707}) = 0 <0.000015>
823   00:09:53.119098 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 63998373}) = 0 <0.000015>
823   00:09:53.119138 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64020343}) = 0 <0.000015>
823   00:09:53.119179 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64043031}) = 0 <0.000015>
823   00:09:53.119220 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64066089}) = 0 <0.000015>
823   00:09:53.119261 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64089121}) = 0 <0.000016>
823   00:09:53.119308 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64111098}) = 0 <0.000015>
823   00:09:53.119349 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64134147}) = 0 <0.000015>
823   00:09:53.119390 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64156610}) = 0 <0.000015>
823   00:09:53.119434 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64182820}) = 0 <0.000015>
823   00:09:53.119476 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64206632}) = 0 <0.000015>
823   00:09:53.119516 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64228518}) = 0 <0.000015>
823   00:09:53.119569 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64246140}) = 0 <0.000013>
823   00:09:53.119610 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64269077}) = 0 <0.000012>
823   00:09:53.119646 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64288447}) = 0 <0.000013>
823   00:09:53.119680 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64306200}) = 0 <0.000013>
823   00:09:53.119715 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64324944}) = 0 <0.000013>
823   00:09:53.119753 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64346751}) = 0 <0.000013>
823   00:09:53.119792 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64369315}) = 0 <0.000012>
823   00:09:53.119828 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64388581}) = 0 <0.000013>
823   00:09:53.119862 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64406287}) = 0 <0.000013>
823   00:09:53.119896 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64424838}) = 0 <0.000012>
823   00:09:53.119931 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64442867}) = 0 <0.000013>
823   00:09:53.119969 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64464727}) = 0 <0.000013>
823   00:09:53.120008 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64487373}) = 0 <0.000012>
823   00:09:53.120044 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64506478}) = 0 <0.000013>
823   00:09:53.120078 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64524708}) = 0 <0.000013>
823   00:09:53.120113 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64543334}) = 0 <0.000013>
823   00:09:53.120147 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64561434}) = 0 <0.000013>
823   00:09:53.120185 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64583153}) = 0 <0.000013>
823   00:09:53.120221 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64602696}) = 0 <0.000013>
823   00:09:53.120255 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64620631}) = 0 <0.000013>
823   00:09:53.120290 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64639497}) = 0 <0.000013>
823   00:09:53.120324 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64657894}) = 0 <0.000012>
823   00:09:53.120371 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64688485}) = 0 <0.000013>
823   00:09:53.120411 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64710876}) = 0 <0.000013>
823   00:09:53.120447 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64730591}) = 0 <0.000013>
823   00:09:53.120481 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64748409}) = 0 <0.000013>
823   00:09:53.120517 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64768520}) = 0 <0.000013>
823   00:09:53.120552 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64786723}) = 0 <0.000012>
823   00:09:53.120590 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64808992}) = 0 <0.000012>
823   00:09:53.120630 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64832283}) = 0 <0.000012>
823   00:09:53.120666 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64851577}) = 0 <0.000013>
823   00:09:53.120700 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64869371}) = 0 <0.000013>
823   00:09:53.120735 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64888254}) = 0 <0.000013>
823   00:09:53.120769 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64906659}) = 0 <0.000012>
823   00:09:53.120804 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64925004}) = 0 <0.000013>
823   00:09:53.120846 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64951108}) = 0 <0.000013>
823   00:09:53.120885 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64973317}) = 0 <0.000013>
823   00:09:53.120921 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 64992618}) = 0 <0.000013>
823   00:09:53.120955 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65010475}) = 0 <0.000010>
823   00:09:53.120992 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65027001}) = 0 <0.000013>
823   00:09:53.121026 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65045435}) = 0 <0.000012>
823   00:09:53.121065 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65067227}) = 0 <0.000013>
823   00:09:53.121101 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65086974}) = 0 <0.000013>
823   00:09:53.121135 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65104689}) = 0 <0.000013>
823   00:09:53.121209 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65162431}) = 0 <0.000013>
823   00:09:53.121251 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65186230}) = 0 <0.000013>
823   00:09:53.121285 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65204259}) = 0 <0.000013>
823   00:09:53.121321 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65224067}) = 0 <0.000012>
823   00:09:53.121359 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65245315}) = 0 <0.000013>
823   00:09:53.121424 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65293443}) = 0 <0.000013>
823   00:09:53.121592 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 65435819}) = 0 <0.000047>
823   00:09:53.122073 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.122403 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\365\242\206H\362]D\355g/\3463ab\307\322\323Q\vK\252VS\214\252?\370\1#b7a'a8\35\16W\24:\0\215_^z~\7`\10hg\244%w\n\32\265\275T'h\206\372nU\343iZ\264\303\222\0211Xn@{7\253\376\5\244\352@^Y\316_\31/\362\0\263\216Z\35\325`\264$\360\225\314X\371#:\365\6\203\252LV\33#\205W\223\332\347\347\202R\v\20*\317\223\264W\24Z\212\355s\n\340\323\356\v\230\345\374\240\0028\303|h \247B\337\6\202E\250\333q\321\253\\W\362{\240r\10\274-\301f\203Ft\332\335\236\252AR\0\36f\251r\205\266\373\276GHKvPv\364\217<xGs?\33\357\370\225\353~\7\3661\3707\250I\20\24x_{R\321\302\247>\5cr\21\245\33\v5y\321\275\24\34\221I\335\2100>\362", 250, MSG_NOSIGNAL, NULL, 0) = 250 <0.000037>
823   00:09:53.122731 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000014>
823   00:09:53.123077 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000052>
823   00:09:53.123617 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\6\206", 5, 0, NULL, NULL) = 5 <0.000036>
823   00:09:53.123942 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30T\374\311\2#~\307\243\376\253\346\265,\366\316\1\261\330\"\364\tUh\232\r\2030\204JD\241\214\251U\252\200\32*\222\326:\33\271\240)\2243\345\355WMXe\370\232E;\7\7\322\n\310\0208A\362\215\22|\264\4-P\216\330\376`\202\364\225\314\27\211\316c\2007\4\357\305!\361g~\233\4\313\341\243\263I\242F\303\34\353\3u\371D\34422FP(y\375d\374*\264XE\255T\"\262\327b\233\345'\314\320\203\247B)\26\24\20\211'\203\365\270z\276\317\376n\370\17b \334\310\"'\367!\307Y\266\347\370l\257@\214\262t\232@\203\260\t\34a\314w\21;@\315\1\35+\24$w4\301\26\203\366S\236U\305S\342\252p1\263+\243w\345-|\302W\222\216g\2\225l\22\310OqP\34\36y\337\233\3215\205w\263\23\224\320\322\230\267\234\37b\217\0048\10\337\303\3656NM\336\5Y\204\215b\250|\r\20\235\341WSS\274#4\222\32\325\300\31e\315Kk<\205\235\312\210b\256\10\364\253`\2674\30\364\230\236=XU\201X.:`\27\322K\333\t\235@\3013\355\245\3\342z`<\277/r\312\t\325f\261:\344=\366~P\327\203\\k\240\366\f[*7\316\237\211\25\357\252\366\362\37\252\255o\323\212\205\230u|]\n\224I\2\337\310\261\330\231\314\311w\306\275Q\236\235<L\16xg\177h^vd\217Y\277\253.#\16\35$\334\272\36/y}\30\366\214\266\374u\260\311\245\337\210\224\363\371X\222\276J\212GQ\357Wm\\\27\277\243Q\21\260\246\22\2v?5\203\335,F\253Zg\365I\214\221Lq\256rb\272P\334\231\242*\203\365\360\20\313H30d\302\243\210\317\270C\266\353\331G\310\260\200\212s\227n\232\234\267\363O\260\202\275n\327!\314\3\270O\255\3236\242\371\206V\257k\317\3\202+A,0\31\336\302\365\366'\374\226\20\300\353-\377\366\7]rt9A\222\231\236#\343\v#\324Qo\254;\320\307\367\341\352\216y\364\200>R\220\256\307{^\375\275\332\370\36\3176h\25\300\256\212\274T3Qr\247u\203Q<~\371\310x\200e\37\302Jf\317\35Aa\303\"\354\353\24TH\340\273\276{K\264\327\247i\221D6i\305]\21_W)\212\332\213\251\220\241\255Z\347(\372{\233\243\344\222\327\3V\35\v\344\233\r\224\322Y&\244\256\272\16+\342\6\21+\32l\203\274d\33\232\320\341\311\5\35:p\26\254t\1\321\274\377\6\323;pja\v\26d\374\25\212\2\203-\271\"_\236\272Y_)\243f\300\252\304\36\f\273.Gv7[q\320P,\322\217\273\215[~\210\376c*+p\16$\0\200\0038n\276\335\372\24-\362C\35s\237\233\341\245\340p\312\263,\311\315>$\275-\336\375\245\263\300\243\216\212E\267\360\260\354$\331L\35\372\315:\16\"*\304>\315\340\245>\21\230\1D3%\310\350\256\247s\323\255\234\4\305oW\231\261H5I\20\357&VR8\30\257\347\310\302\22j)\224Kf\273\24&\224\267\240\316\317J\347\227\242\323_h`\246ks\205\214\301\256\376D\276\227x\323\3675\370g\313s?\301N\307\270+\317\362m\222\343yMX\230\211\363\231\235\34q\364\367 \324\277\272\320\7l\244\23=\357s\356>:\270\n\f\2430\204\325g\305\306\333\252\25\267\352\347\353\347\236,\30\210\267\370\t\276\25\21\267\236\317LX\301\35\\\231\1\236\212\314\374~p\5SLz\371\200\315\244\253\346\362\313\275x\267\17\255Q\342\22\3439\25\213Q(4\257u6`d\276\252l\203\311_Vd6\227I-g\326\342\315\233=\341\6d\360\3136"..., 1670, 0, NULL, NULL) = 1670 <0.000021>
823   00:09:53.124727 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 66546641}) = 0 <0.000018>
823   00:09:53.125156 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 66940508}) = 0 <0.000026>
823   00:09:53.125243 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 66986773}) = 0 <0.000016>
823   00:09:53.125339 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67062066}) = 0 <0.000016>
823   00:09:53.125391 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67092495}) = 0 <0.000015>
823   00:09:53.125455 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67138407}) = 0 <0.000015>
823   00:09:53.125601 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67264705}) = 0 <0.000015>
823   00:09:53.125728 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67370574}) = 0 <0.000016>
823   00:09:53.125783 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67403377}) = 0 <0.000015>
823   00:09:53.125830 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67431055}) = 0 <0.000016>
823   00:09:53.125872 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67454076}) = 0 <0.000015>
823   00:09:53.125928 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67491497}) = 0 <0.000016>
823   00:09:53.125971 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67515122}) = 0 <0.000016>
823   00:09:53.126011 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67537324}) = 0 <0.000015>
823   00:09:53.126076 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67583736}) = 0 <0.000016>
823   00:09:53.126117 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67605812}) = 0 <0.000015>
823   00:09:53.126166 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 67637135}) = 0 <0.000015>
823   00:09:53.126622 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:53.126957 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\260\242\206H\362]D\355h@{y\t\27\v\344]\241\tA|\6S-\370\377\311\350\206\326.\376\2737%\267\233\324\33\276\22\ru\251P\300\n{\307\2008\3609\221\356#}\211\267\236\10\246&\305\363\212\244\225\372\0035\327\245\373\0\34\276)\240,h\306\332j\343\365\16\205\270g\250\326(\357\300v\377\327\240`\22\0025\246cZ\6\26385\10\362\273\16C\251k\220=\346\254X\270\36\301\322Vu\235m\23\2171\252\27632\312}[<\227zsUU*\327|\242'\3\341\353&\36\337\230\1\226\321\307\206$l\321\303S\\WRvj\231\177\361\203", 181, MSG_NOSIGNAL, NULL, 0) = 181 <0.000038>
823   00:09:53.127290 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.127626 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000025>
823   00:09:53.127965 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2Z", 5, 0, NULL, NULL) = 5 <0.000021>
823   00:09:53.128293 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30U\235\241\247FV<Ma\243\201\374\266\252\216BAX\231W\352\205\362\336\3009W\0+\347\21\267%i\313/J\235\213mMP[\311\\\266i\333M\vs\213J\4cg\277#l\352\221\256\310\335v\261g\337^\332\36\217M\313-\306u\270\210\214R\321C\23\373`\230\0\370\256|\306W\220\221%\350\274\372\177\271|p\263\223\217\212\321\250\271#,\274\1[\r\352\265\361\320\240\310\220\22\343\266B\352\344\272~G\206uy\25\273%\243\332\343K{^\255\2756f?\204=\254)w!\373:o\262|\340\7\237\227\217\361\227U\26\220\246V\307\260\377h\333\30\370R\215\261it\t\371\245\t9\256\242\267ER\337@\350\357\fA\\\231\204\34\352\353\230\312.#W\242h\343L\375\3\316\25\17m\260\201'\376+\273!@!\341\24\323\"Yk\251]$E\301I\301\357\276\201z{\23\217\337\353\241\33U\20\324\206:?r\36496$\356\245\327\16\223\310\315\271\362\200\367;\223\367\2336\334\4\235\26o\304\3417\254heU\312\334\r\346\373\222\234\233\351\301Fp\300`9\337\17\3623\364\33\321U\34\177\365\200\277a\202\375\27\243G\205\220%\233\21U\374\t\16\363\327c_o\327\237\32{\264\211\377\363\335\334?\354\357 \260Dq+\0\"K\237\312)\316\334\3735\317\4\342\245\252l\263\314\326\303.\365\250\306k\23+\217Z3L3G\362\237]\201\273\266\263r\355hP<\27\270oE\324\261\373\0j\252\346\247\330\247c\31\202\330\0\2S\1=\277J\362\266\357\177a\355\235\315\256\2067O+\227\345\215\33\366\306!\327\264PI5\310\372h0\216\305\3341\177\225g\32y\26\0018m9\216\31{l\226\273x\226\223\252\26\255$fUvM\256\6\22\201\345\0\36\202\267\305)\303SEp\37m\234\342+y!\304U\360\26\311\233F\312\371\0\17\0\211\361\372\25\364\231\22\301\324\320\371fm\354\371D\236\315\365\17D\t\6\277u\326q\247!\365\356{x\330\251B\370\267\356\2125\276j;\230\233\354\306\263\247bE\310\245\301\33\262\276\36\311\260\2013'\262\245\343\344\354+rg", 602, 0, NULL, NULL) = 602 <0.000023>
823   00:09:53.135614 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:53.135959 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1E\242\206H\362]D\355i\23471\234\332\336\371\3774I\354\23\207\2578t\332\304\34\256wX\23\302\331.\335)\322\237\363\323x\7W\302d\241\tT.ze(-8\316\346F\322`\347\261\205t/\304\303|A\370\375\17\360^\322\230B\232@3i\341-\32\177\257\351>\344X\22\373\26\37._J]\217t\315x\327e\214Vzzs3\275\367\276^\352\367\303\204R\335\325\254\223\33ZJ\327e\n\250\27\233z\35\237@d\355\216\257\v\267\272)\357\273\367\346/\251\214\331J\227D\260jD\30\347w\343\335\370<\321:\v\324\23\216\331m\332 \33\244\232\242\223\272D^\5\6\21\364\360\1H\314`\304\266\3Z\202\346?:0\4\362\245\213\27\202\t|\272}\321\243\177X\245q\350R\341\324\201.\262\262\331\204\241\16\243\375\243\256\237\211\0323j\267\324\211bi*\17q\301}\217A\301\246\2727:\235\266s\217\366h/\0f.\35uf\201R\\\271\323\360V\235\316\304~\300}\353j\1!/b\362-\f\310G\357\210!\330\216V\322\212\264:u\n8\v\336\341\260\340oq|x\3729\307\247.\366y\316\211\322,\353", 330, MSG_NOSIGNAL, NULL, 0) = 330 <0.000040>
823   00:09:53.136297 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.136606 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000061>
823   00:09:53.136958 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\f\202", 5, 0, NULL, NULL) = 5 <0.000034>
823   00:09:53.137278 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30V\256\341\224V\255\222\372\17M\363\202\30tq\321\333F\374\361\30662\301\327\34du\360\335\334-X\351O\33\306s\224\210\230\335\271U+\374s!\245\234\312\351\375*m\305\265[\320\361\341n\212\233@l\243\317\200u(U\234\257\"\263oC\363&\371\262\255\363S\10\3110!\351\3]\266c\213s\230m\365\270a\311\213#\266w\371\r\304\24\353\372}Nkf\333r]\220\305[\22@AO\246t*\2227\313\270\230!\360\370.\v\223\22bo\t\\\206\5\341\362\252\211\316\274\250/\346\240\t\224\347Q\320?q\362tV\351\243@\23\377J\353\266\24\252x\224@r*J\220\251\323\244.djJ\334\305g\333\3741\326Es\224\237\320&\35\255\231\3511$i\\\23%\2\301d\241\23\261\314\214rm\322D[\313CR}\10\201\205\374\244\t\237\n\367\327PR&]\"\0366C\207C&e\264\262I\334u)\231\v\264Hr\345\261}c\324\323%\235\230L\375\210\311\23\245\300X\177\352E\374N\3\242\24\10z\36f\237\"W\204\332\\$\350\377*\206+\24.\376\223\23NI&\203Zm\303\n\263\337\365\241y\306\31\350\366\334\236\305#9I\315\223\23\214s;\5\265-ye`[\210$\246\221\263\305p\365V#\33\345G\253}8`\304.\251'\235SY\5\210b\302\201\2674h%\233\227:\253\264\277\355G\374\270\260qy*\211\250\276;\2348\2\207y\376\273\314\204\16D\377E\207\225(\324\311\273\3310\345\323T\24iq\332\330k_\271e\363\363p\26\254[ef\27h\222\36\274\357\275\263\301\342M\25\361\3041\330\306\30\274C\314Oh\334\230D\335]\206\332$E&E.\26\355\213\204(\335+\310i\7a$o\241\241cH+G\331y<\24\10\314dX\207\207^|5J\335\220\355o\274\300\224\231YRR\240\243\352\246\367N\230is8\347\340\351\16\225\334\254L\10aN\311i\223\216\265\215\0365\0219\245\240\343b\347N\245\366\232\27?z\30\237\323\4\36\34\377ji\f[\274\33\377\204\251\6=\6\330$\341\321P(\2508U\256&\20_t\340\n\313n-4\366\313\371\20\240\32'\334\271\211\343pJD1\366\201\200\314\35\370\304\370m\226\17\17\300\253l\363\342\370\232\315\254a\3449\2\315\216\240\366\6\274c8\216\16*wpUd\251\273\303\361\7\275\373\314\321m<\373M Fu\240\367\206\17\376is\33\333B\352E\346\273\341\31\27\236J\256\341\3434\275\35H0\350\3330\3437\3\316\270/U\305i\371\3149g((p\347\307\317Q\33\240\267y6\240\351\225\32\1WL\6Em\210\360\371\376\201)@\361Q\240\5&-\230\24Q\207\241\2\25^\17\23\254\0\243\223\345v\1\245\276\333\357\345\37\5K0:i\253\256x\335\24\"\271\23\205^V\317\327\6\325mPMzr\33\264\304\240%\25\330\305#\247rwd\245\22\201S\312\335\273v\33\260\25\237\20\32\17\250\213\0203\344d\321\332y6\234\265\352\267\33t\237\314,\367\3\320\350q\342#f\0318q\344r\26\212\331\252\354\354\271\305\263\377\277S\2212G\255\177\302X\325\301\2072\r!\266\36\20\247e\247>\302r\3e:~\t%\2436\367\350\216n\"\242\3273\35\373_\377\264\237\25ac\2731\"\32o\254\2671?\212\"]\376/\256\272\25\317\334%N\221\356\27$;\220\264o\260`\325\36\2h\37J\304B\263\217\344f9H$\34\244\222\330:\360\25\16u\244\341\353\215\202\2760/\335\227\241\274\25\346t8\3m\24?\243\326\311\225w\r\332\20f\4L\354\17\335\33\203\276\374n>e\20\356\222\212\304X"..., 3202, 0, NULL, NULL) = 3202 <0.000022>
823   00:09:53.137956 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000024>
823   00:09:53.138291 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1g\242\206H\362]D\355j\363\177\314\374\32Z\200$\v\245X\345\251\364h\364\371&\307W:\307\261@\305\17\10\v\7\242\257VU'h'\240\23M\323\3004\346f!\350\343\335--O1\371\350\347I\203\24\r\353x\263F\350J\17\3\26\275K\357r*\312\240\327\277\0\rI\321\36J\340@\305\24\207w\1772\336\3463?\177V\225f\304\206F\vh\313-&\244y\f\261\2V\0}\302\214\t\20r.\0\7\244\305\314=\214\351\221\223\201\213\377\205\273\207-\23\250t\264\27\r\22\2S2\210\345g8\2318\277\356\224)\327\2)\365CJ_|\352\0304\36\26|\23\226\325\f\205O\2\r/\334\306=\377K\242\21\346Ks\312FlN\36468\240C#t\372y\215\322p\304`\221\213\265\202\347B\206\6C0\315\34\6:\203\323\0007\225\340\f}\16w\367\215\355\367\0=?l\30G\264\316m<c\r\346\201\227h\10 X\373w\371\200WR}\333\354\356G\"\347\2\203\275d\227\200\351)R\250~\275\n\264\343Q\t6\236\267\275\2577ll\337\224\342$\251\256\10X\301\247k\23}\316\351\5\2409\266\245\327\30qB\312\337s\215\326\253*W\36P9\240\215\277\234\320Y6\335\240\21\240;\21\352\264\333\277E\21\234\203%", 364, MSG_NOSIGNAL, NULL, 0) = 364 <0.000038>
823   00:09:53.138624 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
823   00:09:53.138933 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000039>
823   00:09:53.139263 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0W", 5, 0, NULL, NULL) = 5 <0.000038>
823   00:09:53.139591 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30W\207T\343\325\303$\312o}\2551\334\2571\f\327=\206\361\313\352\327\331o\215\350e-\315P\235\354\323\6\3\20\201\0162oJ\241P?\317k-\254;\20\352\325\10Wd\302\33Q\254\267=\205\325*I4\300Z\211\257\302B:\347\272\336\33\324\210", 87, 0, NULL, NULL) = 87 <0.000022>
823   00:09:53.145123 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 81302559}) = 0 <0.000020>
823   00:09:53.145206 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 81347663}) = 0 <0.000016>
823   00:09:53.145256 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 81374995}) = 0 <0.000015>
823   00:09:53.145312 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 81412246}) = 0 <0.000015>
823   00:09:53.145608 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 81687961}) = 0 <0.000018>
823   00:09:53.145782 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 81831462}) = 0 <0.000017>
823   00:09:53.152162 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000022>
823   00:09:53.152503 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2\6\242\206H\362]D\355k)\311\262f\333\5\255A\212\252\221\223\261\354\177\241\230\330\371 m\360j\177\373\4\274\35\277Il\36\30\305\\x|-:U\367z\337\214\277Y\326 \236\16\22\260df\331\352Ei\377\206\336\225\235\252;\310\205\314Al\10,\224v\222f\220\r\262C5b\5\341;\277u\357\331d6\216\261\300\356\211\237\362\250?j\223\220nk\247\1v\32\341\345a\331\22?\324.\331\307\364\320B\321Q\277\335q\366]1\35\353\316.\35 |s\336\347\342h\3026\335aC+\361\271n2\310\217\322\24\377Wj4\267\v!.\177\216\234\337A\324\3744\275&JD\310\351G{\357[Uye\20\261\360\37{=\5\373u\22a\363\260\32U%\22f\372g\17k\307\"\266\325[\342>\377v8IX\222\355\264\316F\263\360\226\17:\366Q\347w\223:\325\372\5Y\362\221:l\3\7\227\371\3353\273#\n\234\207\327`D\2713\367\327\365\230\216}o\314G\247\307\263\254\346\v\315|\0\241{u71o7\375\353\32\300H+\370\225\f\260iIf\264UE<\300;l\323\206\223\365\t\35\17'\337\306y9\347\276~\330\263\330\3\371u\357\\\3474I,\36\205A\27\244r\0245\324\226\217e7\335\25\336\210%\231\255\212\214*0@\247&[\31\220Y\256\301\216\237>\303\377\255\317\201^\342RN\247*\33{Kr\223\223+\23]l6a\251*(\243\213Y\21Iy\305\270\33\334[$\350\217+\233\300x\343)7\252/\365-\211\254\35\323\352k\250%\36E\35\245`Wd\177\354\261\346\331\223\36/\225-\234i\7\330>\1\361\257n\347d\21559\242\327\232h\244\307\33\245M%\226\32\333\271\375R0\f\232\22?v|\350\252\261Xs\3g\21\266\246\267\305\345\271\f\35\37\247\5\237\254\23\367\340Kq\266\370/\347", 523, MSG_NOSIGNAL, NULL, 0) = 523 <0.000037>
823   00:09:53.152837 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:53.153138 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000259>
823   00:09:53.153684 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\3l", 5, 0, NULL, NULL) = 5 <0.000021>
823   00:09:53.153999 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30X\20\353\336\262\250@\26\24\6\34\333\\d\10\"\365\271U\364\255\336h\244\3640\346+=l\223\224\272`H\332\355`%\215\375>\275{\240\20\266\357\nP\306\354(\263{\257SGd\273\226A\4)tL\201\274=\370\234#\33ab\ry\251\205f\220\210\0320\2210W\266\300\16 iSpqDG\32g\241\311Qy\201\\\262O\6\243\342\367\317\201\265\220\216\360\275\10\366\36\275\17\301u\267u3P\213\232\307\312\20\372\2\204\27\361\267\224\372+\30\221\3\324\260w\304\207\222bC\343\t\251\240WhR\25n\343o\242\227\16\10\241f\316~ \346\375\30\225{Ai\375U\370\10\21\302\27\222\214\21\355|Y\374u\373g\243\177}\332\1\32\217\260\215R|fG\2433u\243}@\24\213H\371\341M\5\255\241_\335h\235\227\274\253&\307\221\10\325\304e\30iVH\327\312\23\346 H^7\206\312\223-\251I;\350\213\17/\342s\376 \336\203\274\4\323\0_\235\32\202\266\223\365lH\17OD\306s\246;r\207\365\336\231\360\245X\372.\22\6\342\272\310\312m\210\275\34\37\360\351*\362\0025\344\3@R\v\260~\250\317p\314\360\224`\343\332\341W\\\300\330\n{\226\204o\320.\372\5\34\356\245\353ku\325\325\37\352&\201\312\367\343\272\310\225\10,\237\362\335\364k\250\277\373W\327\216\201\276\23\16I\234\17\23689\r \310\302L\275\17\323\213\276\357_\376aBF\243\"/(\221v\200[P\331\270\301\2370\265\353\327\354[\274\326\366/\204o\3\20\24\232ej\366\3)\217\21\365\24\203\242\23\300\312\f\212\355|l\tC\331\346\4.\243\363\267\265\200\21XJ'&\301\272&\307\340\315=8|\326\250\232\363(\252\244\310\222\330\303C\356\251\33\265MV\241\273\354v\256u\336'\261\333\326\312yf\266@\226@FV\25\1w1\37\262\310N\213H\303\353\250d\210>@\253\23j\317\311\21\210\317\1;:\200\277s\v=\267\31\21\343\322b\373\222|\0161\336\211\r\33\3765\03268\352\226r\241!\351\304\307+vI[*\207r\220du\365Xg\25v\233\353\23\226'!!\236\265\16\317^\"\r\372\203\241\370\243\347< `\212\3309\262\r\37T\227|\204\335\212L\335\233\366\342\307\342\234Z\330{\310\0348\334?\7\2730`>\243\277\232H\3625\37\221?\327\274\25\330\31##e\217\215\366\201\f\332@Ib\307\2010\312\333\10\323\233\3749\354\37K\r\307\345\203\213\357\252\371\370\30D\202\21\212q\316o\321@\274\346\v\"t\313\203\213|\2074\260i\367\304\365d\300\304\254\303}X:Y\\\3\240\315\215\7 \247xi\345\21E\257R b7>\10\265BSK2\23'\300\226\3\277\212m\323\304\246o\0b\362\331\10\265\340\276\243-\227\355\0176\1a\332\320\217\254dx\372\310\3660\6\215\212|\306\252\311rW\326a\337\273\374\ry\354a\0wB%M\350\1Z\235\350HY*J\235\223+\270\r\356\201\326\357\212B(\2231%\373C\370\307*\202\231r@\32\f\233#\322=\251t=X\300\315PX\237k\302\202\342\217A", 876, 0, NULL, NULL) = 876 <0.000020>
823   00:09:53.155151 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:53.155499 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\353\242\206H\362]D\355lb\240\302\4\0\257\204\272\223(\310\377\223\377\242(\243\300\256jv3\t\23\t\335O\2\372\206\"\312\272\243#\374\367\275\224\246ney\237}\fo\242) \23\316&\207\tI\20kSB\20\276\203\353^ \304\20\307\221\200\232\350\31[\304\204|ZH\271\16\312\323\353\3628Rt\243\332\307\333pK1\322\3269%\310\215<\246Q\217\344\317H\262g\313cJ\253,g\241\303\256\312\371Df\276\302\314f\361\t\317\26\207\342\361_\336\7\337*\360\252VX\253\241\345\243Y\255\226EE\3\6\301\356\272\325\\\364\201\273F\353\327\307\207\341'\36\210\23\270\243u\345\32\315\21\327,f\312j\260\371]`i\356y\224\340\227V\347\243v\25\n\247\276\361\222\303\233\371\255\353q'\301F<\364.\243KG\303\7\3331i\367B", 240, MSG_NOSIGNAL, NULL, 0) = 240 <0.000039>
823   00:09:53.155868 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:53.156179 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000359>
823   00:09:53.156827 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1|", 5, 0, NULL, NULL) = 5 <0.000021>
823   00:09:53.157130 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30Y\365\351\365a\270\5(\212\340\323Bk\21K\336#\356*\20\223%\334\32\224m\202\372-G\275*]\322\224\371$\222I\327\7T\265\276K\263+\177\5\223?:\257\25\264(d\253\374\251\345\r\353w\371Jp\362\16\210\362\345\317x\376\0'\216f6\200\"\210\36\370\347\306;\250\10\4\222\26\263.\236Wg~\265\27\332x\353\264\263\254\350\355;\364w5W)\376#\255\25\305\315Z\2030(\305\364\24\354\r\377|k' >\237r]\210J@\317\rF\326{\32go\377\37\276\0030\v\24\354\255j\271\212*V\t\326\n\232\326\"vq\210{\343\221\371h\22\4_\260%\266\34\253g\3\212\200\332\265<\203VBX\230\347\350\312\306\27\23\2431\336A:\256_\227\344\27&\372\360\374<\201\217n!\23\267x\3224U)\217\23e\376\227\300\346G\303^\356\262\27\254\0Rx8oP\342\7\306\1\20c\315\307w\345\206A\240\337\4M\252\347\255\221\325\364\243y\355\36$L\220\225\214(\301\252\30\254\16\210.7\372\31\315\224%\205\374\304X\36\375^\275\r\212\\\35\2442\253\215N\244\303\306\0y\272\305lj\342\332\2505\276\337\365\307\372\33(\330\0035k\35\305\257H\226\314\32l\5\345\342m\332-ss>\353d\225\246+>\333\243\363w:\30\357\n\260\22\313_\345X", 380, 0, NULL, NULL) = 380 <0.000021>
823   00:09:53.158012 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:53.158350 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\3\334\242\206H\362]D\355m\327\r\314g4(\365 \251\35\362\f%\360/Bz\265\30\334MQ<\365\n\356w=\210\345\344\3513\220#\34\222K\244\355\373\255\366\302w\301\340d\363\306\356A\325\32\357rE\364\272\22\37\201\27B\226\201By\224\207\343\27x\26\357\314J\252\312\3360\347{\217\215~\0\35|\3413\206\216\313\331\224}\376rU\230\206\265Z\364\321+\315\3749O\205c\231\240]N4\fh\232\351\303\3531BX\330Z\275pn\262\5\326\263\324\331\216\211B\202\321\337\322\215+7f\357\373\350\36\251\355\200\0040`\352\213.\332\214\366\272\3f\fu\235yKO\242\23\205\373\26\31\234*H\25\306{~=S\247B\34\0260\213\251\314N_\374nd\300z\5\302\1G\30\305\351\2123\273\265\24\323\274%\37\21\233t\36G\255\0\0327{\244Vl\303\344\26\337\314\17H\306Kc\276\t\225b\225Q.1\306>L1F|?D\10j\2227Sp\273\314\332(\v\267\270S1%*u\262\331\237h\314i\33a\361\273{\320M\27Z\257\355R\263\304\277\262\2441\376\316t\266[\25\245EMO\322\336V1\344&[\260\217\25\6\22fy:\236DG9\355$\3437\344\347\205\207{\224v\261?k\10\345f\254s\276\356F\212F\315\263o\326\242\30A\4\335\221\3624\2234Fl\16\1\342\335j\311\312X\270\vrI\376\337\302%\20\2279\371x\313\347-\214\273\363\243\261\370$|\227&\223l\r\337\323o#\35 \350|:v\333 \26\2\300\335\17\275@\262gY\313\244o\7\375q\f\343-\203\213\254\370\36\241=\377\37W\212\205\214\276\266\233\244\\\5j\16\21\374\235\322\357p\355\371\327\311\265QI\372\364\374\257\245\331qkX\370&*\304l\317\344\232\211\344\256@\0267\306\305\213\301\364\357g\262\335\233\271<2\177\222K\362=\345AY#\241\330-5\20\34z(\\\2534\245rg\274\364W\244\30u\240\273\246\347W\334\263\177J\224T\260[\313\207\256\221\325\207\236\31\202rO\351\374\3770\203\305\240\265F\314\217Jm\351O$w\377W\4\350\363\266\361\320\204\325\177\23\26\306\207\367>\233Q\237\264)\4\365$\210!\t\321\354\vp\327\236\277\264\260\322\343@C{r\277\355Zvt\303\246\263\341\211<CM8\335\320\263\300\2b\224\340\346\"K\376\307U\220),\200J\27\356-\17\360\247\213\375\345>\17\304\234\313e \263o\240\230\352#\22\243\315\350\364\4=\370\362*\221\221 ,\306]\21\327\225\374\247\22\254\255c\346\7\3423Wn\323\202\341\216g\2540\366,,CW\301\352h\300\243C\223c\206\314\305\273\217b|>qjW\330t\302\3\3\365\354\377\231c\35\316\270\347\377\265\0\343\210{\266\312\341\353\304-Z+n\223\326\212\0058\370k\245j\374r\rR\226\336,\323\5\312\352\247\320\372\352\27\211eV\311\311!\32\210\336@\"\246\375{\310L\n\"\372kb\355\3563(\275~\3277\3259\2\244\3659\v\323\241\373\221k%#R\3547D\322*\351\346\373\376\251\345qL\277\330i4Z=\314\7\261Y|\211\23\340\227\345t\361\375\4\342\26pS\301\367,\235\300H\314\3.\334\324\f\257A\7\\\22\31B>R[\357\224l\310\264{I\274\342\30\271\274QZ\256\317J\377\273\16\37\232\257F\240\240\323)\23\257\36y\300\226\330R\267JG\371pg\17m4\353P\362\320g\23\340kG\2236\365\335\366t(Q\322\4\363\224\227\275\213\315\36R/\252\264\35\336\243\271\370\30\201!^\27", 993, MSG_NOSIGNAL, NULL, 0) = 993 <0.000039>
823   00:09:53.158697 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:53.159007 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000474>
823   00:09:53.159770 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\3\2", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:53.160068 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30Z\366j`\346\321&v)\34LW\365\224\223\264.\200\377\372\363\321q\372\224\356\207\371L]\20\2054`\0302\300\302\324\241\254 1\\@+\245\6\313N\222#\f\360\352]\254\327\343\347x@\234\203\221\311\312\222Z\324@\337\23\26\220\16\301\247p\277q&\350-g\232\261\26\203\f\257r\354\362\221\371\v\264\263\306\257$&K\21*S\7\2539{\20s\\\306J\256T\24:A\210\344\354\326Fc4\36dbJG\242U\357\303\371\302f\244\372\273g\216\304\253\3666\5)t\271\230\362\356\1YL\223`*\242\21\313h\273\0170?h\365t\242\325^2\253\247$\240\270\351H\360\305\3539C2\265\244(b\203\246\16\21\314SSGN\324\272\2651\337\225{PY>\242\314\342\267\2101.\341\334\246\t\367Ncq\307\n`\4\363<\0046\323/\345h\247BAp\213q\1\224C\0hKv\0165\n\347\312\222y\372e\200\367\217\r\2\245iy\211\216{I\337\4\350D\346d:~=H\304\2509\266\217|=*\22\5\354\322\21\265;\354h\360\356\337\307\301.\321|\365\23lq\342P0\rG\32\263\355\224=w\202\304\255b<\21\17\346^\273\345B\341\f\254)L\377\260W\243cb\243#\202PA\4#\337\337:\311[\36^\326\262\217y\6\205\213\255\340)E\357M\272\202z\275\215CiY\335\363!\213JA\235v\3556KT\246\242\236\21\356(R\24:\37*\303\271\22K3\201\261\330\2\210\367\3753\r\232V\353\224\0\303\23\210\31\353\255mY1#\374\217\0370};\"\202<\332\1\"8my\31\200}\360\27c\270!R\257\335@u{\312\213{\202 t\205\16\355\205^\240m\340w0\310~\212i\317\30\22\312Y\355Q\350\306|\330z\207\301\265\214\333v\375;\36\t\323\352\306\342@\332<P\27n\255\301g\223]\345\7\213w\3\315P\376m\233\322f/\333\323Y\35\21~\334\2\10Q\200\257\2k\223}\2252\266\237\231\254\233,n\211M\206pk{`\212+h\371\342EJ\254\240J\237\271,g\276%_\256HQ./\214\253`(4\333{O{;\370\200<\271\230fyt\321\20\337#\334\26\31\2\26\313,PY\261a\367\315\227\223\245 \256m\343\220`\6W8\212+d\30\251=\251\201\v\220I\306`\2\227\371\31\1\324R\256\25\31\242\343k\22\371\264&X\"\0351\206\241\261)\21\365\360\313\341\323\335\254)\321p\302|^\250\17\307\212\315\365r\247\371-;\250\3508\336m\364r\207\n\351\226\342\226\231\2332\332\320\\\337\272gT\202^\16L\344&Y\376\320l\3022\34\n\370\235\27\212\227\271\313\241\335+\254\33\324\304\24\35\203^5\311\365W\235X\3623<\2602", 770, 0, NULL, NULL) = 770 <0.000014>
823   00:09:53.160823 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90589222}) = 0 <0.000013>
823   00:09:53.160889 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90622138}) = 0 <0.000013>
823   00:09:53.160930 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90644529}) = 0 <0.000013>
823   00:09:53.160970 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90667441}) = 0 <0.000013>
823   00:09:53.161008 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90689258}) = 0 <0.000012>
823   00:09:53.161046 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90710339}) = 0 <0.000013>
823   00:09:53.161086 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90734112}) = 0 <0.000013>
823   00:09:53.161126 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90757159}) = 0 <0.000012>
823   00:09:53.161169 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90783457}) = 0 <0.000012>
823   00:09:53.161208 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90806077}) = 0 <0.000012>
823   00:09:53.161248 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90829362}) = 0 <0.000012>
823   00:09:53.161283 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 90847223}) = 0 <0.000013>
823   00:09:53.161499 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91046205}) = 0 <0.000011>
823   00:09:53.161544 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91070369}) = 0 <0.000013>
823   00:09:53.161581 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91090119}) = 0 <0.000013>
823   00:09:53.161615 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91107821}) = 0 <0.000013>
823   00:09:53.161656 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91132833}) = 0 <0.000012>
823   00:09:53.161692 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91151845}) = 0 <0.000013>
823   00:09:53.161732 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91176092}) = 0 <0.000013>
823   00:09:53.161771 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91198026}) = 0 <0.000012>
823   00:09:53.161811 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91221409}) = 0 <0.000013>
823   00:09:53.161849 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91242832}) = 0 <0.000013>
823   00:09:53.161883 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91261006}) = 0 <0.000012>
823   00:09:53.161918 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91279409}) = 0 <0.000013>
823   00:09:53.161955 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91300105}) = 0 <0.000013>
823   00:09:53.161995 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91323908}) = 0 <0.000013>
823   00:09:53.162057 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91370218}) = 0 <0.000013>
823   00:09:53.162105 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91400417}) = 0 <0.000013>
823   00:09:53.162140 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91418853}) = 0 <0.000013>
823   00:09:53.162179 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91441650}) = 0 <0.000013>
823   00:09:53.162215 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91460246}) = 0 <0.000012>
823   00:09:53.162252 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91481833}) = 0 <0.000013>
823   00:09:53.162294 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91506411}) = 0 <0.000013>
823   00:09:53.162334 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91530081}) = 0 <0.000013>
823   00:09:53.162377 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91549608}) = 0 <0.000013>
823   00:09:53.162412 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91567710}) = 0 <0.000012>
823   00:09:53.162446 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91586012}) = 0 <0.000013>
823   00:09:53.162482 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 91605219}) = 0 <0.000012>
823   00:09:53.163309 write(8</var/log/gitlab/gitlab-rails/production.log>, "Completed 200 OK in 81ms (Views: 0.2ms | ActiveRecord: 31.8ms | Elasticsearch: 0.0ms)\n", 86) = 86 <0.000024>
823   00:09:53.164002 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
823   00:09:53.164311 write(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$14\r\npeek:requests:\r\n$4\r\n1800\r\n$336\r\n{\"context\":{},\"data\":{\"host\":{\"hostname\":\"aabecb3049c7\"},\"pg\":{\"duration\":\"31ms\",\"calls\":15,\"queries\":[]},\"gitaly\":{\"duration\":\"0ms\",\"calls\":0,\"details\":[]},\"redis\":{\"duration\":\"1ms\",\"calls\":1},\"sidekiq\":{\"duration\":\"0ms\",\"calls\":0},\"gc\":{\"invokes\":0,\"invoke_time\":\"0.00\",\"use_size\":0,\"total_size\":0,\"total_object\":0,\"gc_time\":\"0.00\"}}}\r\n", 390) = 390 <0.000040>
823   00:09:53.164643 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000019>
823   00:09:53.164945 read(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000022>
823   00:09:53.165474 write(15</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/ealoc-engineering/loccms/noteable/merge_request/2114/notes\",\"format\":\"json\",\"controller\":\"Projects::NotesController\",\"action\":\"index\",\"status\":200,\"duration\":83.47,\"view\":0.19,\"db\":31.83,\"time\":\"2018-09-25T00:09:53.081Z\",\"params\":[{\"key\":\"namespace_id\",\"value\":\"ealoc-engineering\"},{\"key\":\"project_id\",\"value\":\"loccms\"},{\"key\":\"target_type\",\"value\":\"merge_request\"},{\"key\":\"target_id\",\"value\":\"2114\"}],\"remote_ip\":\"10.7.7.46\",\"user_id\":379,\"username\":\"ccraciun\",\"ua\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\"}\n", 574) = 574 <0.000023>
823   00:09:53.165600 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000023>
823   00:09:53.165660 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000016>
823   00:09:53.165704 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000016>
823   00:09:53.165750 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000015>
823   00:09:53.165795 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490820 kB\nVmRSS:\t  490820 kB\nRssAnon:\t  476264 kB\nRssFile:\t   14500 kB\nRssShmem:\t      56 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000030>
823   00:09:53.165857 read(44</proc/823/status>, "", 6881) = 0 <0.000015>
823   00:09:53.165901 close(44</proc/823/status>) = 0 <0.000016>
823   00:09:53.166747 fcntl(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000017>
823   00:09:53.166967 write(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$47\r\nsession:gitlab:e3db34af92ce75a754809c69bbc89e42\r\n$6\r\n604800\r\n$286\r\n\4\10{\nI\"\rsaml_uid\6:\6ETI\"\24ccraciun@ea.com\6;\0TI\"\27saml_session_index\6;\0TI\"*_9e8f6987-2d37-4694-ac42-e9c53e929094\6;\0TI\"\31warden.user.user.key\6;\0T[\7[\6i\2{\1I\"\"$2a$10$c8YgmOQm12hm4leSpZCqFu\6;\0TI\"\20_csrf_token\6;\0FI\"163mrP9pqgi821T+KhvxUmtGB3KLU7jUTDKNvfkRmpdo=\6;\0FI\" ask_for_usage_stats_consent\6;\0FF\r\n", 375) = 375 <0.000034>
823   00:09:53.167194 fcntl(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000012>
823   00:09:53.167389 read(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000025>
823   00:09:53.167839 write(26<UNIX:[3605184->3605183,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "HTTP/1.1 200 OK\r\nDate: Tue, 25 Sep 2018 00:09:53 GMT\r\nConnection: close\r\nX-Frame-Options: DENY\r\nX-XSS-Protection: 1; mode=block\r\nX-Content-Type-Options: nosniff\r\nX-UA-Compatible: IE=edge\r\nPoll-Interval: 6000\r\nPage-Title: GitLab\r\nContent-Type: application/json; charset=utf-8\r\nETag: W/\"f4817bdcc3430263b12078d9c8c50c45\"\r\nCache-Control: max-age=0, private, must-revalidate\r\nX-Request-Id: 030e1ba3-ac50-4be8-a63f-fdbb1bacd226\r\nX-Runtime: 0.120402\r\n\r\n", 447) = 447 <0.000148>
823   00:09:53.168080 write(26<UNIX:[3605184->3605183,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "{\"notes\":[],\"last_fetched_at\":1537834193}", 41) = 41 <0.000036>
823   00:09:53.168313 shutdown(26<UNIX:[3605184->3605183,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, SHUT_RDWR) = 0 <0.000317>
823   00:09:53.168698 close(26<UNIX:[3605184,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>) = 0 <0.000017>
823   00:09:53.168788 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000011>
823   00:09:53.168844 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000016>
823   00:09:53.168902 getppid()         = 495 <0.000012>
823   00:09:53.168960 select(26, [14<pipe:[3579145]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
2690  00:09:53.188450 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000810>
2690  00:09:53.188480 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000011>
2690  00:09:53.188512 clock_gettime(CLOCK_MONOTONIC, {282499, 272975952}) = 0 <0.000012>
2690  00:09:53.188550 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4006, {282500, 273834003}, ffffffff <unfinished ...>
7407  00:09:53.940457 <... nanosleep resumed> NULL) = 0 <1.000097>
7407  00:09:53.940543 close(1<pipe:[3578440]>) = 0 <0.000020>
7407  00:09:53.940609 close(2<pipe:[3578440]>) = 0 <0.000016>
7407  00:09:53.940657 exit_group(0)     = ?
7407  00:09:53.940762 +++ exited with 0 +++
477   00:09:53.940792 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7407 <1.002467>
477   00:09:53.940824 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
477   00:09:53.940878 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:53.940915 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7407, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:53.940942 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000014>
477   00:09:53.940979 rt_sigreturn({mask=[]}) = 0 <0.000014>
477   00:09:53.941019 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000014>
477   00:09:53.941056 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:53.941140 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000024>
477   00:09:53.941198 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:53.941238 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000015>
477   00:09:53.941288 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:53.941325 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000014>
477   00:09:53.941370 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000014>
477   00:09:53.941416 close(3</dev/null>) = 0 <0.000014>
477   00:09:53.941453 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:53.941490 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000014>
477   00:09:53.941531 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:53.941568 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000014>
477   00:09:53.941605 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000014>
477   00:09:53.941646 fcntl(1</dev/null>, F_GETFD) = 0 <0.000014>
477   00:09:53.941683 kill(495, SIG_0)  = 0 <0.000014>
477   00:09:53.941718 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000014>
477   00:09:53.941760 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000014>
477   00:09:53.941798 close(11<pipe:[3578440]>) = 0 <0.000015>
477   00:09:53.941835 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000015>
477   00:09:53.941876 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000014>
477   00:09:53.941913 close(10<pipe:[3578440]>) = 0 <0.000014>
477   00:09:53.941972 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000015>
477   00:09:53.942011 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7408 <0.000287>
7408  00:09:53.942345 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:53.942403 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7408  00:09:53.942429 <... close resumed> ) = 0 <0.000035>
477   00:09:53.942451 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000030>
7408  00:09:53.942465 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
7408  00:09:53.942509 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:53.942543 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7408  00:09:53.942557 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000023>
477   00:09:53.942571 <... rt_sigprocmask resumed> [], 8) = 0 <0.000021>
7408  00:09:53.942584 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:53.942597 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7408  00:09:53.942616 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000024>
477   00:09:53.942630 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000026>
7408  00:09:53.942643 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:53.942656 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7408  00:09:53.942668 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000019>
477   00:09:53.942681 <... rt_sigprocmask resumed> [], 8) = 0 <0.000020>
477   00:09:53.942698 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7408  00:09:53.942714 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:53.942727 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7408  00:09:53.942740 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
477   00:09:53.942753 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7408  00:09:53.942767 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:53.942780 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7408  00:09:53.942795 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000021>
477   00:09:53.942809 wait4(-1,  <unfinished ...>
7408  00:09:53.942820 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000011>
7408  00:09:53.942860 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000011>
7408  00:09:53.942902 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7408  00:09:53.942949 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000015>
7408  00:09:53.942993 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000024>
7408  00:09:53.943047 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7408  00:09:53.943083 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7408  00:09:53.943126 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000013>
7408  00:09:53.943208 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000173>
7408  00:09:53.943439 brk(NULL)         = 0x25c1000 <0.000015>
7408  00:09:53.943495 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000021>
7408  00:09:53.943582 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000014>
7408  00:09:53.943623 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000025>
7408  00:09:53.943678 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000010>
7408  00:09:53.943717 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f4f60969000 <0.000014>
7408  00:09:53.943765 close(3</etc/ld.so.cache>) = 0 <0.000009>
7408  00:09:53.943798 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000015>
7408  00:09:53.943838 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000015>
7408  00:09:53.943874 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000022>
7408  00:09:53.943927 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000009>
7408  00:09:53.943960 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f4f60968000 <0.000013>
7408  00:09:53.944005 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f4f6037d000 <0.000015>
7408  00:09:53.944042 mprotect(0x7f4f6053d000, 2097152, PROT_NONE) = 0 <0.000022>
7408  00:09:53.944085 mmap(0x7f4f6073d000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f4f6073d000 <0.000017>
7408  00:09:53.944134 mmap(0x7f4f60743000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f4f60743000 <0.000015>
7408  00:09:53.944177 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000009>
7408  00:09:53.944231 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f4f60967000 <0.000014>
7408  00:09:53.944268 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f4f60966000 <0.000022>
7408  00:09:53.944314 arch_prctl(ARCH_SET_FS, 0x7f4f60967700) = 0 <0.000013>
7408  00:09:53.944407 mprotect(0x7f4f6073d000, 16384, PROT_READ) = 0 <0.000016>
7408  00:09:53.944456 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000014>
7408  00:09:53.944493 mprotect(0x7f4f6096c000, 4096, PROT_READ) = 0 <0.000014>
7408  00:09:53.944529 munmap(0x7f4f60969000, 10600) = 0 <0.000015>
7408  00:09:53.944654 brk(NULL)         = 0x25c1000 <0.000014>
7408  00:09:53.944698 brk(0x25e2000)    = 0x25e2000 <0.000014>
7408  00:09:53.944758 nanosleep({1, 0},  <unfinished ...>
1093  00:09:53.978618 <... nanosleep resumed> NULL) = 0 <1.000081>
1093  00:09:53.978658 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000013>
1093  00:09:53.978703 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.978737 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000011>
1093  00:09:53.978770 open("/var/log/gitlab/gitlab-monitor/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-monitor/current> <0.000016>
1093  00:09:53.978809 fstat(33</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000011>
1093  00:09:53.978841 close(33</var/log/gitlab/gitlab-monitor/current>) = 0 <0.000012>
1093  00:09:53.978871 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000011>
1093  00:09:53.978904 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000011>
1093  00:09:53.978935 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000011>
1093  00:09:53.978967 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121384, ...}) = 0 <0.000011>
1093  00:09:53.979000 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/ealoc-engineering/loccms/noteable/merge_request/2114/notes\",\"format\":\"json\",\"controller\":\"Projects::NotesController\",\"action\":\"index\",\"status\":200,\"duration\":83.47,\"view\":0.19,\"db\":31.83,\"time\":\"2018-09-25T00:09:53.081Z\",\"params\":[{\"key\":\"namespace_id\",\"value\":\"ealoc-engineering\"},{\"key\":\"project_id\",\"value\":\"loccms\"},{\"key\":\"target_type\",\"value\":\"merge_request\"},{\"key\":\"target_id\",\"value\":\"2114\"}],\"remote_ip\":\"10.7.7.46\",\"user_id\":379,\"username\":\"ccraciun\",\"ua\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\"}\n", 8192) = 574 <0.000012>
1093  00:09:53.979046 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "", 8192) = 0 <0.000013>
1093  00:09:53.979080 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117798, ...}) = 0 <0.000013>
1093  00:09:53.979116 read(10</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/ealoc-engineering/loccms/noteable/merge_request/2114/notes\" for 10.7.7.46 at 2018-09-25 00:09:53 +0000\nProcessing by Projects::NotesController#index as JSON\n  Parameters: {\"namespace_id\"=>\"ealoc-engineering\", \"project_id\"=>\"loccms\", \"target_type\"=>\"merge_request\", \"target_id\"=>\"2114\"}\nCompleted 200 OK in 81ms (Views: 0.2ms | ActiveRecord: 31.8ms | Elasticsearch: 0.0ms)\n", 8192) = 386 <0.000013>
1093  00:09:53.979161 read(10</var/log/gitlab/gitlab-rails/production.log>, "", 8192) = 0 <0.000013>
1093  00:09:53.979196 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:53.979231 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000012>
1093  00:09:53.979267 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000013>
1093  00:09:53.979303 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000013>
1093  00:09:53.979339 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000015>
1093  00:09:53.979377 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56772, ...}) = 0 <0.000012>
1093  00:09:53.979413 read(16</var/log/gitlab/gitlab-workhorse/current>, "2018-09-25_00:09:53.16852 gitlabts.ea.com @ - - [2018/09/25:00:09:53 +0000] \"GET /ealoc-engineering/loccms/noteable/merge_request/2114/notes HTTP/1.1\" 200 41 \"https://gitlabts.ea.com/ealoc-engineering/loccms/merge_requests/102/diffs\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\" 0.122\n", 8192) = 321 <0.000013>
1093  00:09:53.979448 read(16</var/log/gitlab/gitlab-workhorse/current>, "", 8192) = 0 <0.000012>
1093  00:09:53.979482 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000013>
1093  00:09:53.979518 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.979565 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.979603 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.979639 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42869, ...}) = 0 <0.000012>
1093  00:09:53.979675 read(21</var/log/gitlab/nginx/gitlab_access.log>, "10.7.7.46 - - [25/Sep/2018:00:09:53 +0000] \"GET /ealoc-engineering/loccms/noteable/merge_request/2114/notes HTTP/1.1\" 200 41 \"https://gitlabts.ea.com/ealoc-engineering/loccms/merge_requests/102/diffs\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\"\n", 8192) = 282 <0.000013>
1093  00:09:53.979711 read(21</var/log/gitlab/nginx/gitlab_access.log>, "", 8192) = 0 <0.000013>
1093  00:09:53.979747 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.979783 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.979818 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.979853 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.979888 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.979924 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.979959 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.979994 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.980031 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000012>
1093  00:09:53.980067 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000013>
1093  00:09:53.980102 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000013>
1093  00:09:53.980141 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000012>
1093  00:09:53.980176 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.980211 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000013>
1093  00:09:53.980246 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000013>
1093  00:09:53.980281 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000012>
1093  00:09:53.980315 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000012>
1093  00:09:53.980350 open("/var/log/gitlab/gitlab-rails/api_json.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/api_json.log> <0.000015>
1093  00:09:53.980388 fstat(33</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000012>
1093  00:09:53.980423 close(33</var/log/gitlab/gitlab-rails/api_json.log>) = 0 <0.000013>
1093  00:09:53.980457 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121384, ...}) = 0 <0.000012>
1093  00:09:53.980491 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117798, ...}) = 0 <0.000012>
1093  00:09:53.980526 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000012>
1093  00:09:53.980561 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:53.980596 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000012>
1093  00:09:53.980630 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000012>
1093  00:09:53.980665 open("/var/log/gitlab/alertmanager/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/alertmanager/current> <0.000014>
1093  00:09:53.980702 fstat(33</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000012>
1093  00:09:53.980736 close(33</var/log/gitlab/alertmanager/current>) = 0 <0.000012>
1093  00:09:53.980769 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000013>
1093  00:09:53.980804 open("/var/log/gitlab/registry/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/registry/current> <0.000014>
1093  00:09:53.980840 fstat(33</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000012>
1093  00:09:53.980875 close(33</var/log/gitlab/registry/current>) = 0 <0.000013>
1093  00:09:53.980908 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56772, ...}) = 0 <0.000013>
1093  00:09:53.980943 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000013>
1093  00:09:53.980978 open("/var/log/gitlab/gitlab-shell/gitlab-shell.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-shell/gitlab-shell.log> <0.000014>
1093  00:09:53.981015 fstat(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000012>
1093  00:09:53.981049 close(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>) = 0 <0.000012>
1093  00:09:53.981082 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.981117 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.981152 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981186 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42869, ...}) = 0 <0.000012>
1093  00:09:53.981221 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981262 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981298 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981332 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.981367 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981401 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981436 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:53.981470 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:53.981505 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000013>
1093  00:09:53.981539 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000012>
1093  00:09:53.981574 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000013>
1093  00:09:53.981609 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/gitlab-rails/production_json.log <==\n{\"method\":\"GET\",\"path\":\"/ealoc-engineering/loccms/noteable/merge_request/2114/notes\",\"format\":\"json\",\"controller\":\"Projects::NotesController\",\"action\":\"index\",\"status\":200,\"duration\":83.47,\"view\":0.19,\"db\":31.83,\"time\":\"2018-09-25T00:09:53.081Z\",\"params\":[{\"key\":\"namespace_id\",\"value\":\"ealoc-engineering\"},{\"key\":\"project_id\",\"value\":\"loccms\"},{\"key\":\"target_type\",\"value\":\"merge_request\"},{\"key\":\"target_id\",\"value\":\"2114\"}],\"remote_ip\":\"10.7.7.46\",\"user_id\":379,\"username\":\"ccraciun\",\"ua\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\"}\n\n==> /var/log/gitlab/gitlab-rails/production.log <==\nStarted GET \"/ealoc-engineering/loccms/noteable/merge_request/2114/notes\" for 10.7.7.46 at 2018-09-25 00:09:53 +0000\nProcessing by Projects::NotesController#index as JSON\n  Parameters: {\"namespace_id\"=>\"ealoc-engineering\", \"project_id\"=>\"loccms\", \"target_type\"=>\"merge_request\", \"target_id\"=>\"2114\"}\nCompleted 200 OK in 81ms (Views: 0.2ms "..., 1773) = 1773 <0.000058>
1093  00:09:53.981792 nanosleep({1, 0},  <unfinished ...>
7113  00:09:54.117960 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000882>
7113  00:09:54.118018 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000015>
7113  00:09:54.118057 clock_gettime(CLOCK_MONOTONIC, {282500, 202525392}) = 0 <0.000014>
7113  00:09:54.118105 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 112, {282501, 167328885}, ffffffff <unfinished ...>
2690  00:09:54.189468 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000908>
2690  00:09:54.189525 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000017>
2690  00:09:54.189568 clock_gettime(CLOCK_MONOTONIC, {282500, 274035223}) = 0 <0.000017>
2690  00:09:54.189619 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4008, {282501, 274834003}, ffffffff <unfinished ...>
7408  00:09:54.944863 <... nanosleep resumed> NULL) = 0 <1.000093>
7408  00:09:54.944949 close(1<pipe:[3578440]>) = 0 <0.000017>
7408  00:09:54.945016 close(2<pipe:[3578440]>) = 0 <0.000015>
7408  00:09:54.945063 exit_group(0)     = ?
7408  00:09:54.945168 +++ exited with 0 +++
477   00:09:54.945205 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7408 <1.002390>
477   00:09:54.945240 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
477   00:09:54.945293 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:54.945331 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7408, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:54.945366 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000014>
477   00:09:54.945404 rt_sigreturn({mask=[]}) = 0 <0.000015>
477   00:09:54.945443 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000015>
477   00:09:54.945481 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:54.945566 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000026>
477   00:09:54.945630 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:54.945670 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000014>
477   00:09:54.945711 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:54.945748 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000014>
477   00:09:54.945792 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000015>
477   00:09:54.945834 close(3</dev/null>) = 0 <0.000014>
477   00:09:54.945871 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000015>
477   00:09:54.945908 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000015>
477   00:09:54.945949 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000015>
477   00:09:54.945986 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000014>
477   00:09:54.946023 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000014>
477   00:09:54.946064 fcntl(1</dev/null>, F_GETFD) = 0 <0.000014>
477   00:09:54.946105 kill(495, SIG_0)  = 0 <0.000014>
477   00:09:54.946141 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000014>
477   00:09:54.946182 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000014>
477   00:09:54.946220 close(11<pipe:[3578440]>) = 0 <0.000014>
477   00:09:54.946257 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000015>
477   00:09:54.946299 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000015>
477   00:09:54.946336 close(10<pipe:[3578440]>) = 0 <0.000015>
477   00:09:54.946393 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000015>
477   00:09:54.946432 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7409 <0.000126>
477   00:09:54.946621 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7409  00:09:54.946836 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:54.946870 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000222>
7409  00:09:54.946883 <... close resumed> ) = 0 <0.000023>
7409  00:09:54.946927 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
477   00:09:54.946945 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7409  00:09:54.946958 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000021>
477   00:09:54.946985 <... rt_sigprocmask resumed> [], 8) = 0 <0.000033>
7409  00:09:54.946998 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:54.947012 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7409  00:09:54.947024 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000017>
477   00:09:54.947037 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7409  00:09:54.947058 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:54.947073 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7409  00:09:54.947085 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000019>
477   00:09:54.947098 <... rt_sigprocmask resumed> [], 8) = 0 <0.000019>
7409  00:09:54.947111 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:54.947125 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7409  00:09:54.947138 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000021>
477   00:09:54.947152 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000021>
7409  00:09:54.947175 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:54.947188 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7409  00:09:54.947200 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
477   00:09:54.947222 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000027>
7409  00:09:54.947248 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:54.947261 wait4(-1,  <unfinished ...>
7409  00:09:54.947273 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7409  00:09:54.947294 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7409  00:09:54.947338 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7409  00:09:54.947382 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000016>
7409  00:09:54.947422 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7409  00:09:54.947462 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7409  00:09:54.947505 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7409  00:09:54.947544 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7409  00:09:54.947598 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000014>
7409  00:09:54.947681 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000162>
7409  00:09:54.947905 brk(NULL)         = 0x155c000 <0.000008>
7409  00:09:54.947952 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000024>
7409  00:09:54.948009 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000014>
7409  00:09:54.948050 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000018>
7409  00:09:54.948104 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000014>
7409  00:09:54.948153 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f20e0b04000 <0.000011>
7409  00:09:54.948186 close(3</etc/ld.so.cache>) = 0 <0.000010>
7409  00:09:54.948231 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7409  00:09:54.948269 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000015>
7409  00:09:54.948318 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000012>
7409  00:09:54.948368 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000024>
7409  00:09:54.948417 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f20e0b03000 <0.000013>
7409  00:09:54.948455 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f20e0518000 <0.000019>
7409  00:09:54.948508 mprotect(0x7f20e06d8000, 2097152, PROT_NONE) = 0 <0.000020>
7409  00:09:54.948550 mmap(0x7f20e08d8000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f20e08d8000 <0.000020>
7409  00:09:54.948603 mmap(0x7f20e08de000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f20e08de000 <0.000015>
7409  00:09:54.948657 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000014>
7409  00:09:54.948706 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f20e0b02000 <0.000020>
7409  00:09:54.948754 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f20e0b01000 <0.000014>
7409  00:09:54.948791 arch_prctl(ARCH_SET_FS, 0x7f20e0b02700) = 0 <0.000016>
7409  00:09:54.948890 mprotect(0x7f20e08d8000, 16384, PROT_READ) = 0 <0.000016>
7409  00:09:54.948931 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000014>
7409  00:09:54.948980 mprotect(0x7f20e0b07000, 4096, PROT_READ) = 0 <0.000015>
7409  00:09:54.949015 munmap(0x7f20e0b04000, 10600) = 0 <0.000023>
7409  00:09:54.949144 brk(NULL)         = 0x155c000 <0.000011>
7409  00:09:54.949177 brk(0x157d000)    = 0x157d000 <0.000013>
7409  00:09:54.949244 nanosleep({1, 0},  <unfinished ...>
1093  00:09:54.982012 <... nanosleep resumed> NULL) = 0 <1.000206>
1093  00:09:54.982065 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000019>
1093  00:09:54.982128 open("/var/log/gitlab/gitaly/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitaly/current> <0.000023>
1093  00:09:54.982185 fstat(33</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000017>
1093  00:09:54.982233 close(33</var/log/gitlab/gitaly/current>) = 0 <0.000018>
1093  00:09:54.982273 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:54.982310 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000012>
1093  00:09:54.982347 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000012>
1093  00:09:54.982383 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000013>
1093  00:09:54.982418 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000013>
1093  00:09:54.982454 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121384, ...}) = 0 <0.000021>
1093  00:09:54.982499 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117798, ...}) = 0 <0.000012>
1093  00:09:54.982536 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:54.982572 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:54.982608 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000012>
1093  00:09:54.982643 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000013>
1093  00:09:54.982679 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000013>
1093  00:09:54.982724 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56772, ...}) = 0 <0.000013>
1093  00:09:54.982760 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000012>
1093  00:09:54.982795 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:54.982831 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:54.982866 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:54.982902 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42869, ...}) = 0 <0.000013>
1093  00:09:54.982937 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:54.982972 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:54.983007 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:54.983042 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:54.983078 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:54.983113 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:54.983148 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:54.983184 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:54.983220 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000013>
1093  00:09:54.983255 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000012>
1093  00:09:54.983290 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000013>
1093  00:09:54.983328 nanosleep({1, 0},  <unfinished ...>
7113  00:09:55.082963 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.964847>
7113  00:09:55.083012 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000007>
7113  00:09:55.083040 clock_gettime(CLOCK_MONOTONIC, {282501, 167503248}) = 0 <0.000007>
7113  00:09:55.083072 futex(0x7f5ef33fb464, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7f5ef33fb460, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1}) = 1 <0.000009>
7113  00:09:55.083102 epoll_wait(33<anon_inode:[eventpoll]>,  <unfinished ...>
7110  00:09:55.083133 <... futex resumed> ) = 0 <4.999763>
7113  00:09:55.083145 <... epoll_wait resumed> [], 100, 0) = 0 <0.000020>
7110  00:09:55.083155 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
7113  00:09:55.083164 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
7110  00:09:55.083173 <... futex resumed> ) = 0 <0.000013>
7113  00:09:55.083182 <... clock_gettime resumed> {282501, 167630629}) = 0 <0.000012>
7110  00:09:55.083195 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
7113  00:09:55.083203 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 115, {282501, 203328885}, ffffffff <unfinished ...>
7110  00:09:55.083216 <... clock_gettime resumed> {282501, 167661711}) = 0 <0.000017>
7110  00:09:55.083245 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 116, NULL <unfinished ...>
7113  00:09:55.118953 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.035740>
7113  00:09:55.118987 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000012>
7113  00:09:55.119020 clock_gettime(CLOCK_MONOTONIC, {282501, 203484280}) = 0 <0.000011>
7113  00:09:55.119056 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 118, {282502, 204328885}, ffffffff <unfinished ...>
2690  00:09:55.190462 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000833>
2690  00:09:55.190514 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000015>
2690  00:09:55.190564 clock_gettime(CLOCK_MONOTONIC, {282501, 275031732}) = 0 <0.000014>
2690  00:09:55.190611 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4010, {282501, 841834003}, ffffffff) = -1 ETIMEDOUT (Connection timed out) <0.566846>
2690  00:09:55.757508 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000016>
2690  00:09:55.757570 clock_gettime(CLOCK_MONOTONIC, {282501, 842040083}) = 0 <0.000015>
2690  00:09:55.757622 futex(0x7f5ef33fb464, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7f5ef33fb460, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1}) = 1 <0.000022>
2686  00:09:55.757658 <... futex resumed> ) = 0 <4.999752>
2690  00:09:55.757673 epoll_wait(36<anon_inode:[eventpoll]>,  <unfinished ...>
2686  00:09:55.757701 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
2690  00:09:55.757711 <... epoll_wait resumed> [], 100, 0) = 0 <0.000016>
2686  00:09:55.757722 <... futex resumed> ) = 0 <0.000015>
2690  00:09:55.757737 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
2686  00:09:55.757748 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
2690  00:09:55.757757 <... clock_gettime resumed> {282501, 842207337}) = 0 <0.000015>
2686  00:09:55.757768 <... clock_gettime resumed> {282501, 842219139}) = 0 <0.000015>
2690  00:09:55.757780 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4013, {282502, 275834003}, ffffffff <unfinished ...>
2686  00:09:55.757793 futex(0x7f5ef33fb464, FUTEX_WAIT_PRIVATE, 4014, NULL <unfinished ...>
2690  00:09:55.757813 <... futex resumed> ) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
2690  00:09:55.757840 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4014, {282502, 275834003}, ffffffff <unfinished ...>
7409  00:09:55.949343 <... nanosleep resumed> NULL) = 0 <1.000086>
7409  00:09:55.949426 close(1<pipe:[3578440]>) = 0 <0.000012>
7409  00:09:55.949479 close(2<pipe:[3578440]>) = 0 <0.000011>
7409  00:09:55.949519 exit_group(0)     = ?
7409  00:09:55.949622 +++ exited with 0 +++
477   00:09:55.949650 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7409 <1.002384>
477   00:09:55.949684 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
477   00:09:55.949739 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:55.949777 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7409, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:55.949804 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000014>
477   00:09:55.949843 rt_sigreturn({mask=[]}) = 0 <0.000015>
477   00:09:55.949879 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000014>
477   00:09:55.949918 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:55.950003 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000024>
477   00:09:55.950058 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:55.950093 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000010>
477   00:09:55.950125 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:55.950158 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000010>
477   00:09:55.950198 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000010>
477   00:09:55.950241 close(3</dev/null>) = 0 <0.000010>
477   00:09:55.950274 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:55.950307 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000010>
477   00:09:55.950340 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:55.950373 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000010>
477   00:09:55.950406 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000010>
477   00:09:55.950438 fcntl(1</dev/null>, F_GETFD) = 0 <0.000009>
477   00:09:55.950471 kill(495, SIG_0)  = 0 <0.000015>
477   00:09:55.950507 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000010>
477   00:09:55.950540 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000010>
477   00:09:55.950574 close(11<pipe:[3578440]>) = 0 <0.000011>
477   00:09:55.950620 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000010>
477   00:09:55.950657 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000010>
477   00:09:55.950690 close(10<pipe:[3578440]>) = 0 <0.000010>
477   00:09:55.950744 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000015>
477   00:09:55.950783 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7410 <0.000148>
7410  00:09:55.951177 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:55.951216 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7410  00:09:55.951233 <... close resumed> ) = 0 <0.000028>
477   00:09:55.951246 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000020>
7410  00:09:55.951259 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000044>
477   00:09:55.951321 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7410  00:09:55.951336 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:55.951350 <... rt_sigprocmask resumed> [], 8) = 0 <0.000020>
7410  00:09:55.951362 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000018>
7410  00:09:55.951390 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:55.951405 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7410  00:09:55.951416 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000020>
477   00:09:55.951429 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000019>
7410  00:09:55.951441 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:55.951463 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7410  00:09:55.951477 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000029>
477   00:09:55.951490 <... rt_sigprocmask resumed> [], 8) = 0 <0.000020>
7410  00:09:55.951503 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:55.951516 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7410  00:09:55.951529 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
477   00:09:55.951543 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000021>
7410  00:09:55.951585 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:55.951598 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7410  00:09:55.951610 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
477   00:09:55.951623 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7410  00:09:55.951636 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
477   00:09:55.951668 wait4(-1,  <unfinished ...>
7410  00:09:55.951679 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7410  00:09:55.951734 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000011>
7410  00:09:55.951771 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000010>
7410  00:09:55.951815 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7410  00:09:55.951856 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7410  00:09:55.951905 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7410  00:09:55.951942 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000014>
7410  00:09:55.952022 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000175>
7410  00:09:55.952254 brk(NULL)         = 0x25ef000 <0.000010>
7410  00:09:55.952309 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000011>
7410  00:09:55.952352 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000022>
7410  00:09:55.952405 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000015>
7410  00:09:55.952448 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000021>
7410  00:09:55.952496 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f448b71b000 <0.000015>
7410  00:09:55.952536 close(3</etc/ld.so.cache>) = 0 <0.000012>
7410  00:09:55.952578 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7410  00:09:55.952614 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000021>
7410  00:09:55.952658 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000014>
7410  00:09:55.952716 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000011>
7410  00:09:55.952751 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f448b71a000 <0.000014>
7410  00:09:55.952798 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f448b12f000 <0.000016>
7410  00:09:55.952835 mprotect(0x7f448b2ef000, 2097152, PROT_NONE) = 0 <0.000018>
7410  00:09:55.952886 mmap(0x7f448b4ef000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f448b4ef000 <0.000020>
7410  00:09:55.952936 mmap(0x7f448b4f5000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f448b4f5000 <0.000026>
7410  00:09:55.952992 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000010>
7410  00:09:55.953045 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f448b719000 <0.000011>
7410  00:09:55.953081 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f448b718000 <0.000010>
7410  00:09:55.953123 arch_prctl(ARCH_SET_FS, 0x7f448b719700) = 0 <0.000014>
7410  00:09:55.953226 mprotect(0x7f448b4ef000, 16384, PROT_READ) = 0 <0.000016>
7410  00:09:55.953266 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000016>
7410  00:09:55.953323 mprotect(0x7f448b71e000, 4096, PROT_READ) = 0 <0.000014>
7410  00:09:55.953372 munmap(0x7f448b71b000, 10600) = 0 <0.000017>
7410  00:09:55.953493 brk(NULL)         = 0x25ef000 <0.000011>
7410  00:09:55.953537 brk(0x2610000)    = 0x2610000 <0.000011>
7410  00:09:55.953589 nanosleep({1, 0},  <unfinished ...>
1093  00:09:55.983413 <... nanosleep resumed> NULL) = 0 <1.000077>
1093  00:09:55.983442 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000014>
1093  00:09:55.983486 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:55.983518 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000009>
1093  00:09:55.983551 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000013>
1093  00:09:55.983588 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000008>
1093  00:09:55.983618 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000013>
1093  00:09:55.983652 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121384, ...}) = 0 <0.000012>
1093  00:09:55.983685 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117798, ...}) = 0 <0.000009>
1093  00:09:55.983715 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000012>
1093  00:09:55.983749 open("/var/log/gitlab/gitlab-rails/sidekiq.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sidekiq/current> <0.000020>
1093  00:09:55.983793 fstat(33</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000008>
1093  00:09:55.983822 close(33</var/log/gitlab/sidekiq/current>) = 0 <0.000012>
1093  00:09:55.983854 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000008>
1093  00:09:55.983884 open("/var/log/gitlab/sidekiq/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sidekiq/current> <0.000012>
1093  00:09:55.983915 fstat(33</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:55.983944 close(33</var/log/gitlab/sidekiq/current>) = 0 <0.000009>
1093  00:09:55.983971 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000008>
1093  00:09:55.984001 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000012>
1093  00:09:55.984035 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000013>
1093  00:09:55.984070 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56772, ...}) = 0 <0.000008>
1093  00:09:55.984100 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000008>
1093  00:09:55.984130 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:55.984160 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:55.984193 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:55.984227 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42869, ...}) = 0 <0.000008>
1093  00:09:55.984256 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:55.984286 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:55.984319 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:55.984348 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000008>
1093  00:09:55.984382 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:55.984415 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:55.984449 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:55.984483 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:55.984516 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000012>
1093  00:09:55.984550 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000013>
1093  00:09:55.984584 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000012>
1093  00:09:55.984618 nanosleep({1, 0},  <unfinished ...>
823   00:09:56.117087 <... select resumed> ) = 1 (in [25], left {27, 52101}) <2.947933>
813   00:09:56.117151 <... select resumed> ) = 1 (in [25], left {26, 931993}) <3.068097>
817   00:09:56.117172 <... select resumed> ) = 1 (in [25], left {26, 930716}) <3.069297>
823   00:09:56.117269 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
817   00:09:56.117336 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
813   00:09:56.117373 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
817   00:09:56.117405 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000041>
823   00:09:56.117426 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000096>
817   00:09:56.117438 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:56.117469 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:56.117506 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = 27<UNIX:[3605691->3605690,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> <0.000043>
823   00:09:56.117543 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000046>
813   00:09:56.117556 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000159>
817   00:09:56.117587 recvfrom(27<UNIX:[3605691->3605690,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:56.117625 getppid( <unfinished ...>
817   00:09:56.117637 <... recvfrom resumed> "GET /help HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.59.0\r\nAccept: */*\r\nGitlab-Workhorse: v6.1.0-20180921.115425\r\nGitlab-Workhorse-Proxy-Start: 1537834196116935432\r\nX-Forwarded-For: 127.0.0.1\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Ssl: on\r\nX-Real-Ip: 127.0.0.1\r\nX-Sendfile-Type: X-Sendfile\r\nAccept-Encoding: gzip\r\n\r\n", 16384, MSG_DONTWAIT, NULL, NULL) = 319 <0.000019>
823   00:09:56.117655 <... getppid resumed> ) = 495 <0.000023>
813   00:09:56.117664 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000013>
813   00:09:56.117723 getppid()         = 495 <0.000008>
813   00:09:56.117762 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:56.119404 select(26, [14<pipe:[3579145]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
817   00:09:56.119709 write(8</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/help\" for 127.0.0.1 at 2018-09-25 00:09:56 +0000\n", 63) = 63 <0.000069>
7113  00:09:56.119945 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000881>
7113  00:09:56.119971 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
817   00:09:56.119985 sendto(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, "\27\3\3\0& \213\247\256n3\r\370\203A\242\233\31\23ZL\5\270\7\331\370W`}\306\267\337\27\236\200\260\235\242\212X\233\177\314", 43, MSG_NOSIGNAL, NULL, 0 <unfinished ...>
7113  00:09:56.120449 <... futex resumed> ) = 0 <0.000469>
7113  00:09:56.120479 clock_gettime(CLOCK_MONOTONIC, {282502, 204945434}) = 0 <0.000009>
7113  00:09:56.120515 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 120, {282503, 205328885}, ffffffff <unfinished ...>
817   00:09:56.120713 <... sendto resumed> ) = 43 <0.000271>
817   00:09:56.120820 poll([{fd=31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, events=POLLIN|POLLERR}], 1, -1) = 1 ([{fd=31, revents=POLLIN}]) <0.000103>
817   00:09:56.121269 recvfrom(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, "\27\3\3\0Z", 5, 0, NULL, NULL) = 5 <0.000016>
817   00:09:56.121574 recvfrom(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, "\202\371\0\10p\355\27\236\22)1\3720E\314\202\5\341i\237\345\3\271\1\371H\215\4+?JS\362\3327\371T\206T\202}e\305\204\231B\204W\252^z\277\244\275\334\344\2525~Q\211\17\267\335\375Z\330?\347\204sS\256\v\364T\f\0371m_/U&R\347g?p\1", 90, 0, NULL, NULL) = 90 <0.000014>
817   00:09:56.122170 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.122467 write(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$48\r\ncache:gitlab:ApplicationSetting:11.3.0-ee:4.2.10\r\n", 68) = 68 <0.000036>
817   00:09:56.122794 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000380>
817   00:09:56.123496 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "$13766\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\27ApplicationSetting\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\1\246I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\33default_projects_limit\6;\fT@\vI\"\23signup_enabled\6;\fTo: ActiveRecord::Type::Boolean\10;\0160;\0170;\0200I\"\25gravatar_enabled\6;\fT@\21I\"\21sign_in_text\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\17created_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\17updated_at\6;\fTU;\30[\t;\31[\0[\0@\32I\"\22home_page_url\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\36default_branch_protection\6;\fT@\vI\"\16help_text\6;\fT@\24I\"!restricted_visibility_levels\6;\fTU:#ActiveRecord::Type::Serialized[\t;\31[\7:\r@subtype:\v@coder[\7@\24o:%ActiveRecord::Coders::YAMLColumn\6:\22@object_classc\vObject@\24I\"\32version_check_enabled\6;\fT@\21I\"\30max_attachment_size\6;\fT@\vI\"\37de", 1024) = 1024 <0.000017>
817   00:09:56.123914 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.124210 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "fault_project_visibility\6;\fT@\vI\"\37default_snippet_visibility\6;\fT@\vI\"\25domain_whitelist\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; c\nArray@\24I\"\34user_oauth_applications\6;\fT@\21I\"\30after_sign_out_path\6;\fT@!I\"\31session_expire_delay\6;\fT@\vI\"\23import_sources\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; @*@\24I\"\23help_page_text\6;\fT@\24I\"\35admin_notification_email\6;\fT@!I\"\33shared_runners_enabled\6;\fT@\21I\"\27max_artifacts_size\6;\fT@\vI\"\37runners_registration_token\6;\fT@!I\"\23max_pages_size\6;\fT@\vI\"&require_two_factor_authentication\6;\fT@\21I\"\34two_factor_grace_period\6;\fT@\vI\"\24metrics_enabled\6;\fT@\21I\"\21metrics_host\6;\fT@!I\"\26metrics_pool_size\6;\fT@\vI\"\24metrics_timeout\6;\fT@\vI\"\"metrics_method_call_threshold\6;\fT@\vI\"\26recaptcha_enabled\6;\fT@\21I\"\27recaptcha_site_key\6;\fT@!I\"\32recaptcha_private_key\6;\fT@!I\"\21metrics_port\6;\fT@\vI\"\24akismet_enabled\6;\fT@\21I\"\24akismet_api_key\6;\fT@!I\"\34metrics_sample_interval\6;\fT@\vI\"\23sentry_enabled\6;\fT@\21I\"\17sentry_dsn\6;\fT@!I\"\31email_author_in_body\6;\fT@\21I\"\35default_group_visibility\6;\fT@\vI\"\36repository_checks_enabled\6;\fT@\21I\"\30shared_runners_text\6;\fT@\24I\"\30metrics_packet_size\6;\fT@\vI\"#disable"..., 12750) = 12750 <0.000028>
817   00:09:56.124537 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000049>
817   00:09:56.124861 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000022>
817   00:09:56.125762 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 35</proc/817/status> <0.000021>
817   00:09:56.125827 ioctl(35</proc/817/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
817   00:09:56.125864 fstat(35</proc/817/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000010>
817   00:09:56.125901 lseek(35</proc/817/status>, 0, SEEK_CUR) = 0 <0.000009>
817   00:09:56.125936 read(35</proc/817/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t817\nNgid:\t0\nPid:\t817\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t817\nNSpid:\t817\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  799580 kB\nVmSize:\t  799580 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  489776 kB\nVmRSS:\t  489776 kB\nRssAnon:\t  476792 kB\nRssFile:\t   12936 kB\nRssShmem:\t      48 kB\nVmData:\t  517028 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1644 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t2\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1312 <0.000026>
817   00:09:56.125990 read(35</proc/817/status>, "", 6880) = 0 <0.000010>
817   00:09:56.126024 close(35</proc/817/status>) = 0 <0.000013>
817   00:09:56.130160 write(8</var/log/gitlab/gitlab-rails/production.log>, "Processing by HelpController#index as */*\n", 42) = 42 <0.000021>
817   00:09:56.134019 open("/opt/gitlab/embedded/service/gitlab-rails/doc/README.md", O_RDONLY|O_CLOEXEC) = 35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md> <0.000022>
817   00:09:56.134088 ioctl(35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md>, TCGETS, 0x7ffc6d3c9740) = -1 ENOTTY (Inappropriate ioctl for device) <0.000010>
817   00:09:56.134125 fstat(35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md>, {st_mode=S_IFREG|0644, st_size=18123, ...}) = 0 <0.000010>
817   00:09:56.134161 lseek(35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md>, 0, SEEK_CUR) = 0 <0.000010>
817   00:09:56.134197 read(35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md>, "---\ncomments: false\ndescription: 'Learn how to use and administer GitLab, the most scalable Git-based fully integrated platform for software development.'\n---\n\n# GitLab Documentation\n\nWelcome to [GitLab](https://about.gitlab.com/), a Git-based fully featured\nplatform for software development!\n\nGitLab offers the most scalable Git-based fully integrated platform for\nsoftware development, with flexible products and subscriptions.\nTo understand what features you have access to, check the [GitLab subscriptions](#gitlab-subscriptions) below.\n\n**Shortcuts to GitLab's most visited docs:**\n\n| General documentation | GitLab CI/CD docs |\n| :----- | :----- |\n| [User documentation](user/index.md) | [GitLab CI/CD quick start guide](ci/quick_start/README.md) |\n| [Administrator documentation](administration/index.md) | [GitLab CI/CD examples](ci/examples/README.md) |\n| [Contributor documentation](#contributor-documentation) | [Configuring `.gitlab-ci.yml`](ci/yaml/README.md) |\n| [Getting started with GitLab](#getting-started"..., 18123) = 18123 <0.000019>
817   00:09:56.134256 read(35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md>, "", 8192) = 0 <0.000009>
817   00:09:56.134290 close(35</opt/gitlab/embedded/service/gitlab-rails/doc/README.md>) = 0 <0.000013>
817   00:09:56.137490 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 700669243}) = 0 <0.000015>
817   00:09:56.137551 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 700694567}) = 0 <0.000013>
817   00:09:56.137588 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 700713452}) = 0 <0.000012>
817   00:09:56.137632 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 700740498}) = 0 <0.000013>
817   00:09:56.137673 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 700765140}) = 0 <0.000013>
817   00:09:56.137710 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 700786011}) = 0 <0.000012>
817   00:09:56.140118 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 703199658}) = 0 <0.000017>
817   00:09:56.154965 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718008338}) = 0 <0.000019>
817   00:09:56.155146 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718146028}) = 0 <0.000016>
817   00:09:56.155204 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718181173}) = 0 <0.000016>
817   00:09:56.155310 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718268186}) = 0 <0.000016>
817   00:09:56.155359 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718296851}) = 0 <0.000016>
817   00:09:56.155459 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718377854}) = 0 <0.000015>
817   00:09:56.155508 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718407132}) = 0 <0.000015>
817   00:09:56.155626 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718505963}) = 0 <0.000016>
817   00:09:56.155677 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718535582}) = 0 <0.000016>
817   00:09:56.155798 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718638222}) = 0 <0.000016>
817   00:09:56.155849 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718668155}) = 0 <0.000016>
817   00:09:56.155952 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718752550}) = 0 <0.000016>
817   00:09:56.156001 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718781929}) = 0 <0.000016>
817   00:09:56.156117 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718880014}) = 0 <0.000016>
817   00:09:56.156167 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718909988}) = 0 <0.000015>
817   00:09:56.156265 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 718989429}) = 0 <0.000015>
817   00:09:56.156315 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719019689}) = 0 <0.000015>
817   00:09:56.156428 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719113344}) = 0 <0.000016>
817   00:09:56.156478 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719143800}) = 0 <0.000015>
817   00:09:56.156601 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719248612}) = 0 <0.000016>
817   00:09:56.156653 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719280227}) = 0 <0.000016>
817   00:09:56.156788 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719396244}) = 0 <0.000016>
817   00:09:56.156839 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719426391}) = 0 <0.000016>
817   00:09:56.156953 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719521697}) = 0 <0.000016>
817   00:09:56.157015 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719546918}) = 0 <0.000055>
817   00:09:56.157233 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719698913}) = 0 <0.000017>
817   00:09:56.157291 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719727988}) = 0 <0.000016>
817   00:09:56.157416 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719830906}) = 0 <0.000015>
817   00:09:56.157477 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719867939}) = 0 <0.000016>
817   00:09:56.157623 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 719991314}) = 0 <0.000016>
817   00:09:56.157675 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720019048}) = 0 <0.000016>
817   00:09:56.157814 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720135312}) = 0 <0.000017>
817   00:09:56.157880 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720177118}) = 0 <0.000016>
817   00:09:56.158018 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720293883}) = 0 <0.000018>
817   00:09:56.158080 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720322299}) = 0 <0.000016>
817   00:09:56.158192 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720411193}) = 0 <0.000016>
817   00:09:56.158238 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720433322}) = 0 <0.000016>
817   00:09:56.158306 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720479018}) = 0 <0.000015>
817   00:09:56.158356 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720506207}) = 0 <0.000016>
817   00:09:56.158477 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720605593}) = 0 <0.000016>
817   00:09:56.158530 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720634389}) = 0 <0.000015>
817   00:09:56.158665 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720746703}) = 0 <0.000016>
817   00:09:56.158716 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720774039}) = 0 <0.000015>
817   00:09:56.158835 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720870166}) = 0 <0.000016>
817   00:09:56.158887 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 720898072}) = 0 <0.000016>
817   00:09:56.159024 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721012672}) = 0 <0.000016>
817   00:09:56.159076 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721041053}) = 0 <0.000016>
817   00:09:56.159194 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721141126}) = 0 <0.000020>
817   00:09:56.159249 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721168074}) = 0 <0.000016>
817   00:09:56.159356 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721252669}) = 0 <0.000016>
817   00:09:56.159409 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721281989}) = 0 <0.000016>
817   00:09:56.159530 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721380513}) = 0 <0.000026>
817   00:09:56.159589 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721420528}) = 0 <0.000015>
817   00:09:56.159670 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721482804}) = 0 <0.000016>
817   00:09:56.159720 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721512810}) = 0 <0.000016>
817   00:09:56.159834 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721609029}) = 0 <0.000015>
817   00:09:56.159885 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721639719}) = 0 <0.000016>
817   00:09:56.160004 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721740446}) = 0 <0.000015>
817   00:09:56.160053 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 721769934}) = 0 <0.000016>
817   00:09:56.160193 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 721865783}) = 0 <0.000017>
817   00:09:56.160254 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 721904513}) = 0 <0.000016>
817   00:09:56.160352 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 721982853}) = 0 <0.000016>
817   00:09:56.160408 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 722018809}) = 0 <0.000016>
817   00:09:56.161378 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 722966916}) = 0 <0.000018>
817   00:09:56.161436 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 722994783}) = 0 <0.000018>
817   00:09:56.161592 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 723152895}) = 0 <0.000017>
817   00:09:56.161652 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 723184276}) = 0 <0.000016>
817   00:09:56.162085 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 723593793}) = 0 <0.000017>
817   00:09:56.162142 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 723622812}) = 0 <0.000016>
817   00:09:56.162407 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 723865036}) = 0 <0.000017>
817   00:09:56.162462 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 723894168}) = 0 <0.000016>
817   00:09:56.163527 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 724929421}) = 0 <0.000028>
817   00:09:56.163597 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 724959570}) = 0 <0.000015>
817   00:09:56.164286 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 725628769}) = 0 <0.000016>
817   00:09:56.164337 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 725657633}) = 0 <0.000015>
817   00:09:56.164631 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 725931743}) = 0 <0.000017>
817   00:09:56.164685 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 725962355}) = 0 <0.000015>
817   00:09:56.164885 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726122020}) = 0 <0.000010>
817   00:09:56.164945 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726154717}) = 0 <0.000015>
817   00:09:56.165069 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726259543}) = 0 <0.000016>
817   00:09:56.165116 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726287400}) = 0 <0.000015>
817   00:09:56.165229 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726368338}) = 0 <0.000065>
817   00:09:56.165333 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726393500}) = 0 <0.000016>
817   00:09:56.165429 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726453618}) = 0 <0.000018>
817   00:09:56.165481 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726481430}) = 0 <0.000019>
817   00:09:56.165548 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726525652}) = 0 <0.000015>
817   00:09:56.165596 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726551329}) = 0 <0.000016>
817   00:09:56.165730 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726662684}) = 0 <0.000016>
817   00:09:56.165783 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726691651}) = 0 <0.000015>
817   00:09:56.166027 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726913386}) = 0 <0.000016>
817   00:09:56.166083 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 726942480}) = 0 <0.000016>
817   00:09:56.166294 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727130143}) = 0 <0.000016>
817   00:09:56.166349 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727159412}) = 0 <0.000015>
817   00:09:56.166547 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727334568}) = 0 <0.000017>
817   00:09:56.166597 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727360797}) = 0 <0.000015>
817   00:09:56.166722 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727462835}) = 0 <0.000015>
817   00:09:56.166775 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727491676}) = 0 <0.000015>
817   00:09:56.166941 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727636217}) = 0 <0.000016>
817   00:09:56.166994 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727665026}) = 0 <0.000015>
817   00:09:56.167193 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727841073}) = 0 <0.000017>
817   00:09:56.167248 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 727870406}) = 0 <0.000015>
817   00:09:56.167431 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728030520}) = 0 <0.000016>
817   00:09:56.167486 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728059738}) = 0 <0.000015>
817   00:09:56.167712 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728262614}) = 0 <0.000022>
817   00:09:56.167774 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728296573}) = 0 <0.000015>
817   00:09:56.167935 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728435046}) = 0 <0.000016>
817   00:09:56.167988 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728463945}) = 0 <0.000015>
817   00:09:56.168172 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728625573}) = 0 <0.000017>
817   00:09:56.168227 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728653261}) = 0 <0.000016>
817   00:09:56.168373 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728776907}) = 0 <0.000016>
817   00:09:56.168425 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728805573}) = 0 <0.000015>
817   00:09:56.168588 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728945746}) = 0 <0.000017>
817   00:09:56.168642 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 728974435}) = 0 <0.000016>
817   00:09:56.168777 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729086550}) = 0 <0.000016>
817   00:09:56.168830 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729115403}) = 0 <0.000016>
817   00:09:56.168988 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729249896}) = 0 <0.000017>
817   00:09:56.169041 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729277266}) = 0 <0.000015>
817   00:09:56.169195 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729409140}) = 0 <0.000016>
817   00:09:56.169250 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729438299}) = 0 <0.000016>
817   00:09:56.169415 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729581392}) = 0 <0.000016>
817   00:09:56.169474 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729615079}) = 0 <0.000015>
817   00:09:56.169653 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729771613}) = 0 <0.000016>
817   00:09:56.169713 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729800091}) = 0 <0.000015>
817   00:09:56.169849 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729913761}) = 0 <0.000016>
817   00:09:56.169903 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 729942989}) = 0 <0.000016>
817   00:09:56.170079 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730097195}) = 0 <0.000016>
817   00:09:56.170136 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730128654}) = 0 <0.000015>
817   00:09:56.170287 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730257228}) = 0 <0.000016>
817   00:09:56.170339 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730286119}) = 0 <0.000015>
817   00:09:56.170506 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730430540}) = 0 <0.000016>
817   00:09:56.170559 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730458882}) = 0 <0.000015>
817   00:09:56.170704 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730580918}) = 0 <0.000016>
817   00:09:56.170764 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730617050}) = 0 <0.000016>
817   00:09:56.171001 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730829685}) = 0 <0.000017>
817   00:09:56.171069 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 730868279}) = 0 <0.000016>
817   00:09:56.171430 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731202900}) = 0 <0.000018>
817   00:09:56.171497 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731237362}) = 0 <0.000015>
817   00:09:56.171784 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731499393}) = 0 <0.000017>
817   00:09:56.171851 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731536160}) = 0 <0.000015>
817   00:09:56.172044 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731706251}) = 0 <0.000016>
817   00:09:56.172102 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731738114}) = 0 <0.000015>
817   00:09:56.172258 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731871836}) = 0 <0.000016>
817   00:09:56.172315 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 731905056}) = 0 <0.000015>
817   00:09:56.172463 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732030462}) = 0 <0.000015>
817   00:09:56.172513 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732058589}) = 0 <0.000015>
817   00:09:56.172620 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732143877}) = 0 <0.000015>
817   00:09:56.172677 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732177729}) = 0 <0.000015>
817   00:09:56.172823 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732301978}) = 0 <0.000015>
817   00:09:56.172883 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732338508}) = 0 <0.000015>
817   00:09:56.173035 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732468441}) = 0 <0.000016>
817   00:09:56.173092 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732499655}) = 0 <0.000015>
817   00:09:56.173262 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732647790}) = 0 <0.000016>
817   00:09:56.173318 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732678428}) = 0 <0.000015>
817   00:09:56.173453 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732791127}) = 0 <0.000016>
817   00:09:56.173509 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732821955}) = 0 <0.000015>
817   00:09:56.173671 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732962187}) = 0 <0.000016>
817   00:09:56.173734 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 732999484}) = 0 <0.000015>
817   00:09:56.173889 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733132833}) = 0 <0.000016>
817   00:09:56.173950 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733168070}) = 0 <0.000015>
817   00:09:56.174107 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733302900}) = 0 <0.000016>
817   00:09:56.174164 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733334651}) = 0 <0.000015>
817   00:09:56.174309 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733458437}) = 0 <0.000016>
817   00:09:56.174364 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733488286}) = 0 <0.000015>
817   00:09:56.174495 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733596181}) = 0 <0.000016>
817   00:09:56.174557 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733633255}) = 0 <0.000015>
817   00:09:56.174692 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733747039}) = 0 <0.000016>
817   00:09:56.174752 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733777668}) = 0 <0.000014>
817   00:09:56.174898 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733901835}) = 0 <0.000016>
817   00:09:56.174959 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 733938202}) = 0 <0.000015>
817   00:09:56.175107 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734063870}) = 0 <0.000016>
817   00:09:56.175161 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734092982}) = 0 <0.000022>
817   00:09:56.175308 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734210430}) = 0 <0.000017>
817   00:09:56.175373 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734248839}) = 0 <0.000016>
817   00:09:56.175503 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734355179}) = 0 <0.000016>
817   00:09:56.175569 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734396499}) = 0 <0.000016>
817   00:09:56.175717 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734520073}) = 0 <0.000017>
817   00:09:56.175776 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734553919}) = 0 <0.000016>
817   00:09:56.175913 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734667449}) = 0 <0.000016>
817   00:09:56.175974 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734703756}) = 0 <0.000017>
817   00:09:56.176136 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734842489}) = 0 <0.000016>
817   00:09:56.176192 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 734872566}) = 0 <0.000015>
817   00:09:56.176347 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735004212}) = 0 <0.000017>
817   00:09:56.176404 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735035457}) = 0 <0.000016>
817   00:09:56.176577 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735185539}) = 0 <0.000017>
817   00:09:56.176637 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735219764}) = 0 <0.000015>
817   00:09:56.176769 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735329215}) = 0 <0.000016>
817   00:09:56.176827 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735363477}) = 0 <0.000016>
817   00:09:56.176998 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735511222}) = 0 <0.000017>
817   00:09:56.177052 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735539004}) = 0 <0.000016>
817   00:09:56.177181 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735644568}) = 0 <0.000017>
817   00:09:56.177238 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735675592}) = 0 <0.000016>
817   00:09:56.177381 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735794971}) = 0 <0.000016>
817   00:09:56.177434 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735824534}) = 0 <0.000015>
817   00:09:56.177590 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735957831}) = 0 <0.000017>
817   00:09:56.177650 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 735991212}) = 0 <0.000016>
817   00:09:56.177787 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736104552}) = 0 <0.000016>
817   00:09:56.177840 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736134400}) = 0 <0.000016>
817   00:09:56.178002 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736273432}) = 0 <0.000016>
817   00:09:56.178058 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736303535}) = 0 <0.000016>
817   00:09:56.178189 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736412012}) = 0 <0.000017>
817   00:09:56.178244 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736441942}) = 0 <0.000015>
817   00:09:56.178395 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736569723}) = 0 <0.000016>
817   00:09:56.178453 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736602195}) = 0 <0.000016>
817   00:09:56.178632 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736758252}) = 0 <0.000017>
817   00:09:56.178690 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736789530}) = 0 <0.000015>
817   00:09:56.178841 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736917279}) = 0 <0.000016>
817   00:09:56.178894 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 736943850}) = 0 <0.000016>
817   00:09:56.178997 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737024065}) = 0 <0.000017>
817   00:09:56.179051 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737054011}) = 0 <0.000016>
817   00:09:56.179204 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737184100}) = 0 <0.000017>
817   00:09:56.179265 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737214750}) = 0 <0.000016>
817   00:09:56.179430 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737355730}) = 0 <0.000017>
817   00:09:56.179488 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737387769}) = 0 <0.000015>
817   00:09:56.179650 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737528312}) = 0 <0.000017>
817   00:09:56.179706 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737561173}) = 0 <0.000015>
817   00:09:56.179882 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737718523}) = 0 <0.000016>
817   00:09:56.179938 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737752097}) = 0 <0.000016>
817   00:09:56.180118 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737913570}) = 0 <0.000016>
817   00:09:56.180176 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 737949874}) = 0 <0.000016>
817   00:09:56.180364 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738118040}) = 0 <0.000017>
817   00:09:56.180419 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738151006}) = 0 <0.000016>
817   00:09:56.180552 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738265767}) = 0 <0.000016>
817   00:09:56.180605 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738298577}) = 0 <0.000016>
817   00:09:56.180768 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738442733}) = 0 <0.000017>
817   00:09:56.180824 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738477163}) = 0 <0.000015>
817   00:09:56.181007 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738641895}) = 0 <0.000017>
817   00:09:56.181070 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738682574}) = 0 <0.000016>
817   00:09:56.181264 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738857395}) = 0 <0.000017>
817   00:09:56.181318 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 738889841}) = 0 <0.000015>
817   00:09:56.181478 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739030407}) = 0 <0.000016>
817   00:09:56.181531 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739061763}) = 0 <0.000015>
817   00:09:56.181652 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739164001}) = 0 <0.000016>
817   00:09:56.181704 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739196858}) = 0 <0.000016>
817   00:09:56.181823 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739297178}) = 0 <0.000016>
817   00:09:56.181888 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739340236}) = 0 <0.000015>
817   00:09:56.182076 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739510043}) = 0 <0.000028>
817   00:09:56.182158 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739546363}) = 0 <0.000016>
817   00:09:56.182335 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739703508}) = 0 <0.000016>
817   00:09:56.182403 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739747925}) = 0 <0.000015>
817   00:09:56.182565 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739891158}) = 0 <0.000030>
817   00:09:56.182641 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 739923300}) = 0 <0.000019>
817   00:09:56.182809 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740066941}) = 0 <0.000017>
817   00:09:56.182874 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740106639}) = 0 <0.000016>
817   00:09:56.183063 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740273370}) = 0 <0.000017>
817   00:09:56.183120 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740304529}) = 0 <0.000015>
817   00:09:56.183298 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740459665}) = 0 <0.000016>
817   00:09:56.183356 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740491883}) = 0 <0.000016>
817   00:09:56.183534 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740643467}) = 0 <0.000019>
817   00:09:56.183591 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740670381}) = 0 <0.000015>
817   00:09:56.183765 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740822277}) = 0 <0.000016>
817   00:09:56.183818 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 740849478}) = 0 <0.000015>
817   00:09:56.184021 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741030439}) = 0 <0.000016>
817   00:09:56.184071 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741054976}) = 0 <0.000015>
817   00:09:56.184177 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741139720}) = 0 <0.000015>
817   00:09:56.184239 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741167926}) = 0 <0.000015>
817   00:09:56.184449 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741355615}) = 0 <0.000016>
817   00:09:56.184501 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741382165}) = 0 <0.000015>
817   00:09:56.184667 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741526366}) = 0 <0.000016>
817   00:09:56.184719 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741553966}) = 0 <0.000015>
817   00:09:56.184916 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741728517}) = 0 <0.000015>
817   00:09:56.184968 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741756217}) = 0 <0.000015>
817   00:09:56.185140 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741905777}) = 0 <0.000016>
817   00:09:56.185203 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 741942753}) = 0 <0.000015>
817   00:09:56.185405 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742121846}) = 0 <0.000017>
817   00:09:56.185460 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742150642}) = 0 <0.000016>
817   00:09:56.185633 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742299536}) = 0 <0.000017>
817   00:09:56.185687 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742328727}) = 0 <0.000019>
817   00:09:56.185886 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742503333}) = 0 <0.000017>
817   00:09:56.185940 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742532315}) = 0 <0.000016>
817   00:09:56.186108 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742676924}) = 0 <0.000017>
817   00:09:56.186167 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742710095}) = 0 <0.000015>
817   00:09:56.186384 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742903538}) = 0 <0.000017>
817   00:09:56.186438 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 742931634}) = 0 <0.000016>
817   00:09:56.186606 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743076905}) = 0 <0.000016>
817   00:09:56.186657 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743105178}) = 0 <0.000015>
817   00:09:56.186845 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743269951}) = 0 <0.000017>
817   00:09:56.186905 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743304132}) = 0 <0.000016>
817   00:09:56.187097 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743473637}) = 0 <0.000016>
817   00:09:56.187151 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743502306}) = 0 <0.000016>
817   00:09:56.187332 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743660019}) = 0 <0.000017>
817   00:09:56.187388 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743689729}) = 0 <0.000015>
817   00:09:56.187567 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743845082}) = 0 <0.000011>
817   00:09:56.187613 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 743869913}) = 0 <0.000010>
817   00:09:56.187781 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744021506}) = 0 <0.000010>
817   00:09:56.187822 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744045052}) = 0 <0.000010>
817   00:09:56.187983 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744190182}) = 0 <0.000011>
817   00:09:56.188027 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744214792}) = 0 <0.000009>
817   00:09:56.188212 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744382999}) = 0 <0.000011>
817   00:09:56.188249 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744400517}) = 0 <0.000010>
817   00:09:56.188313 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744448554}) = 0 <0.000010>
817   00:09:56.188357 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744473759}) = 0 <0.000010>
817   00:09:56.188534 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744634598}) = 0 <0.000012>
817   00:09:56.188578 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744658603}) = 0 <0.000010>
817   00:09:56.188723 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744787664}) = 0 <0.000010>
817   00:09:56.188764 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744811966}) = 0 <0.000009>
817   00:09:56.188953 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 744984652}) = 0 <0.000011>
817   00:09:56.188997 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745008195}) = 0 <0.000010>
817   00:09:56.189166 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745161323}) = 0 <0.000011>
817   00:09:56.189214 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745184901}) = 0 <0.000010>
817   00:09:56.189382 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745336959}) = 0 <0.000010>
817   00:09:56.189424 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745360474}) = 0 <0.000010>
817   00:09:56.189587 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745507046}) = 0 <0.000011>
817   00:09:56.189629 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745529601}) = 0 <0.000010>
817   00:09:56.189809 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745692913}) = 0 <0.000011>
817   00:09:56.189851 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745715587}) = 0 <0.000009>
817   00:09:56.190005 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745853157}) = 0 <0.000011>
817   00:09:56.190049 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 745877908}) = 0 <0.000010>
817   00:09:56.190238 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746050429}) = 0 <0.000011>
817   00:09:56.190281 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746074203}) = 0 <0.000010>
817   00:09:56.190436 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746212368}) = 0 <0.000010>
817   00:09:56.190478 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746235558}) = 0 <0.000010>
817   00:09:56.190673 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746416664}) = 0 <0.000017>
817   00:09:56.190728 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746446933}) = 0 <0.000015>
817   00:09:56.190910 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746610299}) = 0 <0.000016>
817   00:09:56.190961 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746639191}) = 0 <0.000015>
817   00:09:56.191133 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746792857}) = 0 <0.000016>
817   00:09:56.191185 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746823120}) = 0 <0.000016>
817   00:09:56.191357 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 746976683}) = 0 <0.000017>
817   00:09:56.191410 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747006578}) = 0 <0.000029>
2690  00:09:56.191453 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <0.433606>
2690  00:09:56.191484 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000022>
2690  00:09:56.191539 clock_gettime(CLOCK_MONOTONIC, {282502, 276018821}) = 0 <0.000015>
2690  00:09:56.191598 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4016, {282503, 276834003}, ffffffff <unfinished ...>
817   00:09:56.191704 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747232308}) = 0 <0.000016>
817   00:09:56.191760 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747267224}) = 0 <0.000015>
817   00:09:56.191937 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747426002}) = 0 <0.000016>
817   00:09:56.191989 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747456304}) = 0 <0.000015>
817   00:09:56.192167 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747616519}) = 0 <0.000015>
817   00:09:56.192219 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747648867}) = 0 <0.000015>
817   00:09:56.192397 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747809137}) = 0 <0.000016>
817   00:09:56.192448 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747837870}) = 0 <0.000015>
817   00:09:56.192627 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 747999026}) = 0 <0.000016>
817   00:09:56.192678 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748028466}) = 0 <0.000015>
817   00:09:56.192860 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748191869}) = 0 <0.000015>
817   00:09:56.192911 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748224734}) = 0 <0.000019>
817   00:09:56.193110 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748402235}) = 0 <0.000016>
817   00:09:56.193162 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748432181}) = 0 <0.000015>
817   00:09:56.193340 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748592655}) = 0 <0.000016>
817   00:09:56.193392 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748622152}) = 0 <0.000015>
817   00:09:56.193558 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748770767}) = 0 <0.000016>
817   00:09:56.193608 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748798902}) = 0 <0.000015>
817   00:09:56.193757 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748928873}) = 0 <0.000015>
817   00:09:56.193809 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 748957323}) = 0 <0.000015>
817   00:09:56.193985 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749115211}) = 0 <0.000016>
817   00:09:56.194036 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749145129}) = 0 <0.000015>
817   00:09:56.194223 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749314604}) = 0 <0.000016>
817   00:09:56.194277 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749346087}) = 0 <0.000015>
817   00:09:56.194496 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749547506}) = 0 <0.000016>
817   00:09:56.194549 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749577004}) = 0 <0.000015>
817   00:09:56.194723 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749732892}) = 0 <0.000016>
817   00:09:56.194780 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749768642}) = 0 <0.000015>
817   00:09:56.194999 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749969074}) = 0 <0.000016>
817   00:09:56.195050 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 749998874}) = 0 <0.000015>
817   00:09:56.195227 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750157586}) = 0 <0.000016>
817   00:09:56.195281 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750191708}) = 0 <0.000016>
817   00:09:56.195485 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750377213}) = 0 <0.000017>
817   00:09:56.195540 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750406706}) = 0 <0.000016>
817   00:09:56.195766 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750596344}) = 0 <0.000016>
817   00:09:56.195822 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750625331}) = 0 <0.000019>
817   00:09:56.196017 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750797476}) = 0 <0.000016>
817   00:09:56.196072 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750826780}) = 0 <0.000015>
817   00:09:56.196261 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 750993365}) = 0 <0.000017>
817   00:09:56.196315 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751022611}) = 0 <0.000015>
817   00:09:56.196533 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751217310}) = 0 <0.000017>
817   00:09:56.196589 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751247847}) = 0 <0.000015>
817   00:09:56.196760 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751395850}) = 0 <0.000016>
817   00:09:56.196812 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751424867}) = 0 <0.000015>
817   00:09:56.197034 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751624594}) = 0 <0.000017>
817   00:09:56.197088 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751652359}) = 0 <0.000015>
817   00:09:56.197283 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751824177}) = 0 <0.000017>
817   00:09:56.197337 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 751853324}) = 0 <0.000016>
817   00:09:56.197544 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752036993}) = 0 <0.000017>
817   00:09:56.197599 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752066271}) = 0 <0.000019>
817   00:09:56.197777 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752221052}) = 0 <0.000015>
817   00:09:56.197829 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752249961}) = 0 <0.000018>
817   00:09:56.198046 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752443523}) = 0 <0.000016>
817   00:09:56.198100 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752471415}) = 0 <0.000015>
817   00:09:56.198278 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752627263}) = 0 <0.000016>
817   00:09:56.198333 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752657253}) = 0 <0.000018>
817   00:09:56.198549 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752852425}) = 0 <0.000019>
817   00:09:56.198606 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 752881906}) = 0 <0.000015>
817   00:09:56.198764 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753017191}) = 0 <0.000015>
817   00:09:56.198821 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753051714}) = 0 <0.000015>
817   00:09:56.199030 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753238150}) = 0 <0.000017>
817   00:09:56.199084 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753267335}) = 0 <0.000015>
817   00:09:56.199260 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753420064}) = 0 <0.000017>
817   00:09:56.199323 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753451342}) = 0 <0.000018>
817   00:09:56.199528 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753633019}) = 0 <0.000027>
817   00:09:56.199595 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753676082}) = 0 <0.000014>
817   00:09:56.199778 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753835180}) = 0 <0.000015>
817   00:09:56.199830 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 753860736}) = 0 <0.000014>
817   00:09:56.200032 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754039462}) = 0 <0.000015>
817   00:09:56.200083 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754064024}) = 0 <0.000014>
817   00:09:56.200255 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754212251}) = 0 <0.000015>
817   00:09:56.200308 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754239368}) = 0 <0.000014>
817   00:09:56.200509 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754415917}) = 0 <0.000015>
817   00:09:56.200562 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754442075}) = 0 <0.000014>
817   00:09:56.200738 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754593849}) = 0 <0.000016>
817   00:09:56.200790 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754619044}) = 0 <0.000014>
817   00:09:56.200927 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754732438}) = 0 <0.000014>
817   00:09:56.200982 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754762356}) = 0 <0.000014>
817   00:09:56.201142 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754898687}) = 0 <0.000015>
817   00:09:56.201193 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 754926092}) = 0 <0.000014>
817   00:09:56.201399 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755107615}) = 0 <0.000015>
817   00:09:56.201455 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755136386}) = 0 <0.000014>
817   00:09:56.201638 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755295861}) = 0 <0.000015>
817   00:09:56.201691 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755323252}) = 0 <0.000014>
817   00:09:56.201889 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755496431}) = 0 <0.000015>
817   00:09:56.201938 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755520674}) = 0 <0.000015>
817   00:09:56.202094 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755652160}) = 0 <0.000015>
817   00:09:56.202147 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755678859}) = 0 <0.000014>
817   00:09:56.202331 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755838531}) = 0 <0.000015>
817   00:09:56.202379 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755860173}) = 0 <0.000014>
817   00:09:56.202459 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755916577}) = 0 <0.000014>
817   00:09:56.202505 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 755939355}) = 0 <0.000014>
817   00:09:56.202605 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756015623}) = 0 <0.000015>
817   00:09:56.202651 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756037390}) = 0 <0.000014>
817   00:09:56.202738 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756101033}) = 0 <0.000015>
817   00:09:56.202783 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756122066}) = 0 <0.000014>
817   00:09:56.202881 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756197038}) = 0 <0.000015>
817   00:09:56.202927 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756217699}) = 0 <0.000015>
817   00:09:56.203017 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756285006}) = 0 <0.000014>
817   00:09:56.203064 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756306978}) = 0 <0.000014>
817   00:09:56.203167 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756398805}) = 0 <0.000040>
817   00:09:56.203246 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756428288}) = 0 <0.000016>
817   00:09:56.203339 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756497297}) = 0 <0.000015>
817   00:09:56.203390 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756525596}) = 0 <0.000019>
817   00:09:56.203487 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756600123}) = 0 <0.000016>
817   00:09:56.203542 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756626016}) = 0 <0.000014>
817   00:09:56.203643 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756692722}) = 0 <0.000015>
817   00:09:56.203710 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756715413}) = 0 <0.000018>
817   00:09:56.203821 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756802957}) = 0 <0.000015>
817   00:09:56.203868 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756827870}) = 0 <0.000015>
817   00:09:56.203980 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756918315}) = 0 <0.000016>
817   00:09:56.204031 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 756943641}) = 0 <0.000015>
817   00:09:56.204138 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 757029634}) = 0 <0.000016>
817   00:09:56.204189 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 757057046}) = 0 <0.000015>
817   00:09:56.204464 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 757308570}) = 0 <0.000016>
817   00:09:56.204519 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 757337136}) = 0 <0.000015>
817   00:09:56.205446 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 758238498}) = 0 <0.000018>
817   00:09:56.205506 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 758264160}) = 0 <0.000018>
817   00:09:56.205817 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 758551537}) = 0 <0.000016>
817   00:09:56.205866 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 758576110}) = 0 <0.000018>
817   00:09:56.206188 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 758874653}) = 0 <0.000016>
817   00:09:56.206237 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 758898832}) = 0 <0.000019>
817   00:09:56.206457 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759096629}) = 0 <0.000016>
817   00:09:56.206507 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759121942}) = 0 <0.000019>
817   00:09:56.206852 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759443631}) = 0 <0.000017>
817   00:09:56.206901 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759467675}) = 0 <0.000015>
817   00:09:56.207140 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759683727}) = 0 <0.000016>
817   00:09:56.207190 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759709207}) = 0 <0.000019>
817   00:09:56.207447 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759942818}) = 0 <0.000017>
817   00:09:56.207498 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 759967428}) = 0 <0.000018>
817   00:09:56.207751 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760194840}) = 0 <0.000015>
817   00:09:56.207798 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760215173}) = 0 <0.000014>
817   00:09:56.208087 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760479921}) = 0 <0.000015>
817   00:09:56.208135 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760502917}) = 0 <0.000014>
817   00:09:56.208368 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760711841}) = 0 <0.000015>
817   00:09:56.208417 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760736344}) = 0 <0.000014>
817   00:09:56.208687 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 760983420}) = 0 <0.000014>
817   00:09:56.208734 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761005015}) = 0 <0.000014>
817   00:09:56.209001 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761248121}) = 0 <0.000014>
817   00:09:56.209049 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761271250}) = 0 <0.000014>
817   00:09:56.209306 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761504544}) = 0 <0.000014>
817   00:09:56.209351 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761522788}) = 0 <0.000014>
817   00:09:56.209484 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761632211}) = 0 <0.000015>
817   00:09:56.209534 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761656187}) = 0 <0.000015>
817   00:09:56.209865 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761963593}) = 0 <0.000015>
817   00:09:56.209913 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 761986292}) = 0 <0.000014>
817   00:09:56.210321 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 762369903}) = 0 <0.000014>
817   00:09:56.210368 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 762391936}) = 0 <0.000014>
817   00:09:56.210883 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 762879911}) = 0 <0.000016>
817   00:09:56.210940 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 762906320}) = 0 <0.000014>
817   00:09:56.211334 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 763276988}) = 0 <0.000015>
817   00:09:56.211389 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 763299988}) = 0 <0.000014>
817   00:09:56.211799 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 763688130}) = 0 <0.000016>
817   00:09:56.211853 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 763716129}) = 0 <0.000017>
817   00:09:56.212150 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 763987960}) = 0 <0.000016>
817   00:09:56.212205 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764017375}) = 0 <0.000015>
817   00:09:56.212500 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764290815}) = 0 <0.000015>
817   00:09:56.212553 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764318277}) = 0 <0.000015>
817   00:09:56.212784 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764526709}) = 0 <0.000016>
817   00:09:56.212837 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764555183}) = 0 <0.000015>
817   00:09:56.213158 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764854124}) = 0 <0.000016>
817   00:09:56.213212 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 764882587}) = 0 <0.000015>
817   00:09:56.213454 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765101362}) = 0 <0.000017>
817   00:09:56.213514 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765129940}) = 0 <0.000017>
817   00:09:56.213681 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765271334}) = 0 <0.000016>
817   00:09:56.213735 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765298877}) = 0 <0.000015>
817   00:09:56.213888 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765426693}) = 0 <0.000018>
817   00:09:56.213943 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765452404}) = 0 <0.000015>
817   00:09:56.214208 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765695225}) = 0 <0.000015>
817   00:09:56.214256 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765719701}) = 0 <0.000015>
817   00:09:56.214511 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765952874}) = 0 <0.000016>
817   00:09:56.214560 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 765978060}) = 0 <0.000015>
817   00:09:56.214870 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 766265815}) = 0 <0.000016>
817   00:09:56.214919 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 766291394}) = 0 <0.000015>
817   00:09:56.215233 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 766583883}) = 0 <0.000017>
817   00:09:56.215284 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 766610102}) = 0 <0.000015>
817   00:09:56.215594 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 766896936}) = 0 <0.000016>
817   00:09:56.215645 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 766921841}) = 0 <0.000019>
817   00:09:56.215802 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767055482}) = 0 <0.000017>
817   00:09:56.215854 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767080932}) = 0 <0.000016>
817   00:09:56.216108 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767312295}) = 0 <0.000017>
817   00:09:56.216159 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767337190}) = 0 <0.000016>
817   00:09:56.216389 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767544365}) = 0 <0.000016>
817   00:09:56.216439 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767575318}) = 0 <0.000024>
817   00:09:56.216738 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767846942}) = 0 <0.000016>
817   00:09:56.216787 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 767871643}) = 0 <0.000016>
817   00:09:56.217012 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768073510}) = 0 <0.000016>
817   00:09:56.217060 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768098350}) = 0 <0.000016>
817   00:09:56.217281 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768296567}) = 0 <0.000016>
817   00:09:56.217330 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768321570}) = 0 <0.000016>
817   00:09:56.217565 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768534532}) = 0 <0.000016>
817   00:09:56.217614 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768563843}) = 0 <0.000023>
817   00:09:56.217854 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768775312}) = 0 <0.000016>
817   00:09:56.217902 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 768799619}) = 0 <0.000019>
817   00:09:56.218182 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 769050364}) = 0 <0.000017>
817   00:09:56.218240 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 769078879}) = 0 <0.000016>
817   00:09:56.220362 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771175671}) = 0 <0.000019>
817   00:09:56.220426 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771205084}) = 0 <0.000015>
817   00:09:56.220664 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771418531}) = 0 <0.000017>
817   00:09:56.220725 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771447921}) = 0 <0.000016>
817   00:09:56.220910 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771608684}) = 0 <0.000017>
817   00:09:56.220968 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771636237}) = 0 <0.000016>
817   00:09:56.221100 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771745787}) = 0 <0.000017>
817   00:09:56.221156 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771776760}) = 0 <0.000015>
817   00:09:56.221299 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771900888}) = 0 <0.000022>
817   00:09:56.221359 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 771931140}) = 0 <0.000015>
817   00:09:56.221564 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772112214}) = 0 <0.000017>
817   00:09:56.221622 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772140329}) = 0 <0.000015>
817   00:09:56.221791 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772286179}) = 0 <0.000016>
817   00:09:56.221844 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772312234}) = 0 <0.000015>
817   00:09:56.221956 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772401358}) = 0 <0.000017>
817   00:09:56.222011 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772430781}) = 0 <0.000016>
817   00:09:56.222163 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772560821}) = 0 <0.000017>
817   00:09:56.222217 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772588003}) = 0 <0.000016>
817   00:09:56.222305 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772654129}) = 0 <0.000016>
817   00:09:56.222356 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772680306}) = 0 <0.000016>
817   00:09:56.222445 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772747239}) = 0 <0.000017>
817   00:09:56.222497 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772774044}) = 0 <0.000016>
817   00:09:56.222575 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772830130}) = 0 <0.000016>
817   00:09:56.222626 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772856142}) = 0 <0.000016>
817   00:09:56.222706 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772914649}) = 0 <0.000016>
817   00:09:56.222757 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772940537}) = 0 <0.000016>
817   00:09:56.222829 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 772990959}) = 0 <0.000016>
817   00:09:56.222881 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773018258}) = 0 <0.000016>
817   00:09:56.222962 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773077241}) = 0 <0.000017>
817   00:09:56.223011 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773102877}) = 0 <0.000015>
817   00:09:56.223088 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773157401}) = 0 <0.000016>
817   00:09:56.223138 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773183406}) = 0 <0.000015>
817   00:09:56.223222 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773244986}) = 0 <0.000016>
817   00:09:56.223272 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773270773}) = 0 <0.000016>
817   00:09:56.223346 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773322801}) = 0 <0.000016>
817   00:09:56.223396 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773348330}) = 0 <0.000016>
817   00:09:56.223477 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773407076}) = 0 <0.000016>
817   00:09:56.223527 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773432746}) = 0 <0.000027>
817   00:09:56.223610 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773481239}) = 0 <0.000013>
817   00:09:56.223651 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773501133}) = 0 <0.000009>
817   00:09:56.223719 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773556622}) = 0 <0.000016>
817   00:09:56.223763 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773578269}) = 0 <0.000010>
817   00:09:56.223827 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773625452}) = 0 <0.000011>
817   00:09:56.223866 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773646410}) = 0 <0.000011>
817   00:09:56.223944 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773702976}) = 0 <0.000011>
817   00:09:56.223983 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773723209}) = 0 <0.000010>
817   00:09:56.224051 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773775546}) = 0 <0.000010>
817   00:09:56.224089 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773795493}) = 0 <0.000009>
817   00:09:56.224159 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773848775}) = 0 <0.000010>
817   00:09:56.224196 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773868095}) = 0 <0.000009>
817   00:09:56.224255 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773908662}) = 0 <0.000024>
817   00:09:56.224325 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773933194}) = 0 <0.000014>
817   00:09:56.224410 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 773995153}) = 0 <0.000014>
817   00:09:56.224455 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774016033}) = 0 <0.000014>
817   00:09:56.224524 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774061936}) = 0 <0.000014>
817   00:09:56.224571 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774083800}) = 0 <0.000014>
817   00:09:56.224647 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774137360}) = 0 <0.000014>
817   00:09:56.224691 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774157456}) = 0 <0.000014>
817   00:09:56.224784 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774227551}) = 0 <0.000016>
817   00:09:56.224837 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774252833}) = 0 <0.000015>
817   00:09:56.224918 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774311302}) = 0 <0.000016>
817   00:09:56.224966 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774335960}) = 0 <0.000015>
817   00:09:56.225055 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774404022}) = 0 <0.000016>
817   00:09:56.225105 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774429668}) = 0 <0.000015>
817   00:09:56.225179 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774482573}) = 0 <0.000016>
817   00:09:56.225238 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774507760}) = 0 <0.000016>
817   00:09:56.225308 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774556000}) = 0 <0.000016>
817   00:09:56.225357 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774580871}) = 0 <0.000015>
817   00:09:56.225433 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774634991}) = 0 <0.000016>
817   00:09:56.225481 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774660294}) = 0 <0.000015>
817   00:09:56.225553 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774709995}) = 0 <0.000015>
817   00:09:56.225602 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774735205}) = 0 <0.000016>
817   00:09:56.225672 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774783133}) = 0 <0.000016>
817   00:09:56.225719 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774807303}) = 0 <0.000015>
817   00:09:56.225792 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774857557}) = 0 <0.000015>
817   00:09:56.225840 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774882240}) = 0 <0.000015>
817   00:09:56.225917 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774937724}) = 0 <0.000016>
817   00:09:56.225966 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 774962470}) = 0 <0.000015>
817   00:09:56.226072 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775045929}) = 0 <0.000016>
817   00:09:56.226122 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775071150}) = 0 <0.000016>
817   00:09:56.226198 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775125559}) = 0 <0.000016>
817   00:09:56.226248 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775151419}) = 0 <0.000015>
817   00:09:56.226328 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775208917}) = 0 <0.000016>
817   00:09:56.226381 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775238820}) = 0 <0.000015>
817   00:09:56.226464 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775299677}) = 0 <0.000016>
817   00:09:56.226520 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775331089}) = 0 <0.000015>
817   00:09:56.226604 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775393175}) = 0 <0.000016>
817   00:09:56.226656 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775421057}) = 0 <0.000016>
817   00:09:56.226773 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775509010}) = 0 <0.000016>
817   00:09:56.226819 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775531047}) = 0 <0.000015>
817   00:09:56.226871 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775561162}) = 0 <0.000016>
817   00:09:56.226927 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775594039}) = 0 <0.000015>
817   00:09:56.227017 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775662634}) = 0 <0.000016>
817   00:09:56.227069 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775693724}) = 0 <0.000022>
817   00:09:56.227158 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775756994}) = 0 <0.000016>
817   00:09:56.227211 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775785366}) = 0 <0.000016>
817   00:09:56.227322 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775874311}) = 0 <0.000016>
817   00:09:56.227376 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775904104}) = 0 <0.000015>
817   00:09:56.227480 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 775985714}) = 0 <0.000016>
817   00:09:56.227531 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776012575}) = 0 <0.000029>
817   00:09:56.227655 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776112099}) = 0 <0.000016>
817   00:09:56.227709 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776141154}) = 0 <0.000015>
817   00:09:56.227812 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776221990}) = 0 <0.000016>
817   00:09:56.227866 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776251991}) = 0 <0.000015>
817   00:09:56.227975 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776338749}) = 0 <0.000016>
817   00:09:56.228026 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776365475}) = 0 <0.000015>
817   00:09:56.228112 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776429233}) = 0 <0.000015>
817   00:09:56.228163 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776456508}) = 0 <0.000016>
817   00:09:56.228266 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776537407}) = 0 <0.000016>
817   00:09:56.228316 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776563634}) = 0 <0.000015>
817   00:09:56.228428 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776652934}) = 0 <0.000016>
817   00:09:56.228486 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776685605}) = 0 <0.000016>
817   00:09:56.228591 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776768620}) = 0 <0.000016>
817   00:09:56.228640 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776793865}) = 0 <0.000015>
817   00:09:56.228712 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776843655}) = 0 <0.000016>
817   00:09:56.228765 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776872278}) = 0 <0.000016>
817   00:09:56.228846 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776931469}) = 0 <0.000016>
817   00:09:56.228899 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 776960073}) = 0 <0.000016>
817   00:09:56.229000 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777038720}) = 0 <0.000015>
817   00:09:56.229056 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777070627}) = 0 <0.000016>
817   00:09:56.229167 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777159274}) = 0 <0.000016>
817   00:09:56.229218 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777186445}) = 0 <0.000015>
817   00:09:56.229299 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777245008}) = 0 <0.000015>
817   00:09:56.229348 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777270583}) = 0 <0.000015>
817   00:09:56.229479 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777379313}) = 0 <0.000022>
817   00:09:56.229537 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777411569}) = 0 <0.000015>
817   00:09:56.229646 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777497804}) = 0 <0.000016>
817   00:09:56.229699 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777527166}) = 0 <0.000015>
817   00:09:56.229783 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777588535}) = 0 <0.000016>
817   00:09:56.229836 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777618303}) = 0 <0.000015>
817   00:09:56.229913 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777672824}) = 0 <0.000016>
817   00:09:56.229963 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777699559}) = 0 <0.000016>
817   00:09:56.230051 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777759196}) = 0 <0.000016>
817   00:09:56.230105 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777788392}) = 0 <0.000015>
817   00:09:56.230176 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777837318}) = 0 <0.000016>
817   00:09:56.230232 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777870091}) = 0 <0.000015>
817   00:09:56.230339 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777955227}) = 0 <0.000016>
817   00:09:56.230390 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 777981453}) = 0 <0.000016>
817   00:09:56.230491 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778060606}) = 0 <0.000016>
817   00:09:56.230541 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778086382}) = 0 <0.000015>
817   00:09:56.230603 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778126346}) = 0 <0.000016>
817   00:09:56.230653 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778151906}) = 0 <0.000015>
817   00:09:56.230744 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778220920}) = 0 <0.000015>
817   00:09:56.230793 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778246586}) = 0 <0.000015>
817   00:09:56.230876 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778307281}) = 0 <0.000016>
817   00:09:56.230926 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778333465}) = 0 <0.000015>
817   00:09:56.231005 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778389976}) = 0 <0.000015>
817   00:09:56.231055 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778416468}) = 0 <0.000015>
817   00:09:56.231128 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778466777}) = 0 <0.000016>
817   00:09:56.231179 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778493925}) = 0 <0.000016>
817   00:09:56.231252 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778545321}) = 0 <0.000016>
817   00:09:56.231307 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778576161}) = 0 <0.000015>
817   00:09:56.231385 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778631872}) = 0 <0.000015>
817   00:09:56.231436 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778659528}) = 0 <0.000015>
817   00:09:56.231535 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778733373}) = 0 <0.000018>
817   00:09:56.231594 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778763020}) = 0 <0.000015>
817   00:09:56.231675 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778822554}) = 0 <0.000016>
817   00:09:56.231723 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778846113}) = 0 <0.000015>
817   00:09:56.231780 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778881891}) = 0 <0.000015>
817   00:09:56.231827 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778905622}) = 0 <0.000015>
817   00:09:56.231915 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778971845}) = 0 <0.000015>
817   00:09:56.231966 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 778998674}) = 0 <0.000015>
817   00:09:56.232063 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779074185}) = 0 <0.000015>
817   00:09:56.232116 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779103638}) = 0 <0.000015>
817   00:09:56.232196 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779161880}) = 0 <0.000015>
817   00:09:56.232244 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779186542}) = 0 <0.000015>
817   00:09:56.232339 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779260357}) = 0 <0.000016>
817   00:09:56.232389 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779285664}) = 0 <0.000015>
817   00:09:56.232467 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779341982}) = 0 <0.000016>
817   00:09:56.232523 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779375037}) = 0 <0.000015>
817   00:09:56.232668 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779498353}) = 0 <0.000016>
817   00:09:56.232723 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779529523}) = 0 <0.000015>
817   00:09:56.232844 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779628770}) = 0 <0.000016>
817   00:09:56.232900 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779660452}) = 0 <0.000015>
817   00:09:56.233035 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779774589}) = 0 <0.000015>
817   00:09:56.233095 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779809926}) = 0 <0.000016>
817   00:09:56.233237 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779924504}) = 0 <0.000015>
817   00:09:56.233297 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 779960884}) = 0 <0.000016>
817   00:09:56.233448 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780090254}) = 0 <0.000015>
817   00:09:56.233506 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780123832}) = 0 <0.000015>
817   00:09:56.233642 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780237904}) = 0 <0.000016>
817   00:09:56.233698 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780269707}) = 0 <0.000015>
817   00:09:56.233819 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780368922}) = 0 <0.000015>
817   00:09:56.233868 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780393871}) = 0 <0.000015>
817   00:09:56.233947 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780451289}) = 0 <0.000015>
817   00:09:56.234009 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780489570}) = 0 <0.000015>
817   00:09:56.234163 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780621558}) = 0 <0.000016>
817   00:09:56.234224 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780658446}) = 0 <0.000015>
817   00:09:56.234387 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780799430}) = 0 <0.000016>
817   00:09:56.234441 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780829052}) = 0 <0.000015>
817   00:09:56.234577 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780943972}) = 0 <0.000016>
817   00:09:56.234635 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 780978359}) = 0 <0.000015>
817   00:09:56.234774 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781094771}) = 0 <0.000016>
817   00:09:56.234830 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781126302}) = 0 <0.000015>
817   00:09:56.234980 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781254482}) = 0 <0.000016>
817   00:09:56.235042 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781292215}) = 0 <0.000015>
817   00:09:56.235276 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781503423}) = 0 <0.000016>
817   00:09:56.235336 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781538380}) = 0 <0.000015>
817   00:09:56.235495 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781674151}) = 0 <0.000016>
817   00:09:56.235564 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781723500}) = 0 <0.000016>
817   00:09:56.235774 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781908531}) = 0 <0.000016>
817   00:09:56.235831 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 781940237}) = 0 <0.000016>
817   00:09:56.235996 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782082052}) = 0 <0.000016>
817   00:09:56.236055 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782116697}) = 0 <0.000015>
817   00:09:56.236206 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782245425}) = 0 <0.000015>
817   00:09:56.236264 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782278473}) = 0 <0.000016>
817   00:09:56.236402 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782394930}) = 0 <0.000016>
817   00:09:56.236463 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782431326}) = 0 <0.000015>
817   00:09:56.236630 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782576057}) = 0 <0.000016>
817   00:09:56.236689 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782610055}) = 0 <0.000016>
817   00:09:56.236889 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782787971}) = 0 <0.000017>
817   00:09:56.236945 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 782817433}) = 0 <0.000016>
817   00:09:56.237162 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783012631}) = 0 <0.000016>
817   00:09:56.237219 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783044215}) = 0 <0.000015>
817   00:09:56.237397 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783199376}) = 0 <0.000016>
817   00:09:56.237458 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783236173}) = 0 <0.000015>
817   00:09:56.237620 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783375609}) = 0 <0.000016>
817   00:09:56.237672 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783403008}) = 0 <0.000015>
817   00:09:56.237806 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783514918}) = 0 <0.000016>
817   00:09:56.237857 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783541560}) = 0 <0.000016>
817   00:09:56.238016 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783671645}) = 0 <0.000016>
817   00:09:56.238066 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783697401}) = 0 <0.000016>
817   00:09:56.238269 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783877816}) = 0 <0.000016>
817   00:09:56.238332 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 783916389}) = 0 <0.000015>
817   00:09:56.238547 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784108594}) = 0 <0.000017>
817   00:09:56.238609 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784145229}) = 0 <0.000015>
817   00:09:56.238745 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784259050}) = 0 <0.000016>
817   00:09:56.238804 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784293823}) = 0 <0.000022>
817   00:09:56.238978 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784444282}) = 0 <0.000017>
817   00:09:56.239040 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784481680}) = 0 <0.000015>
817   00:09:56.239195 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784613533}) = 0 <0.000016>
817   00:09:56.239252 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784645249}) = 0 <0.000016>
817   00:09:56.239443 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784814120}) = 0 <0.000017>
817   00:09:56.239500 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 784846545}) = 0 <0.000016>
817   00:09:56.239695 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785017813}) = 0 <0.000016>
817   00:09:56.239755 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785051403}) = 0 <0.000015>
817   00:09:56.239954 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785227842}) = 0 <0.000016>
817   00:09:56.240015 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785263672}) = 0 <0.000015>
817   00:09:56.240179 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785404512}) = 0 <0.000017>
817   00:09:56.240234 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785434571}) = 0 <0.000015>
817   00:09:56.240359 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785537288}) = 0 <0.000016>
817   00:09:56.240415 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785568923}) = 0 <0.000015>
817   00:09:56.240602 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785733136}) = 0 <0.000016>
817   00:09:56.240658 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785763921}) = 0 <0.000016>
817   00:09:56.240833 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785916974}) = 0 <0.000016>
817   00:09:56.240893 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 785952227}) = 0 <0.000015>
817   00:09:56.241063 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786099474}) = 0 <0.000016>
817   00:09:56.241117 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786128851}) = 0 <0.000016>
817   00:09:56.241296 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786285942}) = 0 <0.000016>
817   00:09:56.241348 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786312354}) = 0 <0.000015>
817   00:09:56.241512 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786454161}) = 0 <0.000016>
817   00:09:56.241560 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786478160}) = 0 <0.000015>
817   00:09:56.241716 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786611745}) = 0 <0.000016>
817   00:09:56.241775 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 786645614}) = 0 <0.000016>
817   00:09:56.242771 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 787616642}) = 0 <0.000018>
817   00:09:56.242847 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 787658039}) = 0 <0.000016>
817   00:09:56.244146 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 788932322}) = 0 <0.000012>
817   00:09:56.244198 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 788960266}) = 0 <0.000010>
817   00:09:56.244859 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 789601450}) = 0 <0.000012>
817   00:09:56.244916 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 789630315}) = 0 <0.000010>
817   00:09:56.245223 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 789919314}) = 0 <0.000012>
817   00:09:56.245275 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 789947991}) = 0 <0.000010>
817   00:09:56.245581 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 790238267}) = 0 <0.000018>
817   00:09:56.245641 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 790271259}) = 0 <0.000016>
817   00:09:56.245973 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 790573804}) = 0 <0.000018>
817   00:09:56.246042 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 790610683}) = 0 <0.000015>
817   00:09:56.248593 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 793133473}) = 0 <0.000019>
817   00:09:56.248670 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 793169628}) = 0 <0.000016>
817   00:09:56.248974 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 793449935}) = 0 <0.000016>
817   00:09:56.249036 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 793486140}) = 0 <0.000016>
817   00:09:56.249299 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 793725304}) = 0 <0.000017>
817   00:09:56.249354 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 793754508}) = 0 <0.000016>
817   00:09:56.249631 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794009715}) = 0 <0.000016>
817   00:09:56.249686 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794038016}) = 0 <0.000016>
817   00:09:56.249925 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794254245}) = 0 <0.000016>
817   00:09:56.249978 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794283175}) = 0 <0.000016>
817   00:09:56.250216 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794498056}) = 0 <0.000016>
817   00:09:56.250275 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794531605}) = 0 <0.000016>
817   00:09:56.250558 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794791942}) = 0 <0.000016>
817   00:09:56.250613 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 794820920}) = 0 <0.000015>
817   00:09:56.250879 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 795063841}) = 0 <0.000017>
817   00:09:56.250930 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 795089167}) = 0 <0.000016>
817   00:09:56.253644 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 797775582}) = 0 <0.000020>
817   00:09:56.253709 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 797800639}) = 0 <0.000015>
817   00:09:56.253877 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 797944941}) = 0 <0.000016>
817   00:09:56.253933 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 797974739}) = 0 <0.000015>
817   00:09:56.254079 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 798098160}) = 0 <0.000016>
817   00:09:56.254137 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 798131373}) = 0 <0.000015>
817   00:09:56.254527 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 798498515}) = 0 <0.000016>
817   00:09:56.254588 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 798534096}) = 0 <0.000015>
817   00:09:56.255105 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 799028159}) = 0 <0.000017>
817   00:09:56.255166 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 799060453}) = 0 <0.000026>
817   00:09:56.255703 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 799572717}) = 0 <0.000017>
817   00:09:56.255766 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 799606235}) = 0 <0.000015>
817   00:09:56.256400 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 800215904}) = 0 <0.000017>
817   00:09:56.256461 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 800249853}) = 0 <0.000015>
817   00:09:56.256964 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 800729211}) = 0 <0.000017>
817   00:09:56.257021 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 800759032}) = 0 <0.000015>
817   00:09:56.257313 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 801028039}) = 0 <0.000017>
817   00:09:56.257369 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 801057574}) = 0 <0.000015>
817   00:09:56.257844 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 801509518}) = 0 <0.000017>
817   00:09:56.257904 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 801542904}) = 0 <0.000015>
817   00:09:56.258174 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 801789977}) = 0 <0.000016>
817   00:09:56.258237 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 801826656}) = 0 <0.000016>
817   00:09:56.258451 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802017981}) = 0 <0.000017>
817   00:09:56.258509 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802046744}) = 0 <0.000016>
817   00:09:56.258676 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802189468}) = 0 <0.000017>
817   00:09:56.258730 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802217375}) = 0 <0.000017>
817   00:09:56.259067 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802524897}) = 0 <0.000017>
817   00:09:56.259121 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802551776}) = 0 <0.000016>
817   00:09:56.259588 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 802995671}) = 0 <0.000017>
817   00:09:56.259647 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 803027228}) = 0 <0.000015>
817   00:09:56.260458 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 803816952}) = 0 <0.000021>
817   00:09:56.260517 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 803847402}) = 0 <0.000015>
817   00:09:56.260733 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 804040847}) = 0 <0.000016>
817   00:09:56.260786 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 804067951}) = 0 <0.000016>
817   00:09:56.261594 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 804852507}) = 0 <0.000017>
817   00:09:56.261646 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 804878035}) = 0 <0.000016>
817   00:09:56.262232 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 805441646}) = 0 <0.000017>
817   00:09:56.262283 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 805466354}) = 0 <0.000015>
817   00:09:56.263140 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 806299714}) = 0 <0.000017>
817   00:09:56.263199 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 806333147}) = 0 <0.000016>
817   00:09:56.263661 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 806771198}) = 0 <0.000012>
817   00:09:56.263712 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 806800102}) = 0 <0.000010>
817   00:09:56.264407 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 807479259}) = 0 <0.000011>
817   00:09:56.264456 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 807508169}) = 0 <0.000010>
817   00:09:56.265134 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 808166847}) = 0 <0.000012>
817   00:09:56.265198 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 808205920}) = 0 <0.000010>
817   00:09:56.266276 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 809252218}) = 0 <0.000019>
817   00:09:56.266346 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 809293115}) = 0 <0.000018>
817   00:09:56.267288 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810210661}) = 0 <0.000022>
817   00:09:56.267360 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810249544}) = 0 <0.000021>
817   00:09:56.267679 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810540973}) = 0 <0.000022>
817   00:09:56.267747 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810578078}) = 0 <0.000020>
817   00:09:56.267922 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810728082}) = 0 <0.000021>
817   00:09:56.267988 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810768501}) = 0 <0.000021>
817   00:09:56.268180 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810936055}) = 0 <0.000021>
817   00:09:56.268251 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 810981344}) = 0 <0.000021>
817   00:09:56.268423 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811129453}) = 0 <0.000021>
817   00:09:56.268492 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811173685}) = 0 <0.000020>
817   00:09:56.268749 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811404602}) = 0 <0.000022>
817   00:09:56.268811 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811434230}) = 0 <0.000021>
817   00:09:56.268891 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811490594}) = 0 <0.000021>
817   00:09:56.268947 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811521001}) = 0 <0.000020>
817   00:09:56.269022 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811572304}) = 0 <0.000021>
817   00:09:56.269097 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811621721}) = 0 <0.000020>
817   00:09:56.269261 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811761983}) = 0 <0.000021>
817   00:09:56.269333 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811807829}) = 0 <0.000021>
817   00:09:56.269458 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811909731}) = 0 <0.000021>
817   00:09:56.269528 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 811953557}) = 0 <0.000020>
817   00:09:56.269649 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812051142}) = 0 <0.000021>
817   00:09:56.269719 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812095203}) = 0 <0.000021>
817   00:09:56.269854 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812197857}) = 0 <0.000020>
817   00:09:56.269926 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812244514}) = 0 <0.000021>
817   00:09:56.270049 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812342933}) = 0 <0.000022>
817   00:09:56.270112 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812381030}) = 0 <0.000020>
817   00:09:56.270218 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812462823}) = 0 <0.000020>
817   00:09:56.270290 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812512977}) = 0 <0.000023>
817   00:09:56.270429 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812625054}) = 0 <0.000021>
817   00:09:56.270501 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812670815}) = 0 <0.000020>
817   00:09:56.270637 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812783428}) = 0 <0.000021>
817   00:09:56.270711 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812831621}) = 0 <0.000021>
817   00:09:56.270834 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812929997}) = 0 <0.000021>
817   00:09:56.270903 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 812973465}) = 0 <0.000021>
817   00:09:56.271035 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813082072}) = 0 <0.000021>
817   00:09:56.271101 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813122191}) = 0 <0.000021>
817   00:09:56.271213 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813210029}) = 0 <0.000021>
817   00:09:56.271279 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813250893}) = 0 <0.000020>
817   00:09:56.271387 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813335296}) = 0 <0.000021>
817   00:09:56.271448 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813370725}) = 0 <0.000020>
817   00:09:56.271536 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813431978}) = 0 <0.000030>
817   00:09:56.271615 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813472354}) = 0 <0.000020>
817   00:09:56.271744 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813577478}) = 0 <0.000021>
817   00:09:56.271809 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813616185}) = 0 <0.000020>
817   00:09:56.271915 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813699590}) = 0 <0.000021>
817   00:09:56.271983 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813742655}) = 0 <0.000020>
817   00:09:56.272085 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813820973}) = 0 <0.000020>
817   00:09:56.272148 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813859175}) = 0 <0.000020>
817   00:09:56.272254 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813941606}) = 0 <0.000020>
817   00:09:56.272319 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 813981315}) = 0 <0.000020>
817   00:09:56.272427 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814066368}) = 0 <0.000020>
817   00:09:56.272493 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814106924}) = 0 <0.000020>
817   00:09:56.272602 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814193664}) = 0 <0.000021>
817   00:09:56.272665 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814232984}) = 0 <0.000022>
817   00:09:56.272769 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814312068}) = 0 <0.000020>
817   00:09:56.272834 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814350682}) = 0 <0.000020>
817   00:09:56.272939 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814433186}) = 0 <0.000021>
817   00:09:56.273005 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814473542}) = 0 <0.000020>
817   00:09:56.273116 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814560614}) = 0 <0.000020>
817   00:09:56.273184 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814603029}) = 0 <0.000020>
817   00:09:56.273293 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814688889}) = 0 <0.000020>
817   00:09:56.273358 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814729007}) = 0 <0.000020>
817   00:09:56.273467 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814814531}) = 0 <0.000020>
817   00:09:56.273533 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814855195}) = 0 <0.000020>
817   00:09:56.273649 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814947693}) = 0 <0.000021>
817   00:09:56.273709 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 814983435}) = 0 <0.000020>
817   00:09:56.273808 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815053188}) = 0 <0.000020>
817   00:09:56.273873 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815093452}) = 0 <0.000020>
817   00:09:56.273984 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815180558}) = 0 <0.000020>
817   00:09:56.274048 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815219257}) = 0 <0.000020>
817   00:09:56.274164 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815313023}) = 0 <0.000020>
817   00:09:56.274234 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815356677}) = 0 <0.000020>
817   00:09:56.274345 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815444400}) = 0 <0.000020>
817   00:09:56.274409 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815483822}) = 0 <0.000020>
817   00:09:56.274515 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815565940}) = 0 <0.000020>
817   00:09:56.274575 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815601785}) = 0 <0.000020>
817   00:09:56.274668 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815670900}) = 0 <0.000020>
817   00:09:56.274732 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815710421}) = 0 <0.000020>
817   00:09:56.274840 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815795031}) = 0 <0.000021>
817   00:09:56.274905 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815835185}) = 0 <0.000020>
817   00:09:56.275017 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815923984}) = 0 <0.000021>
817   00:09:56.275080 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 815961313}) = 0 <0.000020>
817   00:09:56.275191 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816041423}) = 0 <0.000021>
817   00:09:56.275260 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816084733}) = 0 <0.000021>
817   00:09:56.275374 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816175028}) = 0 <0.000021>
817   00:09:56.275440 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816215075}) = 0 <0.000020>
817   00:09:56.275542 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816290203}) = 0 <0.000022>
817   00:09:56.275622 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816332100}) = 0 <0.000021>
817   00:09:56.275742 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816428396}) = 0 <0.000021>
817   00:09:56.275814 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816474111}) = 0 <0.000021>
817   00:09:56.275944 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816578851}) = 0 <0.000021>
817   00:09:56.276012 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816621221}) = 0 <0.000020>
817   00:09:56.276139 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816724087}) = 0 <0.000021>
817   00:09:56.276210 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816769371}) = 0 <0.000020>
817   00:09:56.276339 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816875007}) = 0 <0.000021>
817   00:09:56.276411 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 816921396}) = 0 <0.000020>
817   00:09:56.276549 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817035158}) = 0 <0.000021>
817   00:09:56.276609 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817069646}) = 0 <0.000020>
817   00:09:56.276695 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817132080}) = 0 <0.000021>
817   00:09:56.276766 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817177127}) = 0 <0.000021>
817   00:09:56.276900 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817287183}) = 0 <0.000022>
817   00:09:56.276969 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817330723}) = 0 <0.000021>
817   00:09:56.277093 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817430833}) = 0 <0.000021>
817   00:09:56.277167 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817479092}) = 0 <0.000021>
817   00:09:56.277311 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817599428}) = 0 <0.000021>
817   00:09:56.277383 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817645613}) = 0 <0.000020>
817   00:09:56.277507 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817746128}) = 0 <0.000021>
817   00:09:56.277577 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817789981}) = 0 <0.000020>
817   00:09:56.277706 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817895351}) = 0 <0.000021>
817   00:09:56.277774 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 817938057}) = 0 <0.000021>
817   00:09:56.277899 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818034085}) = 0 <0.000021>
817   00:09:56.277969 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818078262}) = 0 <0.000020>
817   00:09:56.278093 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818178020}) = 0 <0.000021>
817   00:09:56.278157 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818216495}) = 0 <0.000021>
817   00:09:56.278270 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818305259}) = 0 <0.000021>
817   00:09:56.278337 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818347835}) = 0 <0.000021>
817   00:09:56.278452 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818437934}) = 0 <0.000021>
817   00:09:56.278518 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818477779}) = 0 <0.000021>
817   00:09:56.278625 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818560957}) = 0 <0.000021>
817   00:09:56.278689 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818599224}) = 0 <0.000021>
817   00:09:56.278795 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818681709}) = 0 <0.000021>
817   00:09:56.278857 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818718723}) = 0 <0.000020>
817   00:09:56.278950 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818788274}) = 0 <0.000021>
817   00:09:56.279018 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818830522}) = 0 <0.000020>
817   00:09:56.279144 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818933022}) = 0 <0.000021>
817   00:09:56.279214 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 818977356}) = 0 <0.000020>
817   00:09:56.279324 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819063455}) = 0 <0.000021>
817   00:09:56.279391 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819104447}) = 0 <0.000020>
817   00:09:56.279512 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819201494}) = 0 <0.000021>
817   00:09:56.279583 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819241696}) = 0 <0.000021>
817   00:09:56.279694 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819326777}) = 0 <0.000021>
817   00:09:56.279763 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819370920}) = 0 <0.000020>
817   00:09:56.279894 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819477820}) = 0 <0.000021>
817   00:09:56.279957 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819515062}) = 0 <0.000020>
817   00:09:56.280073 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819606987}) = 0 <0.000021>
817   00:09:56.280139 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819647316}) = 0 <0.000021>
817   00:09:56.280253 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819738211}) = 0 <0.000021>
817   00:09:56.280313 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819772314}) = 0 <0.000020>
817   00:09:56.280408 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819844245}) = 0 <0.000020>
817   00:09:56.280472 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819882836}) = 0 <0.000021>
817   00:09:56.280594 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 819980296}) = 0 <0.000021>
817   00:09:56.280659 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820020093}) = 0 <0.000021>
817   00:09:56.280764 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820100337}) = 0 <0.000021>
817   00:09:56.280823 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820133757}) = 0 <0.000020>
817   00:09:56.280914 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820201466}) = 0 <0.000021>
817   00:09:56.280978 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820239205}) = 0 <0.000021>
817   00:09:56.281097 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820335333}) = 0 <0.000021>
817   00:09:56.281158 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820370452}) = 0 <0.000021>
817   00:09:56.281282 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820470506}) = 0 <0.000021>
817   00:09:56.281347 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820510335}) = 0 <0.000021>
817   00:09:56.281479 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820617546}) = 0 <0.000021>
817   00:09:56.281543 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820655473}) = 0 <0.000021>
817   00:09:56.281665 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820753519}) = 0 <0.000021>
817   00:09:56.281726 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820789382}) = 0 <0.000021>
817   00:09:56.281843 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820877004}) = 0 <0.000021>
817   00:09:56.281909 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 820916794}) = 0 <0.000021>
817   00:09:56.282024 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821008490}) = 0 <0.000021>
817   00:09:56.282085 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821043647}) = 0 <0.000020>
817   00:09:56.282191 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821125606}) = 0 <0.000021>
817   00:09:56.282253 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821162140}) = 0 <0.000020>
817   00:09:56.282363 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821247707}) = 0 <0.000021>
817   00:09:56.282427 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821286438}) = 0 <0.000021>
817   00:09:56.282530 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821366022}) = 0 <0.000021>
817   00:09:56.282599 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821409129}) = 0 <0.000020>
817   00:09:56.282743 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821528868}) = 0 <0.000021>
817   00:09:56.282805 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821565963}) = 0 <0.000021>
817   00:09:56.282937 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821673895}) = 0 <0.000022>
817   00:09:56.283005 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821715638}) = 0 <0.000020>
817   00:09:56.283147 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821834213}) = 0 <0.000021>
817   00:09:56.283215 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821876610}) = 0 <0.000021>
817   00:09:56.283343 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 821980803}) = 0 <0.000022>
817   00:09:56.283412 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822023529}) = 0 <0.000020>
817   00:09:56.283581 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822169888}) = 0 <0.000018>
817   00:09:56.283644 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822209685}) = 0 <0.000017>
817   00:09:56.283770 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822315877}) = 0 <0.000018>
817   00:09:56.283836 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822359084}) = 0 <0.000017>
817   00:09:56.283974 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822476876}) = 0 <0.000018>
817   00:09:56.284035 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822515689}) = 0 <0.000017>
817   00:09:56.284160 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822620814}) = 0 <0.000018>
817   00:09:56.284224 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822663122}) = 0 <0.000018>
817   00:09:56.284364 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822782996}) = 0 <0.000018>
817   00:09:56.284411 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822808048}) = 0 <0.000017>
817   00:09:56.284457 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822833998}) = 0 <0.000017>
817   00:09:56.284502 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822859176}) = 0 <0.000017>
817   00:09:56.284547 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822884494}) = 0 <0.000017>
817   00:09:56.284592 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822909551}) = 0 <0.000017>
817   00:09:56.284638 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822935200}) = 0 <0.000017>
817   00:09:56.284682 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822959945}) = 0 <0.000017>
817   00:09:56.284727 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 822984762}) = 0 <0.000017>
817   00:09:56.284775 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823013286}) = 0 <0.000017>
817   00:09:56.284853 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823071772}) = 0 <0.000017>
817   00:09:56.284914 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823110570}) = 0 <0.000017>
817   00:09:56.285025 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823202305}) = 0 <0.000017>
817   00:09:56.285089 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823243696}) = 0 <0.000017>
817   00:09:56.285235 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823370064}) = 0 <0.000018>
817   00:09:56.285295 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823408186}) = 0 <0.000017>
817   00:09:56.285431 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823523631}) = 0 <0.000018>
817   00:09:56.285494 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823564286}) = 0 <0.000017>
817   00:09:56.285603 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823648549}) = 0 <0.000018>
817   00:09:56.285660 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823683317}) = 0 <0.000018>
817   00:09:56.285769 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823772006}) = 0 <0.000017>
817   00:09:56.285828 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823808908}) = 0 <0.000018>
817   00:09:56.285946 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823907032}) = 0 <0.000018>
817   00:09:56.286011 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 823949381}) = 0 <0.000017>
817   00:09:56.286147 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824065520}) = 0 <0.000018>
817   00:09:56.286207 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824103571}) = 0 <0.000017>
817   00:09:56.286350 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824226943}) = 0 <0.000018>
817   00:09:56.286409 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824263553}) = 0 <0.000018>
817   00:09:56.286531 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824365261}) = 0 <0.000018>
817   00:09:56.286593 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824406025}) = 0 <0.000017>
817   00:09:56.286715 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824507593}) = 0 <0.000017>
817   00:09:56.286772 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824542960}) = 0 <0.000017>
817   00:09:56.286866 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824616546}) = 0 <0.000018>
817   00:09:56.286924 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824652480}) = 0 <0.000017>
817   00:09:56.287030 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824738021}) = 0 <0.000018>
817   00:09:56.287085 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824771196}) = 0 <0.000017>
817   00:09:56.287179 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824845351}) = 0 <0.000018>
817   00:09:56.287254 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 824898399}) = 0 <0.000018>
817   00:09:56.287405 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825028414}) = 0 <0.000018>
817   00:09:56.287460 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825060395}) = 0 <0.000018>
817   00:09:56.287718 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 825241024}) = 0 <0.000018>
817   00:09:56.287902 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825424529}) = 0 <0.000019>
817   00:09:56.287963 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825460023}) = 0 <0.000035>
817   00:09:56.288186 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825640470}) = 0 <0.000021>
817   00:09:56.288247 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825674053}) = 0 <0.000021>
817   00:09:56.288443 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825846402}) = 0 <0.000021>
817   00:09:56.288508 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 825884372}) = 0 <0.000020>
817   00:09:56.288709 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826061037}) = 0 <0.000021>
817   00:09:56.288771 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826097506}) = 0 <0.000021>
817   00:09:56.288942 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826244321}) = 0 <0.000021>
817   00:09:56.289002 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826278733}) = 0 <0.000021>
817   00:09:56.289168 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826420602}) = 0 <0.000021>
817   00:09:56.289225 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826451430}) = 0 <0.000021>
817   00:09:56.289354 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826556810}) = 0 <0.000021>
817   00:09:56.289411 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826587610}) = 0 <0.000021>
817   00:09:56.289548 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826700995}) = 0 <0.000021>
817   00:09:56.289604 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826731777}) = 0 <0.000021>
817   00:09:56.289773 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826876483}) = 0 <0.000021>
817   00:09:56.289838 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 826915238}) = 0 <0.000020>
817   00:09:56.290011 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827064406}) = 0 <0.000021>
817   00:09:56.290080 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827107128}) = 0 <0.000020>
817   00:09:56.290232 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827235566}) = 0 <0.000021>
817   00:09:56.290307 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827279158}) = 0 <0.000021>
817   00:09:56.290480 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827427932}) = 0 <0.000021>
817   00:09:56.290545 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827466689}) = 0 <0.000021>
817   00:09:56.290677 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827575795}) = 0 <0.000021>
817   00:09:56.290743 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827615407}) = 0 <0.000021>
817   00:09:56.290926 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 827749455}) = 0 <0.000022>
817   00:09:56.291001 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827822621}) = 0 <0.000021>
817   00:09:56.291067 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 827863764}) = 0 <0.000021>
817   00:09:56.291171 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 827919407}) = 0 <0.000021>
817   00:09:56.291231 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 827953485}) = 0 <0.000020>
817   00:09:56.291465 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828162122}) = 0 <0.000021>
817   00:09:56.291624 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828292001}) = 0 <0.000021>
817   00:09:56.291680 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828320403}) = 0 <0.000020>
817   00:09:56.291741 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828357595}) = 0 <0.000020>
817   00:09:56.291800 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828393068}) = 0 <0.000020>
817   00:09:56.291899 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828469113}) = 0 <0.000020>
817   00:09:56.291958 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 828503917}) = 0 <0.000020>
817   00:09:56.293127 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 829646912}) = 0 <0.000021>
817   00:09:56.293191 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 829677957}) = 0 <0.000020>
817   00:09:56.293440 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 829927792}) = 0 <0.000022>
817   00:09:56.293508 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 829967682}) = 0 <0.000020>
817   00:09:56.293866 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 830301325}) = 0 <0.000021>
817   00:09:56.293929 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 830336915}) = 0 <0.000021>
817   00:09:56.294192 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 830577038}) = 0 <0.000021>
817   00:09:56.294256 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 830615310}) = 0 <0.000020>
817   00:09:56.294424 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830734253}) = 0 <0.000020>
817   00:09:56.294481 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830766527}) = 0 <0.000020>
817   00:09:56.294536 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830797338}) = 0 <0.000020>
817   00:09:56.294589 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830827745}) = 0 <0.000020>
817   00:09:56.294640 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830854878}) = 0 <0.000020>
817   00:09:56.294692 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830884273}) = 0 <0.000020>
817   00:09:56.294746 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830915038}) = 0 <0.000020>
817   00:09:56.294802 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 830948472}) = 0 <0.000020>
817   00:09:56.294882 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 831004552}) = 0 <0.000020>
817   00:09:56.295006 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 831129275}) = 0 <0.000020>
817   00:09:56.295068 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 831166400}) = 0 <0.000020>
817   00:09:56.295599 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 831669666}) = 0 <0.000023>
817   00:09:56.295678 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 831711270}) = 0 <0.000021>
817   00:09:56.295751 recvfrom(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000026>
817   00:09:56.296193 sendto(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, "\27\3\3\0\221 \213\247\256n3\r\371\34\22\26p\353\354\213\233p6\233\214\230_Sy~G}\271\16\6\277\302c\312\31\365;p0&\326B\\\325r\6\356\27\20\216\347B\322\31i\266\344\327\325$\227kz>\177\242\325\205\345\v\2\341K\315An\5\226\221\366\360(N\320\261\324\1\302jl\331g\271\235Lr\327]<\217v`\367\10+\260>3\264Pc\223\215~\342\306\266H\330\356\336\354\203\372\"\202\211\341\224J<\233\n\5\376\2108j\0k\205\6\220\272[", 150, MSG_NOSIGNAL, NULL, 0) = 150 <0.000066>
817   00:09:56.296609 recvfrom(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000022>
817   00:09:56.296945 select(32, [31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [31]) <0.000027>
817   00:09:56.297316 recvfrom(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, "\27\3\3\7\217", 5, 0, NULL, NULL) = 5 <0.000023>
817   00:09:56.297627 recvfrom(31<TCP:[172.17.0.2:33408->10.7.7.48:5432]>, "\202\371\0\10p\355\27\237\27\234\236\225\360r\364\10\347}#-T\250\241\320<\267\237\31V\245\332:\242\270\21\236\216\372-:\303\322\310\326\377\313\361C\211\343\266\212/&\240\f\317&\373\256;\304_\252i\34J9{\344\374\v\262\322q'\332vUh\326CE\213\310\261\374\210\24[3\357\320|;Hfr\205z\241\263\5Er\273$\361/\245`\305Tw\276\30X\313\243\0\5<\33z'\247E\333w_\267Ck\327\f\3168\375\16\344\271\330\276;\250\361r\367\340i;\34774\354\263GW&\260\364\236\331\22S\371\215\10rUj\210U\33\211A\306\251\224(\364\227\flV\232\204\23(\333r\203Yn!\177\326\361\367\313\346\367\t/Y\300\310eR\377\306qm\240\340\255L\25\215)\350Q\34\201+\325f\1\372\214+e}\36\201\37v\231[\360\273\\\1\3718\"\357=\345\35\202\377\321M\3074 \203\350\2\16\233@\224~\301\274\375G\247\361\257:UY\30\262\375\f1^\3274\274?'\266\301\315c\317#\\\31\374\2454\2f?|\320\332\304\205V\216}xe<\237tQ\324\226\325\335\231W\10y\267\254\21]z\221\321\264F5`\332\17a$#)\337{:8\321\37\10\204\317 \33\374N\31b4\300+k\351\330W\1s\267\346^\355\7K\324=9\341\266f\260\17T\223\377\372\331\374\353\355\\\315\325\240\334\240\336g\333a\16\262\261\20!\322\317\235\1I\327\335el\331\n\7\341\325\3\226\273\334\t\231\200\240\320b_H\326N\342a)\320\35\227\374\23\21yI\21\222\372\4\357&\3223\336\353\207\371\334\230a\26X\24\0&\346[\240\341\274f\376\367\t\337\226\315\353\251\216xW\215i\3708\22\303A\357&\"5C\321lz3\315\7<\325\16\327o\317\2062r\273\250\242\320k4j\36\222\226\251\276\207\16w\370\\ >\254-\20.l\212\212\241\240_L\0240\224q\334\237\25U\304d@\343L\272\253\207\2628\367\305\254\235\303\n\210Q\307g\242\177Yb\346J\261NID\201\0336\370\347\212\304\266\2457!\376\366\31\321s\313\360G2e\312\245ajS.\313\221\2573\0Z\362\363\24\334O\314\245JpeC\302\302\336\302e\231\345\347v\357\355s{;\354\372\330\240Rs\266\23Q5\354b+\27\37vO\377\242\7\241+\266o\276R+\rl\206\"H\32\316\324\237*\344|\274\"\222\262S\251*\303\262\2059\310\270\360\305\357f\232\35Q\3}N\262_Y\334\2522 }\251kv\211\0\335u\272/\372\206\304'O\356\2426\360\25\24\254\337]F\314\v\212\346\30\320\367\272S@1D(\336u3\256\276\243\301\246\264A\10Qi\22Cw\326\227G\216\317o\361\35\243\36[\33\335\207\213\36\3\365\335W\237B\243\374T\273\363\346\233\322\276\333\202!\211\206\237\21*\200*\210K\273SL\311\2\230r\262\232'\331\353\r\333\277\330\210BX)\251\325\371T\241\376\230Ux\31,)F7\311,\214\272\370\352b\324\303z.\3\270\273;\226\360]5UV3\247'\4/\35\25C\321\217\210\353/6nw\341\333\nr\361\354Y:\322\253\342\257\230\3465dE\352\2\250\343\313\357\207\233\262\315\270\236\200\335,\343\316D\363\267\231\36\4\0\357\221\210\236\213\267J\251#\26=y\273tE)\217\355\222\342(L\36\34H\264\252b\f8\330\vD\342ua{>\206\244cJ\250=\2722\217\275\311\3513/\304\21$(c&\16\262N\370\3\344\2\7\252\36P\373TS\233\324\317\\\211\27\22/\364\20\211\215\34\205\225\225o*.4T\355\31X\370\34\207\305\327h\f\4\204\r\16u\7k#Q\37\351\211\354\205"..., 1935, 0, NULL, NULL) = 1935 <0.000024>
817   00:09:56.298493 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 832576367}) = 0 <0.000021>
817   00:09:56.298564 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 832612073}) = 0 <0.000017>
817   00:09:56.298887 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 832887790}) = 0 <0.000020>
817   00:09:56.298946 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 832918744}) = 0 <0.000017>
817   00:09:56.299002 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 832954869}) = 0 <0.000017>
817   00:09:56.299056 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 832987749}) = 0 <0.000017>
817   00:09:56.299128 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833039377}) = 0 <0.000018>
817   00:09:56.299182 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833067008}) = 0 <0.000017>
817   00:09:56.299678 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833536918}) = 0 <0.000014>
817   00:09:56.299725 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833559070}) = 0 <0.000012>
817   00:09:56.299760 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833577218}) = 0 <0.000013>
817   00:09:56.299795 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833596283}) = 0 <0.000013>
817   00:09:56.299830 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833614804}) = 0 <0.000013>
817   00:09:56.299866 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833634544}) = 0 <0.000013>
817   00:09:56.299904 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833656418}) = 0 <0.000013>
817   00:09:56.299949 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833684736}) = 0 <0.000012>
817   00:09:56.299989 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833708441}) = 0 <0.000012>
817   00:09:56.300030 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833732340}) = 0 <0.000013>
817   00:09:56.300064 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 833750656}) = 0 <0.000012>
817   00:09:56.300124 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 833819601}) = 0 <0.000013>
817   00:09:56.300166 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 833844647}) = 0 <0.000012>
817   00:09:56.301439 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 835079685}) = 0 <0.000013>
817   00:09:56.301495 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 835105575}) = 0 <0.000013>
817   00:09:56.302930 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 836521960}) = 0 <0.000012>
817   00:09:56.302981 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 836549412}) = 0 <0.000013>
817   00:09:56.303572 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837123656}) = 0 <0.000016>
817   00:09:56.303628 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837153526}) = 0 <0.000015>
817   00:09:56.303748 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837254797}) = 0 <0.000015>
817   00:09:56.303793 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837280958}) = 0 <0.000015>
817   00:09:56.303926 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837395673}) = 0 <0.000015>
817   00:09:56.303970 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837420677}) = 0 <0.000015>
817   00:09:56.304094 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837527338}) = 0 <0.000015>
817   00:09:56.304152 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837566337}) = 0 <0.000015>
817   00:09:56.304432 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837828425}) = 0 <0.000016>
817   00:09:56.304491 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 837863887}) = 0 <0.000015>
817   00:09:56.305243 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 838596814}) = 0 <0.000016>
817   00:09:56.305306 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 838636748}) = 0 <0.000016>
817   00:09:56.306125 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 839436157}) = 0 <0.000017>
817   00:09:56.306177 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 839466337}) = 0 <0.000016>
817   00:09:56.306317 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 839561756}) = 0 <0.000016>
817   00:09:56.306366 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 839589509}) = 0 <0.000016>
817   00:09:56.306421 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 839625687}) = 0 <0.000016>
817   00:09:56.306477 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 839662077}) = 0 <0.000015>
817   00:09:56.306605 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 839796222}) = 0 <0.000016>
817   00:09:56.306659 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 839827604}) = 0 <0.000015>
817   00:09:56.306757 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 839907481}) = 0 <0.000015>
817   00:09:56.306813 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 839943070}) = 0 <0.000016>
817   00:09:56.307020 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840130918}) = 0 <0.000016>
817   00:09:56.307073 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840162720}) = 0 <0.000016>
817   00:09:56.307275 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840345820}) = 0 <0.000016>
817   00:09:56.307332 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840381247}) = 0 <0.000015>
817   00:09:56.307578 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840606375}) = 0 <0.000011>
817   00:09:56.307634 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840634217}) = 0 <0.000013>
817   00:09:56.307790 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840772464}) = 0 <0.000013>
817   00:09:56.307839 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840803312}) = 0 <0.000012>
817   00:09:56.307985 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840932473}) = 0 <0.000013>
817   00:09:56.308029 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 840957856}) = 0 <0.000013>
817   00:09:56.308180 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841092028}) = 0 <0.000010>
817   00:09:56.308220 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841114153}) = 0 <0.000012>
817   00:09:56.308390 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841267440}) = 0 <0.000014>
817   00:09:56.308439 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841297101}) = 0 <0.000013>
817   00:09:56.308612 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841455951}) = 0 <0.000019>
817   00:09:56.308670 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841489431}) = 0 <0.000017>
817   00:09:56.308828 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841627208}) = 0 <0.000017>
817   00:09:56.308882 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841660314}) = 0 <0.000017>
817   00:09:56.309037 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841795010}) = 0 <0.000036>
817   00:09:56.309107 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841822017}) = 0 <0.000017>
817   00:09:56.309248 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841942329}) = 0 <0.000018>
817   00:09:56.309300 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 841972565}) = 0 <0.000017>
817   00:09:56.309376 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 842004175}) = 0 <0.000017>
817   00:09:56.310339 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 842969781}) = 0 <0.000022>
817   00:09:56.310418 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 843012524}) = 0 <0.000017>
817   00:09:56.310682 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000025>
817   00:09:56.311021 write(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$40\r\ncache:gitlab:Appearance:11.3.0-ee:4.2.10\r\n", 60) = 60 <0.000055>
817   00:09:56.311380 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000022>
817   00:09:56.311703 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "$2193\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\17Appearance\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\30I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\ntitle\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\20description\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\tlogo\6;\fT@\20I\"\17updated_by\6;\fT@\vI\"\20header_logo\6;\fT@\20I\"\17created_at\6;\fTo:LActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTimeWithTimeZone\10;\0160;\0170;\0200I\"\17updated_at\6;\fT@\27I\"\25description_html\6;\fT@\22I\"\34cached_markdown_version\6;\fT@\vI\"\33new_project_guidelines\6;\fT@\22I\" new_project_guidelines_html\6;\fT@\22I\"\23header_message\6;\fT@\22I\"\30header_message_html\6;\fT@\22I\"\23footer_message\6;\fT@\22I\"\30footer_message_html\6;\fT@\22I\"\35message_background_color\6;\fT@\22I\"\27message_font_color\6;\fT@\22I\"\ffavicon\6;\fT@\20o:\36ActiveRecord::Type::Value\10;\0160;\0170;\0200:\f@values{\30I\"\7id\6;\fTI\"\0061\6;\fTI\"\ntitle\6;\fTI\"\25Welcome To GLaaS\6;\fTI\"\20description\6;\fTI\"\1\250(GitLab as a Ser", 1024) = 1024 <0.000018>
817   00:09:56.312070 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.312359 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "vice)\r\n\r\n**To login, select the _EA AD_ tab and use your EA email address as the _EA AD Username_ and then your AD password as the _Password._** </span>\6;\fTI\"\tlogo\6;\fT0I\"\17updated_by\6;\fT0I\"\20header_logo\6;\fT0I\"\17created_at\6;\fTI\"\"2017-11-16 21:10:42.622553+00\6;\fTI\"\17updated_at\6;\fTI\"\"2018-06-13 16:24:23.891341+00\6;\fTI\"\25description_html\6;\fTI\"\1\345<p dir=\"auto\">(GitLab as a Service)</p>\n\n<p dir=\"auto\"><strong>To login, select the <em>EA AD</em> tab and use your EA email address as the <em>EA AD Username</em> and then your AD password as the <em>Password.</em></strong> </p>\6;\fTI\"\34cached_markdown_version\6;\fTI\"\0063\6;\fTI\"\33new_project_guidelines\6;\fTI\"\0\6;\fTI\" new_project_guidelines_html\6;\fTI\"\0\6;\fTI\"\23header_message\6;\fT0I\"\30header_message_html\6;\fT0I\"\23footer_message\6;\fT0I\"\30footer_message_html\6;\fT0I\"\35message_background_color\6;\fT0I\"\27message_font_color\6;\fT0I\"\ffavicon\6;\fT0:\26@additional_types{\0:\22@materializedF:\23@delegate_hash{\0:\27@aggregation_cache{\0:\27@association_cache{\0:\16@readonlyF:\17@destroyedF:\34@marked_for_destructionF:\36@destroyed_by_a"..., 1176) = 1176 <0.000013>
817   00:09:56.312662 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000013>
817   00:09:56.312946 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000018>
817   00:09:56.313563 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 843849993}) = 0 <0.000012>
817   00:09:56.313622 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 843880846}) = 0 <0.000012>
817   00:09:56.313973 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.314271 write(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$51\r\ncache:gitlab:flipper/v1/feature/asset_host_prefetch\r\n", 71) = 71 <0.000037>
817   00:09:56.314598 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
817   00:09:56.314888 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "$192\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@value{\n:\fboolean0:\vgroupso:\10Set\6:\n@hash}\0F:\vactorso;\t\6;\n}\0F:\31percentage_of_actors0:\27percentage_of_time0:\20@created_atf\0271537830942.4272008:\20@expires_inf\n3.6e3\r\n", 1024) = 200 <0.000016>
817   00:09:56.315493 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 844603332}) = 0 <0.000013>
817   00:09:56.315573 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 844653253}) = 0 <0.000013>
817   00:09:56.316048 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 845105998}) = 0 <0.000013>
817   00:09:56.316109 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 845138893}) = 0 <0.000013>
817   00:09:56.316572 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 845580822}) = 0 <0.000015>
817   00:09:56.316634 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 845613759}) = 0 <0.000013>
817   00:09:56.316928 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 845889630}) = 0 <0.000014>
817   00:09:56.316977 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 845917164}) = 0 <0.000012>
817   00:09:56.317214 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 846136438}) = 0 <0.000013>
817   00:09:56.317263 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 846167288}) = 0 <0.000012>
817   00:09:56.317581 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 846466067}) = 0 <0.000015>
817   00:09:56.317638 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 846495695}) = 0 <0.000012>
817   00:09:56.317872 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.318171 write(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "*1\r\n$5\r\nmulti\r\n", 15) = 15 <0.000037>
817   00:09:56.318581 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.318872 write(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "*3\r\n$5\r\nsetnx\r\n$47\r\nsession:gitlab:afb7877ddba33e74e5f88491ed5ed36a\r\n$4\r\n\4\10{\0\r\n", 79) = 79 <0.000033>
817   00:09:56.319230 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
817   00:09:56.319541 write(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "*3\r\n$6\r\nexpire\r\n$47\r\nsession:gitlab:afb7877ddba33e74e5f88491ed5ed36a\r\n$6\r\n604800\r\n", 82) = 82 <0.000039>
817   00:09:56.319905 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000021>
817   00:09:56.320206 write(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "*1\r\n$4\r\nexec\r\n", 14) = 14 <0.000037>
817   00:09:56.320551 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000021>
817   00:09:56.320853 read(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "+OK\r\n+QUEUED\r\n+QUEUED\r\n*2\r\n:1\r\n:1\r\n", 1024) = 35 <0.000025>
817   00:09:56.321246 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 847171430}) = 0 <0.000018>
817   00:09:56.321313 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 847210711}) = 0 <0.000017>
817   00:09:56.321498 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 847374495}) = 0 <0.000018>
817   00:09:56.321553 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 847405748}) = 0 <0.000017>
817   00:09:56.321733 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 847565572}) = 0 <0.000018>
817   00:09:56.321791 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 847599932}) = 0 <0.000018>
817   00:09:56.322228 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 848015085}) = 0 <0.000020>
817   00:09:56.322295 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 848049455}) = 0 <0.000017>
817   00:09:56.322749 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 848482553}) = 0 <0.000020>
817   00:09:56.322823 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 848523316}) = 0 <0.000017>
817   00:09:56.323156 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 848834983}) = 0 <0.000019>
817   00:09:56.323221 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 848869776}) = 0 <0.000017>
817   00:09:56.323485 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 849113010}) = 0 <0.000019>
817   00:09:56.323543 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 849141221}) = 0 <0.000017>
817   00:09:56.323788 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849322028}) = 0 <0.000011>
817   00:09:56.323831 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849342883}) = 0 <0.000014>
817   00:09:56.323878 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849373305}) = 0 <0.000013>
817   00:09:56.323925 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849403471}) = 0 <0.000012>
817   00:09:56.324036 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849497019}) = 0 <0.000013>
817   00:09:56.324074 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849516907}) = 0 <0.000012>
817   00:09:56.324113 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849539053}) = 0 <0.000013>
817   00:09:56.324151 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 849560433}) = 0 <0.000013>
817   00:09:56.324306 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 849723434}) = 0 <0.000014>
817   00:09:56.324350 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 849744823}) = 0 <0.000013>
817   00:09:56.324593 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 849970282}) = 0 <0.000012>
817   00:09:56.324641 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 849996356}) = 0 <0.000013>
817   00:09:56.324880 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850218312}) = 0 <0.000015>
817   00:09:56.324935 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850249983}) = 0 <0.000012>
817   00:09:56.325089 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850386847}) = 0 <0.000011>
817   00:09:56.325127 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850405153}) = 0 <0.000013>
817   00:09:56.325214 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850475122}) = 0 <0.000013>
817   00:09:56.325255 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850497959}) = 0 <0.000012>
817   00:09:56.325327 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850552519}) = 0 <0.000013>
817   00:09:56.325379 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850587080}) = 0 <0.000013>
817   00:09:56.325679 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850868538}) = 0 <0.000012>
817   00:09:56.325731 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 850896062}) = 0 <0.000013>
817   00:09:56.325943 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 851089483}) = 0 <0.000015>
817   00:09:56.326001 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 851124597}) = 0 <0.000010>
817   00:09:56.326355 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 851424956}) = 0 <0.000011>
817   00:09:56.326418 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 851488467}) = 0 <0.000013>
817   00:09:56.326469 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 851521025}) = 0 <0.000013>
817   00:09:56.326568 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
817   00:09:56.326865 write(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$29\r\ncache:gitlab:geo_node_enabled\r\n", 49) = 49 <0.000041>
817   00:09:56.327191 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.327478 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "$92\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueF:\20@created_atf\0271537834194.5045602:\20@expires_inf\00715\r\n", 1024) = 99 <0.000024>
817   00:09:56.328034 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000024>
817   00:09:56.328349 write(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$38\r\ncache:gitlab:broadcast_message_current\r\n", 58) = 58 <0.000041>
817   00:09:56.328685 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000022>
817   00:09:56.329006 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "$1475\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@value[\6o:\25BroadcastMessage\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\17I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\fmessage\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\16starts_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\fends_at\6;\fTU;\27[\t;\30[\0[\0@\27I\"\17created_at\6;\fTU;\27[\t;\30[\0[\0@\27I\"\17updated_at\6;\fTU;\27[\t;\30[\0[\0@\27I\"\ncolor\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\tfont\6;\fT@(I\"\21message_html\6;\fT@\21I\"\34cached_markdown_version\6;\fT@\fo:\36ActiveRecord::Type::Value\10;\0160;\0170;\0200:\f@values{\17I\"\7id\6;\fTI\"\0066\6;\fTI\"\fmessage\6;\fTI\"\25TEST ENVIRONMENT\6;\fTI\"\16starts_at\6;\fTI\"\0302018-09-16 15:38:00\6;\fTI\"\fends_at\6;\fTI\"\0302023-09-16 15:38:00\6;\fTI\"\17created_at\6;\fTI\"\0372018-09-16 15:39:20.641038\6;\fTI\"\17updated_at\6;\fTI\"\0372018-09-16 15:39:20.641038\6", 1024) = 1024 <0.000036>
817   00:09:56.329360 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000022>
817   00:09:56.329686 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, ";\fTI\"\ncolor\6;\fTI\"\f#008040\6;\fTI\"\tfont\6;\fTI\"\f#ffffff\6;\fTI\"\21message_html\6;\fTI\"\34<p>TEST ENVIRONMENT</p>\6;\fTI\"\34cached_markdown_version\6;\fTI\"\00711\6;\fT:\26@additional_types{\0:\22@materializedF:\23@delegate_hash{\0:\27@aggregation_cache{\0:\27@association_cache{\0:\16@readonlyF:\17@destroyedF:\34@marked_for_destructionF:\36@destroyed_by_association0:\20@new_recordF:\t@txn0:\36@_start_transaction_state{\0:\27@transaction_state0:\24@reflects_state[\6F:\20@created_atf\0271537112360.7409678:\20@expires_in0", 458) = 458 <0.000025>
817   00:09:56.330000 fcntl(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
817   00:09:56.330317 read(13<TCP:[172.17.0.2:60620->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000023>
817   00:09:56.330773 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 852412405}) = 0 <0.000019>
817   00:09:56.330840 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 852450135}) = 0 <0.000017>
817   00:09:56.331166 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 852729690}) = 0 <0.000020>
817   00:09:56.331358 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 852891173}) = 0 <0.000019>
817   00:09:56.331475 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 853007459}) = 0 <0.000019>
817   00:09:56.331544 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 853044011}) = 0 <0.000018>
817   00:09:56.331661 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {3, 853091720}) = 0 <0.000014>
817   00:09:56.331918 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 853353489}) = 0 <0.000012>
817   00:09:56.331974 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 853384983}) = 0 <0.000013>
817   00:09:56.332335 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 853726797}) = 0 <0.000012>
817   00:09:56.332394 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 853758532}) = 0 <0.000012>
817   00:09:56.333029 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 854373553}) = 0 <0.000013>
817   00:09:56.333090 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 854403786}) = 0 <0.000012>
817   00:09:56.333360 write(8</var/log/gitlab/gitlab-rails/production.log>, "Completed 200 OK in 203ms (Views: 194.2ms | ActiveRecord: 2.5ms | Elasticsearch: 0.0ms)\n", 88) = 88 <0.000020>
817   00:09:56.333601 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 854862703}) = 0 <0.000011>
817   00:09:56.333647 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 854885547}) = 0 <0.000013>
817   00:09:56.333855 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 855076539}) = 0 <0.000011>
817   00:09:56.333900 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 855101044}) = 0 <0.000012>
817   00:09:56.334068 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 855251412}) = 0 <0.000011>
817   00:09:56.334113 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 855277897}) = 0 <0.000013>
817   00:09:56.334227 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 855374271}) = 0 <0.000013>
817   00:09:56.334270 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {3, 855399436}) = 0 <0.000013>
817   00:09:56.334351 fcntl(21<TCP:[172.17.0.2:60622->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
817   00:09:56.334648 write(21<TCP:[172.17.0.2:60622->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$14\r\npeek:requests:\r\n$4\r\n1800\r\n$338\r\n{\"context\":{},\"data\":{\"host\":{\"hostname\":\"aabecb3049c7\"},\"pg\":{\"duration\":\"2ms\",\"calls\":1,\"queries\":[]},\"gitaly\":{\"duration\":\"0ms\",\"calls\":0,\"details\":[]},\"redis\":{\"duration\":\"8ms\",\"calls\":4},\"sidekiq\":{\"duration\":\"0ms\",\"calls\":0},\"gc\":{\"invokes\":\"98\",\"invoke_time\":\"3.70\",\"use_size\":0,\"total_size\":0,\"total_object\":0,\"gc_time\":\"33.83\"}}}\r\n", 392) = 392 <0.000037>
817   00:09:56.334973 fcntl(21<TCP:[172.17.0.2:60622->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.335297 read(21<TCP:[172.17.0.2:60622->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000022>
817   00:09:56.335813 write(15</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/help\",\"format\":\"*/*\",\"controller\":\"HelpController\",\"action\":\"index\",\"status\":200,\"duration\":205.4,\"view\":194.17,\"db\":2.46,\"time\":\"2018-09-25T00:09:56.130Z\",\"params\":[],\"remote_ip\":\"127.0.0.1\",\"user_id\":null,\"username\":null,\"ua\":\"curl/7.59.0\"}\n", 268) = 268 <0.000025>
817   00:09:56.335931 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 35</proc/817/status> <0.000025>
817   00:09:56.335995 ioctl(35</proc/817/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000018>
817   00:09:56.336048 fstat(35</proc/817/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000018>
817   00:09:56.336100 lseek(35</proc/817/status>, 0, SEEK_CUR) = 0 <0.000017>
817   00:09:56.336150 read(35</proc/817/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t817\nNgid:\t0\nPid:\t817\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t817\nNSpid:\t817\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  799580 kB\nVmSize:\t  799580 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490512 kB\nVmRSS:\t  490512 kB\nRssAnon:\t  477528 kB\nRssFile:\t   12936 kB\nRssShmem:\t      48 kB\nVmData:\t  517028 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1644 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t2\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1312 <0.000031>
817   00:09:56.336221 read(35</proc/817/status>, "", 6880) = 0 <0.000017>
817   00:09:56.336271 close(35</proc/817/status>) = 0 <0.000018>
817   00:09:56.336696 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
817   00:09:56.336992 write(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$47\r\nsession:gitlab:afb7877ddba33e74e5f88491ed5ed36a\r\n$4\r\n7200\r\n$74\r\n\4\10{\6I\"\20_csrf_token\6:\6EFI\"1ZT1VYcamCZHEuHwJUQ2DI//8wbkw8Wgm0Zqrkuc8dTM=\6;\0F\r\n", 160) = 160 <0.000035>
817   00:09:56.337315 fcntl(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
817   00:09:56.337605 read(34<TCP:[172.17.0.2:32838->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000015>
817   00:09:56.338167 write(27<UNIX:[3605691->3605690,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "HTTP/1.1 200 OK\r\nDate: Tue, 25 Sep 2018 00:09:56 GMT\r\nConnection: close\r\nX-Frame-Options: DENY\r\nX-XSS-Protection: 1; mode=block\r\nX-Content-Type-Options: nosniff\r\nX-UA-Compatible: IE=edge\r\nContent-Type: text/html; charset=utf-8\r\nETag: W/\"d222ec7dfbef9216d1a684ed4891b705\"\r\nCache-Control: max-age=0, private, must-revalidate\r\nSet-Cookie: _gitlab_session=afb7877ddba33e74e5f88491ed5ed36a; path=/; expires=Tue, 25 Sep 2018 02:09:56 -0000; secure; HttpOnly\r\nX-Request-Id: afcbb0c1-9974-4547-92ee-fd53d4ac0072\r\nX-Runtime: 0.220174\r\n\r\n", 528) = 528 <0.000145>
817   00:09:56.338406 write(27<UNIX:[3605691->3605690,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, "<!DOCTYPE html>\n<html class=\"\" lang=\"en\">\n<head prefix=\"og: http://ogp.me/ns#\">\n<meta charset=\"utf-8\">\n<meta content=\"IE=edge\" http-equiv=\"X-UA-Compatible\">\n<meta content=\"object\" property=\"og:type\">\n<meta content=\"GitLab\" property=\"og:site_name\">\n<meta content=\"Help\" property=\"og:title\">\n<meta content=\"Welcome To GLaaS\" property=\"og:description\">\n<meta content=\"https://localhost/assets/gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png\" property=\"og:image\">\n<meta content=\"64\" property=\"og:image:width\">\n<meta content=\"64\" property=\"og:image:height\">\n<meta content=\"https://localhost/help\" property=\"og:url\">\n<meta content=\"summary\" property=\"twitter:card\">\n<meta content=\"Help\" property=\"twitter:title\">\n<meta content=\"Welcome To GLaaS\" property=\"twitter:description\">\n<meta content=\"https://localhost/assets/gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png\" property=\"twitter:image\">\n\n<title>Help \302\267 GitLab</title>\n<meta content=\"Welcome To GLaaS\" name=\"d"..., 41979) = 41979 <0.000098>
817   00:09:56.339016 shutdown(27<UNIX:[3605691->3605690,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, SHUT_RDWR) = 0 <0.000162>
817   00:09:56.340162 close(27<UNIX:[3605691,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>) = 0 <0.000160>
817   00:09:56.340552 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000018>
817   00:09:56.340636 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000034>
817   00:09:56.340805 getppid()         = 495 <0.002763>
817   00:09:56.343619 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
7410  00:09:56.953689 <... nanosleep resumed> NULL) = 0 <1.000087>
7410  00:09:56.953774 close(1<pipe:[3578440]>) = 0 <0.000014>
7410  00:09:56.953830 close(2<pipe:[3578440]>) = 0 <0.000014>
7410  00:09:56.953873 exit_group(0)     = ?
7410  00:09:56.953975 +++ exited with 0 +++
477   00:09:56.954005 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7410 <1.002332>
477   00:09:56.954038 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
477   00:09:56.954091 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:56.954129 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7410, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:56.954155 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000013>
477   00:09:56.954192 rt_sigreturn({mask=[]}) = 0 <0.000014>
477   00:09:56.954231 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000013>
477   00:09:56.954268 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000013>
477   00:09:56.954352 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000023>
477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000014>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000014>
477   00:09:56.954568 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000014>
477   00:09:56.954609 close(3</dev/null>) = 0 <0.000014>
477   00:09:56.954645 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:56.954682 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000014>
477   00:09:56.954722 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000014>
477   00:09:56.954758 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000014>
477   00:09:56.954795 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000014>
477   00:09:56.954835 fcntl(1</dev/null>, F_GETFD) = 0 <0.000014>
477   00:09:56.954875 kill(495, SIG_0)  = 0 <0.000014>
477   00:09:56.954910 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000014>
477   00:09:56.954951 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000014>
477   00:09:56.954988 close(11<pipe:[3578440]>) = 0 <0.000014>
477   00:09:56.955024 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000014>
477   00:09:56.955065 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000014>
477   00:09:56.955102 close(10<pipe:[3578440]>) = 0 <0.000014>
477   00:09:56.955159 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000022>
477   00:09:56.955207 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7419 <0.000129>
7419  00:09:56.955602 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:56.955640 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7419  00:09:56.955662 <... close resumed> ) = 0 <0.000034>
477   00:09:56.955674 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000025>
7419  00:09:56.955688 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
477   00:09:56.955732 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7419  00:09:56.955747 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000051>
477   00:09:56.955759 <... rt_sigprocmask resumed> [], 8) = 0 <0.000018>
7419  00:09:56.955772 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:56.955806 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7419  00:09:56.955818 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000020>
477   00:09:56.955831 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000019>
7419  00:09:56.955842 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:56.955855 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7419  00:09:56.955879 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000030>
477   00:09:56.955900 <... rt_sigprocmask resumed> [], 8) = 0 <0.000028>
7419  00:09:56.955913 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:56.955926 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7419  00:09:56.955939 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000019>
477   00:09:56.955962 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000029>
7419  00:09:56.955976 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:56.955989 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7419  00:09:56.956001 <... rt_sigaction resumed> {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
477   00:09:56.956014 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7419  00:09:56.956037 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:56.956051 wait4(-1,  <unfinished ...>
7419  00:09:56.956062 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000018>
7419  00:09:56.956083 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7419  00:09:56.956127 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7419  00:09:56.956171 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000023>
7419  00:09:56.956216 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000010>
7419  00:09:56.956250 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7419  00:09:56.956300 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000014>
7419  00:09:56.956338 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000025>
7419  00:09:56.956387 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000014>
7419  00:09:56.956470 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000170>
7419  00:09:56.956699 brk(NULL)         = 0x7b2000 <0.000011>
7419  00:09:56.956747 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000022>
7419  00:09:56.956804 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000015>
7419  00:09:56.956853 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000018>
7419  00:09:56.956906 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000015>
7419  00:09:56.956949 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f6e4628f000 <0.000015>
7419  00:09:56.956989 close(3</etc/ld.so.cache>) = 0 <0.000015>
7419  00:09:56.957033 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000014>
7419  00:09:56.957071 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000028>
7419  00:09:56.957123 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000014>
7419  00:09:56.957187 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000015>
7419  00:09:56.957229 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6e4628e000 <0.000014>
7419  00:09:56.957275 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7f6e45ca3000 <0.000015>
7419  00:09:56.957316 mprotect(0x7f6e45e63000, 2097152, PROT_NONE) = 0 <0.000027>
7419  00:09:56.957366 mmap(0x7f6e46063000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7f6e46063000 <0.000020>
7419  00:09:56.957416 mmap(0x7f6e46069000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f6e46069000 <0.000022>
7419  00:09:56.957468 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000014>
7419  00:09:56.957528 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6e4628d000 <0.000011>
7419  00:09:56.957563 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f6e4628c000 <0.000013>
7419  00:09:56.957610 arch_prctl(ARCH_SET_FS, 0x7f6e4628d700) = 0 <0.000015>
7419  00:09:56.957714 mprotect(0x7f6e46063000, 16384, PROT_READ) = 0 <0.000016>
7419  00:09:56.957764 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000011>
7419  00:09:56.957798 mprotect(0x7f6e46292000, 4096, PROT_READ) = 0 <0.000015>
7419  00:09:56.957845 munmap(0x7f6e4628f000, 10600) = 0 <0.000019>
7419  00:09:56.957970 brk(NULL)         = 0x7b2000 <0.000013>
7419  00:09:56.958015 brk(0x7d3000)     = 0x7d3000 <0.000014>
7419  00:09:56.958070 nanosleep({1, 0},  <unfinished ...>
1093  00:09:56.984700 <... nanosleep resumed> NULL) = 0 <1.000075>
1093  00:09:56.984731 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000012>
1093  00:09:56.984773 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.984807 open("/var/log/gitlab/logrotate/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/logrotate/current> <0.000015>
1093  00:09:56.984845 fstat(33</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000011>
1093  00:09:56.984877 close(33</var/log/gitlab/logrotate/current>) = 0 <0.000011>
1093  00:09:56.984907 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000012>
1093  00:09:56.984939 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000011>
1093  00:09:56.984972 open("/var/log/gitlab/gitlab-rails/sidekiq_exporter.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/sidekiq_exporter.log> <0.000013>
1093  00:09:56.985005 fstat(33</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000011>
1093  00:09:56.985043 close(33</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>) = 0 <0.000012>
1093  00:09:56.985072 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000011>
1093  00:09:56.985104 open("/var/log/gitlab/gitlab-rails/grpc.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/grpc.log> <0.000012>
1093  00:09:56.985137 fstat(33</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000011>
1093  00:09:56.985167 close(33</var/log/gitlab/gitlab-rails/grpc.log>) = 0 <0.000017>
1093  00:09:56.985203 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000011>
1093  00:09:56.985235 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121652, ...}) = 0 <0.000011>
1093  00:09:56.985270 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/help\",\"format\":\"*/*\",\"controller\":\"HelpController\",\"action\":\"index\",\"status\":200,\"duration\":205.4,\"view\":194.17,\"db\":2.46,\"time\":\"2018-09-25T00:09:56.130Z\",\"params\":[],\"remote_ip\":\"127.0.0.1\",\"user_id\":null,\"username\":null,\"ua\":\"curl/7.59.0\"}\n", 8192) = 268 <0.000022>
1093  00:09:56.985317 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "", 8192) = 0 <0.000013>
1093  00:09:56.985351 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117991, ...}) = 0 <0.000013>
1093  00:09:56.985388 read(10</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/help\" for 127.0.0.1 at 2018-09-25 00:09:56 +0000\nProcessing by HelpController#index as */*\nCompleted 200 OK in 203ms (Views: 194.2ms | ActiveRecord: 2.5ms | Elasticsearch: 0.0ms)\n", 8192) = 193 <0.000013>
1093  00:09:56.985424 read(10</var/log/gitlab/gitlab-rails/production.log>, "", 8192) = 0 <0.000013>
1093  00:09:56.985458 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000012>
1093  00:09:56.985494 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000012>
1093  00:09:56.985529 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000012>
1093  00:09:56.985566 open("/var/log/gitlab/prometheus/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/prometheus/current> <0.000015>
1093  00:09:56.985603 fstat(33</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000012>
1093  00:09:56.985638 close(33</var/log/gitlab/prometheus/current>) = 0 <0.000012>
1093  00:09:56.985671 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000012>
1093  00:09:56.985706 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000012>
1093  00:09:56.985742 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56896, ...}) = 0 <0.000013>
1093  00:09:56.985779 read(16</var/log/gitlab/gitlab-workhorse/current>, "2018-09-25_00:09:56.33920 localhost @ - - [2018/09/25:00:09:56 +0000] \"GET /help HTTP/1.1\" 200 41979 \"\" \"curl/7.59.0\" 0.222\n", 8192) = 124 <0.000013>
1093  00:09:56.985814 read(16</var/log/gitlab/gitlab-workhorse/current>, "", 8192) = 0 <0.000012>
1093  00:09:56.985848 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000013>
1093  00:09:56.985884 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.985919 open("/var/log/gitlab/nginx/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/current> <0.000014>
1093  00:09:56.985956 fstat(33</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.985991 close(33</var/log/gitlab/nginx/current>) = 0 <0.000012>
1093  00:09:56.986024 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.986063 open("/var/log/gitlab/nginx/access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/access.log> <0.000013>
1093  00:09:56.986099 fstat(33</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.986134 close(33</var/log/gitlab/nginx/access.log>) = 0 <0.000013>
1093  00:09:56.986167 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.986203 open("/var/log/gitlab/nginx/error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/error.log> <0.000014>
1093  00:09:56.986240 fstat(33</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.986275 close(33</var/log/gitlab/nginx/error.log>) = 0 <0.000012>
1093  00:09:56.986308 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42960, ...}) = 0 <0.000012>
1093  00:09:56.986344 read(21</var/log/gitlab/nginx/gitlab_access.log>, "127.0.0.1 - - [25/Sep/2018:00:09:56 +0000] \"GET /help HTTP/1.1\" 200 42038 \"\" \"curl/7.59.0\"\n", 8192) = 91 <0.000013>
1093  00:09:56.986379 read(21</var/log/gitlab/nginx/gitlab_access.log>, "", 8192) = 0 <0.000012>
1093  00:09:56.986413 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.986449 open("/var/log/gitlab/nginx/gitlab_pages_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_pages_error.log> <0.000014>
1093  00:09:56.986486 fstat(33</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.986521 close(33</var/log/gitlab/nginx/gitlab_pages_error.log>) = 0 <0.000013>
1093  00:09:56.986554 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.986589 open("/var/log/gitlab/nginx/gitlab_registry_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_registry_error.log> <0.000013>
1093  00:09:56.986625 fstat(33</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.986660 close(33</var/log/gitlab/nginx/gitlab_registry_error.log>) = 0 <0.000012>
1093  00:09:56.986693 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.986729 open("/var/log/gitlab/nginx/gitlab_pages_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_pages_access.log> <0.000014>
1093  00:09:56.986765 fstat(33</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.986800 close(33</var/log/gitlab/nginx/gitlab_pages_access.log>) = 0 <0.000012>
1093  00:09:56.986833 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.986868 open("/var/log/gitlab/nginx/gitlab_registry_access.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_registry_access.log> <0.000013>
1093  00:09:56.986904 fstat(33</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.986939 close(33</var/log/gitlab/nginx/gitlab_registry_access.log>) = 0 <0.000013>
1093  00:09:56.986972 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.987008 open("/var/log/gitlab/nginx/gitlab_error.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/nginx/gitlab_error.log> <0.000014>
1093  00:09:56.987044 fstat(33</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.987078 close(33</var/log/gitlab/nginx/gitlab_error.log>) = 0 <0.000012>
1093  00:09:56.987112 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.987147 open("/var/log/gitlab/gitlab-pages/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-pages/current> <0.000014>
1093  00:09:56.987186 fstat(33</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.987221 close(33</var/log/gitlab/gitlab-pages/current>) = 0 <0.000013>
1093  00:09:56.987255 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.987290 open("/var/log/gitlab/node-exporter/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/node-exporter/current> <0.000014>
1093  00:09:56.987327 fstat(33</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.987361 close(33</var/log/gitlab/node-exporter/current>) = 0 <0.000012>
1093  00:09:56.987395 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.987430 open("/var/log/gitlab/unicorn/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/current> <0.000014>
1093  00:09:56.987466 fstat(33</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.987501 close(33</var/log/gitlab/unicorn/current>) = 0 <0.000012>
1093  00:09:56.987534 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000026>
1093  00:09:56.987585 open("/var/log/gitlab/unicorn/unicorn_stderr.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/unicorn_stderr.log> <0.000014>
1093  00:09:56.987622 fstat(33</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000012>
1093  00:09:56.987658 close(33</var/log/gitlab/unicorn/unicorn_stderr.log>) = 0 <0.000012>
1093  00:09:56.987691 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000013>
1093  00:09:56.987726 open("/var/log/gitlab/unicorn/unicorn_stdout.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/unicorn/unicorn_stdout.log> <0.000013>
1093  00:09:56.987762 fstat(33</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000012>
1093  00:09:56.987797 close(33</var/log/gitlab/unicorn/unicorn_stdout.log>) = 0 <0.000012>
1093  00:09:56.987830 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000013>
1093  00:09:56.987866 open("/var/log/gitlab/sshd/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/sshd/current> <0.000014>
1093  00:09:56.987903 fstat(33</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000013>
1093  00:09:56.987938 close(33</var/log/gitlab/sshd/current>) = 0 <0.000013>
1093  00:09:56.987971 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000013>
1093  00:09:56.988006 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.988041 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000012>
1093  00:09:56.988076 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000012>
1093  00:09:56.988111 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000012>
1093  00:09:56.988146 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000012>
1093  00:09:56.988181 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121652, ...}) = 0 <0.000012>
1093  00:09:56.988216 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=117991, ...}) = 0 <0.000012>
1093  00:09:56.988251 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000012>
1093  00:09:56.988287 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000013>
1093  00:09:56.988322 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000013>
1093  00:09:56.988357 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000013>
1093  00:09:56.988395 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=100650, ...}) = 0 <0.000012>
1093  00:09:56.988430 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56896, ...}) = 0 <0.000012>
1093  00:09:56.988465 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000012>
1093  00:09:56.988500 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:56.988535 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988570 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988605 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42960, ...}) = 0 <0.000013>
1093  00:09:56.988640 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988675 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988710 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988745 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988780 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988815 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988850 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988885 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000013>
1093  00:09:56.988920 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000012>
1093  00:09:56.988955 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000012>
1093  00:09:56.988989 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000012>
1093  00:09:56.989025 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/gitlab-rails/production_json.log <==\n{\"method\":\"GET\",\"path\":\"/help\",\"format\":\"*/*\",\"controller\":\"HelpController\",\"action\":\"index\",\"status\":200,\"duration\":205.4,\"view\":194.17,\"db\":2.46,\"time\":\"2018-09-25T00:09:56.130Z\",\"params\":[],\"remote_ip\":\"127.0.0.1\",\"user_id\":null,\"username\":null,\"ua\":\"curl/7.59.0\"}\n\n==> /var/log/gitlab/gitlab-rails/production.log <==\nStarted GET \"/help\" for 127.0.0.1 at 2018-09-25 00:09:56 +0000\nProcessing by HelpController#index as */*\nCompleted 200 OK in 203ms (Views: 194.2ms | ActiveRecord: 2.5ms | Elasticsearch: 0.0ms)\n\n==> /var/log/gitlab/gitlab-workhorse/current <==\n2018-09-25_00:09:56.33920 localhost @ - - [2018/09/25:00:09:56 +0000] \"GET /help HTTP/1.1\" 200 41979 \"\" \"curl/7.59.0\" 0.222\n\n==> /var/log/gitlab/nginx/gitlab_access.log <==\n127.0.0.1 - - [25/Sep/2018:00:09:56 +0000] \"GET /help HTTP/1.1\" 200 42038 \"\" \"curl/7.59.0\"\n", 886) = 886 <0.000062>
1093  00:09:56.989182 nanosleep({1, 0},  <unfinished ...>
7113  00:09:57.120961 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000432>
7113  00:09:57.121017 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000016>
7113  00:09:57.121062 clock_gettime(CLOCK_MONOTONIC, {282503, 205531249}) = 0 <0.000015>
7113  00:09:57.121111 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 122, {282504, 206328885}, ffffffff <unfinished ...>
2690  00:09:57.192463 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000850>
2690  00:09:57.192516 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000014>
2690  00:09:57.192554 clock_gettime(CLOCK_MONOTONIC, {282503, 277021324}) = 0 <0.000013>
2690  00:09:57.192610 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4018, {282504, 277834003}, ffffffff <unfinished ...>
823   00:09:57.391977 <... select resumed> ) = 1 (in [24], left {28, 727749}) <1.272274>
817   00:09:57.392042 <... select resumed> ) = 1 (in [24], left {28, 951969}) <1.048133>
813   00:09:57.392063 <... select resumed> ) = 1 (in [24], left {28, 726154}) <1.273975>
823   00:09:57.392108 fcntl(24<TCP:[127.0.0.1:8080]>, F_GETFL <unfinished ...>
817   00:09:57.392353 fcntl(24<TCP:[127.0.0.1:8080]>, F_GETFL <unfinished ...>
823   00:09:57.392541 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000198>
817   00:09:57.392556 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000022>
823   00:09:57.392570 accept4(24<TCP:[127.0.0.1:8080]>,  <unfinished ...>
817   00:09:57.392746 accept4(24<TCP:[127.0.0.1:8080]>,  <unfinished ...>
823   00:09:57.392912 <... accept4 resumed> {sa_family=AF_INET, sin_port=htons(47924), sin_addr=inet_addr("127.0.0.1")}, [16], SOCK_CLOEXEC) = 26<TCP:[127.0.0.1:8080->127.0.0.1:47924]> <0.000173>
817   00:09:57.393085 <... accept4 resumed> 0x7ffc6d3d47b0, 0x7ffc6d3d477c, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000180>
813   00:09:57.393100 fcntl(24<TCP:[127.0.0.1:8080]>, F_GETFL <unfinished ...>
823   00:09:57.393271 recvfrom(26<TCP:[127.0.0.1:8080->127.0.0.1:47924]>,  <unfinished ...>
817   00:09:57.393434 getppid( <unfinished ...>
823   00:09:57.393447 <... recvfrom resumed> "GET /-/metrics HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Prometheus/1.8.2\r\nAccept: application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,text/plain;version=0.0.4;q=0.3,*/*;q=0.1\r\nX-Prometheus-Scrape-Timeout-Seconds: 15.000000\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", 16384, MSG_DONTWAIT, NULL, NULL) = 316 <0.000022>
817   00:09:57.393465 <... getppid resumed> ) = 495 <0.000024>
813   00:09:57.393474 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000213>
813   00:09:57.393495 accept4(24<TCP:[127.0.0.1:8080]>, 0x7ffc6d3d47b0, 0x7ffc6d3d477c, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000016>
813   00:09:57.393726 getppid()         = 495 <0.000007>
813   00:09:57.393767 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:57.394039 write(8</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/-/metrics\" for 127.0.0.1 at 2018-09-25 00:09:57 +0000\n", 68 <unfinished ...>
817   00:09:57.394063 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:57.394263 <... write resumed> ) = 68 <0.000206>
823   00:09:57.394418 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0&\242\206H\362]D\355n'\26\343&\210H\363\223\257\256\356\216\320\357\n\"\372x\n\231\204F\211M9el\r\266\313", 43, MSG_NOSIGNAL, NULL, 0) = 43 <0.000042>
823   00:09:57.394785 poll([{fd=32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, events=POLLIN|POLLERR}], 1, -1) = 1 ([{fd=32, revents=POLLIN}]) <0.000273>
823   00:09:57.395366 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0Z", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:57.395687 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30[\352D\271@\252\256\346\26\"\2\30\334\306-\5AJ\227\0\f\224KP\210\202H\302\264\343\250\221\233'\374\352\265\226\201^\271\204\343}\241\244\326\376\262Y\315\210=Is\312\253u\26~\353\247\350A\337\t\223\350\322\270-\260L\371\206\342\372u\246\327\245\35n", 90, 0, NULL, NULL) = 90 <0.000018>
823   00:09:57.396286 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
823   00:09:57.396583 write(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$48\r\ncache:gitlab:ApplicationSetting:11.3.0-ee:4.2.10\r\n", 68) = 68 <0.000035>
823   00:09:57.396905 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000018>
823   00:09:57.397205 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "$13766\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\27ApplicationSetting\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\1\246I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\33default_projects_limit\6;\fT@\vI\"\23signup_enabled\6;\fTo: ActiveRecord::Type::Boolean\10;\0160;\0170;\0200I\"\25gravatar_enabled\6;\fT@\21I\"\21sign_in_text\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\17created_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\17updated_at\6;\fTU;\30[\t;\31[\0[\0@\32I\"\22home_page_url\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\36default_branch_protection\6;\fT@\vI\"\16help_text\6;\fT@\24I\"!restricted_visibility_levels\6;\fTU:#ActiveRecord::Type::Serialized[\t;\31[\7:\r@subtype:\v@coder[\7@\24o:%ActiveRecord::Coders::YAMLColumn\6:\22@object_classc\vObject@\24I\"\32version_check_enabled\6;\fT@\21I\"\30max_attachment_size\6;\fT@\vI\"\37de", 1024) = 1024 <0.000018>
823   00:09:57.397653 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000018>
823   00:09:57.397942 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "fault_project_visibility\6;\fT@\vI\"\37default_snippet_visibility\6;\fT@\vI\"\25domain_whitelist\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; c\nArray@\24I\"\34user_oauth_applications\6;\fT@\21I\"\30after_sign_out_path\6;\fT@!I\"\31session_expire_delay\6;\fT@\vI\"\23import_sources\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; @*@\24I\"\23help_page_text\6;\fT@\24I\"\35admin_notification_email\6;\fT@!I\"\33shared_runners_enabled\6;\fT@\21I\"\27max_artifacts_size\6;\fT@\vI\"\37runners_registration_token\6;\fT@!I\"\23max_pages_size\6;\fT@\vI\"&require_two_factor_authentication\6;\fT@\21I\"\34two_factor_grace_period\6;\fT@\vI\"\24metrics_enabled\6;\fT@\21I\"\21metrics_host\6;\fT@!I\"\26metrics_pool_size\6;\fT@\vI\"\24metrics_timeout\6;\fT@\vI\"\"metrics_method_call_threshold\6;\fT@\vI\"\26recaptcha_enabled\6;\fT@\21I\"\27recaptcha_site_key\6;\fT@!I\"\32recaptcha_private_key\6;\fT@!I\"\21metrics_port\6;\fT@\vI\"\24akismet_enabled\6;\fT@\21I\"\24akismet_api_key\6;\fT@!I\"\34metrics_sample_interval\6;\fT@\vI\"\23sentry_enabled\6;\fT@\21I\"\17sentry_dsn\6;\fT@!I\"\31email_author_in_body\6;\fT@\21I\"\35default_group_visibility\6;\fT@\vI\"\36repository_checks_enabled\6;\fT@\21I\"\30shared_runners_text\6;\fT@\24I\"\30metrics_packet_size\6;\fT@\vI\"#disable"..., 12750) = 12750 <0.000019>
823   00:09:57.398247 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000017>
823   00:09:57.398530 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000018>
823   00:09:57.399421 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000023>
823   00:09:57.399485 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>
823   00:09:57.399524 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000013>
823   00:09:57.399590 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000013>
823   00:09:57.399628 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490820 kB\nVmRSS:\t  490820 kB\nRssAnon:\t  476264 kB\nRssFile:\t   14500 kB\nRssShmem:\t      56 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000028>
823   00:09:57.399690 read(44</proc/823/status>, "", 6881) = 0 <0.000013>
823   00:09:57.399727 close(44</proc/823/status>) = 0 <0.000013>
823   00:09:57.402139 write(8</var/log/gitlab/gitlab-rails/production.log>, "Processing by MetricsController#index as HTML\n", 46) = 46 <0.000021>
823   00:09:57.403108 write(8</var/log/gitlab/gitlab-rails/production.log>, "Filter chain halted as :validate_ip_whitelisted_or_valid_token! rendered or redirected\n", 87) = 87 <0.000019>
823   00:09:57.403264 write(8</var/log/gitlab/gitlab-rails/production.log>, "Completed 404 Not Found in 1ms (Views: 0.5ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\n", 91) = 91 <0.000016>
823   00:09:57.403946 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000019>
823   00:09:57.404256 write(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$14\r\npeek:requests:\r\n$4\r\n1800\r\n$334\r\n{\"context\":{},\"data\":{\"host\":{\"hostname\":\"aabecb3049c7\"},\"pg\":{\"duration\":\"0ms\",\"calls\":0,\"queries\":[]},\"gitaly\":{\"duration\":\"0ms\",\"calls\":0,\"details\":[]},\"redis\":{\"duration\":\"0ms\",\"calls\":0},\"sidekiq\":{\"duration\":\"0ms\",\"calls\":0},\"gc\":{\"invokes\":0,\"invoke_time\":\"0.00\",\"use_size\":0,\"total_size\":0,\"total_object\":0,\"gc_time\":\"0.00\"}}}\r\n", 388) = 388 <0.000037>
823   00:09:57.404589 fcntl(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000018>
823   00:09:57.404879 read(21<TCP:[172.17.0.2:60676->10.7.7.47:6379]>, "+OK\r\n", 1024) = 5 <0.000021>
823   00:09:57.405398 write(15</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/-/metrics\",\"format\":\"html\",\"controller\":\"MetricsController\",\"action\":\"index\",\"status\":404,\"duration\":3.0,\"view\":0.49,\"db\":0.0,\"time\":\"2018-09-25T00:09:57.402Z\",\"params\":[],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n", 256) = 256 <0.000019>
823   00:09:57.405495 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000018>
823   00:09:57.405543 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>
823   00:09:57.405580 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000012>
823   00:09:57.405618 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000012>
823   00:09:57.405657 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490820 kB\nVmRSS:\t  490820 kB\nRssAnon:\t  476264 kB\nRssFile:\t   14500 kB\nRssShmem:\t      56 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000025>
823   00:09:57.405715 read(44</proc/823/status>, "", 6881) = 0 <0.000021>
823   00:09:57.405766 close(44</proc/823/status>) = 0 <0.000014>
823   00:09:57.406077 write(26<TCP:[127.0.0.1:8080->127.0.0.1:47924]>, "HTTP/1.1 404 Not Found\r\nDate: Tue, 25 Sep 2018 00:09:57 GMT\r\nConnection: close\r\nX-Frame-Options: SAMEORIGIN\r\nX-XSS-Protection: 1; mode=block\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\nX-Request-Id: cf24f6d9-e201-4cdf-a721-519397a58dd3\r\nX-Runtime: 0.012259\r\n\r\n", 315) = 315 <0.000020>
823   00:09:57.406312 write(26<TCP:[127.0.0.1:8080->127.0.0.1:47924]>, "<!DOCTYPE html>\n<html>\n<head>\n  <meta content=\"width=device-width, initial-scale=1, maximum-scale=1\" name=\"viewport\">\n  <title>The page you're looking for could not be found (404)</title>\n  <style>\n    body {\n      color: #666;\n      text-align: center;\n      font-family: \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n      margin: auto;\n      font-size: 14px;\n    }\n\n    h1 {\n      font-size: 56px;\n      line-height: 100px;\n      font-weight: 400;\n      color: #456;\n    }\n\n    h2 {\n      font-size: 24px;\n      color: #666;\n      line-height: 1.5em;\n    }\n\n    h3 {\n      color: #456;\n      font-size: 20px;\n      font-weight: 400;\n      line-height: 28px;\n    }\n\n    hr {\n      max-width: 800px;\n      margin: 18px auto;\n      border: 0;\n      border-top: 1px solid #EEE;\n      border-bottom: 1px solid white;\n    }\n\n    img {\n      max-width: 40vw;\n      display: block;\n      margin: 40px auto;\n    }\n\n    a {\n      line-height: 100px;\n      font-weight: 400;\n      color: #4A8BEE;\n      font-size: 18px;\n      text"..., 3108) = 3108 <0.000017>
823   00:09:57.406626 shutdown(26<TCP:[127.0.0.1:8080->127.0.0.1:47924]>, SHUT_RDWR) = 0 <0.000164>
823   00:09:57.406985 close(26<TCP:[3605728]>) = 0 <0.000021>
823   00:09:57.407321 stat("/proc/823/smaps", {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000015>
823   00:09:57.407377 open("/proc/823/smaps", O_RDONLY|O_CLOEXEC) = 26</proc/823/smaps> <0.000016>
823   00:09:57.407420 ioctl(26</proc/823/smaps>, TCGETS, 0x7ffc6d3d4000) = -1 ENOTTY (Inappropriate ioctl for device) <0.000012>
823   00:09:57.407461 read(26</proc/823/smaps>, "00400000-00401000 r-xp 00000000 fd:04 399754                             /opt/gitlab/embedded/bin/ruby\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me dw \n00600000-00601000 r--p 00000000 fd:04 399754                             /opt/gitlab/embedded/bin/ruby\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_D"..., 8192) = 3963 <0.000055>
823   00:09:57.407662 read(26</proc/823/smaps>, "7f5edf5ff000-7f5edf600000 ---p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me ac \n7f5edf600000-7f5ee0000000 rw-p 00000000 00:00 0 \nSize:              10240 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   8 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         8 kB\nReferenced:            8 kB\nAnonymous:             8 kB\nLazyFree:              0 kB\nAnonHugePag"..., 8192) = 3792 <0.000486>
823   00:09:57.408265 read(26</proc/823/smaps>, "7f5ee3fe4000-7f5ee3ffb000 r-xp 00000000 fd:04 533171                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/trans/single_byte.so\nSize:                 92 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  60 kB\nPss:                  23 kB\nShared_Clean:         60 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           60 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ee3ffb000-7f5ee41fa000 ---p 00017000 fd:04 533171                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/trans/single_byte.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_C"..., 8192) = 3547 <0.002222>
823   00:09:57.410590 read(26</proc/823/smaps>, "7f5eee7fc000-7f5eee7ff000 r-xp 00000000 fd:04 535500                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/posix-spawn-0.3.13/lib/posix_spawn_ext.so\nSize:                 12 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  12 kB\nPss:                   1 kB\nShared_Clean:         12 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           12 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5eee7ff000-7f5eee9fe000 ---p 00003000 fd:04 535500                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/posix-spawn-0.3.13/lib/posix_spawn_ext.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:    "..., 8192) = 3603 <0.000391>
823   00:09:57.411072 read(26</proc/823/smaps>, "7f5ef0b39000-7f5ef0b50000 r-xp 00000000 fd:04 394164                     /lib/x86_64-linux-gnu/libresolv-2.23.so\nSize:                 92 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  88 kB\nPss:                  13 kB\nShared_Clean:         88 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           88 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef0b50000-7f5ef0d50000 ---p 00017000 fd:04 394164                     /lib/x86_64-linux-gnu/libresolv-2.23.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:      "..., 8192) = 3411 <0.000039>
823   00:09:57.411194 read(26</proc/823/smaps>, "7f5ef0d54000-7f5ef0d59000 r-xp 00000000 fd:04 394139                     /lib/x86_64-linux-gnu/libnss_dns-2.23.so\nSize:                 20 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  20 kB\nPss:                   3 kB\nShared_Clean:         20 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           20 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef0d59000-7f5ef0f59000 ---p 00005000 fd:04 394139                     /lib/x86_64-linux-gnu/libnss_dns-2.23.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:    "..., 8192) = 3535 <0.000038>
823   00:09:57.411318 read(26</proc/823/smaps>, "7f5ef0f65000-7f5ef1164000 ---p 0000a000 fd:04 535745                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/prometheus-client-mmap-0.9.4/lib/fast_mmaped_file.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef1164000-7f5ef1165000 r--p 00009000 fd:04 535745                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/prometheus-client-mmap-0.9.4/lib/fast_mmaped_file.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                "..., 8192) = 3649 <0.000039>
823   00:09:57.411436 read(26</proc/823/smaps>, "7f5ef1370000-7f5ef1371000 r--p 0000a000 fd:04 394141                     /lib/x86_64-linux-gnu/libnss_files-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef1371000-7f5ef1372000 rw-p 0000b000 fd:04 394141                     /lib/x86_64-linux-gnu/libnss_files-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:"..., 8192) = 3419 <0.000036>
823   00:09:57.411574 read(26</proc/823/smaps>, "7f5ef1582000-7f5ef1583000 r--p 0000a000 fd:04 394145                     /lib/x86_64-linux-gnu/libnss_nis-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef1583000-7f5ef1584000 rw-p 0000b000 fd:04 394145                     /lib/x86_64-linux-gnu/libnss_nis-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:    "..., 8192) = 3465 <0.000037>
823   00:09:57.411688 read(26</proc/823/smaps>, "7f5ef179a000-7f5ef179b000 rw-p 00016000 fd:04 394135                     /lib/x86_64-linux-gnu/libnsl-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5ef179b000-7f5ef179d000 rw-p 00000000 00:00 0 \nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\n"..., 8192) = 3420 <0.000036>
823   00:09:57.411809 read(26</proc/823/smaps>, "7f5ef19a5000-7f5ef19a6000 rw-p 00008000 fd:04 394137                     /lib/x86_64-linux-gnu/libnss_compat-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         4 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5ef19a6000-7f5ef19a7000 r-xp 00000000 fd:04 533188                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/fiber.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          "..., 8192) = 3551 <0.000038>
823   00:09:57.411926 read(26</proc/823/smaps>, "7f5ef1ba8000-7f5ef1bd3000 r-xp 00000000 fd:04 542844                     /opt/gitlab/embedded/postgresql/9.6.8/lib/libpq.so.5.9\nSize:                172 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 160 kB\nPss:                  26 kB\nShared_Clean:        160 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:          160 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef1bd3000-7f5ef1dd2000 ---p 0002b000 fd:04 542844                     /opt/gitlab/embedded/postgresql/9.6.8/lib/libpq.so.5.9\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:     "..., 8192) = 3562 <0.000041>
823   00:09:57.412046 read(26</proc/823/smaps>, "7f5ef1dfe000-7f5ef1ffe000 ---p 00028000 fd:04 535408                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/pg-0.18.4/lib/pg_ext.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef1ffe000-7f5ef1fff000 r--p 00028000 fd:04 535408                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/pg-0.18.4/lib/pg_ext.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:         "..., 8192) = 3571 <0.000144>
823   00:09:57.412272 read(26</proc/823/smaps>, "7f5ef29f7000-7f5ef2bf6000 ---p 00058000 fd:04 273137                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/google-protobuf-3.5.1-x86_64-linux/lib/google/2.4/protobuf_c.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef2bf6000-7f5ef2bfe000 r--p 00057000 fd:04 273137                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/google-protobuf-3.5.1-x86_64-linux/lib/google/2.4/protobuf_c.so\nSize:                 32 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 k"..., 8192) = 3684 <0.000087>
823   00:09:57.412440 read(26</proc/823/smaps>, "7f5ef31df000-7f5ef33df000 ---p 0025c000 fd:04 400074                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/grpc-1.11.0-x86_64-linux/src/ruby/lib/grpc/2.4/grpc_c.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef33df000-7f5ef33f4000 r--p 0025c000 fd:04 400074                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/grpc-1.11.0-x86_64-linux/src/ruby/lib/grpc/2.4/grpc_c.so\nSize:                 84 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:        "..., 8192) = 3539 <0.000068>
823   00:09:57.412592 read(26</proc/823/smaps>, "7f5ef37e2000-7f5ef37ea000 r-xp 00000000 fd:04 3089                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/bcrypt_pbkdf-1.0.0/lib/bcrypt_pbkdf_ext.so\nSize:                 32 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  32 kB\nPss:                   6 kB\nShared_Clean:         32 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           32 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef37ea000-7f5ef39e9000 ---p 00008000 fd:04 3089                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/bcrypt_pbkdf-1.0.0/lib/bcrypt_pbkdf_ext.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:  "..., 8192) = 3709 <0.000039>
823   00:09:57.412709 read(26</proc/823/smaps>, "7f5ef39f8000-7f5ef3bf7000 ---p 0000d000 fd:04 135651                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/ed25519-1.2.4/lib/ed25519_ref10.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef3bf7000-7f5ef3bf8000 r--p 0000c000 fd:04 135651                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/ed25519-1.2.4/lib/ed25519_ref10.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\n"..., 8192) = 3535 <0.000069>
823   00:09:57.412862 read(26</proc/823/smaps>, "7f5ef3fcc000-7f5ef41cc000 ---p 00007000 fd:04 530478                     /opt/gitlab/embedded/lib/libffi.so.6.0.4\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef41cc000-7f5ef41cd000 r--p 00007000 fd:04 530478                     /opt/gitlab/embedded/lib/libffi.so.6.0.4\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0"..., 8192) = 3529 <0.000039>
823   00:09:57.412977 read(26</proc/823/smaps>, "7f5ef43f0000-7f5ef43f1000 r--p 00022000 fd:04 138207                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/ffi-1.9.25/lib/ffi_c.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef43f1000-7f5ef43f2000 rw-p 00023000 fd:04 138207                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/ffi-1.9.25/lib/ffi_c.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:   "..., 8192) = 3652 <0.000037>
823   00:09:57.413091 read(26</proc/823/smaps>, "7f5ef45f4000-7f5ef45f5000 rw-p 00002000 fd:04 12733                      /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/vmstat-2.3.0/lib/vmstat/vmstat.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5ef45f5000-7f5ef45ff000 r-xp 00000000 fd:04 5866                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/ruby-prof-0.17.0/lib/ruby_prof.so\nSize:                 40 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  40 kB\nPss:                 "..., 8192) = 3675 <0.000097>
823   00:09:57.413278 read(26</proc/823/smaps>, "7f5ef4800000-7f5ef4c00000 rw-p 00000000 00:00 0 \nSize:               4096 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                4096 kB\nPss:                1730 kB\nShared_Clean:          0 kB\nShared_Dirty:       3164 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       932 kB\nReferenced:         2768 kB\nAnonymous:          4096 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5ef4d3a000-7f5ef4d3b000 r-xp 00000000 fd:04 1639                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/atomic-1.1.99/lib/atomic_reference.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_D"..., 8192) = 3587 <0.000060>
823   00:09:57.413418 read(26</proc/823/smaps>, "7f5ef4f3c000-7f5ef4f3f000 r-xp 00000000 fd:04 538109                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/rblineprof-0.3.6/lib/rblineprof.so\nSize:                 12 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  12 kB\nPss:                   2 kB\nShared_Clean:         12 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           12 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef4f3f000-7f5ef513e000 ---p 00003000 fd:04 538109                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/rblineprof-0.3.6/lib/rblineprof.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                  "..., 8192) = 3575 <0.000162>
823   00:09:57.413657 read(26</proc/823/smaps>, "7f5ef5400000-7f5ef5c00000 rw-p 00000000 00:00 0 \nSize:               8192 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                8192 kB\nPss:                3606 kB\nShared_Clean:          0 kB\nShared_Dirty:       6136 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:      2056 kB\nReferenced:         6228 kB\nAnonymous:          8192 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5ef5d8b000-7f5ef5d8e000 r-xp 00000000 fd:04 533174                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/trans/utf_16_32.so\nSize:                 12 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  12 kB\nPss:                   2 kB\nShared_Clean:         12 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       "..., 8192) = 3539 <0.000088>
823   00:09:57.413823 read(26</proc/823/smaps>, "7f5ef5f90000-7f5ef5f91000 r-xp 00000000 fd:04 137529                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/fast_blank-1.0.0/lib/fast_blank.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef5f91000-7f5ef6190000 ---p 00001000 fd:04 137529                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/fast_blank-1.0.0/lib/fast_blank.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                  "..., 8192) = 3676 <0.000039>
823   00:09:57.413946 read(26</proc/823/smaps>, "7f5ef61f3000-7f5ef63f3000 ---p 00061000 fd:04 405673                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/nokogumbo-1.5.0/lib/nokogumboc.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef63f3000-7f5ef63f5000 r--p 00061000 fd:04 405673                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/nokogumbo-1.5.0/lib/nokogumboc.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   2 kB\nSh"..., 8192) = 3688 <0.000038>
823   00:09:57.414061 read(26</proc/823/smaps>, "7f5ef65fe000-7f5ef65ff000 r--p 00008000 fd:04 401105                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/http_parser.rb-0.6.0/lib/ruby_http_parser.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef65ff000-7f5ef6600000 rw-p 00009000 fd:04 401105                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/http_parser.rb-0.6.0/lib/ruby_http_parser.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPs"..., 8192) = 3611 <0.000065>
823   00:09:57.414211 read(26</proc/823/smaps>, "7f5ef6b82000-7f5ef6b83000 r--p 00001000 fd:04 12545                      /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/version_sorter-2.1.0/lib/version_sorter.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef6b83000-7f5ef6b84000 rw-p 00002000 fd:04 12545                      /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/version_sorter-2.1.0/lib/version_sorter.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:  "..., 8192) = 3573 <0.000037>
823   00:09:57.414329 read(26</proc/823/smaps>, "7f5ef6ded000-7f5ef6dee000 rw-p 00069000 fd:04 530612                     /opt/gitlab/embedded/lib/libre2.so.0.0.0\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5ef6dee000-7f5ef6df8000 r-xp 00000000 fd:04 538976                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/re2-1.1.1/lib/re2.so\nSize:                 40 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  40 kB\nPss:                   7 kB\nShared_Clean:         40 kB\nShared_Dirty:    "..., 8192) = 3584 <0.000038>
823   00:09:57.414444 read(26</proc/823/smaps>, "7f5ef6ffa000-7f5ef6fff000 r-xp 00000000 fd:04 533191                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/io/console.so\nSize:                 20 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  20 kB\nPss:                   3 kB\nShared_Clean:         20 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           20 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef6fff000-7f5ef71fe000 ---p 00005000 fd:04 533191                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/io/console.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nSh"..., 8192) = 3503 <0.000156>
823   00:09:57.414675 read(26</proc/823/smaps>, "7f5ef7aff000-7f5ef7b04000 r-xp 00000000 fd:04 539871                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/rinku-2.0.0/lib/rinku.so\nSize:                 20 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  20 kB\nPss:                   3 kB\nShared_Clean:         20 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           20 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5ef7b04000-7f5ef7d03000 ---p 00005000 fd:04 539871                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/rinku-2.0.0/lib/rinku.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean: "..., 8192) = 3638 <0.000038>
823   00:09:57.414792 read(26</proc/823/smaps>, "7f5ef7d91000-7f5ef7f90000 ---p 0008c000 fd:04 533498                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/RedCloth-4.3.2/lib/redcloth_scan.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef7f90000-7f5ef7f91000 r--p 0008b000 fd:04 533498                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/RedCloth-4.3.2/lib/redcloth_scan.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 k"..., 8192) = 3597 <0.000042>
823   00:09:57.414914 read(26</proc/823/smaps>, "7f5ef7fe0000-7f5ef81e0000 ---p 0004d000 fd:04 132806                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/commonmarker-0.17.13/lib/commonmarker/commonmarker.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5ef81e0000-7f5ef81e9000 r--p 0004d000 fd:04 132806                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/commonmarker-0.17.13/lib/commonmarker/commonmarker.so\nSize:                 36 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:              "..., 8192) = 3724 <0.000039>
823   00:09:57.415033 read(26</proc/823/smaps>, "7f5ef83fe000-7f5ef83ff000 r--p 00014000 fd:04 539075                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/redcarpet-3.4.0/lib/redcarpet.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef83ff000-7f5ef8400000 rw-p 00015000 fd:04 539075                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/redcarpet-3.4.0/lib/redcarpet.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 k"..., 8192) = 3569 <0.000169>
823   00:09:57.415277 read(26</proc/823/smaps>, "7f5ef8fcb000-7f5ef8fcc000 r--p 00004000 fd:04 400264                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/hamlit-2.8.8/lib/hamlit/hamlit.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5ef8fcc000-7f5ef8fcd000 rw-p 00005000 fd:04 400264                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/hamlit-2.8.8/lib/hamlit/hamlit.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4"..., 8192) = 3609 <0.000039>
823   00:09:57.415396 read(26</proc/823/smaps>, "7f5ef91ff000-7f5ef9200000 rw-p 00032000 fd:04 533212                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/ripper.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         4 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5ef9200000-7f5f01a00000 rw-p 00000000 00:00 0 \nSize:             139264 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:              125188 kB\nPss:               94392 kB\nShared_Clean:          0 kB\nShared_Dirty:      41160 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:     84028 kB\nRefere"..., 8192) = 3589 <0.001686>
823   00:09:57.417182 read(26</proc/823/smaps>, "7f5f01dff000-7f5f01e00000 rw-p 00006000 fd:04 271024                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/github-linguist-5.3.3/lib/linguist/linguist.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f01e00000-7f5f02200000 rw-p 00000000 00:00 0 \nSize:               4096 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                3724 kB\nPss:                2710 kB\nShared_Clean:          0 kB\nShared_Dirty:       1352 kB\nPrivate_Clean:         0 kB\n"..., 8192) = 3638 <0.000091>
823   00:09:57.417361 read(26</proc/823/smaps>, "7f5f025ca000-7f5f025cb000 rw-p 0000b000 fd:04 136811                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/escape_utils-1.1.1/lib/escape_utils/escape_utils.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         4 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f025cb000-7f5f025ce000 r-xp 00000000 fd:04 533126                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/big5.so\nSize:                 12 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  12 kB\nPss:                  "..., 8192) = 3617 <0.000038>
823   00:09:57.417479 read(26</proc/823/smaps>, "7f5f027cf000-7f5f027d1000 r-xp 00000000 fd:04 533131                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/euc_kr.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   1 kB\nShared_Clean:          8 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            8 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f027d1000-7f5f029d0000 ---p 00002000 fd:04 533131                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/euc_kr.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nSh"..., 8192) = 3588 <0.000038>
823   00:09:57.417601 read(26</proc/823/smaps>, "7f5f029d4000-7f5f02bd3000 ---p 00002000 fd:04 533133                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/gb18030.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f02bd3000-7f5f02bd4000 r--p 00001000 fd:04 533133                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/gb18030.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared"..., 8192) = 3592 <0.000037>
823   00:09:57.417717 read(26</proc/823/smaps>, "7f5f02dd6000-7f5f02dd7000 r--p 00001000 fd:04 533150                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_9.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f02dd7000-7f5f02dd8000 rw-p 00002000 fd:04 533150                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_9.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:         "..., 8192) = 3595 <0.000037>
823   00:09:57.417830 read(26</proc/823/smaps>, "7f5f02fda000-7f5f02fdb000 rw-p 00002000 fd:04 533151                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/koi8_r.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f02fdb000-7f5f02fdd000 r-xp 00000000 fd:04 533180                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1251.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   1 kB\nShared_Clean:        "..., 8192) = 3614 <0.000037>
823   00:09:57.417943 read(26</proc/823/smaps>, "7f5f031de000-7f5f031e0000 r-xp 00000000 fd:04 533148                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_7.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   1 kB\nShared_Clean:          8 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            8 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f031e0000-7f5f033df000 ---p 00002000 fd:04 533148                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_7.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:         "..., 8192) = 3607 <0.000037>
823   00:09:57.418056 read(26</proc/823/smaps>, "7f5f033e2000-7f5f035e2000 ---p 00001000 fd:04 533147                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_6.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f035e2000-7f5f035e3000 r--p 00001000 fd:04 533147                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_6.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\n"..., 8192) = 3601 <0.000037>
823   00:09:57.418167 read(26</proc/823/smaps>, "7f5f037e5000-7f5f037e6000 r--p 00001000 fd:04 533146                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_5.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f037e6000-7f5f037e7000 rw-p 00002000 fd:04 533146                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_5.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:         "..., 8192) = 3607 <0.000036>
823   00:09:57.418279 read(26</proc/823/smaps>, "7f5f039e9000-7f5f039ea000 rw-p 00002000 fd:04 533143                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_2.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f039ea000-7f5f039ec000 r-xp 00000000 fd:04 533136                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_1.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   1 kB\nShared_Clean:      "..., 8192) = 3610 <0.000038>
823   00:09:57.418395 read(26</proc/823/smaps>, "7f5f03bed000-7f5f03bee000 r-xp 00000000 fd:04 533149                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_8.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f03bee000-7f5f03dee000 ---p 00001000 fd:04 533149                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/iso_8859_8.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:         "..., 8192) = 3609 <0.000036>
823   00:09:57.418514 read(26</proc/823/smaps>, "7f5f03df2000-7f5f03ff1000 ---p 00002000 fd:04 533183                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1254.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f03ff1000-7f5f03ff2000 r--p 00001000 fd:04 533183                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1254.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0"..., 8192) = 3611 <0.000036>
823   00:09:57.418626 read(26</proc/823/smaps>, "7f5f041f4000-7f5f041f5000 r--p 00001000 fd:04 533182                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1253.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f041f5000-7f5f041f6000 rw-p 00002000 fd:04 533182                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1253.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:     "..., 8192) = 3617 <0.000036>
823   00:09:57.418736 read(26</proc/823/smaps>, "7f5f043f8000-7f5f043f9000 rw-p 00002000 fd:04 533181                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1252.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f043f9000-7f5f043fb000 r-xp 00000000 fd:04 533179                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_1250.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   1 kB\nShared_Clean:  "..., 8192) = 3620 <0.000037>
823   00:09:57.418851 read(26</proc/823/smaps>, "7f5f045fc000-7f5f045fd000 r--p 00000000 fd:04 530505                     /opt/gitlab/embedded/lib/libicudata.so.57.1\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me \n7f5f045fd000-7f5f047fc000 ---p 00001000 fd:04 530505                     /opt/gitlab/embedded/lib/libicudata.so.57.1\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean: "..., 8192) = 3484 <0.000040>
823   00:09:57.418971 read(26</proc/823/smaps>, "7f5f04b6f000-7f5f04b79000 r--p 00172000 fd:04 394980                     /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21\nSize:                 40 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  40 kB\nPss:                  10 kB\nShared_Clean:          0 kB\nShared_Dirty:         40 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:            40 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f04b79000-7f5f04b7b000 rw-p 0017c000 fd:04 394980                     /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   2 kB\nShared_Clean:          0 kB\nShared_Dirty:          8 kB\nPrivate_"..., 8192) = 3431 <0.000042>
823   00:09:57.419091 read(26</proc/823/smaps>, "7f5f04feb000-7f5f04ff8000 r--p 0026c000 fd:04 530508                     /opt/gitlab/embedded/lib/libicui18n.so.57.1\nSize:                 52 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  52 kB\nPss:                  13 kB\nShared_Clean:          0 kB\nShared_Dirty:         52 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:            52 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f04ff8000-7f5f04ffa000 rw-p 00279000 fd:04 530508                     /opt/gitlab/embedded/lib/libicui18n.so.57.1\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   2 kB\nShared_Clean:          0 kB\nShared_Dirty:          8 kB\nPrivate_Clea"..., 8192) = 3423 <0.000041>
823   00:09:57.419209 read(26</proc/823/smaps>, "7f5f0538f000-7f5f053a1000 r--p 00194000 fd:04 530526                     /opt/gitlab/embedded/lib/libicuuc.so.57.1\nSize:                 72 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  72 kB\nPss:                  18 kB\nShared_Clean:          0 kB\nShared_Dirty:         72 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:            72 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f053a1000-7f5f053a2000 rw-p 001a6000 fd:04 530526                     /opt/gitlab/embedded/lib/libicuuc.so.57.1\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:  "..., 8192) = 3549 <0.000038>
823   00:09:57.419328 read(26</proc/823/smaps>, "7f5f055a8000-7f5f055a9000 r--p 00004000 fd:04 3895                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/charlock_holmes-0.7.6/lib/charlock_holmes/charlock_holmes.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f055a9000-7f5f055aa000 rw-p 00005000 fd:04 3895                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/charlock_holmes-0.7.6/lib/charlock_holmes/charlock_holmes.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 k"..., 8192) = 3684 <0.000037>
823   00:09:57.419443 read(26</proc/823/smaps>, "7f5f057ad000-7f5f057ae000 rw-p 00003000 fd:04 533153                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/shift_jis.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f057ae000-7f5f057f6000 r-xp 00000000 fd:04 533201                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/nkf.so\nSize:                288 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  64 kB\nPss:                  12 kB\nShared_Clean:         64 kB\nSha"..., 8192) = 3565 <0.000038>
823   00:09:57.419572 read(26</proc/823/smaps>, "7f5f059fd000-7f5f05a00000 rw-p 00000000 00:00 0 \nSize:                 12 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f05a00000-7f5f05c00000 rw-p 00000000 00:00 0 \nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                1964 kB\nPss:                1119 kB\nShared_Clean:          0 kB\nShared_Dirty:       1128 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       836 kB\nReferenced:         1508 kB\nAnonymous:          1964 kB\nLazyFree:              0 kB\nAnonH"..., 8192) = 4077 <0.000069>
823   00:09:57.419741 read(26</proc/823/smaps>, "7f5f05f98000-7f5f05faa000 r-xp 00000000 fd:04 530441                     /opt/gitlab/embedded/lib/libassuan.so.0.7.4\nSize:                 72 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  64 kB\nPss:                  12 kB\nShared_Clean:         64 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           64 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f05faa000-7f5f061a9000 ---p 00012000 fd:04 530441                     /opt/gitlab/embedded/lib/libassuan.so.0.7.4\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clea"..., 8192) = 3493 <0.000038>
823   00:09:57.419855 read(26</proc/823/smaps>, "7f5f061ef000-7f5f063ee000 ---p 00044000 fd:04 530493                     /opt/gitlab/embedded/lib/libgpgme.so.11.18.0\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f063ee000-7f5f063ef000 r--p 00043000 fd:04 530493                     /opt/gitlab/embedded/lib/libgpgme.so.11.18.0\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:  "..., 8192) = 3549 <0.000038>
823   00:09:57.419969 read(26</proc/823/smaps>, "7f5f065fe000-7f5f065ff000 r--p 0000d000 fd:04 273341                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/gpgme-2.0.13/lib/gpgme_n.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f065ff000-7f5f06600000 rw-p 0000e000 fd:04 273341                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/gpgme-2.0.13/lib/gpgme_n.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_C"..., 8192) = 3483 <0.000367>
823   00:09:57.420417 read(26</proc/823/smaps>, "7f5f07ece000-7f5f07ed0000 r--p 0006e000 fd:04 530449                     /opt/gitlab/embedded/lib/libcurl.so.4.5.0\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   2 kB\nShared_Clean:          0 kB\nShared_Dirty:          8 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             8 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f07ed0000-7f5f07ed1000 rw-p 00070000 fd:04 530449                     /opt/gitlab/embedded/lib/libcurl.so.4.5.0\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:  "..., 8192) = 3599 <0.000040>
823   00:09:57.420539 read(26</proc/823/smaps>, "7f5f081f8000-7f5f081ff000 rw-p 00127000 fd:04 7148                       /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/rugged-0.27.4/lib/rugged/rugged.so\nSize:                 28 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  28 kB\nPss:                   6 kB\nShared_Clean:          8 kB\nShared_Dirty:         20 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           12 kB\nAnonymous:            20 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f081ff000-7f5f08200000 rw-p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirt"..., 8192) = 3439 <0.000104>
823   00:09:57.420719 read(26</proc/823/smaps>, "7f5f089fe000-7f5f089ff000 r--p 00003000 fd:04 533208                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/racc/cparse.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f089ff000-7f5f08a00000 rw-p 00004000 fd:04 533208                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/racc/cparse.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\n"..., 8192) = 3465 <0.000094>
823   00:09:57.420887 read(26</proc/823/smaps>, "7f5f09200000-7f5f09202000 r--p 000e2000 fd:04 530502                     /opt/gitlab/embedded/lib/libiconv.so.2.6.0\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   2 kB\nShared_Clean:          0 kB\nShared_Dirty:          8 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             8 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f09202000-7f5f09203000 rw-p 000e4000 fd:04 530502                     /opt/gitlab/embedded/lib/libiconv.so.2.6.0\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:"..., 8192) = 3484 <0.000037>
823   00:09:57.421004 read(26</proc/823/smaps>, "7f5f09428000-7f5f09429000 rw-p 00025000 fd:04 530560                     /opt/gitlab/embedded/lib/liblzma.so.5.2.2\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f09429000-7f5f09586000 r-xp 00000000 fd:04 530632                     /opt/gitlab/embedded/lib/libxml2.so.2.9.8\nSize:               1396 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 904 kB\nPss:                 160 kB\nShared_Clean:        904 kB\nShared_Dirty:          0 kB\nPrivate_Clean"..., 8192) = 3485 <0.000050>
823   00:09:57.421141 read(26</proc/823/smaps>, "7f5f09790000-7f5f09791000 rw-p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         4 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f09791000-7f5f097cf000 r-xp 00000000 fd:04 530635                     /opt/gitlab/embedded/lib/libxslt.so.1.1.32\nSize:                248 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  64 kB\nPss:                   9 kB\nShared_Clean:         64 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           "..., 8192) = 4057 <0.000039>
823   00:09:57.421268 read(26</proc/823/smaps>, "7f5f099d1000-7f5f099e4000 r-xp 00000000 fd:04 530471                     /opt/gitlab/embedded/lib/libexslt.so.0.8.20\nSize:                 76 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  64 kB\nPss:                   9 kB\nShared_Clean:         64 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           64 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f099e4000-7f5f09be3000 ---p 00013000 fd:04 530471                     /opt/gitlab/embedded/lib/libexslt.so.0.8.20\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clea"..., 8192) = 3534 <0.000039>
823   00:09:57.421387 read(26</proc/823/smaps>, "7f5f09bff000-7f5f09dfe000 ---p 0001a000 fd:04 405395                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/nokogiri-1.8.4/lib/nokogiri/nokogiri.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f09dfe000-7f5f09dff000 r--p 00019000 fd:04 405395                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/nokogiri-1.8.4/lib/nokogiri/nokogiri.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:              "..., 8192) = 3566 <0.000095>
823   00:09:57.421563 read(26</proc/823/smaps>, "7f5f0a3f7000-7f5f0a5f7000 ---p 00011000 fd:04 533218                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/zlib.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f0a5f7000-7f5f0a5f8000 r--p 00011000 fd:04 533218                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/zlib.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:       "..., 8192) = 3565 <0.000037>
823   00:09:57.421679 read(26</proc/823/smaps>, "7f5f0a7fa000-7f5f0a7fb000 r--p 00001000 fd:04 533124                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/digest/sha2.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0a7fb000-7f5f0a7fc000 rw-p 00002000 fd:04 533124                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/digest/sha2.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\n"..., 8192) = 3592 <0.000037>
823   00:09:57.421793 read(26</proc/823/smaps>, "7f5f0a9fd000-7f5f0a9fe000 rw-p 00001000 fd:04 533123                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/digest/sha1.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f0a9fe000-7f5f0a9ff000 r-xp 00000000 fd:04 533121                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/digest/md5.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 k"..., 8192) = 3591 <0.000101>
823   00:09:57.421969 read(26</proc/823/smaps>, "7f5f0ac00000-7f5f0b000000 rw-p 00000000 00:00 0 \nSize:               4096 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                4096 kB\nPss:                1800 kB\nShared_Clean:          0 kB\nShared_Dirty:       3080 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:      1016 kB\nReferenced:         3244 kB\nAnonymous:          4096 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f0b1e2000-7f5f0b1ec000 r-xp 00000000 fd:04 402251                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/json-1.8.6/lib/json/ext/generator.so\nSize:                 40 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  40 kB\nPss:                   7 kB\nShared_Clean:         40 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Di"..., 8192) = 3583 <0.000061>
823   00:09:57.422117 read(26</proc/823/smaps>, "7f5f0b3ed000-7f5f0b3ee000 r-xp 00000000 fd:04 533178                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_32le.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   0 kB\nShared_Clean:          4 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f0b3ee000-7f5f0b5ee000 ---p 00001000 fd:04 533178                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_32le.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 k"..., 8192) = 3597 <0.000037>
823   00:09:57.422231 read(26</proc/823/smaps>, "7f5f0b5f1000-7f5f0b7f1000 ---p 00001000 fd:04 533177                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_32be.so\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f0b7f1000-7f5f0b7f2000 r--p 00001000 fd:04 533177                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_32be.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShar"..., 8192) = 3591 <0.000036>
823   00:09:57.422343 read(26</proc/823/smaps>, "7f5f0b9f4000-7f5f0b9f5000 r--p 00001000 fd:04 533176                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_16le.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0b9f5000-7f5f0b9f6000 rw-p 00002000 fd:04 533176                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_16le.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 k"..., 8192) = 3597 <0.000036>
823   00:09:57.422459 read(26</proc/823/smaps>, "7f5f0bbf8000-7f5f0bbf9000 rw-p 00002000 fd:04 533175                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/utf_16be.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f0bbf9000-7f5f0bbff000 r-xp 00000000 fd:04 402252                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/json-1.8.6/lib/json/ext/parser.so\nSize:                 24 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  24 kB\nPss:                   4 kB\nShared_C"..., 8192) = 3660 <0.000096>
823   00:09:57.422630 read(26</proc/823/smaps>, "7f5f0be00000-7f5f0c200000 rw-p 00000000 00:00 0 \nSize:               4096 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                3800 kB\nPss:                2071 kB\nShared_Clean:          0 kB\nShared_Dirty:       2320 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:      1480 kB\nReferenced:         3408 kB\nAnonymous:          3800 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f0c3cf000-7f5f0c3d5000 r-xp 00000000 fd:04 533216                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/strscan.so\nSize:                 24 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  24 kB\nPss:                   2 kB\nShared_Clean:         24 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nRefer"..., 8192) = 3491 <0.000059>
823   00:09:57.422766 read(26</proc/823/smaps>, "7f5f0c5d6000-7f5f0c5f4000 r-xp 00000000 fd:04 530637                     /opt/gitlab/embedded/lib/libyaml-0.so.2.0.5\nSize:                120 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 120 kB\nPss:                  14 kB\nShared_Clean:        120 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:          120 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f0c5f4000-7f5f0c7f3000 ---p 0001e000 fd:04 530637                     /opt/gitlab/embedded/lib/libyaml-0.so.2.0.5\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clea"..., 8192) = 3506 <0.000039>
823   00:09:57.422879 read(26</proc/823/smaps>, "7f5f0c7fb000-7f5f0c9fa000 ---p 00006000 fd:04 533205                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/psych.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f0c9fa000-7f5f0c9fb000 r--p 00005000 fd:04 533205                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/psych.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:     "..., 8192) = 3640 <0.000038>
823   00:09:57.422995 read(26</proc/823/smaps>, "7f5f0cbfe000-7f5f0cbff000 r--p 00002000 fd:04 133005                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/concurrent-ruby-ext-1.0.5/lib/concurrent/extension.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0cbff000-7f5f0cc00000 rw-p 00003000 fd:04 133005                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/concurrent-ruby-ext-1.0.5/lib/concurrent/extension.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:        "..., 8192) = 3579 <0.000067>
823   00:09:57.423140 read(26</proc/823/smaps>, "7f5f0d09b000-7f5f0d09c000 r--p 00001000 fd:04 533192                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/io/nonblock.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0d09c000-7f5f0d09d000 rw-p 00002000 fd:04 533192                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/io/nonblock.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\n"..., 8192) = 3577 <0.000037>
823   00:09:57.423257 read(26</proc/823/smaps>, "7f5f0d2a1000-7f5f0d2a2000 rw-p 00004000 fd:04 533119                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/digest.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         4 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f0d2a2000-7f5f0d2b8000 r-xp 00000000 fd:04 530641                     /opt/gitlab/embedded/lib/libz.so.1.2.11\nSize:                 88 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  88 kB\nPss:                   9 kB\nShared_Clean:         88 kB\nShared_Dirty:          0 k"..., 8192) = 3494 <0.000066>
823   00:09:57.423401 read(26</proc/823/smaps>, "7f5f0d4b9000-7f5f0d6e9000 r-xp 00000000 fd:04 530446                     /opt/gitlab/embedded/lib/libcrypto.so.1.0.0\nSize:               2240 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                1732 kB\nPss:                 193 kB\nShared_Clean:       1732 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:         1732 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f0d6e9000-7f5f0d8e9000 ---p 00230000 fd:04 530446                     /opt/gitlab/embedded/lib/libcrypto.so.1.0.0\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clea"..., 8192) = 3427 <0.000053>
823   00:09:57.423536 read(26</proc/823/smaps>, "7f5f0d913000-7f5f0d97c000 r-xp 00000000 fd:04 530617                     /opt/gitlab/embedded/lib/libssl.so.1.0.0\nSize:                420 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 372 kB\nPss:                  39 kB\nShared_Clean:        372 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:          372 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f0d97c000-7f5f0db7b000 ---p 00069000 fd:04 530617                     /opt/gitlab/embedded/lib/libssl.so.1.0.0\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:    "..., 8192) = 3496 <0.000061>
823   00:09:57.423685 read(26</proc/823/smaps>, "7f5f0dbde000-7f5f0dddd000 ---p 00058000 fd:04 533203                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/openssl.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f0dddd000-7f5f0dddf000 r--p 00057000 fd:04 533203                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/openssl.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   2 kB\nShared_Clean:          0 kB\nShared_Dirty: "..., 8192) = 3494 <0.000038>
823   00:09:57.423801 read(26</proc/823/smaps>, "7f5f0ddf6000-7f5f0dff5000 ---p 00014000 fd:04 533112                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/bigdecimal.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f0dff5000-7f5f0dff6000 r--p 00013000 fd:04 533112                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/bigdecimal.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_D"..., 8192) = 3623 <0.000039>
823   00:09:57.423920 read(26</proc/823/smaps>, "7f5f0e1fc000-7f5f0e1fd000 r--p 00005000 fd:04 537818                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/raindrops-0.18.0/lib/raindrops_ext.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0e1fd000-7f5f0e1fe000 rw-p 00006000 fd:04 537818                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/raindrops-0.18.0/lib/raindrops_ext.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:            "..., 8192) = 3614 <0.000037>
823   00:09:57.424033 read(26</proc/823/smaps>, "7f5f0e3ff000-7f5f0e400000 rw-p 00001000 fd:04 533187                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/fcntl.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f0e400000-7f5f0e600000 rw-p 00000000 00:00 0 \nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                2040 kB\nPss:                 726 kB\nShared_Clean:          0 kB\nShared_Dirty:       1752 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       288 kB\nReferen"..., 8192) = 3549 <0.000071>
823   00:09:57.424184 read(26</proc/823/smaps>, "7f5f0e986000-7f5f0e987000 rw-p 0000b000 fd:04 12393                      /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/unicorn-5.1.0/lib/unicorn_http.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         4 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f0e987000-7f5f0e9ba000 r-xp 00000000 fd:04 533117                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/date_core.so\nSize:                204 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 204 kB\nPss:                  23 kB\nShared_Clea"..., 8192) = 3603 <0.000039>
823   00:09:57.424299 read(26</proc/823/smaps>, "7f5f0ebbb000-7f5f0ebbc000 rw-p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f0ebbc000-7f5f0ebc3000 r-xp 00000000 fd:04 394166                     /lib/x86_64-linux-gnu/librt-2.23.so\nSize:                 28 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  28 kB\nPss:                   3 kB\nShared_Clean:         28 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           28 kB\nA"..., 8192) = 3395 <0.000038>
823   00:09:57.424417 read(26</proc/823/smaps>, "7f5f0edc4000-7f5f0edcf000 r-xp 00000000 fd:04 402765                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/kgio-2.10.0/lib/kgio_ext.so\nSize:                 44 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  44 kB\nPss:                  11 kB\nShared_Clean:         44 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           44 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f0edcf000-7f5f0efce000 ---p 0000b000 fd:04 402765                     /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/kgio-2.10.0/lib/kgio_ext.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_C"..., 8192) = 3628 <0.000038>
823   00:09:57.424530 read(26</proc/823/smaps>, "7f5f0efd2000-7f5f0f1d1000 ---p 00002000 fd:04 533193                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/io/wait.so\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me \n7f5f0f1d1000-7f5f0f1d2000 r--p 00001000 fd:04 533193                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/io/wait.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty: "..., 8192) = 3564 <0.000040>
823   00:09:57.424649 read(26</proc/823/smaps>, "7f5f0f3fe000-7f5f0f3ff000 r--p 0002b000 fd:04 533214                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/socket.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0f3ff000-7f5f0f400000 rw-p 0002c000 fd:04 533214                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/socket.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dir"..., 8192) = 3505 <0.000155>
823   00:09:57.424885 read(26</proc/823/smaps>, "7f5f0fff6000-7f5f0fff7000 r--p 00002000 fd:04 533185                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_31j.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f0fff7000-7f5f0fff8000 rw-p 00003000 fd:04 533185                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/windows_31j.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:       "..., 8192) = 3597 <0.000038>
823   00:09:57.425003 read(26</proc/823/smaps>, "7f5f101fb000-7f5f101fc000 rw-p 00003000 fd:04 533130                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/euc_jp.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f101fc000-7f5f101ff000 r-xp 00000000 fd:04 533114                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/cgi/escape.so\nSize:                 12 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  12 kB\nPss:                   1 kB\nShared_Clean:         12 kB"..., 8192) = 3590 <0.000067>
823   00:09:57.425153 read(26</proc/823/smaps>, "7f5f10400000-7f5f10600000 rw-p 00000000 00:00 0 \nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                1880 kB\nPss:                 693 kB\nShared_Clean:          0 kB\nShared_Dirty:       1584 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       296 kB\nReferenced:         1416 kB\nAnonymous:          1880 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f107f7000-7f5f107ff000 r-xp 00000000 fd:04 533204                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/pathname.so\nSize:                 32 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  32 kB\nPss:                   4 kB\nShared_Clean:         32 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nRefe"..., 8192) = 3495 <0.000101>
823   00:09:57.425330 read(26</proc/823/smaps>, "7f5f10a00000-7f5f10c00000 rw-p 00000000 00:00 0 \nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                1900 kB\nPss:                 812 kB\nShared_Clean:          0 kB\nShared_Dirty:       1452 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       448 kB\nReferenced:         1400 kB\nAnonymous:          1900 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f10df9000-7f5f10dff000 r-xp 00000000 fd:04 533186                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/etc.so\nSize:                 24 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  24 kB\nPss:                   2 kB\nShared_Clean:         24 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReference"..., 8192) = 3475 <0.000080>
823   00:09:57.425506 read(26</proc/823/smaps>, "7f5f11000000-7f5f11200000 rw-p 00000000 00:00 0 \nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                2036 kB\nPss:                 728 kB\nShared_Clean:          0 kB\nShared_Dirty:       1744 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       292 kB\nReferenced:         1504 kB\nAnonymous:          2036 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f113f6000-7f5f113fe000 r-xp 00000000 fd:04 533215                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/stringio.so\nSize:                 32 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  32 kB\nPss:                   3 kB\nShared_Clean:         32 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nRefe"..., 8192) = 3495 <0.000080>
823   00:09:57.425667 read(26</proc/823/smaps>, "7f5f11600000-7f5f11800000 rw-p 00000000 00:00 0 \nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                1904 kB\nPss:                 677 kB\nShared_Clean:          0 kB\nShared_Dirty:       1636 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       268 kB\nReferenced:         1500 kB\nAnonymous:          1904 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f118f8000-7f5f118f9000 ---p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonH"..., 8192) = 4065 <0.000050>
823   00:09:57.425804 read(26</proc/823/smaps>, "7f5f11bfc000-7f5f11bfd000 rw-p 00003000 fd:04 533172                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/trans/transdb.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f11bfd000-7f5f11bff000 r-xp 00000000 fd:04 533129                     /opt/gitlab/embedded/lib/ruby/2.4.0/x86_64-linux/enc/encdb.so\nSize:                  8 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   8 kB\nPss:                   0 kB\nShared_Clean:        "..., 8192) = 3593 <0.000088>
823   00:09:57.425969 read(26</proc/823/smaps>, "7f5f11e00000-7f5f12400000 rw-p 00000000 00:00 0 \nSize:               6144 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                3032 kB\nPss:                1339 kB\nShared_Clean:          0 kB\nShared_Dirty:       2260 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:       772 kB\nReferenced:         2328 kB\nAnonymous:          3032 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me nr \n7f5f1247f000-7f5f12480000 ---p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonH"..., 8192) = 3972 <0.000058>
823   00:09:57.426116 read(26</proc/823/smaps>, "7f5f12789000-7f5f1278a000 rw-p 00009000 fd:04 394100                     /lib/x86_64-linux-gnu/libcrypt-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f1278a000-7f5f127b8000 rw-p 00000000 00:00 0 \nSize:                184 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 k"..., 8192) = 4092 <0.000039>
823   00:09:57.426247 read(26</proc/823/smaps>, "7f5f129bc000-7f5f129d2000 r-xp 00000000 fd:04 394113                     /lib/x86_64-linux-gnu/libgcc_s.so.1\nSize:                 88 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  60 kB\nPss:                   8 kB\nShared_Clean:         60 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:           60 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f129d2000-7f5f12bd1000 ---p 00016000 fd:04 394113                     /lib/x86_64-linux-gnu/libgcc_s.so.1\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\n"..., 8192) = 3456 <0.000039>
823   00:09:57.426373 read(26</proc/823/smaps>, "7f5f12de9000-7f5f12dea000 r--p 00017000 fd:04 394160                     /lib/x86_64-linux-gnu/libpthread-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me ac \n7f5f12dea000-7f5f12deb000 rw-p 00018000 fd:04 394160                     /lib/x86_64-linux-gnu/libpthread-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:    "..., 8192) = 4093 <0.000044>
823   00:09:57.426507 read(26</proc/823/smaps>, "7f5f130f7000-7f5f130f8000 rw-p 00108000 fd:04 394124                     /lib/x86_64-linux-gnu/libm-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd wr mr mw me ac \n7f5f130f8000-7f5f132b8000 r-xp 00000000 fd:04 394092                     /lib/x86_64-linux-gnu/libc-2.23.so\nSize:               1792 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                1492 kB\nPss:                  43 kB\nShared_Clean:       1492 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB"..., 8192) = 4084 <0.000104>
823   00:09:57.426696 read(26</proc/823/smaps>, "7f5f134c2000-7f5f137b4000 r-xp 00000000 fd:04 530615                     /opt/gitlab/embedded/lib/libruby.so.2.4.4\nSize:               3016 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                2544 kB\nPss:                 284 kB\nShared_Clean:       2544 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:         2544 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f137b4000-7f5f139b3000 ---p 002f2000 fd:04 530615                     /opt/gitlab/embedded/lib/libruby.so.2.4.4\nSize:               2044 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:  "..., 8192) = 3419 <0.000055>
823   00:09:57.426853 read(26</proc/823/smaps>, "7f5f139cc000-7f5f13a19000 r-xp 00000000 fd:04 530528                     /opt/gitlab/embedded/lib/libjemalloc.so.2\nSize:                308 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 268 kB\nPss:                  53 kB\nShared_Clean:        268 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:          268 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me \n7f5f13a19000-7f5f13c19000 ---p 0004d000 fd:04 530528                     /opt/gitlab/embedded/lib/libjemalloc.so.2\nSize:               2048 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:  "..., 8192) = 3419 <0.000044>
823   00:09:57.426977 read(26</proc/823/smaps>, "7f5f13c2e000-7f5f13c54000 r-xp 00000000 fd:04 394072                     /lib/x86_64-linux-gnu/ld-2.23.so\nSize:                152 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                 152 kB\nPss:                   2 kB\nShared_Clean:        152 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:          152 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex mr mw me dw \n7f5f13d31000-7f5f13d41000 rw-s 00000000 00:28 3578817                    /dev/shm/gitlab/unicorn/histogram_worker_id_2-0.db\nSize:                 64 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  48 kB\nPss:                  48 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean"..., 8192) = 4056 <0.000045>
823   00:09:57.427114 read(26</proc/823/smaps>, "7f5f13e46000-7f5f13e47000 ---p 00000000 00:00 0 \nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: mr mw me ac \n7f5f13e47000-7f5f13e4f000 rw-p 00000000 00:00 0 \nSize:                 32 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                  28 kB\nPss:                  25 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:        24 kB\nReferenced:           28 kB\nAnonymous:            28 kB\nLazyFree:              0 kB\nAnonHugePag"..., 8192) = 3946 <0.000040>
823   00:09:57.427252 read(26</proc/823/smaps>, "7f5f13e53000-7f5f13e54000 r--p 00025000 fd:04 394072                     /lib/x86_64-linux-gnu/ld-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   1 kB\nShared_Clean:          0 kB\nShared_Dirty:          4 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            4 kB\nAnonymous:             4 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd mr mw me dw ac \n7f5f13e54000-7f5f13e55000 rw-p 00026000 fd:04 394072                     /lib/x86_64-linux-gnu/ld-2.23.so\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   4 kB\nPss:                   4 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPri"..., 8192) = 4018 <0.000042>
823   00:09:57.427388 read(26</proc/823/smaps>, "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]\nSize:                  4 kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\nRss:                   0 kB\nPss:                   0 kB\nShared_Clean:          0 kB\nShared_Dirty:          0 kB\nPrivate_Clean:         0 kB\nPrivate_Dirty:         0 kB\nReferenced:            0 kB\nAnonymous:             0 kB\nLazyFree:              0 kB\nAnonHugePages:         0 kB\nShmemPmdMapped:        0 kB\nShared_Hugetlb:        0 kB\nPrivate_Hugetlb:       0 kB\nSwap:                  0 kB\nSwapPss:               0 kB\nLocked:                0 kB\nProtectionKey:         0\nVmFlags: rd ex \n", 8192) = 657 <0.000018>
823   00:09:57.427442 read(26</proc/823/smaps>, "", 8192) = 0 <0.000013>
823   00:09:57.427480 close(26</proc/823/smaps>) = 0 <0.000014>
823   00:09:57.430609 fcntl(24<TCP:[127.0.0.1:8080]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
823   00:09:57.430833 accept4(24<TCP:[127.0.0.1:8080]>, 0x7ffc6d3d4820, 0x7ffc6d3d47ec, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:57.431035 getppid()         = 495 <0.000013>
823   00:09:57.431079 select(26, [14<pipe:[3579145]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
7419  00:09:57.958177 <... nanosleep resumed> NULL) = 0 <1.000093>
7419  00:09:57.958388 close(1<pipe:[3578440]>) = 0 <0.000038>
7419  00:09:57.959345 close(2<pipe:[3578440]>) = 0 <0.000015>
7419  00:09:57.959394 exit_group(0)     = ?
7419  00:09:57.959506 +++ exited with 0 +++
477   00:09:57.959534 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7419 <1.003478>
477   00:09:57.959582 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000015>
477   00:09:57.959640 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000015>
477   00:09:57.959679 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=7419, si_uid=998, si_status=0, si_utime=0, si_stime=0} ---
477   00:09:57.959706 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000014>
477   00:09:57.959744 rt_sigreturn({mask=[]}) = 0 <0.000015>
477   00:09:57.959783 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000015>
477   00:09:57.959821 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000014>
477   00:09:57.959904 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000024>
477   00:09:57.959959 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000010>
477   00:09:57.959994 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000028>
477   00:09:57.960062 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000015>
477   00:09:57.960107 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000015>
477   00:09:57.960153 dup2(3</dev/null>, 1<pipe:[3578440]>) = 1</dev/null> <0.000016>
477   00:09:57.960200 close(3</dev/null>) = 0 <0.000015>
477   00:09:57.960241 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000015>
477   00:09:57.960282 fcntl(2<pipe:[3578440]>, F_DUPFD, 10) = 11<pipe:[3578440]> <0.000016>
477   00:09:57.960326 fcntl(2<pipe:[3578440]>, F_GETFD) = 0 <0.000016>
477   00:09:57.960367 fcntl(11<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.000015>
477   00:09:57.960408 dup2(1</dev/null>, 2<pipe:[3578440]>) = 2</dev/null> <0.000016>
477   00:09:57.960453 fcntl(1</dev/null>, F_GETFD) = 0 <0.000016>
477   00:09:57.960496 kill(495, SIG_0)  = 0 <0.000017>
477   00:09:57.960537 dup2(11<pipe:[3578440]>, 2</dev/null>) = 2<pipe:[3578440]> <0.000015>
477   00:09:57.960582 fcntl(11<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000015>
477   00:09:57.960624 close(11<pipe:[3578440]>) = 0 <0.000015>
477   00:09:57.960665 dup2(10<pipe:[3578440]>, 1</dev/null>) = 1<pipe:[3578440]> <0.000016>
477   00:09:57.960708 fcntl(10<pipe:[3578440]>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000013>
477   00:09:57.960742 close(10<pipe:[3578440]>) = 0 <0.000013>
477   00:09:57.960798 rt_sigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0 <0.000013>
477   00:09:57.960834 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7420 <0.000137>
477   00:09:57.961048 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7420  00:09:57.961254 close(255</opt/gitlab/embedded/bin/gitlab-unicorn-wrapper> <unfinished ...>
477   00:09:57.961288 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000043>
7420  00:09:57.961300 <... close resumed> ) = 0 <0.000020>
477   00:09:57.961356 rt_sigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
7420  00:09:57.961372 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
477   00:09:57.961385 <... rt_sigprocmask resumed> [], 8) = 0 <0.000019>
477   00:09:57.961414 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
7420  00:09:57.961427 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000048>
477   00:09:57.961439 <... rt_sigprocmask resumed> NULL, 8) = 0 <0.000018>
7420  00:09:57.961450 rt_sigaction(SIGTSTP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:57.961467 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0 <0.000014>
7420  00:09:57.961497 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000039>
477   00:09:57.961517 rt_sigaction(SIGINT, {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7420  00:09:57.961530 rt_sigaction(SIGTTIN, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:57.961543 <... rt_sigaction resumed> {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000019>
7420  00:09:57.961556 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000020>
477   00:09:57.961570 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
7420  00:09:57.961583 rt_sigaction(SIGTTOU, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0},  <unfinished ...>
477   00:09:57.961597 <... rt_sigaction resumed> {0x4449b0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000020>
7420  00:09:57.961609 <... rt_sigaction resumed> {SIG_DFL, [], 0}, 8) = 0 <0.000020>
477   00:09:57.961622 wait4(-1,  <unfinished ...>
7420  00:09:57.961654 rt_sigaction(SIGHUP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7420  00:09:57.961692 rt_sigaction(SIGINT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7420  00:09:57.961732 rt_sigaction(SIGQUIT, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, {SIG_IGN, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7420  00:09:57.961767 rt_sigaction(SIGUSR1, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7420  00:09:57.961815 rt_sigaction(SIGUSR2, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7420  00:09:57.961852 rt_sigaction(SIGALRM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7420  00:09:57.961897 rt_sigaction(SIGTERM, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7420  00:09:57.961935 rt_sigaction(SIGCHLD, {SIG_DFL, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, {0x447ad0, [], SA_RESTORER|SA_RESTART, 0x7fe563ec54b0}, 8) = 0 <0.000012>
7420  00:09:57.961975 rt_sigaction(SIGCONT, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, {0x45c8f0, [], SA_RESTORER, 0x7fe563ec54b0}, 8) = 0 <0.000013>
7420  00:09:57.962010 rt_sigaction(SIGSTOP, {SIG_DFL, [], SA_RESTORER, 0x7fe563ec54b0}, 0x7ffe09dbba40, 8) = -1 EINVAL (Invalid argument) <0.000012>
7420  00:09:57.962090 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000165>
7420  00:09:57.962318 brk(NULL)         = 0x1c5a000 <0.000012>
7420  00:09:57.962376 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000015>
7420  00:09:57.962421 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory) <0.000023>
7420  00:09:57.962471 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000014>
7420  00:09:57.962513 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=10600, ...}) = 0 <0.000022>
7420  00:09:57.962561 mmap(NULL, 10600, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7fcb7ae6e000 <0.000013>
7420  00:09:57.962598 close(3</etc/ld.so.cache>) = 0 <0.000022>
7420  00:09:57.962644 access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory) <0.000013>
7420  00:09:57.962679 open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/x86_64-linux-gnu/libc-2.23.so> <0.000021>
7420  00:09:57.962724 read(3</lib/x86_64-linux-gnu/libc-2.23.so>, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0@\0\0\0\0\0\0\0\270r\34\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0H\0G\0\6\0\0\0\5\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0`f\31\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\373\33\0\0\0\0\0\20\373\33\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0`O\0\0\0\0\0\0\340\221\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\240;\34\0\0\0\0\0\240;<\0\0\0\0\0\240;<\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0\20\0\0\0\0\0\0\0x\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0|f\31\0\0\0\0\0\274T\0\0\0\0\0\0\274T\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\300\7\34\0\0\0\0\0\300\7<\0\0\0\0\0\300\7<\0\0\0\0\0@8\0\0\0\0\0\0@8\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\2658\32Ey\6\322y\0078\"\245\316\262LK\376\371M\333\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\2\0\0\0\6\0\0\0 \0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0\10\0\5\204\0`\300\200\0\r\212\f\0\4\20\0\210@2\10*@\210T<, \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\4f\300\0\3002\0\300\0P\1 \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\20\30B\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832 <0.000014>
7420  00:09:57.962787 fstat(3</lib/x86_64-linux-gnu/libc-2.23.so>, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0 <0.000011>
7420  00:09:57.962826 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fcb7ae6d000 <0.000013>
7420  00:09:57.962868 mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0) = 0x7fcb7a882000 <0.000015>
7420  00:09:57.962907 mprotect(0x7fcb7aa42000, 2097152, PROT_NONE) = 0 <0.000017>
7420  00:09:57.962954 mmap(0x7fcb7ac42000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.23.so>, 0x1c0000) = 0x7fcb7ac42000 <0.000016>
7420  00:09:57.962996 mmap(0x7fcb7ac48000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fcb7ac48000 <0.000019>
7420  00:09:57.963039 close(3</lib/x86_64-linux-gnu/libc-2.23.so>) = 0 <0.000010>
7420  00:09:57.963081 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fcb7ae6c000 <0.000023>
7420  00:09:57.963127 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fcb7ae6b000 <0.000013>
7420  00:09:57.963162 arch_prctl(ARCH_SET_FS, 0x7fcb7ae6c700) = 0 <0.000024>
7420  00:09:57.963269 mprotect(0x7fcb7ac42000, 16384, PROT_READ) = 0 <0.000015>
7420  00:09:57.963309 mprotect(0x606000, 4096, PROT_READ) = 0 <0.000013>
7420  00:09:57.963349 mprotect(0x7fcb7ae71000, 4096, PROT_READ) = 0 <0.000015>
7420  00:09:57.963385 munmap(0x7fcb7ae6e000, 10600) = 0 <0.000016>
7420  00:09:57.963512 brk(NULL)         = 0x1c5a000 <0.000013>
7420  00:09:57.963559 brk(0x1c7b000)    = 0x1c7b000 <0.000014>
7420  00:09:57.963612 nanosleep({1, 0},  <unfinished ...>
1093  00:09:57.989286 <... nanosleep resumed> NULL) = 0 <1.000080>
1093  00:09:57.989320 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000013>
1093  00:09:57.989368 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000012>
1093  00:09:57.989403 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000009>
1093  00:09:57.989434 open("/var/log/gitlab/gitlab-monitor/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-monitor/current> <0.000019>
1093  00:09:57.989478 fstat(33</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000009>
1093  00:09:57.989508 close(33</var/log/gitlab/gitlab-monitor/current>) = 0 <0.000013>
1093  00:09:57.989540 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000008>
1093  00:09:57.989570 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000008>
1093  00:09:57.989600 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000008>
1093  00:09:57.989635 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121908, ...}) = 0 <0.000008>
1093  00:09:57.989668 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "{\"method\":\"GET\",\"path\":\"/-/metrics\",\"format\":\"html\",\"controller\":\"MetricsController\",\"action\":\"index\",\"status\":404,\"duration\":3.0,\"view\":0.49,\"db\":0.0,\"time\":\"2018-09-25T00:09:57.402Z\",\"params\":[],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n", 8192) = 256 <0.000023>
1093  00:09:57.989717 read(9</var/log/gitlab/gitlab-rails/production_json.log>, "", 8192) = 0 <0.000010>
1093  00:09:57.989750 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=118283, ...}) = 0 <0.000014>
1093  00:09:57.989789 read(10</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/-/metrics\" for 127.0.0.1 at 2018-09-25 00:09:57 +0000\nProcessing by MetricsController#index as HTML\nFilter chain halted as :validate_ip_whitelisted_or_valid_token! rendered or redirected\nCompleted 404 Not Found in 1ms (Views: 0.5ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\n", 8192) = 292 <0.000015>
1093  00:09:57.989829 read(10</var/log/gitlab/gitlab-rails/production.log>, "", 8192) = 0 <0.000010>
1093  00:09:57.989861 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000010>
1093  00:09:57.989895 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:57.989930 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000009>
1093  00:09:57.989964 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:57.989998 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=101177, ...}) = 0 <0.000009>
1093  00:09:57.990033 read(15</var/log/gitlab/registry/current>, "2018-09-25_00:09:57.36496 time=\"2018-09-25T00:09:57.364915817Z\" level=debug msg=\"s3aws.Stat(\\\"/\\\")\" environment=production go.version=go1.10.3 instance.id=e8df01bb-477a-4ea2-9667-91aa4b6682d9 service=registry trace.duration=55.681353ms trace.file=\"/var/cache/omnibus/src/registry/src/github.com/docker/distribution/registry/storage/driver/base/base.go\" trace.func=\"github.com/docker/distribution/registry/storage/driver/base.(*Base).Stat\" trace.id=31b054f1-8063-4db4-8863-5f08fefcb2e6 trace.line=137 version=v2.6.2-2-g91c17ef \n", 8192) = 527 <0.000010>
1093  00:09:57.990068 read(15</var/log/gitlab/registry/current>, "", 8192) = 0 <0.000010>
1093  00:09:57.990100 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56896, ...}) = 0 <0.000010>
1093  00:09:57.990134 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000010>
1093  00:09:57.990168 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000014>
1093  00:09:57.990207 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.990241 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.990275 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42960, ...}) = 0 <0.000009>
1093  00:09:57.990309 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.990343 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.990377 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.990410 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.990444 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.990479 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.990516 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.990550 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.990585 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000009>
1093  00:09:57.990619 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:57.990652 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000009>
1093  00:09:57.990687 fstat(3</var/log/gitlab/gitaly/current>, {st_mode=S_IFREG|0644, st_size=29710, ...}) = 0 <0.000010>
1093  00:09:57.990720 fstat(4</var/log/gitlab/logrotate/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.990754 fstat(5</var/log/gitlab/gitlab-monitor/current>, {st_mode=S_IFREG|0644, st_size=54391, ...}) = 0 <0.000010>
1093  00:09:57.990787 fstat(6</var/log/gitlab/gitlab-rails/sidekiq_exporter.log>, {st_mode=S_IFREG|0644, st_size=15520, ...}) = 0 <0.000009>
1093  00:09:57.990821 fstat(7</var/log/gitlab/gitlab-rails/grpc.log>, {st_mode=S_IFREG|0644, st_size=66, ...}) = 0 <0.000010>
1093  00:09:57.990854 fstat(8</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000009>
1093  00:09:57.990888 open("/var/log/gitlab/gitlab-rails/api_json.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-rails/api_json.log> <0.000018>
1093  00:09:57.990926 fstat(33</var/log/gitlab/gitlab-rails/api_json.log>, {st_mode=S_IFREG|0644, st_size=1706, ...}) = 0 <0.000009>
1093  00:09:57.990960 close(33</var/log/gitlab/gitlab-rails/api_json.log>) = 0 <0.000015>
1093  00:09:57.990996 fstat(9</var/log/gitlab/gitlab-rails/production_json.log>, {st_mode=S_IFREG|0644, st_size=121908, ...}) = 0 <0.000009>
1093  00:09:57.991030 fstat(10</var/log/gitlab/gitlab-rails/production.log>, {st_mode=S_IFREG|0644, st_size=118283, ...}) = 0 <0.000010>
1093  00:09:57.991063 fstat(11</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000014>
1093  00:09:57.991101 fstat(12</var/log/gitlab/sidekiq/current>, {st_mode=S_IFREG|0644, st_size=50785, ...}) = 0 <0.000009>
1093  00:09:57.991135 fstat(13</var/log/gitlab/prometheus/current>, {st_mode=S_IFREG|0644, st_size=1860, ...}) = 0 <0.000010>
1093  00:09:57.991168 fstat(14</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:57.991201 open("/var/log/gitlab/alertmanager/current", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/alertmanager/current> <0.000014>
1093  00:09:57.991236 fstat(33</var/log/gitlab/alertmanager/current>, {st_mode=S_IFREG|0644, st_size=188, ...}) = 0 <0.000010>
1093  00:09:57.991269 close(33</var/log/gitlab/alertmanager/current>) = 0 <0.000010>
1093  00:09:57.991301 fstat(15</var/log/gitlab/registry/current>, {st_mode=S_IFREG|0644, st_size=101177, ...}) = 0 <0.000010>
1093  00:09:57.991334 fstat(16</var/log/gitlab/gitlab-workhorse/current>, {st_mode=S_IFREG|0644, st_size=56896, ...}) = 0 <0.000009>
1093  00:09:57.991367 fstat(17</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000009>
1093  00:09:57.991401 open("/var/log/gitlab/gitlab-shell/gitlab-shell.log", O_RDONLY|O_NONBLOCK) = 33</var/log/gitlab/gitlab-shell/gitlab-shell.log> <0.000019>
1093  00:09:57.991439 fstat(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>, {st_mode=S_IFREG|0644, st_size=507, ...}) = 0 <0.000009>
1093  00:09:57.991472 close(33</var/log/gitlab/gitlab-shell/gitlab-shell.log>) = 0 <0.000009>
1093  00:09:57.991504 fstat(18</var/log/gitlab/nginx/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.991537 fstat(19</var/log/gitlab/nginx/access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000020>
1093  00:09:57.991579 fstat(20</var/log/gitlab/nginx/error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.991612 fstat(21</var/log/gitlab/nginx/gitlab_access.log>, {st_mode=S_IFREG|0644, st_size=42960, ...}) = 0 <0.000010>
1093  00:09:57.991642 fstat(22</var/log/gitlab/nginx/gitlab_pages_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.991671 fstat(23</var/log/gitlab/nginx/gitlab_registry_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.991701 fstat(24</var/log/gitlab/nginx/gitlab_pages_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.991730 fstat(25</var/log/gitlab/nginx/gitlab_registry_access.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.991759 fstat(26</var/log/gitlab/nginx/gitlab_error.log>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000010>
1093  00:09:57.991788 fstat(27</var/log/gitlab/gitlab-pages/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.991817 fstat(28</var/log/gitlab/node-exporter/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.991847 fstat(29</var/log/gitlab/unicorn/current>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0 <0.000009>
1093  00:09:57.991875 fstat(30</var/log/gitlab/unicorn/unicorn_stderr.log>, {st_mode=S_IFREG|0644, st_size=536, ...}) = 0 <0.000009>
1093  00:09:57.991905 fstat(31</var/log/gitlab/unicorn/unicorn_stdout.log>, {st_mode=S_IFREG|0644, st_size=88, ...}) = 0 <0.000010>
1093  00:09:57.991934 fstat(32</var/log/gitlab/sshd/current>, {st_mode=S_IFREG|0644, st_size=127, ...}) = 0 <0.000010>
1093  00:09:57.991967 write(1<pipe:[3576493]>, "\n==> /var/log/gitlab/gitlab-rails/production_json.log <==\n{\"method\":\"GET\",\"path\":\"/-/metrics\",\"format\":\"html\",\"controller\":\"MetricsController\",\"action\":\"index\",\"status\":404,\"duration\":3.0,\"view\":0.49,\"db\":0.0,\"time\":\"2018-09-25T00:09:57.402Z\",\"params\":[],\"remote_ip\":null,\"user_id\":null,\"username\":null,\"ua\":null}\n\n==> /var/log/gitlab/gitlab-rails/production.log <==\nStarted GET \"/-/metrics\" for 127.0.0.1 at 2018-09-25 00:09:57 +0000\nProcessing by MetricsController#index as HTML\nFilter chain halted as :validate_ip_whitelisted_or_valid_token! rendered or redirected\nCompleted 404 Not Found in 1ms (Views: 0.5ms | ActiveRecord: 0.0ms | Elasticsearch: 0.0ms)\n\n==> /var/log/gitlab/registry/current <==\n2018-09-25_00:09:57.36496 time=\"2018-09-25T00:09:57.364915817Z\" level=debug msg=\"s3aws.Stat(\\\"/\\\")\" environment=production go.version=go1.10.3 instance.id=e8df01bb-477a-4ea2-9667-91aa4b6682d9 service=registry trace.duration=55.681353ms trace.file=\"/var/cache/omnibus/src/registry/src/github.com/docker/distribution/registry"..., 1228) = 1228 <0.000072>
1093  00:09:57.992135 nanosleep({1, 0},  <unfinished ...>
7113  00:09:58.121953 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000832>
7113  00:09:58.121999 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000011>
7113  00:09:58.122032 clock_gettime(CLOCK_MONOTONIC, {282504, 206496999}) = 0 <0.000011>
7113  00:09:58.122071 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 124, {282505, 207328885}, ffffffff <unfinished ...>
2690  00:09:58.193465 <... futex resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000844>
2690  00:09:58.193522 futex(0x7f5ef33fb4a0, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000016>
2690  00:09:58.193565 clock_gettime(CLOCK_MONOTONIC, {282504, 278032579}) = 0 <0.000016>
2690  00:09:58.193616 futex(0x7f5ef33fb464, FUTEX_WAIT_BITSET_PRIVATE, 4020, {282505, 278834003}, ffffffff <unfinished ...>
823   00:09:58.629260 <... select resumed> ) = 1 (in [25], left {28, 802152}) <1.197980>
817   00:09:58.629322 <... select resumed> ) = 1 (in [25], left {28, 765028}) <1.235068>
813   00:09:58.629343 <... select resumed> ) = 1 (in [25], left {28, 764797}) <1.235319>
823   00:09:58.629405 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
817   00:09:58.629475 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:58.629520 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000053>
817   00:09:58.629535 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000022>
823   00:09:58.629547 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:58.629579 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
823   00:09:58.629610 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = 26<UNIX:[3605400->3605748,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> <0.000038>
817   00:09:58.629644 <... accept4 resumed> NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000040>
813   00:09:58.629657 fcntl(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, F_GETFL <unfinished ...>
823   00:09:58.629693 recvfrom(26<UNIX:[3605400->3605748,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>,  <unfinished ...>
817   00:09:58.629724 getppid( <unfinished ...>
823   00:09:58.629735 <... recvfrom resumed> "GET /ealoc-engineering/loccms/merge_requests/102.json?serializer=sidebar HTTP/1.1\r\nHost: gitlabts.ea.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\r\nAccept: application/json, text/plain, */*\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nCookie: _ga=GA1.2.1866266439.1526069804; sidebar_collapsed=false; frequently_used_emojis=alien; auto_devops_settings_dismissed=true; _gid=GA1.2.1802602330.1537799390; _gitlab_session=e3db34af92ce75a754809c69bbc89e42\r\nGitlab-Workhorse: v6.1.0-20180921.115425\r\nGitlab-Workhorse-Proxy-Start: 1537834198629040655\r\nIf-None-Match: W/\"d76856cceba572f590ff8ab526cf56d9\"\r\nReferer: https://gitlabts.ea.com/ealoc-engineering/loccms/merge_requests/102/diffs\r\nX-Csrf-Token: BIXXFdicfD7nSHLguLhOeQ0rKtsEh0y1o5K+Jr8Bw+bv/HwqAvb+EdGdTWo+RBrj3Kr2edBpeaavMdFY+2dmPA==\r\nX-Forwarded-For: 10.45.32.103, 10.7.7.46\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Ssl: on\r\nX-Real-Ip: 10.7.7.46\r\nX-Requested-With: XMLHttpRequ"..., 16384, MSG_DONTWAIT, NULL, NULL) = 1060 <0.000018>
817   00:09:58.629755 <... getppid resumed> ) = 495 <0.000026>
813   00:09:58.629765 <... fcntl resumed> ) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000080>
813   00:09:58.629785 accept4(25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>, NULL, NULL, SOCK_CLOEXEC) = -1 EAGAIN (Resource temporarily unavailable) <0.000011>
813   00:09:58.629842 getppid()         = 495 <0.000009>
813   00:09:58.629880 select(27, [24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]> 26<pipe:[3578808]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:58.630338 write(8</var/log/gitlab/gitlab-rails/production.log>, "Started GET \"/ealoc-engineering/loccms/merge_requests/102.json?serializer=sidebar\" for 10.7.7.46 at 2018-09-25 00:09:58 +0000\n", 126 <unfinished ...>
817   00:09:58.630373 select(26, [14<pipe:[3579142]> 24<TCP:[127.0.0.1:8080]> 25<UNIX:[3578806,"/var/opt/gitlab/gitlab-rails/sockets/gitlab.socket"]>], NULL, NULL, {30, 0} <unfinished ...>
823   00:09:58.630608 <... write resumed> ) = 126 <0.000243>
823   00:09:58.630757 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0&\242\206H\362]D\355o\4\262>\232\347q\t\235d\344\351j\203\324\26\234\1\311*\216\323\216}m\315\247\216y\3262", 43, MSG_NOSIGNAL, NULL, 0) = 43 <0.000047>
823   00:09:58.631119 poll([{fd=32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, events=POLLIN|POLLERR}], 1, -1) = 1 ([{fd=32, revents=POLLIN}]) <0.000201>
823   00:09:58.631634 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0Z", 5, 0, NULL, NULL) = 5 <0.000018>
823   00:09:58.631937 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30\\\317\263'9\217.$\26\301Dk+D\220\3K\315\354G&\362\236:`\25\307\330\375\271\n\216\325U#>\212bd)eSV(\270.\301\271\351\7)\177\211U\233\356\321\337a8@\20\\\22\34\7\267\367?\217\215\343q\316\300Z\341\375\351\2339\224\243", 90, 0, NULL, NULL) = 90 <0.000018>
823   00:09:58.632527 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000015>
823   00:09:58.632824 write(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$48\r\ncache:gitlab:ApplicationSetting:11.3.0-ee:4.2.10\r\n", 68) = 68 <0.000036>
823   00:09:58.633147 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000017>
823   00:09:58.633437 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "$13766\r\n\4\10o: ActiveSupport::Cache::Entry\10:\v@valueo:\27ApplicationSetting\21:\20@attributeso:\37ActiveRecord::AttributeSet\6;\10o:$ActiveRecord::LazyAttributeHash\n:\v@types}\1\246I\"\7id\6:\6ETo:?ActiveRecord::ConnectionAdapters::PostgreSQL::OID::Integer\t:\17@precision0:\v@scale0:\v@limit0:\v@rangeo:\nRange\10:\texclT:\nbeginl-\7\0\0\0\200:\10endl+\7\0\0\0\200I\"\33default_projects_limit\6;\fT@\vI\"\23signup_enabled\6;\fTo: ActiveRecord::Type::Boolean\10;\0160;\0170;\0200I\"\25gravatar_enabled\6;\fT@\21I\"\21sign_in_text\6;\fTo:\35ActiveRecord::Type::Text\10;\0160;\0170;\0200I\"\17created_at\6;\fTU:JActiveRecord::AttributeMethods::TimeZoneConversion::TimeZoneConverter[\t:\v__v2__[\0[\0o:@ActiveRecord::ConnectionAdapters::PostgreSQL::OID::DateTime\10;\0160;\0170;\0200I\"\17updated_at\6;\fTU;\30[\t;\31[\0[\0@\32I\"\22home_page_url\6;\fTo:\37ActiveRecord::Type::String\10;\0160;\0170;\0200I\"\36default_branch_protection\6;\fT@\vI\"\16help_text\6;\fT@\24I\"!restricted_visibility_levels\6;\fTU:#ActiveRecord::Type::Serialized[\t;\31[\7:\r@subtype:\v@coder[\7@\24o:%ActiveRecord::Coders::YAMLColumn\6:\22@object_classc\vObject@\24I\"\32version_check_enabled\6;\fT@\21I\"\30max_attachment_size\6;\fT@\vI\"\37de", 1024) = 1024 <0.000021>
823   00:09:58.633789 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000014>
823   00:09:58.634097 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "fault_project_visibility\6;\fT@\vI\"\37default_snippet_visibility\6;\fT@\vI\"\25domain_whitelist\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; c\nArray@\24I\"\34user_oauth_applications\6;\fT@\21I\"\30after_sign_out_path\6;\fT@!I\"\31session_expire_delay\6;\fT@\vI\"\23import_sources\6;\fTU;\34[\t;\31[\7;\35;\36[\7@\24o;\37\6; @*@\24I\"\23help_page_text\6;\fT@\24I\"\35admin_notification_email\6;\fT@!I\"\33shared_runners_enabled\6;\fT@\21I\"\27max_artifacts_size\6;\fT@\vI\"\37runners_registration_token\6;\fT@!I\"\23max_pages_size\6;\fT@\vI\"&require_two_factor_authentication\6;\fT@\21I\"\34two_factor_grace_period\6;\fT@\vI\"\24metrics_enabled\6;\fT@\21I\"\21metrics_host\6;\fT@!I\"\26metrics_pool_size\6;\fT@\vI\"\24metrics_timeout\6;\fT@\vI\"\"metrics_method_call_threshold\6;\fT@\vI\"\26recaptcha_enabled\6;\fT@\21I\"\27recaptcha_site_key\6;\fT@!I\"\32recaptcha_private_key\6;\fT@!I\"\21metrics_port\6;\fT@\vI\"\24akismet_enabled\6;\fT@\21I\"\24akismet_api_key\6;\fT@!I\"\34metrics_sample_interval\6;\fT@\vI\"\23sentry_enabled\6;\fT@\21I\"\17sentry_dsn\6;\fT@!I\"\31email_author_in_body\6;\fT@\21I\"\35default_group_visibility\6;\fT@\vI\"\36repository_checks_enabled\6;\fT@\21I\"\30shared_runners_text\6;\fT@\24I\"\30metrics_packet_size\6;\fT@\vI\"#disable"..., 12750) = 12750 <0.000021>
823   00:09:58.634407 fcntl(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000011>
823   00:09:58.634686 read(13<TCP:[172.17.0.2:60674->10.7.7.47:6379]>, "\r\n", 2) = 2 <0.000019>
823   00:09:58.635648 open("/proc/self/status", O_RDONLY|O_CLOEXEC) = 44</proc/823/status> <0.000022>
823   00:09:58.635714 ioctl(44</proc/823/status>, TCGETS, 0x7ffc6d3d2d10) = -1 ENOTTY (Inappropriate ioctl for device) <0.000013>
823   00:09:58.635753 fstat(44</proc/823/status>, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0 <0.000012>
823   00:09:58.635792 lseek(44</proc/823/status>, 0, SEEK_CUR) = 0 <0.000013>
823   00:09:58.635830 read(44</proc/823/status>, "Name:\tbundle\nUmask:\t0022\nState:\tR (running)\nTgid:\t823\nNgid:\t0\nPid:\t823\nPPid:\t495\nTracerPid:\t7388\nUid:\t998\t998\t998\t998\nGid:\t998\t998\t998\t998\nFDSize:\t64\nGroups:\t998 \nNStgid:\t823\nNSpid:\t823\nNSpgid:\t492\nNSsid:\t492\nVmPeak:\t  838536 kB\nVmSize:\t  838536 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t  490820 kB\nVmRSS:\t  490820 kB\nRssAnon:\t  476264 kB\nRssFile:\t   14500 kB\nRssShmem:\t      56 kB\nVmData:\t  555940 kB\nVmStk:\t   10236 kB\nVmExe:\t       4 kB\nVmLib:\t   27836 kB\nVmPTE:\t    1676 kB\nVmPMD:\t      16 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nThreads:\t7\nSigQ:\t0/62793\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000008300801\nSigCgt:\t00000001c200764e\nCapInh:\t0000003fffffffff\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSpeculation_Store_Bypass:\tvulnerable\nCpus_allowed:\t3\nCpus_allowed_list:\t0-1\nMems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,000"..., 8192) = 1311 <0.000027>
823   00:09:58.635890 read(44</proc/823/status>, "", 6881) = 0 <0.000012>
823   00:09:58.635927 close(44</proc/823/status>) = 0 <0.000013>
823   00:09:58.643466 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.643849 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\275\242\206H\362]D\355p\220\1771\355\24\274\374RC>Z\326\362ZL\223\17ye\353\\\261\222\227J\27\2\260\337\37\236\313\216\21\370\340\0\212J\t\270\234e\1W,ut\6\263\252YE%\223\260\21\227H\247f\245\353\225\330\371mz\221\336\2v\334\340\217\\\r#p\10\t^\210\227\330z\320\327\5\304\330K\211G\304\v\231KGIQQW7\202^\3122%\21\322\22.$\315O8T\312S\326\310\364\234X\244?\312Pt\224\273e\247<\263\325\374\341@\262\3422R\246\6\211\26\223\365\217Y\303\350<\2541\261\17\2072!a\217\241\206\224\20I\17\334\322a\330\323\4\270;\212\2141y\34\310c\363<I\320\203\315\277\323\361c\260\305\324\301A?P\17\35a\5ymD\320\36F\316\226\34\236\271\264\203\302 n\311\200\267R\20-\2308\23\26\245\255\204\333o\1\10\237\35\325\324$\364\232\\~_QW\333\242\367\324\350-6\246q\374\372.\277m8PC\202Q\253\320p\360\23|[\233\227U\235cfZ\332\270\235s8\356!b\314\34\274#g\260\346jG\332\247w\217\316)\231\316\206\247\27i\"l\203\20\306\244\355$\341p\361\276\216\370\247\243\37\260M$\16\303b\17z\213\323\214\333i'\36A-X\35\r\270\305G\342\234\370\36\306a5[D\321s\24\5]\262lh\251$c\244\360t\245\253Wm\22% \214\372Y\261K\336\236i\1\351f\250\317V\227\3\301,\260\363\355\343\311\310\270sA\17\314BS\32\222\3707\340\327\5\300\276T\f#\224\\l\376w[\260\30\362\247\204", 450, MSG_NOSIGNAL, NULL, 0) = 450 <0.000038>
823   00:09:58.644185 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000017>
823   00:09:58.644486 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000931>
823   00:09:58.645701 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\4d", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:58.645963 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30]Q\355;!\0206\272\276\325xB\f\34\367\365>\360F}.\354\214\225\321i\35Q\207\326\257\203\356\7h\212\203@k$\325po\\I\21:5\204\0{\227K\372\n\271-\201\33\325\272\231C\357\315\270\267\240\270\34\227\344\0\23\340'\260\33O\241v\250X\331iW\341[\272\261\312v,\321\346\0uV\341\322\230x\254\366 }G]\17\365\356\374\tY\31\306t<\320\177\254\202\374\222\250H=\276\\\20ie\334\337\272\355b\377\24\232\364Kq\362\10\201~\270\np\30\22\3\206\240x\25\n\224\210\265\247\317\24\17\355\247\214\335\305\266\206\3601\3\366\10SH\305Y\327\7\346u\5\252k\334<\276\323\244\266\336\6G\233[!i\352I\244m|\357\260_\f\336\177\246\236L\376\377\363\31z\213\3523F\335>`H\253\305\272\364\351_P\374\255L\261c\22.-|\225\266\376\360(\353\263\2G\305Q\205I\235vJX\203\26\250?Joj\341\227\345q]pW\326\177\252]E\370\264\360\267\335S\310\0060i\362\364c\370\262\16\325n\326\267:\2048\t<\361\206\36\2211\24Ks\335\374\24G\204\224E\267\353\310\377FXU\323\267\232\207\315v\266\230\22:\1\334\217D\316\360sq\226\254W\373z\233bj\253\352\325\327\330\302-EJ\276\343\316\275)\225I\317\10e\354\203\16\213zx\232\345\"\210\375\241\240\301D\253\35\17t\3\2668\fA<G\1\355\336q\257w\17\351\351\v\277\"j\t\214\263\373%\270\300\25\16HK3=\377\247\201\262\323\"\2409\327\313\316\326\236x-)\35\230\240\332\\\243-\3564/\1\0074!-\232\2312\314mW\362\30\270\325\2606\226\303\247b\371\207{Q\32H\325\266\326,{l\335\20TP\26$\362P?\235s\333\22\332m\262\375e\345;\317\352ht\2470\25}\17\205\247\223\0\2\30\334\177\\Q]\271a%\215O\3227]c\367\364\366\320d\251V\201\363$0\345\235i\327\303\301\16p+\5\276\277b\216\261\315\251\322\303d\367\316\17B\272j\311\342e\363\315\206e\220\253\346J/\273\375\243\"\344\327\253C\264b\301\370\n\255\n\331\355b\37Q\f\355\266\272\376\"\266 \320$\304\207\26qj\373#\2341\223\351V\321\302\210\272\20\237\t\334\202/OJ\333/\234}?^(\355\241wH N{\2773\372\232H\373+\341\216\3\7>e/\340yrF\23=\302g\205K\300I\267\206\223\337\334Ul*\333\33\274\233\357\t\22@\265\244%2l\23091\210\274\6\337\361<\207M\0003\346\343G\306,\211\315K\20K\213.\353h\346\207b\0\31d\314\22(\356\200\3\200\221\263\264\357\"\0343j+t\6\311IA\270\277\375\345\307\314nH\32\312@a<Dw\276\231\202\376\261Q\10\232\2\304f\341kh\250\335&\200Q83\305\30\202\5p\25\254PL\33+B{W[\236,\7\213\370%\370$\243\33\v\254RQq\36\355\10\343\232\32\261\206D\6\24\0173\244,\230|\313\263\3032;\326\3455J\305\365\243\220\307\316i\316\317\340V\315\365\10R\343\351FD(H\226\252\265\0008\177\334\n\351w:&\201\320\337\210\2\10\4\23\225\2038\375e\35\242\335\341\234\30w\35Q\237w\336\253zt$\364\232C\372k\267\233k\306\305_\345\26\203G\242\250\376e3\337\335\316\240H\235\333\215+\354(&\260\2454lq\36\316%\212\367\273\333w\251u\f\201\222\360r\327Vs\356}\222U\334!\276\326g\250\240O\324\242\272us~\323\360j\253\372\332\254=\232\0Qv\200\271w'\272\230\235\231\237\233\26\211\342\27m\357\354o\223\377\317\233L\336PfSp"..., 1124, 0, NULL, NULL) = 1124 <0.000016>
823   00:09:58.647187 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:58.647538 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1z\242\206H\362]D\355q\231\2506\344\367\271\313J\240d R\336\4\32\262\303\356\r\365k\311%\330\16\264\251F\242h\0002\2273\341\323\26o\232,5\177Y\271\304\36\35e(\255E\200cD\363}d#\247\27aar\274JEH\214\0362\315'\247\354\32D\261L\333s\360\6\3441R3\314\245`\337\26\265D\273\0\246\337\1\r\2462=\224\34(]9\244\365i\366\305\272\26\210\306\27\250\211m \271\201\24\235^\3a\261Sma\203\254j\222\352\303.\245\2519\10\333\203v-U,\201\372\35\226f\232\241OwQ $'\366\0333\251B\374\334\222v\33\341\251\222\250\373A\303>\10\316\263*z\307;\342\no{&\273\273/\17\212\360x\364\246\364u\203\342\36Ba/\371\3159\325\fYB\177*\276`A\367\324M\232\231\362l\3\275\225;\242$\r\274\200\213v\177\375@\270\r\30\245.{\361k7\230i8b~\263\205\33Qj\263\317H\250\235p\331\201S\202\351\353=\2350\204\322B\245\217\361\16YR\344\342$\376zu\4\362\361\r\337a\365\2\211[_|\5\241\326\330\232GA\303\5\231\326{\320\234\320\273%\325\312_\361\33\3644\312\361\343@\340i\273&]\5\302_\351/\276Y\267{\344\270\310\312\327\17gt\264$b\202:K\235\310\373\373uC\241\"\317\326\361", 383, MSG_NOSIGNAL, NULL, 0) = 383 <0.000036>
823   00:09:58.647887 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:58.648189 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000702>
823   00:09:58.649178 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\4d", 5, 0, NULL, NULL) = 5 <0.000018>
823   00:09:58.649476 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30^\376\273\224\373\5\30\365\3k+\266'\367kp0q\\2<\307\212\255D_'G\330\260W`\306\32340\2\303\212\246\270g\326\240\224\3661\324z\233\233\2260\262k3[\230\301\331R\261\314\3X\234\355\37\354\373\33\364(\203!d\355\241\311\337\316\247\2568\354Xm\16\2125\207\21\3378\254\273\217C\354\2563\365\265\246\215>\340\vr\3415\272\324\3667:\335/FI6W\316\377k\311\351s\355\303\0005\3403=h\360\311\3708\302\274\334Xh\340\373\340\t\353\306\34\365\235}y\203y\340Vq\vF\0\277a{Q\7\0\320\365\330\262\350\363\232\1BC7\22\233\216\307\275\317!x\321\235o\277\5\335\322\256\36\204a\247\361\36\21\202S\223\340\346O\247p\224\325\16\n\335\27\226\275\365\360\234\245\355\250\2613t\261\355\242_\3164\10S\2\311.\310\242\314\230\247H\205\316\26\3671\2613\20\324\247\347\307\345\2\0\241\357:\352v\265EzOh\323\256|\261\306\v\223\305-zt\377\256\214\235\22\1\326\26\263\"i\325\\\234\236\33\326\274r\235\363\365\0\271\214\320\25\1\365\242>\265\220$?\33\24o?\205\215,p\227%\307\5\302L\313(>\36\253>\346\204C\216\330\347\3116\206D\375b\255:\214n\241\350\375\236I*\330\334\351\251\214\366\361;\225o\0\232V\310\324\221\177_8\205\365\342\271\270\267\216\2130\0026aX*\321^.rZ\321\315\214\243\237\r|\244K2F,f\375\311kgS\343\227\221g]\306\242\312\345!\365\210\370)\3772}@\340D_'\302/\264V\215%\322E\0\7\232,4\252gN\330\254)Ppb\365\4]\342x\254\37\261e\16\210t\234\240\r\275\264<\226\237ci-\320\345\344\264\273|\271\224J7!\301\35\v\206\322s3\206\361\3246\251m'\37\266\206r\240?\232\350\322t\7&\225\315\253\23!=\210h\273\224G\204YhU\221z\6\340\346\226\367\372\374O\26\252\226\2321\377h\365\261\2o\344d\224\20\252\270\351\323(]\264\314>AFBG\272<\ni#\214\206\366\246\"\354\272<\301\250\30\360\20\332\353\222\374\374\274L\237d^\220\340\263G\5\5\305blt\\\3077M\226z\227}\213K\225)\203:&R%2\315Y\363\321u\322W.\265\250#\203\310\366\213#\316\200\245\0\343\375|p\223\270'\240\2\203h\310G\350\2506\272\372.\374\37\356\\W\323\"\354\322\271\245m[\22\\\3\257E\35\236\247\213\317\251\244\300\0\362\276'\204\243[\214\265'\355\203\360\354K\206\371\347e\215\r\324\331\244l\24p}\357\337W\232\2a\0049\361\211K\225M0\232\206\232}\235\247M\350\217\270U\266\224\362y\370\353\234\220\240yv\352i\336\262\274'\33\34\24\350\353\351\"Ij\35x\244\240\377G{\232M*\1\362\274\236\304_y\1\205\211\345\345\31\200\372\204\0\321\v5\235\312\260\232\0f0\230\246\"\31!\17707\245\354\214 \267=y\1\377X\4\tCLb\205\312\200\20\262\313\344\5\207\257\304~\10\332\266\300\235g\202`\347P\350\20\32\260\242\236\336\326v\364\260d\215\20P\312C:\0Hp\361u\345.Kw\346I'\240\212\307\317\372\1\254\"\355\357\232\177\2\272\250^\231x\17\10\215\273\\\216u\247\271`\205\347r\372\371b_\205o\304o\246\364\203\21\241\210\30\0251`\313Z\315\246\3720V9p\347o\225U\200\20\37\332\236\207\342^\33\300%\221\315\200\231:\363u)\351\342\323\347\201\212\321<\261\213\6~\366\34\2149\334J\t\17*?U\35\334q\373\1\345Bp\310\33\3632Y\357\304\f\365\21\336\323R\25\27\20\344\277\4}_"..., 1124, 0, NULL, NULL) = 1124 <0.000017>
823   00:09:58.650668 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.650995 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1j\242\206H\362]D\355r\221^\256\346\274\372\215\332\230d\323\350\205\242\200\260h\357\237\335|\241%n\25D\201z^\34:t\367\250\22\301_\235L\237<\0(\250\327]5\313\377\275\337\0\245\365\222\311\242\277\233\25Bc\327\305\250n\4\210M\3518\5\305\253\t\267\246L]f\334fA\355_(y\32\220\223{\35=\vr\3\251\375\314\23\260jW\25\242\37\355\215\363C\f\201\10EoZ\1774\334\\\266\203\277\341<\3\201\300\374\315>u\33Zu\215\277\16\246u\7P\353'\356\213\315\211m\r\36\367\221\331\222\276L\2\32\321\313\362T\311\t\360&\23\215\310\1(~\343\374\262\260=\243\266\26\2609P\244\225\316\224\231\33\302\376(\3279\345\305?SR\305\377NX4\361\213\370\23\f\200\36A\211q\234\267o\32C\313\20\350\326\20@\347\261^2\260\230%\36\244H\370MC&\371\f\262\233\251\365\22r\323Z\10B\242\244=s\20iNs|p\233\240\273\255^o\376\21~\"\325\6\34\30Z\35T\342\202,\266\232\344\330\335\371A\323\327i\214\352\3212\360\232\370\226\0\375\334wMy4n\2756\206\2070\247\270n\326\302\327\4q\305\33\302\371v\375\214\331N\24Ka\357D\22\304}\276\277@m\\\7\300\220\246\233\203\343\2532\3452", 367, MSG_NOSIGNAL, NULL, 0) = 367 <0.000035>
823   00:09:58.651322 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000016>
823   00:09:58.651658 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.001064>
823   00:09:58.653012 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r0", 5, 0, NULL, NULL) = 5 <0.000028>
823   00:09:58.653289 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30_\30\203\271\25\32\203q\342\257!\220\240th\0\261\241\2500a\362\362\17iq;\370\324\267\322\362\255\207ah\227\"\245\205\274\210\212\362[.\373\267=\301\207f\330\17\5qOZm\337=i\346T\303\26\363\250E\375P\252\335\1\301\\\222\330C!\264\256\202\276LG\331\226\223U&Q\4\227\177\303\200\315\216)\4\274\232\202\214\34B\212\271\262\217\302\3w8\222j5\217[\300\316\221\352\24\200\353\355>\250b{\324}\260X\327t\303\323l\331\300IU-<\320\16\31\21<\\\r\351U\350\16K\331G}\205\17\33\235\272~c.\260`\346\26\253H\262\21x\321g\201\251X\207\10\vT\354\346\350\276\206\300\0\250\315\370\350;\26\337\5\234\r\330\205_?\32\355\360\323qO\0\267q+^N\3765\231\301\264\26\276\230\33\221G\306M~\352\2005\nE\376\352z\234\223\264uZ\363\217\303\266\270\5]\373\340\243\232\1\362\247\245\367K\274\31\25\257]?\273\25\245\215\t\220\313\336S\236T5\333\364\25\5\230(\314\217\350Np/u\257\34_\365~,\336\26\0371X}\37\37r\31\217\265.+B\24*mt\273\301\321\266\2257\340\363\241-.\254\372\244\354\3\324\374\244\331\336\22v#\353\372\35=\374v\343;&\366It(l\373\251;\326\37\375\6d\203\26\313\316\273\222\377\321\243\251a\274@\317\362\265\330\247\362\26\n\354\207\343\3451\354\261\314.\310Z\340q\367\342\250\3252}z\335\253\226*R\302\211j\2207\33\223\270\31c\325N\212\32&\335\1m\374\302\307\5WnD8\n$\364\203\206\310\347\203\7&\250T\366\301\350^?\304Cd\t\252ob>\372\210\204E\310\250e\342F\320\336\277\343~`\337\330\24\310\v\216\340\2556\267\330a\17\265L5\266\241\264\2559\r*\231|e?\230\5\35\330\354T9X\271\21\233\272\213\346\217\376\ta:F\215\224w\277\276\276\246\177Hu\362c\262\0170~\305\33'J\t\n\303* \244]\v\366\3509\246y\331\232\td\202\230\36>T\336K\0015\352@W~@\5j\357\315*_v\"\270\32\"fi[\314\26\3414\301\320&\"\360n\210\240\7\346{Lq\337h\34zm\271\264t\3\234=|\241\n7\37\331\354!\20\374\262)\362\f\356\2261\261\210\r\323\n`\347et\335\232aQ\340~\373E\233\277a\266}\374Z\252|\341\341@\200\214\251@\366Q\276a\0168\323\337Qf\243\210\317\3\377a\324\25 \241\202\275d\351c\356\36\262~\232\366&\322\33\227\277\36\303\353\222\22\203\33\3476\307\251\16E6\23\5~\310\34\331\210\253\265\235\354\370\234 \225\332\370\r\364\302Y\33\276\214Dv\202\37\352\207\350\357\17\22SS\237EJ\360\304\23\331\215Bq\354\351wWg\20P\6\202X\363\374\301K\335\345\307\265\3h\314\201\300&l\7ub\346\310\22\301\372\237M\274\371aT\265$\36\200\234\377vRc\331\3554\203\333\330\304+\240\324\223\27\rm\313\331(\374L\345\216\r)\372\313\4|\331k'\34\364'7\233\261\265\240~\374K\225M\202N\207\251S\25?\324:k\240\"\314c\246:\336|\204\304I\323\350\353ar\354\177{\352r\7\32W\246\222\305\251\v\265\236M\267\216x\325\357\10W\212\264-\21\360V\33\16\30\356\221a\31\376\315\365\241\324\245\332P\214{\373@YF\v\344\265\267\221X)\244\314\210\252\250R%\273\325Ck\216\272\5\vn\242\354\243\33R;\246\223\213/r\250\204\f\326=\261\261r\321\256'\225|\273f!fu\26\324T`\201\365\25\327eJN\256\213\365\375\30\20\301r{;\360K\303F\361H;\200\261\313\313\240"..., 3376, 0, NULL, NULL) = 3376 <0.000018>
823   00:09:58.654870 write(8</var/log/gitlab/gitlab-rails/production.log>, "Processing by Projects::MergeRequestsController#show as JSON\n", 61) = 61 <0.000020>
823   00:09:58.654955 write(8</var/log/gitlab/gitlab-rails/production.log>, "  Parameters: {\"serializer\"=>\"sidebar\", \"namespace_id\"=>\"ealoc-engineering\", \"project_id\"=>\"loccms\", \"id\"=>\"102\"}\n", 114) = 114 <0.000014>
823   00:09:58.655317 fcntl(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
823   00:09:58.655532 write(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, "*2\r\n$3\r\nget\r\n$47\r\nsession:gitlab:e3db34af92ce75a754809c69bbc89e42\r\n", 67) = 67 <0.000038>
823   00:09:58.655791 fcntl(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000020>
823   00:09:58.656001 read(36<TCP:[172.17.0.2:60818->10.7.7.47:6379]>, "$286\r\n\4\10{\nI\"\rsaml_uid\6:\6ETI\"\24ccraciun@ea.com\6;\0TI\"\27saml_session_index\6;\0TI\"*_9e8f6987-2d37-4694-ac42-e9c53e929094\6;\0TI\"\31warden.user.user.key\6;\0T[\7[\6i\2{\1I\"\"$2a$10$c8YgmOQm12hm4leSpZCqFu\6;\0TI\"\20_csrf_token\6;\0FI\"163mrP9pqgi821T+KhvxUmtGB3KLU7jUTDKNvfkRmpdo=\6;\0FI\" ask_for_usage_stats_consent\6;\0FF\r\n", 1024) = 294 <0.000050>
823   00:09:58.656786 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000027>
823   00:09:58.657128 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\240\242\206H\362]D\355sq\374\274\21\354\201\234D\353\23JN\37\216\25\314\344\274\362\304\313\262$\317\263\322\305\324\247Uz\256\24}\221\366T\233\310\371\351xF\271\206M=\373Ul\10\231\331\357\302\26\331Y\25\rO\342\343\251\312\320K\241l\272\225\336\2407S\10\205\r\226\247\230s\340\204\313\376\16\2\307\316z\344\360\351v\376(k\261*r\374b%Q.\305\256\275\235 \200\210\270z\227Vh\260\326\34\372\250p9\365\376\212&\32\200\325\242\217\265\n^\325\261\311\307\16x\24\215\342\351\254o+\20N", 165, MSG_NOSIGNAL, NULL, 0) = 165 <0.000041>
823   00:09:58.657466 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000022>
823   00:09:58.657780 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000138>
823   00:09:58.658211 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r8", 5, 0, NULL, NULL) = 5 <0.000036>
823   00:09:58.658541 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30`\6\23_\235\202\3\331l\320>:\327@\203\330\2303\\\rb\340\372&\30\335?\33\361\4\376\372\336\206\320}XT\261\216\345H\211\261,\300\301\334\226\f\303\300\26\2F\207=\236Z\365\351\3529\"\336n\267_\27\vTh\361\2328\250t\244R\363!\314i\322\322\331\343\22\36767\271I\365\234hY)k\245\342\366\216\rw\275\3243d=:%\256\250\274\260\346\37\3ZS\234\3713\301\342\312\n\4\"\34\321X\306\362\314\257w\t\360\331\305\231'\33\6\20\201\20zH\200]\26\301\301\261\344\\\376\2723\22\0~\30\312go\37\327-\"S\276/t\371)\301\201\244\275=\3158\320z\\z,o8P\n\315c\340\0\37+\223\247U%\34\271\366\326\277\306\255`\225\301\221\16\267\237\254\335\272dgZF\225\320\321\353\316\0043<S|\332\266\222?\344\203\274Fn\200W\354##\313cH\255\200`iO\356K\300*\222\177\257Qr;\262\257\331\3510\317\211\322\241\7\271DS\361\266\306\325=3\234\16\330+\376\322\5\337\370\275M\221<\366f\327\353\367\313<\312\372`\6G\210\277l\211\246fI!\273\343h\251\217bPC\31\364\367\212R\327\372\241\206T\334\247\304\263/\2645\350[\341\200u\214T\262\213\1\253k\342/\7\305X\3005R;xi\371\312\16^\224\300\367.\206\250m\245\252\316\237\22\215H\325.\1,\236x\35R\222\201)\6\\1CG>\20$\243\275\227R\347<\355\267\236G\17\255\356\230\336\3666\322\336\\qOS\312/\257\263\246\277\32-\350\276\37|\333KKT\225\356\226\347\235w\257\361\346\265\26\33\36\200\337\374\370\271\0218\204>V\201\303\304\325\256u\214\321]P\7\365\255gu1\2038Z.\364E\374]\254\34\25\222\26]\375\213@\3x\254cc,\2B\2244\230\vP\367\370n|6m\"o\254\21\335/(\265S,\341=m\302\275?\200\257\360R\204\272\34\3378\304\2\270w\345\5\371M'D\211jJ\260\0341\241\240\367#s\317\233\263\244\300H{0\203e<\274\301\347\333\232\233\277\273\312\275\315\\}3\271\202\204\257\275\313\356\251\23_\177$\347\r\244:;\326&\332\220\7'|\17\23\3237!\222\267\255>\215\272`\271\243\343\370)\247\242tF\4\v\330\236\313\223\230[\336(\304:\262-\215\352\0x\355\307K\334\343.tD\250\351\30\26d\276\226\273)K+HWDB\242\313\230\3-\201\231\177Z0\201g\332\256\277\1\230\352\366\211\345x|[1\222\374\343{\260f\352\24O<,\20~*\260\373\373\262wS\353)\362\306\237\27\354Hn\36\331h*\217\355\226\235\200HZ\274\312\332\203\37\200\3\314\23DQ\326\251\6\373$R\31\341j\362\220\24\376]l\242Zh\344\301[&\371'E-\273\341\303(>\371jA6\246 \365M\325&\360\27119\1773\356\240I\337\361\374\362\20l\377\231\351\255\302\341x\325\vJ\277\3\26\243jyL`\27\231\353\337&\3074\256\2232\232uF\360\34t\231no\344\222\245N;b\25\r~\f\275\206\n\326(\5\306\10\36Ixz\215I\23\31[M\221\361\356/F\273]\233D\342\373-Sb\252'\0231k\362\254\t\235^j\200\204\330*\22t\353\326k\30\6B\322\361\364\274~J\204n^b\2134w\334pU\352\6%\16\t<\315[t\0344\317\264\220\33\344\353\n\271\343\17\1\4\201B\200\246\v\t\354\305P\326C\205\341\rr\270\205\205\253\227\2075\324\376\300?\245z\251!mY\354\331'DJ\235\253!A\303\236\251U\317\340\222N\r\310\273x\200\350>\267\273\315\251\373\22\367\277N\306\207\241"..., 3384, 0, NULL, NULL) = 3384 <0.000024>
823   00:09:58.659664 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 139076589}) = 0 <0.000016>
823   00:09:58.659733 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 139111310}) = 0 <0.000013>
823   00:09:58.660475 fcntl(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000017>
823   00:09:58.660779 write(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, "*4\r\n$5\r\nsetex\r\n$56\r\nsession:user:gitlab:379:e3db34af92ce75a754809c69bbc89e42\r\n$6\r\n604800\r\n$361\r\n\4\10o:\22ActiveSession\r:\20@ip_address\"\01610.7.7.46:\r@browserI\"\fFirefox\6:\6ET:\10@osI\"\fWindows\6;\10T:\21@device_name0:\21@device_typeI\"\fdesktop\6;\10T:\20@created_atU: ActiveSupport::TimeWithZone[\10Iu:\tTime\r\16\243\35\300\313e\316\246\6:\tzoneI\"\10UTC\6;\10FI\"\10UTC\6;\10T@\r:\20@updated_atU;\r[\10Iu;\16\r \243\35\300b\22\252'\t;\17I\"\10UTC\6;\10F:\rnano_numi\2\351\1:\rnano_deni\6:\rsubmicro\"\7H\220@\16@\23:\20@session_idI\"%e3db34af92ce75a754809c69bbc89e42\6;\10T\r\n", 459) = 459 <0.000036>
823   00:09:58.661110 fcntl(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000018>
823   00:09:58.661401 write(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, "*3\r\n$4\r\nsadd\r\n$30\r\nsession:lookup:user:gitlab:379\r\n$32\r\ne3db34af92ce75a754809c69bbc89e42\r\n", 90) = 90 <0.000030>
823   00:09:58.661743 fcntl(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, F_GETFL) = 0x802 (flags O_RDWR|O_NONBLOCK) <0.000018>
823   00:09:58.662034 read(37<TCP:[172.17.0.2:33256->10.7.7.47:6379]>, "+OK\r\n:0\r\n", 1024) = 9 <0.000019>
823   00:09:58.662808 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 140495459}) = 0 <0.000016>
823   00:09:58.663585 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000051>
823   00:09:58.663952 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\312\242\206H\362]D\355t\354\300S^\2330\263\255\270\264D\225C\373U?\246x,T7\n^\26\350<\204\273\3M\316\321\363\372\204\354R\374b:M0\233\347\16\241\332\362\10\f\364\361\373\343;*Jk\340'q\271\317\366\263\223\260\222\252\336b\240\357\200o\2\254\245\241\317e \257\235i_|\4\232\\\213\245\242\22a{\271$\271\213\27T<?8\323\v\344\26\237h\200$W\214O\272\1u\3\364\v.\273\307\266Q\6\27\372\20\304\371\336l\21NJ\1X-&\r\314\3640%ow\347\220\216\340U\213\310\26x\303\210\246\304\235d\325;es4\241\377\350\306\33\326_-pNn\232\202\227h\315U\362\207k\273\263V|\242", 207, MSG_NOSIGNAL, NULL, 0) = 207 <0.000038>
823   00:09:58.664306 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.664616 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.664948 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0_", 5, 0, NULL, NULL) = 5 <0.000021>
823   00:09:58.665263 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30a\265\303MW\225\351\364\212\233\273\235\254\273o\233\t\264\315\243}p\245yiy\f\17\2207\16\371\336h\344\304\36\2713\246\257ko\346\331\236\\\321\340\4\32\353\275\364\323\240\200\v=\252\275\314\355z.\323>\233Kq\177\237j\230u\323\250Pz\335\230\354A\307\242\334F\322", 95, 0, NULL, NULL) = 95 <0.000022>
823   00:09:58.665698 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 141569212}) = 0 <0.000017>
823   00:09:58.665792 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 141634168}) = 0 <0.000016>
823   00:09:58.666250 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000024>
823   00:09:58.666584 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\312\242\206H\362]D\355u\311\265\5\367\342g\256\256\270\221\330\377\341tH\rw\26\2415\312i\203\27\224\251\301T\353\276\206Y\271%\215\300\306\22?\25\1\20\30\270r\231\275\375\3528E\177\352\226\323\261\3\230\264\200\35\241\t_\31A\344\4\24\304\36\246\303\3606\4+T\341N\21\26\250\343k\345\200\2210.\257X\315\37b\266\260\24\337\37\317\2005\r\f\242\277\36\227\242\324'F\325\363\323\255V\336a\351s\237\246\320\376tyr0\23\16\263V\336\271\312b\266\22\5M\33#\201u\305\5A:8\327\235#\5\16\323\266aH\372L\357\227C\v\240/\370\311\356\245\201zvm\232,\341\10\227\v\333\240\265O\2\360E\201XC\334\204", 207, MSG_NOSIGNAL, NULL, 0) = 207 <0.000039>
823   00:09:58.666923 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.667233 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.667605 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0_", 5, 0, NULL, NULL) = 5 <0.000015>
823   00:09:58.667901 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30b;Ykk\n#~\31\263\217\365\16|\20\257\334J\0\36\261\f\335\21\302\227V\324\376\20SJ\357Z\224\246\211\333\247\225\273\254\365\353\334.\215\205\237M\320\f\342\234\270$\350a\252\320\33\272\324\242\21\347\261\346\302+\274\\\246_\346\322' q\344\363-5v\360\205\343'", 95, 0, NULL, NULL) = 95 <0.000018>
823   00:09:58.668316 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 142372989}) = 0 <0.000015>
823   00:09:58.668384 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 142413821}) = 0 <0.000013>
823   00:09:58.668438 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 142449513}) = 0 <0.000013>
823   00:09:58.668868 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
823   00:09:58.669193 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\312\242\206H\362]D\355v\227F\217\0\275\254\20\331h\314\36/\216\33F\6\273\215H\343%\225\341\220\306\37\253\363\\\221\10n\337\340\37{Vn\373\263\213\357\254\354\t.\3\3Zm\322gq\3748\370;~\306\323\373\3743\304c\2020\365\207\213\235S\375V\223W\4ojD\211\365\247me\267\250\234\337\233kL3_f\360\360\204}8F\310\261\373\333a\357T\353\1eJq9\206\266\240\341nO\240\265\306\\S\26:\250\373\t&4\220\350\344(\362\366XD\274\345\20\t\234{\272\27\211\360r!\270?\302{\202\365\272\343\236\343\363+\274\3c\244\210\257\247O\26\33\335\5\23\255\v\212@C\211KSa-B\371=\360\246\274\343", 207, MSG_NOSIGNAL, NULL, 0) = 207 <0.000035>
823   00:09:58.669517 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:58.669819 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000019>
823   00:09:58.670158 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0_", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.670461 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30c\27\264\260\346x\366\253++2\206G\366\365\3010\6\250\343\306\337\213^\324\3252\211wx\v\31\373\341\234\345\230\303\310\326\t\362\364i\v\370M5-5\35I\341\251\35048l\f\325\243\31\352\342\326\360\337I\257A\253\310\370~\262oQ\224pd3\254\261\32+\343X\217", 95, 0, NULL, NULL) = 95 <0.000021>
823   00:09:58.670885 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 143168958}) = 0 <0.000017>
823   00:09:58.671053 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 143307794}) = 0 <0.000017>
823   00:09:58.671198 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 143426231}) = 0 <0.000016>
823   00:09:58.671256 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 143460887}) = 0 <0.000015>
823   00:09:58.672411 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 144594268}) = 0 <0.000019>
823   00:09:58.672488 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 144634013}) = 0 <0.000015>
823   00:09:58.672597 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 144721729}) = 0 <0.000016>
823   00:09:58.674106 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.674445 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\221\242\206H\362]D\355w-%J-\375c\2449\177\321\351%v\313\371U]\246\337x\207\372\t\t\23\223\254\233X\326K\230\264\202\225c\200t\274\254\373\235\347\373Y\r\372\rC\303Y\321F\255\334\277.o\332\265\37\347\344S\302\235\375\27n\277\21\270\20\215.\340\347t\222\330\305\32\2`k\r>\247\376b\22\217\314Yk\305>YN\264\213\374&n\300*4\350\220\t\230\6\26\200\233\331R3\234QXt\352\273]uP:@\260Q\255\363\213\323n\6", 150, MSG_NOSIGNAL, NULL, 0) = 150 <0.000039>
823   00:09:58.674784 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.675093 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.675439 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\7\217", 5, 0, NULL, NULL) = 5 <0.000033>
823   00:09:58.675771 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30d\371\t6i\33\303\345\277H\303/\240d]\325\352k#\213}p\3156J\204\337\\\27\326\354f\16M_\177-\352\3748\344I\254\236\234\372n\t\2\256!\351\2\16\17\331\322\267\257a\272\367\256\naw\250[s\232\6\2305\344}h\0\237\\\207q']\314\0\234\224\6e\354\267z\212\37F\3737%\213\345\264\374\255D\340l\367\243*\351\200C\26\251J\0017K\354\210\341Y\315~\10o\350\204w\2\225q\347E9\27\305\346\303\357\364\222\7\364\370\272\201hX>\314n0\3\34&n\246\342uF\245\27\370e{g\212\321\311\374\237}\314\324\322eYH!\350\37J\36\v\316\335k\257\372\346=\211r\370\177\317\212\356\355\212C)\234\313\231O\213\345\211CD\204\365\30\301\351\270\20\214\257n\36<{]c\226|\344\272K\333\16\212\310\205\2\21\3n\0216S\322#cw\207\vA\363\315h\207#Z+v\257\322Z\307\314\355s-\17\270\374i\261K\236\27\313\261\305\"ROZ\242]\307/v7'\315\376\262\36\261\201\243\265\337\240\377\v\304\333\360\353\344\4*\2072\211/%N\213k\352\201\330\202\237!\24\16^\251*L\270\207\364|W\4\303\327\27+-c6\34\334\217\357pi/j\350i\204\21\v\201\177\2404\216\276\\\203#w\277\366\262\356\225t.\2336o\3`\374l\223\252\355\376t\350\274x\1\342\303\204`\333\304hc\347\225q\f\234k\314&\237\265+\0|!\256\2505\214\206\25]\4\23F\352\1\251\311\375\272\362`\314\371\363PK4_\350\345\232\177\36H\247\216m\f\224\227\357Dl\26\r\v ,H\315\303W\240k@\263e\343\316\314\247\16\26\355\324\244\267\267\2411\212r.\27\325\6\310\324v_\271\16\0\10\v\275F\251l\363\201!\23S\236\327\335+\247\260B\351\357\321Ek\7\322\360Y)\204P\2472:\5\265\343I\201e\177\325I\224Vy1\262HZq\r\306^>\207\224\243r\241;\277\366 \266\3578\317\24\303\247\202]\366\200X\252\n\316\304\340\213\311\323|\360v\246\240\376x?c\202.\357\337\271J\363\273\326\3560\326\276\356\243\200CBdg`\36G)\253MX\203\2\313\364*-\266\221p3p\31\337\355\331\335\35\0\263H_\3536\307\266\20\340Jr0K\34\1\330\377,'\221\21\204\331&\260#Y\7:\177\2455\251\362\367\305\276^\221kG\371\275\317S7\33#Aw91\343|\305QTR\224\16D\340$\377\276\311>a\355\262,\222}\264H\256dM\234\226\343\235\272\321qv@\301\353\270{\251\241\370Un\321Y@j\2454\3654\366\343\351o\22/\36\263\347\2443\331\333\225\37\300\231\3035lY\1\264N\307\3038\266\24\236\314\36\271\276\334\244\260\271!\374\303Z\370\354\325\5\26\253v\35J\333\367\344|\246\211w1\254\21\346R\263\233\244\237C:%\320\260\351\27\341u\263\260\257\307\266e\243\314\233\376\217H,U\f\266[<\273g(\335u\24wGR\247\"BV\f(Wg\7\203\203\3761Q\244\343\225\206\217\355\256\313]\270\235\234\31\177\232\354\252\360\326\233\304\204\34\357\277\333\373HS\325\335\201$MS\274\340b\233S\316\311/\245\32If\233\354|\37O\v\240\353FA\351\223\222\24`\177\302\243`\322p\217o\33\273>\245=\267}\204\252\2638\350@\241j\217-a\354\376\240\332U\272\31\16\3702\4J\36\236\334\237\326V\212Y\372\353i\251\227\364\320\345\7\270\316\223v\202e\273\330\311!X\266\7\24\246/X\275Y\374\341\260\244\205m\371\21\257?\264B\306\22\177l\237AhA1\27]EC^\250A@\321-\335\10\3"..., 1935, 0, NULL, NULL) = 1935 <0.000022>
823   00:09:58.676765 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 147096591}) = 0 <0.000019>
823   00:09:58.677242 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000024>
823   00:09:58.677579 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\266\242\206H\362]D\355x\377\271\371DD\270\20\316\261\f\311\276\310\306\2631M\217\1\346!\266m\260yh\313Z\264j\t\t(\366\3153\356?YF\211\276\22\220d\251\3}\202\212]\234Y\\\311\352\243qOo\1x\371\354\263\277kZM\300*^|W\205\207\347\335\275\22\325\222\360\262\17i\271\325\202\4:\342jq\230FJ\203\371\336/\370n$?u\262\"\352< \345\367\373iA\264=\344\312\244P?\245*B\264/\2070,\355\365\317s(\364\351\3560o\263\304c@61\303\315\1D\326\264j\n\33}\351\357\263E+q\223\313,#r\5>\205\217\235\237", 187, MSG_NOSIGNAL, NULL, 0) = 187 <0.000038>
823   00:09:58.677919 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.678228 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000022>
823   00:09:58.678559 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\213", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.678863 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30e\245\276ns\17\3248\326\261\352\355\10\323\271c\311\301\310\316\224U\252\1\352\217L\2550a\316\300/\23\33P\233\10\326\244@ m\210x\357\301\203F\37\226x:,\f\327\303\25\207\270\252\312\333\21\nb\211Y\216\366F\373\247\300\351&\224`\10\335\17q\222\301\272\36\361_\255\2h\2526S\26p\213\310\3649\204I\252\231p\371\337\201\266A7P\300\r1\33f\352*\272\n1V\354\330\6\365\352\324\205\326k<$a$\3775\241\242\2p\211\317\201\270Z\34\367\25|\320\304Hq\336\200rf\"8\242aM7\35H4\32\221\233A\370:fJ\215r\30\3540\"\370j$\373\334\261\255\246%\3601\271`\340\232\312|*\353\203E\7\337l\343\271v\256j?g\210'\262q=\367\235Q@\6 ^x\22\237\324z\0\311/d\227\311pH\6\271y\211N\n\352\3673K\363\0006GdD\35\v\371\221\351\201\221\201^\211{\\3\366re\357\264\311:\177\214\257\"k1\0034\345\256\24\347BQ\213b\366(a!ZP\331\"\226\36\322\276\327\252,s\0377\f\7=>l\r\246p\\\240\243\213Q\3\7\231[\367\2706~\24\232\307\21r(\255L?H\357+ZC\326\33<\0\252\367|=.\355\254!0\242x\204\232\364\374\356\320a_\366\241K\nM\211\227A\315?.\2366\222\212^@bXB\315x", 395, 0, NULL, NULL) = 395 <0.000021>
823   00:09:58.679612 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 148177143}) = 0 <0.000015>
823   00:09:58.679668 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 148201001}) = 0 <0.000013>
823   00:09:58.680040 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
823   00:09:58.680364 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\256\242\206H\362]D\355y\250W\326Q\302F)t\2629\177\35\344\r\371\305\264\7\233\270\2551O\260{\373\201V@\204\200\243%\212\267\357\343\301\373\303\250F\3054\v\2\210\27\312\310\361\375\371\313|\21\310$\267\252\2276M\345NJ\305a]\264\236\341mp\221\241}\21PU7\361\v\310~\245g\333\335\224{:\366\0\304@S\365\346\23{$u\17\266G\367~MR521\324\277$\307a;\235\\\232\355\7\1\10$\223:^\207\344\2539\10\0378\3\325mC\356\34\263U\311\264/\3313\327;O:\0369S\3101\244\10n\334]\10\372", 179, MSG_NOSIGNAL, NULL, 0) = 179 <0.000035>
823   00:09:58.680756 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.681092 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.681424 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2\r", 5, 0, NULL, NULL) = 5 <0.000019>
823   00:09:58.681761 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30fp\26\3\202(\343\270\345\363S]\26\263=\6{.!X\321=\255\330\322\233N\301?\265\365\370\251\222\10\375\30\302[\27\217*\231\277+*\303+\376~\t\35\370\325\354Tc\227)\\q\305A<\371Yk\207\1\177\361\261\321\327%\341\226\20\256r\177.\317\227UGJ\10e\334\204\357]\343\225\333\351\223FP\374\247\245\231\313\247\r`U\224A\32y\206\361\272\255o\343\243&\315\246\374\10\"\377c`w\245\21\1X\5\204o\342x\236\17'6\373#\342+\201'\262\315+a\247<V\351\335b\202\344\342;k\341\2K\246\22\221\321\242\306\243\254\225?\20\356\265\36\244\7\247\374\204\2170\"2\214;T\221\36\0239m>\372@st\345\34\335\7\30\241(-\255y\261(\n\2525H\233\260HA\210\4\3317\24\223\1/\374s~\320\365\24\365\241\30y\4\310o\322+\321\315\230\262\2035wl\353e\371F\210\264\347>J<\300\30\356i\207b\31=\376\3=\234\341\204\333\244\357}(J\210N]>\2666VG\27\5D\372H\217\37 \37\207\304iw\375L3\337?E[\212%K\337\211\221\315\375\340)\241\1\263\16\210t\27\266\260P\244N\265/\351\353lY8\275k\202a\7\210\f\255\214}\271\332\220\316\354/\245\354v\272G\261\322\213\316b\345\33y\271\236G,=\337\37\345C\1\f\372\243a\0207\\\314\202\222\211@\305\307\325\331\0245HO\0344w\266\227\346\245;\0r\26?\212\323\334;\244\205\236\\A\24rvs\27\211\216\220k\230f\n\365\22\265=\264\206\361\266=\215~\223\177\243&\36V\371\0F\303\2447D\376\363\323\6\306\262\212\2564e*\200(p\217\231_A\352/\317\370\37\360\354\345D\4\204\223\2110\370_-\234dlcS\203\225\357\352\245\3763+\236\263\27a\345\361\345\251\307\204\235\\\323", 525, 0, NULL, NULL) = 525 <0.000022>
823   00:09:58.683265 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000061>
823   00:09:58.683643 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\320\242\206H\362]D\355z\327\260^\314\375\202\202l\214\201\243\230\225\25\253\360\3436\301~\177\347zj\233\366\317\16\225.H~-\217\352YC\216mgO\364\210\362R\353\251X\325\230|\361\27W\25'\346&Y\17^\323uE\214C\343\256\233\200\22\237(\4p\264g\242\213\375\3531\241O\320\366\25\4\37E!+\271\274\2000\215\312\360\277\337K\20\204\253\232/\32\255\5d\237\360\301\357=|B\213\210*9\367\25\374\255\236\v\10\\\277\226\"m\233\313\216\371B\273\250$\367\277\237;\244k\372D\5)\n\227\352\0\343U'\316\256\215Wv\t\235\276\263\32\323\220f\316\376\246?\252\247h\35\241\307U\2043\330Jo\216:\234\315\213\10\266\262\263\234\226f", 213, MSG_NOSIGNAL, NULL, 0) = 213 <0.000038>
823   00:09:58.683978 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.684289 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000090>
823   00:09:58.684671 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\6\206", 5, 0, NULL, NULL) = 5 <0.000033>
823   00:09:58.684989 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30g\325;\23\re\340\327\313ka\256\30\21C_\0107\232\215\377q\2?s\245\275]\273\0051\260(kl+/]G!\365\235]m\233\215\f+T\213-\272\230x\245\320.\211}\2355\22\276\222\337f\224\204~\345n\177 \27\26\304\264!B\357\317N\243W\371\254$\6r\310\373\31l'\257\216\370\357\372\211\24t\230m\332_q\257:1g\235\207{\327\352\353\205\233\366\211\303\223\237\270\361\1\304L\204\320\217\300/\263P\306\336\2\300|\260\260\2\277\243Q/%@\17\214\227G\227Oz\26\266\252\37j\311\303\6\217\f\35326\246\3178VW\f\262m7\322)\37\255V\336c \221\21R\221\350\325\275\203W\330\335\347\306%f\314\211b\263\324\276\25,\16\25\\\31i\355-\356\260I\17\363\372\3522\222t\251\211\245BK\357\271\352\327\17:\366\260\334\337\255\336\251\211\316\214\210\313\236\273)S'\242\334\225\351wc\36\373\234^}\241\17\36fK\\{=\301\261=#\231\214\37\2261\307xf\272\213\351c\251\250\336$\\\366\204\205\303\276}\367\313Q\215^cu\177\6r\33s\\\222\365\335\215d\312eK\7\200\246\211\232\230\177\355\307\247p\2566\243/\26\221>\24\227\326_\0168\317\377=\367\340s\373\360\376\234\371\361\26\353\236&\277\330s\300oP\177\37\227\277\363X\260+\336\250\307\203\326W2*L\270f\2{t\3057\232\5\377r<t\314\277+\36]e\274\17\370\32H\233\301\35\273J?\371\343}\257I\310\203\225Sz\232\366\302\357Nq\310W\301H\226>\242\357[\5\372\v|A\273\376\330\242\277fo@\272t\341\fl\370f\203\377\212\1\335\263\347\216\6\232\16\17bU\315.\32O\244n\10\25\314Ng\23\220gk\274\333\363lo\332\263%G\321(:\223(\f7\336\210\"\275\351\2\1\255A\215\305x\227\\]X9V\304\263\2274dg\313*e)\224\304\0338\202\224\"\351Qn\317\3349\233\214=E\37r\227\313\211Lp\272\3073M\351\350\273\255\304Xr\335T\25g\300\365\324[\362M\22\327\315>kv\vM\346m\n\270\225Q\202\345S[hS\322-K\17\346\200\321\2572+Q\35\264\347\37}\"\221\357\321*\351\32\31\353\274\17~\205\231\334\4\372\340\212\230\0\246d\231\211\r\0361\342\272}\256\342\325\317\203\261\333\235\300\230\257gX\rG<y\314\267\237S\357\337&\254\200\373\\!\342\360\376\221\326\346\301\2\353\311j\227\263M\315\36\247\305e5\17\232!q\233.d\253\375\234V\254'\315\36\22T\302\241E\33\35\214\317\353\207A k\203\245i?zu\337\243X\236\304\364\213\327\342\17\352BBI5j\276\350\366jy\321\335\24\364b\24-:\257\f\201\344+\16I\362\264\21n \20\221\200\2750>sb\250^\255\331\256\\\217\306\327\346\342\361}&\4`\301.\244\362\236\332\twF\370\271\351OI\20 \33\200\37_\26\20\236#\333\177s\17\311\356\250$\2757w\332\4\310\302\355d\23\fJ\37\335>\207\334B\27\242u\277\337\23678\221\227\352\0053\240\217\336\222\260_\371\371rX\21\201\272I+\21z\234Y-\265\262\354fi\364\273\304\252\215y\tN\262\376\3516\0002\222{O\200\0023\301K\372i\n\306w\200\3145K\342\230,\23\213\230\232\271\212\177\234\345\242\230\341/)\226eb\253\374T\225k\310\231\257E&\n\305\\\16$\25(\363KU\217\277\0326rh\30z\271\241\203\212!3\363\300z\267Z5@\315\30O\276\5\255=a\271\270\301P\f\354I\300\20\301<;\301\17\332`\277\321\235\210\264\357\316(\3614\306\0318B*\265O\17I"..., 1670, 0, NULL, NULL) = 1670 <0.000022>
823   00:09:58.685778 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 150602379}) = 0 <0.000018>
823   00:09:58.686179 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 150968090}) = 0 <0.000018>
823   00:09:58.687003 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.687341 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\177\242\206H\362]D\355{\1Y\1\224\202^1\26\233q\245\20I\241\341\277\27\"G[\2\307\245\313$\320e\373q\275\351\345\277\362\200\315)\27\377\273\275\220\334\334\226\36\244~]\357\364q\223\222\217\263\0265\350Tq\315\236\212$\336\331F\24\340x\363m}\304\202\334y\276\267\5\367\226*%\"\6\22a\215\307$7&r.\274eU\27u\251\235\242\220\1 \332\235\1\34\267\232#3E/W|", 132, MSG_NOSIGNAL, NULL, 0) = 132 <0.000034>
823   00:09:58.687688 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:58.687992 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000073>
823   00:09:58.688351 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r ", 5, 0, NULL, NULL) = 5 <0.000031>
823   00:09:58.688667 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30h\0M|\233\375\35\37\216\370hD\204HG\235\t\25z\263\4\312\224T\"\30t\354\326\2661\250\316A{T\313\306\307\232D\224\270\344\240\6\234\375sW\4\232\254^\3&\271\261\244W\31Q\341\263\220f]\204\216K5'\30)\17\26\265&m\372Y\306\303\264\256\262\272W[\364\202\16\241nw\30\37\n\302\206\31\243e\326m\213\337K\253\351\6Ttpr\347\336\324\37\253%\306Q_\31{\3046\346H\245\260\351\337\4H\313E\301\317\223a\221? \f>+\260\326\5\f\237/x\\\372\200\376J\351\222\263\2111\236\214\211\6B\4\37.jd\224\3\247\37\3p\322M\205kI\230~\232\7k\7*\337\345\4\7\206\360\26R\35\230\37\343\311&\313\267\230\213\270\270v\256\377\313\265\321|\334\t\331N\277\20{\303\2638f\10-\202c\21\246\262\277\321i8k\342\306\4\310\273J\224k\6\243\273\316\235Qx9(\25==\211\246{c5\4\256k\276t\370\2464\217\322\340\322\206\347Pu\204\231)\16v\321\303H\273+K\17\215\237\3008\366)\202c\226\271\325\270v\323?\t\275\335DNp\254\301\"\22\270yB\246Z\330V\310!\210\345\373\357`\376\323\355'Q\263N\233\351\31o`\262\207\305AZh\357a}%\361\330\2624W\216\210/\354\352\215\314\357\0\17\220v\364\357;\\\212H{\35\30\351}O\16\312\213!Z\2246\f\222C\177\343\rL\244\325\1m\33\251\2719.?\265\216\240k$\255%\311\0028u\200\345\241\0>\262l\257\226\37\33\30\4\226\16\17V\35\27.<\373V\337\371\3408\213\217\236|\313\203\255\271Kh\33\312\260U\220]\20|\307\24y\242\34\230*\272QP\2608\336\37\212\350\341\177X-\324\337\23:\35\221`m\352\22ct\321\231\7o\213dN.~^\352\201\377\341\241\317\221 \336:1\253\235\330\242\326MF\0\225\0056\215s\20\2025\273\235\323o\270H\25\3503>\206\203Jh\252\6\326\376\306\376\v\37\360\340\205\257\365J:\305\6\371\303B@\223G~\6~\253j\222/:\32\357\23\25\32\36\256\200O)d\20\263#z\20eF:s|\6\335\332\nS\230c\301<`\206\373sDy \373\272\265\31B\24\267Iqv\243\323_\223/I\304_\20d\365\275\375\2227\r\267\235\302\177\20\260\311C0\363RP\374\311\346\377\3560(\245\25\256\243\272\361\202]\304\334]h`m\260\314\22\324\227\204ox\237hj\364M\200\222\3\330\276\314>\333\325\t\354v\f\341\232\230xq\267\266\16F\3243\224\304\307E\253\204\371\224\263\371\271\37G\3153\242\343\340\23\32\310rf\36\10\220\\&9\325B\211\207\10\206\246\17\372\t\362jF\313\254\23\235\243O\7\313\335\304\177\341/Z\314\34_\366\313\24\320\7\322\316]~\242\205\24\26\310\216\1\251\376\324\236\252:h\251\320Q\234\346ZY\327\0365\315\374\2463Q\3\340\2155[\25\363\232\351O\361\311\v\232\245r\351\317\257\326[-\366u\2318\365\275V\272(\206\275{\264\316\277\347\210\377\240}\301V?\26Y9\264\235r\215g\266\377G\226\177u\34\320\215\265\237\216s\0\244\201;\237s\215\22\200\30\346Y\313\354\255qE`!\342\247t\324\371\301\217\22X_\231n\v1\236\2447O\322\221\225>\343\24d/\372\215\214\345\217\352\204\3348\245\226\25\272\205\v ov\365\311\275\357BDH\6\353\34\335.\366\213HL\221\24\37T\v\356E8D\300\270\30>\225{\330\241\303:p\253\340\320\355p\353\307\32FC\"\251\320\334\250\342\307sL\316\227\rx\227\207\276\325ZI\33\325\351k\217W|2\315\375\334m!"..., 3360, 0, NULL, NULL) = 3360 <0.000018>
823   00:09:58.689625 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 152581816}) = 0 <0.000016>
823   00:09:58.689693 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 152616804}) = 0 <0.000013>
823   00:09:58.690289 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
823   00:09:58.690620 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\234\242\206H\362]D\355|\243\325$\276\30\251W\316\252\220\263>\266_\227V\333JE\200\213q\343]\355t>\243\266\256 U\363j\374{\351\257\323\321\264\335n\357\346-\362\320\343W\353\36\32\257\37\4\311\337OJZ^rRC\324\337\320vu\n\347V\33eP\233S\3307\277\353\200>z\31i\200`\314\324\220P\220\22`\\\215Qg\242\27\310\245\212\304g\246ZD\357#\1\234\331\365\367OU\265\21>e\321E\343\230\37Q$HA\265DAG\273\346\361`\31\345\340p\206\267\232M", 161, MSG_NOSIGNAL, NULL, 0) = 161 <0.000035>
823   00:09:58.690945 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.691270 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000024>
823   00:09:58.691617 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\322", 5, 0, NULL, NULL) = 5 <0.000018>
823   00:09:58.691914 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30i\7\357DB\252!S\21\205\30\271\33\245\277jJ\363(k\247\211\362\365\230V\214\23m\26\"B;I\370\23\7\340\241\5\223\3357\33344\2368\350\200\21YP\260\30\370\223qbo\314\243\343\2\354\206\"\250\257S\0\236q\336@\t\275\363\261J\253k\345\330i]\230\33\253Bh\241\343\2\271h\320u\204O^^\302\345g0}\36\236v\7\333vi\323\311\204\221\264\27\343[\17\36t\324\366a\23E\17r\221\7\337p\231\205\33r\35+\2769\216\310\364B\321\306\30j@n\311\3004\241\256&\263\271\227\214xW\t\253\357\275Ju\314\2)\303\370\302\366\4%\213\270\270\355=\353\331\265P\310z\364\307\22B\f)\362B\201/\36", 210, 0, NULL, NULL) = 210 <0.000018>
823   00:09:58.692455 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 153610975}) = 0 <0.000015>
823   00:09:58.692513 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 153638611}) = 0 <0.000012>
823   00:09:58.692570 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 153678153}) = 0 <0.000012>
823   00:09:58.693038 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154127615}) = 0 <0.000015>
823   00:09:58.693110 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154174383}) = 0 <0.000013>
823   00:09:58.693149 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154194450}) = 0 <0.000013>
823   00:09:58.693199 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154227906}) = 0 <0.000013>
823   00:09:58.693239 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154250181}) = 0 <0.000013>
823   00:09:58.693277 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154272029}) = 0 <0.000013>
823   00:09:58.693312 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154290625}) = 0 <0.000012>
823   00:09:58.693354 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154310525}) = 0 <0.000012>
823   00:09:58.693392 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154332127}) = 0 <0.000012>
823   00:09:58.693429 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154351846}) = 0 <0.000013>
823   00:09:58.693463 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154369757}) = 0 <0.000013>
823   00:09:58.693496 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154387138}) = 0 <0.000012>
823   00:09:58.693531 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154405418}) = 0 <0.000013>
823   00:09:58.693566 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154424593}) = 0 <0.000012>
823   00:09:58.693600 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 154442029}) = 0 <0.000013>
823   00:09:58.693754 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:58.694076 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\216\242\206H\362]D\355}\2\323\3455\374/\25\344_\2319\256|)\2771`\225\264\3\361+y\341q\362\377\254\352\312\26toJ\215\305\307d\r\342\f\237\355]\315\333\362\303]\230\226\221\2274\20\376HJ\4\264\23\237\6\26\26\267N\272l\376.\205\2720\355h\344\212\362\306-\30\242\3\300\1J~S\342z\35\333\302%\243`w\34\330,Q\23\354-\177M\217\r\214\266\304\ncs\300\n\310\211\313x[\232a7\334'\257[\"\247\32\242\336", 147, MSG_NOSIGNAL, NULL, 0) = 147 <0.000035>
823   00:09:58.694399 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000018>
823   00:09:58.694700 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000120>
823   00:09:58.695105 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\r0", 5, 0, NULL, NULL) = 5 <0.000030>
823   00:09:58.695429 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30j\177\315\21\20\223\246\206\230\34%G\304]\343\24\226\0Du\336\314\22\17yve%w\6\211\225\320\360\304\340l\324\320\17v\227{Y\277\30\332>\6\n\\\320\327\343\212(\377\357\241z\2\26\237K.\344\360\307:\325\24\207\213\264\1\224\335\222\203\257\1K]\212\321\316\311\341\245\200G\246h\322\205V\261\331\321w\211)\201\334\261p1q\0N\nr\34iy\16\364PH\213\204\370\320\200\264\366\307\35\341:\311\334\257\254M\227W2\1\215\ruV\237E\354An[\315\307\f5\321\321\344\363l_\21\2317\252KS\3\342\371\300\227\322%\224>b\20\214\360\fi\240;\221\37\363%\253'\0\256\235\246\324\320W\17?\324\232\353\260\255\30\236\377X\214Y\26M\4\\\320-\34Fz\210@\265\310\341\311F\217\366\263d\360k?\333\354\262\244\342\216vy\303\332@Zb \305\302Z\331\374\271L\242\322\rI\367\343\333I\v\24?\277TN\235h9\21\204\361\315T6O\203\315;/D\21\3234\212\360\37\341i]\35\215\216}[\244\312\272\210\223\341\267\216\17\5\2631B\340\6O\252\301\254\262\31\273\26\341\266\200\25}\3540\237]\31\t~$\315\235\350^\7\10I\367T\230\242\344\220\373\10\237_t4_+\30\224\1\265,Aob\35\215\340X!\375\326\262\321\352\304 \25}\26\354h\265\20\363\315@\16\216\247\261\241\2\31\347\312\326F\312\24_4y\310\21x\232x\r\316\20\361\245\333\375\353\235\354\353\235\2204d+\353\345lH\10\305\26\264\372\256\233dI7\356\232\351\322Q\177\376\224\24\34#\277cQ\331\363,\303A\7\7PYW3\225\7\324\27\2761\300]/<\262\257L\335Bb*\0\242\336\26\366F\363\274t[4<\\@Y\326_P\232\250z}\250\324\31W\234Z\332\373\353cw\201\234\227\376\325\33\0\222\266\312\353\267\333\217\207A\233\357G\202\243k\253ywl\271\21\373\277*p\351\377\304\26L\213\211\22\342\200\316*':P<\4\36\6\7\2566\264\2077Gq`t\374\312=VcJ\230\310\360\"\204X]\327\213\7\363\256\374\333\334\304Q\331t\256E\326\22\202*C\354\200\220\243/\205+\207\16\37\3343}'(\254 \312\370%\331\"\3\362\372\245E\265\32\211\373\20\227\373\216\360\2379r\327\232`\255\246&Q\273~7\30d\247\320\211\32\253\213w\2222\200y{\262\215\346\210\217~n0n\373^\311\205o\203\330n\247?3z\334\307(\344\311fM5\rs\374v7\310\25\240\206\5\360]\207\32'\272-\335g[\333h\371\266Ir@\220YuG9\256\310?\345@T;\362\323\nX\t$\0209\35\253\262\233cq\2244\361c\272\240\1\264I\\\v\16\336r\n\271\242\323\225@\221\226\215\236\360\330\257`\177\203!\276\227\232\215$.\360g\227\203\206\344\362\316J\257\266\370i\0^Y[i\334\10\206\351\273Vy\23\21@\203\224Q\207%%\352\300N}\"r\3\34\353\240\224\366^\277>c\272\271\264~:\376\340\f\"\"v}\\\324\f\363\243/\311\334 T\211\326\225?4\24\4\233\334Q\33\3307\331\3225\236~\310\220\242/\0k\362\314\337\224z\3\302\220\f\36\331\306i5o\236\200\307|\330V\nx\250\304\0\215,l)\324\306\223\200k\363\16\377\10\232\16D\275m\236\305\355\331\255@\37\365\276p|\217,U\323<\"\235>\v\203C\370*a\360\37\241\312=L_\311\326r\374\0\346\340j?6FV't\205]\260\6!n7\267?a\367m\30.\207i@)k\273\312\317\376\2473\236\271\276\377\374G.\tm\v\23W\260N\230[g\256\333\352\30\341u"..., 3376, 0, NULL, NULL) = 3376 <0.000020>
823   00:09:58.696455 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155459215}) = 0 <0.000019>
823   00:09:58.696521 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155489474}) = 0 <0.000016>
823   00:09:58.696564 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155512534}) = 0 <0.000016>
823   00:09:58.696613 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155542618}) = 0 <0.000016>
823   00:09:58.696654 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155565191}) = 0 <0.000016>
823   00:09:58.696698 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155590185}) = 0 <0.000015>
823   00:09:58.696743 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155617205}) = 0 <0.000015>
823   00:09:58.696800 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155655332}) = 0 <0.000016>
823   00:09:58.697020 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155856373}) = 0 <0.000017>
823   00:09:58.697069 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155880377}) = 0 <0.000015>
823   00:09:58.697111 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155903309}) = 0 <0.000015>
823   00:09:58.697154 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155928270}) = 0 <0.000015>
823   00:09:58.697195 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 155950809}) = 0 <0.000015>
823   00:09:58.697976 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.698317 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\377\242\206H\362]D\355~ZK\314\335\247N$\20J*J\345\320\275U\262\"\24kx\335[\220\204\203\215\2039\311\2106\210\217\366\313\rP#\234\31\224\366\341R\375\210\341\277\17\266\232\235\n\37\354f\201\6\303\253V4r\353:$>\275\226:\220x\273\22\3\r9+\351\320\354\320bQB\330\0342\t\3)\233\22\306\360\225\16\2\240\250d\357\4g\265q\246\265\214\260\326\273\275fi\256]\274\341\16\217\27\230\334,d\367\354\343\222\221\226$\270\336#\232\314\262*\253;\246\33j&\31\373\246pt\220\310b\213\36\273\375\34A{\335G\223\2149\370J`l\rN\271\243\361\360\201s\353>\0+\212\360\34\265\22\320\276\23\351\323\20{\347\232y=\221s=\21\310]S\255\245\371\325\220\35=\220\202U\306\r~\213%\4\r\237\2761\331\272\244\373L{x\363\274\334N\276\345\255\317J\376\2778{v\305", 260, MSG_NOSIGNAL, NULL, 0) = 260 <0.000038>
823   00:09:58.698652 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.698963 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.699294 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\5Q", 5, 0, NULL, NULL) = 5 <0.000018>
823   00:09:58.699652 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30k\302\37\242E\320')\26\23\304\232\204D\220\6\365\304}\2260\326\311\326\23\372\312\241\n\263[\363\276\342\365\6\36\200q\226\v\255\337\305\333\230_\276\276\35\f0\251\344\354Q{Rh\306\205\250\322M\357\331$\343\256w\301\202}N5\37\226\202O\205\16|\363\236\16\224\321/\254\367\233\346c\"\325.n|]\7\325\2239E\30\332\201Yr\343\367J\305\2520w\340^\221z\0106\315Xc\22\2561\202\323\262'\16\214\354/\357\207\20L\1T\222\26\264\345\370\222\373\276i]\317 \322\354\341\253\204\231\377\22\232\254\v\357i\240\330%\326\320Z\342<\271=+0T\334\224&\v{\3366\3509M?>a\232\\\355\266-]6\363Fef\350lj&\264y\203X\"\256O\4\331\\\f\3521\246)\177\273\0057D\212~\250\253\3vR\215d3\3\242V\310\4\344\"@[\244\350\350\362\306\3\373\314khBs\7\25\260\256\307\242\210\n\261p\333\305\320\254\n\374\251\22\v\362\2448\17\263$\355m\340>;J\246\32\215\351\377\32\201\274\v\347\365\223\24u\240-\262\325\312%1.\362\316\320\227\376\224\377\250\253\1\234\27>\357)\v\302\246\341\377!\32B\275\n\223\32\0005\321|hQAN\21Z(F\346\253\327B\312k\202\221\3729$?\233dK\306\317\266:\330c8S\220]\315\320\37\22{z\320\237\224\17=\204\371\202^!n\3425\241\254\262\246{p\332H\267\313/35 \237\326\334\216o]\226\"\270Jj/h\204A\345P\311U\242\10\202\335\5\265vG\333y\257e\340G\35\361\244G/\10\217VBA]\211M\3113\0204\317\n\235\243S\306\236\346\353\2239:\\\36]\237\30\\y\233km^\362j3\205\356n\354\310\373l\377 \351\21C\230\354C\221\230\24\302\271\325\307\367;\371d>\334\371\232\2\3750\17_Y@\274\371\264\350\372\224y\20\343\277\214\34&\213\323\257$3j[\344\261\240\301\312I\212T\7#\240\376{\330\302\31358\233\307\234KGOL\204\23\237\237\223|j\26\266{Y3\265@o1\nW\373\21\253m\274&NG\227\335.\25\353\373\355\357g\6\337\345\342X\201\266\253\230\337\217\314\213\1\224\360P\336X)\366K;\271\236\372)\325 d\16\31J:R\16\"\31>)\263\2\347\204B\356\1\322k\6/[0Z\235\326h\253Lj\26\226\314w\1\f\10C\310O\37\v\377\361\27H)\235\332\311\252.\252\234\32\265\37\3708\272\0034|\301\203\255?\342.\215\243(\277\333\352\264IM\r\305[\323\323\311:\342\252\307\247\211\23\20\263/\372a`\252\311G,[f\177\324+\362%h\317'\327V\23Hi~\355Qc\225F _[\374^\0208j\365\332\0350`\220T\27\231\343\370Pb#\345\366\374 \365\t\334*<\201\307I\5\177Q\213\337\232\346j11\0253\212\374\216\242<\216\350\320c.\217n\316s\336\257\364VP\360\340\232\rp\245\374@\265\252\261M6\\C\332`D\263\326V\17\343\312\16;\306.sW\251o\25\353|\253\0\273Z#\1\r\355B\33\227\225%?\326\36\356\274\t\231\221\20\0#H,g:,\316\207\n'\17\267~\226R\256\217j\314\2463*c\34\252\237\23\244le.0\3677\333%\345f\311\332\6\364s\226!\306\355(\321\25\265\21\312\344\320\37\233\345\343\10\342\250\365\234N0\330]>\374r\252\25M\343\250\346t\221\207N\373Jj\24\314\370\275\310\243\224D\367q(1\2254t\235\330n\362J\2456\312.v~\21=\6\332\363?^\214n\212h\334\27o\20\34V\202\306\221hn\211P\272\274\301|k\310"..., 1361, 0, NULL, NULL) = 1361 <0.000018>
823   00:09:58.700474 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157406024}) = 0 <0.000017>
823   00:09:58.700527 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157426892}) = 0 <0.000013>
823   00:09:58.700582 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157463811}) = 0 <0.000013>
823   00:09:58.700629 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157493354}) = 0 <0.000013>
823   00:09:58.700669 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157516395}) = 0 <0.000012>
823   00:09:58.700706 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157536245}) = 0 <0.000013>
823   00:09:58.700740 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157553939}) = 0 <0.000012>
823   00:09:58.700774 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157572419}) = 0 <0.000012>
823   00:09:58.700812 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157606863}) = 0 <0.000066>
823   00:09:58.700908 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157628395}) = 0 <0.000019>
823   00:09:58.700954 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157651960}) = 0 <0.000013>
823   00:09:58.700990 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157671376}) = 0 <0.000012>
823   00:09:58.701024 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157689517}) = 0 <0.000013>
823   00:09:58.701064 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157713141}) = 0 <0.000012>
823   00:09:58.701106 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157738511}) = 0 <0.000012>
823   00:09:58.701141 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157756987}) = 0 <0.000013>
823   00:09:58.701175 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157774729}) = 0 <0.000013>
823   00:09:58.701210 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157793715}) = 0 <0.000013>
823   00:09:58.701244 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157811277}) = 0 <0.000012>
823   00:09:58.701279 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157830433}) = 0 <0.000013>
823   00:09:58.701323 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157858018}) = 0 <0.000012>
823   00:09:58.701423 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 157940397}) = 0 <0.000014>
823   00:09:58.701645 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158143139}) = 0 <0.000015>
823   00:09:58.701712 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158181650}) = 0 <0.000013>
823   00:09:58.701756 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158207523}) = 0 <0.000013>
823   00:09:58.701791 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158225893}) = 0 <0.000013>
823   00:09:58.701828 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158246317}) = 0 <0.000013>
823   00:09:58.701867 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158269082}) = 0 <0.000012>
823   00:09:58.701920 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158305281}) = 0 <0.000012>
823   00:09:58.701955 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158323255}) = 0 <0.000012>
823   00:09:58.702167 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158518609}) = 0 <0.000014>
823   00:09:58.702216 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158546263}) = 0 <0.000012>
823   00:09:58.702253 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158565395}) = 0 <0.000013>
823   00:09:58.702292 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158588067}) = 0 <0.000012>
823   00:09:58.702331 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158610578}) = 0 <0.000012>
823   00:09:58.702367 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158630000}) = 0 <0.000012>
823   00:09:58.702401 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158647544}) = 0 <0.000013>
823   00:09:58.702436 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158666781}) = 0 <0.000012>
823   00:09:58.702470 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158683988}) = 0 <0.000012>
823   00:09:58.702504 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158701899}) = 0 <0.000013>
823   00:09:58.702538 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158719937}) = 0 <0.000013>
823   00:09:58.702576 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158741242}) = 0 <0.000013>
823   00:09:58.702614 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158762648}) = 0 <0.000013>
823   00:09:58.702649 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158781278}) = 0 <0.000013>
823   00:09:58.702682 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158798592}) = 0 <0.000012>
823   00:09:58.702718 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158817590}) = 0 <0.000013>
823   00:09:58.702752 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158835881}) = 0 <0.000012>
823   00:09:58.702790 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158857444}) = 0 <0.000012>
823   00:09:58.702855 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158905165}) = 0 <0.000013>
823   00:09:58.702895 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158927812}) = 0 <0.000013>
823   00:09:58.702929 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158945344}) = 0 <0.000012>
823   00:09:58.702964 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158964550}) = 0 <0.000012>
823   00:09:58.703001 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 158984776}) = 0 <0.000013>
823   00:09:58.703058 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 159025505}) = 0 <0.000013>
823   00:09:58.703189 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 159138558}) = 0 <0.000013>
823   00:09:58.711215 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000026>
823   00:09:58.711575 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\371\242\206H\362]D\355\1771K+\277\343n\n\21T!E\224?\350\\\240y\33\304\325\20\23227\301g\344brt<\346_\0171iP\363V\342\247\374\2618F$\240\240\330\6ot\315H\222<\236\340\357l;/\356e\215D\326\7\263Eq\247\225\260\243^U\20\2574\323\6_*\274\27\243)k\301\23\177/\"Nmv\371\235\203\262\253]mfF\332\273k\370\300\233a\272l\t\342\3`Aq\272[&\300\177\302\344{\220\357\251\10,H\247\0107\245\5\347\356+\"\211\252\v\313u\256\264\273\346\341~\376<\374\273(g\217\316J5\234r\266Y\306]\217\244\307l\210\302\n\355\255u\365\340\244\16\4'\216[\24\0053\302s\352\370\256\263\277\375\33\264\323C\217\260\227\356\264os\3344\210\353\3\17-m\313\312EG\222p2\251\320\n\30\257\231\344\376\331sF\257\214\252E\345\362\315\240>\4\3\257s\222\312\36\203\0\240\214\310?\36\342\356\266\227\343\241\34\234\276K\220\2635\326Y\334D^\324\30\205\345\320=\217Ts\232\25x\240:)\216\3704\207I\325\6\331\21)\330I,\257\217\214G\235\213I\177\257\220\353\253lah\37 D>\234\335\t'\365C\\\33'\223\334\313?\302n\225/\363\254\v/\27\256\203\244\331\354\343\v\17Q-\334\2023\266\16\236\257J+\377pl\275\277\276\215\"\35 ]\327\20\2033\24\247z\353RqN\243^7\336\274\332,g\313\34013\310\215\373G^\334K1\17\31\227\375 \10\\xl\376\370m\316\326?\221\241\tpk\3646\263\7\10L\220\241\373\271\353|\211\375\256\34\330\331\37\247\373$\374\22s\326\305A\304\315N.F \340\2647\230\27\32ne\324\224\36\237\f\1\366K\272c\201\305\232fS\215\235\217\1\251\211\247\213v\343\7\342", 510, MSG_NOSIGNAL, NULL, 0) = 510 <0.000038>
823   00:09:58.711916 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000030>
823   00:09:58.712240 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000353>
823   00:09:58.712884 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2\351", 5, 0, NULL, NULL) = 5 <0.000019>
823   00:09:58.713188 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30l\2122\341-\220b\232\240\32(\314G\272y\376<\316)\323r\314\343\315u\2337\356\3707:.\4\250,M-\22\202%\336\0229\314\334\340\266\222f\374\240\361}\360\3001\35\213E\23c:\263\354z}y?\273\225D\25\6\27\n\4\3\374\250\277\36\240\266i\351\266\273\235D\216\371}\344\323\377\32\236\317\266\344d\25Y#\347\264o\276n\261_0\210\236\332\306\320mE\373w\312?\216:){s\7\232R\311\2054\37\\\340\311\2428\247\6+r\244\255\10c\\\377\221w\371\5\22\343(\216\262\326\31\27X\33\253B\361E\320\37\276\204\200\200\305\30\342)\260\2p\25w9\252-e\2158\f\0_q\\$\232\202i\32\6\241\353-\356\301\n\370\202,\1|:\301/\f\325=\266\\{3\"\251\211\360`\346=\347o(w-e\207r]\315\26\0369qn\345_\355)!\317{\322\35\360\310%/}\334\227bb12280\224\301\342\232\237Dc\206)\307\363\2120\356\357\0070>I\232>\245\336\314\240d\270U\26\323i\0240o\275\\>\343'\235\1\7d\222?\7\320\253\326\333\231;\264\245s\346\31\274\235\257\357\4\257\360\214\3i\217\360I\0\fP\355Q\377\275\300\230;5SE\253.a2\336'\332\263\253H:\2\236\241S\360\323G\225\v\226\246\350\35\247<\253G(\367\31&\334^\271r[\22|(\364\304i\301W\361\1\312N;\366\377T\253\370&u_\241\214\263$h2HO\37c\23\260,eY\6\214V\242\5\v.H\332\366\2\376\267p<\353\215Inj\340\256\264G\216\32\3329\372\362B5\227h\245\4\307\310\n\341\257\177p\224T\0\33|O\177e@\370\341\364\317\\\273y\361\254\31\355\217\37\236\346\341`\342\361\2238r\337j\346\362\35\211Pr\0375\25U\0;aA[\21:G\361\334\336\261\337d\347S\230\305\0\311Y\5\357\263TN[\254\302E4\3\303&\367\222\213\201s\371i\251\337\240H\333\205\227RL\357cA\224-S*\321\360\353\321\25\233\332\2\227y\307\213\2434\314\356\261v\243\251\330i\327v\207\331\262#\37\363\206c}\343\365PX\351\315S@\234\24,\376\246?\317\304\222\240\304\237\tT\343\376\3026\1]Gg3)\23\214\205\213N\305}\252\302\r\374W%\256v\32\302\202\210\1\224\26\21\327\261\240|\f}-q\346\270\203X\221\260\313\210\333@\346(]1\253\252w\356\270\315P\343\32v+\343?\245o\204\374L*ot\334\266b:\244P\t2\365$\250\263\\\260\353\350\24J\336\367\236\27\261X\311\37\262\347\21o\270\260\270vZ|\377\177K3\207@", 745, 0, NULL, NULL) = 745 <0.000020>
823   00:09:58.714284 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.714621 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\244\242\206H\362]D\355\200\253\227\353\220\314\371\2\30!\341\1i\244\266;Ht\337\7_k\323\320\36}\324\334\261/5\342Ean\376\273\276Pd\360\35\302g\360e\220kS\r\25\220\313\373\4\37\346-v\355,\177\177d\230_\261\fSC\21*\217|7\36\24\231y\276\210@\26\331\2438\237P\372\222\2637\25\355\226\261-C\373\201\250*\306\376*:\3642\354\221\321`\260\235\201x\255\336\347\4Gi\207{)\3504\t}\323\241\232\224\324\307P\244\270H\n\4\346\233Kj\206\264\244\310\361\266;\347\367\235\347\331", 169, MSG_NOSIGNAL, NULL, 0) = 169 <0.000038>
823   00:09:58.714954 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.715275 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.715673 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0^", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.715978 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30m\f\251b\273)G\276\364\347\200\264j\342\346\353\30r\321Y\373-\30sqm\210m!\36\345\247\34X\371\2324\352E\365/h@\32C@g+\325\251\6}\246\37\365\342\367\247?q;\251MI\227$\217\352/f\22.\273\330h>$IM\375\340g\331|K\310y", 94, 0, NULL, NULL) = 94 <0.000020>
823   00:09:58.717066 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169071979}) = 0 <0.000020>
823   00:09:58.717137 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169105301}) = 0 <0.000016>
823   00:09:58.717184 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169132423}) = 0 <0.000015>
823   00:09:58.717248 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169177508}) = 0 <0.000016>
823   00:09:58.717321 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169230423}) = 0 <0.000016>
823   00:09:58.717366 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169255599}) = 0 <0.000015>
823   00:09:58.717454 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169323731}) = 0 <0.000015>
823   00:09:58.717503 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169353206}) = 0 <0.000015>
823   00:09:58.717561 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169391867}) = 0 <0.000015>
823   00:09:58.717640 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169451827}) = 0 <0.000016>
823   00:09:58.717683 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169474693}) = 0 <0.000015>
823   00:09:58.717731 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169504669}) = 0 <0.000015>
823   00:09:58.717773 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169527435}) = 0 <0.000015>
823   00:09:58.717819 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169555096}) = 0 <0.000015>
823   00:09:58.717864 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169580994}) = 0 <0.000015>
823   00:09:58.717904 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169603325}) = 0 <0.000015>
823   00:09:58.717949 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169629932}) = 0 <0.000015>
823   00:09:58.718000 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169662735}) = 0 <0.000015>
823   00:09:58.718041 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169684513}) = 0 <0.000015>
823   00:09:58.718084 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169709278}) = 0 <0.000015>
823   00:09:58.718529 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169722743}) = 0 <0.002589>
823   00:09:58.721191 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169767825}) = 0 <0.000014>
823   00:09:58.721242 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169790406}) = 0 <0.000013>
823   00:09:58.721277 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169808660}) = 0 <0.000012>
823   00:09:58.721318 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169832709}) = 0 <0.000013>
823   00:09:58.721353 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 169851896}) = 0 <0.000012>
823   00:09:58.727300 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 175779890}) = 0 <0.000012>
823   00:09:58.727774 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {4, 176215181}) = 0 <0.000016>
823   00:09:58.732987 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.733395 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\372\242\206H\362]D\355\201\205\256\321\374[1A\4\363\362\252\364\347\372\31\t\261\366\261\246\324B\226\315ly>5\206\204K}\211\322\24\250\230\201\26\314h\221\373\205\227\217#U\256wC\230\342\221\347\343Kf\331j\17\270S\17\367\264\231\2226_\245/\343\371\266\273f\266biU\375`\312a\347\351\212&\333P\251\261\177\t5?6\216$\270u\273\253\\\203\363#f\270\337\372\222e\4\355-\263M!\361\25\307\326\0{\266\272z\360\240\370\320\234\20\306&\303a\257\261\302z,\204\2\317]z\257\220:\254\233\375P\366Q\222\233\365\200<\21\2143\17m#Lk\342\326\tY\365\305fD3^\232bW\27\217\341\300a\211(\377\326\256\240g\202\240p\361;\355\320\222\361\205\372\307G\313[hY\264\210\1\306\335X\372\256\t\317!S\270\"\6\30\270>\25\344}-s\306N\201XA3\366E\367x\366\362V\f\223\224\255\317p\252\1\0\334\335D(A\211\335\340\22\265\221\336\36\265\227\267R\222\357\334Q\322ViO\376e\262wl\16a\303a9?|R\200\367\244\10\313\272]\307>i\331\345|DR\242\366\271\31\202\272\332{\341\225G*]\234Ks1\323z\242pQl\264\22\\\v{A\261_\35\230bTt(\325\250F\261\300\341\310{\375T\223\277\250\271\3\203\371nT3\266\222}\326\33\233\r\3318-\211\217\3672\237B3\v\221M\330\214~B\2056Yu\342\330\250k\245\250\337\306\335\337\331?\354*!\335An=\r!\355j\210\266i9C$0,\211s\\\337\332\"\325c\300\334\16\366\317\356\257\370\260cnx=\322\277\200\231\206\327C\323\276\"\v(_\211^H\355\247\217\2047\270yA\240\263\322\267`?@\202rK\23330?\232O\216<\343\311n\224X\26r|", 511, MSG_NOSIGNAL, NULL, 0) = 511 <0.000051>
823   00:09:58.733776 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000017>
823   00:09:58.734087 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000259>
823   00:09:58.734632 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2w", 5, 0, NULL, NULL) = 5 <0.000017>
823   00:09:58.734930 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30nrr\343\0\242\236\314\331\234d\204\313\262\304=Z\361\322C\f\341\306\303\243m\320\5u\31\253)\257P\317tA\37<)DD\213\211\267\375;\f\240t\265\253\352\370\23g84\"h\252h\331-\373\307/`w\266%\221\231#\335\245]\251\251\371V:\221\326u:\376\253\2125\30\20\23\260\231\224\372\206\34%6$JTi\20%G\312\277\201\36yG\247\212#\251\330\256-\2505\255\224\354\310\264E\301\345{,k\213\334\215\226\256\340\2369\364\30\341\207\303\222\355O|g\345B\203X\236ZK\223\225E\3128\0340\317\336\356f\361\340\v\361\"+\273\274\220\2\234\320<'\20\01607\346\326)\332\351L\257\224\24\31008\231E}\356\253\330S[\250\254\340\255\254\330\215\222\371P\3654\373\363\34\240\214-\261j\364\244\304!\262\206\346J\16\3367\2623!fx\377\307\377\301\332k\357-\16\345\26\260\201\305\20\257\236\37\230\321\244%\0*\321\2170\3233\t\203\230\233\33z\317\354p\202y\25\301\235\311\322(x\270\352\272\6(\"\316\7B\311\244\255\267\236E\251\306\6\213ahg\273\371\232\277\235\360:M-\353\273Bc'\237\306@2\364F\24\250(\257\361CM\322\264\253\0247\354\314~A\27r\256\257\246\332UY\4\371\364&\372\21\r>S\225S\310\\\341\n\367\376-\220\250\350\212\326\324\241\372g\16\223y\317%G\373S\260\n\256v\35\257\333@:?\215&L\366\336\222\347\325i[\362\245\274\334\331\273\35\261,\217\30\tf\354x\307>\352Y\225\226\322\251\2018\344\210\347\224\262)D`6\35f\2430\256\n{s|A\335\210\343\207\322\313t\361\261`%\263J\262{\0\23N?\204\363\263F\r\322\24\f\20\0278Pm\242\274\350\200\324\354\265c'5\272?\205J\vb8\230\305\264\322\256.\311\337\341\364\335`\"\266s\345x#\344E\205)\256\341r5u\212\213\217\313?\26Z\266h]\276l2\374\334\207\351X\37\277\217/\370}h \311\274qH\33\235\232\372q\366-\200\2667\320>&\37\350We\357e\177/y\305\310E\366~\370B\316*~\177\207\264V\231\344\1\324\32X\335s!m\245\241a\310h\223U<+\244\2\212H\3659\305", 631, 0, NULL, NULL) = 631 <0.000017>
823   00:09:58.736136 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.736479 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\277\242\206H\362]D\355\202\4\10\351]\31\215)d\355\372\260Yu5_\227C\346\241\3\22b\242^-\275`\206D3\210\212zK\303n\7\245R\235\232v\21o\303\236\26\223\215\250\1A\366\313j\243l\16\300\204\226\266\374a\240\350[/\264\342\n\261\265\305\177\362\\\244J\372v\203\35\222W\300dQy:R\37\305\351\373\364\256'\25\2255\374\327+\215f\325!\273\t\236\326\301\10\27}\3604\373\344\303\366\224\345\272\241\320\17\206\fR\217\345|6\3502\3443V\37A\23i\220\5!\344\f\332 5\262\322\223P\307\321\362\201\325\255\203hR\226\274j\20\204\243\274\327\220j\261G\253\301\236\264\375z", 196, MSG_NOSIGNAL, NULL, 0) = 196 <0.000040>
823   00:09:58.736815 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.737125 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.737457 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\340", 5, 0, NULL, NULL) = 5 <0.000022>
823   00:09:58.737767 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30o\7\332\346,\363\245\223\317.\343m\35\266\331\264A-j\274Yl\r\345@\276\305!K]\307\216\366_~\250d\30\340\37\240\307\35t\221\207\253\300O\26\331\257q\364\25ik\21Ax~\10pR\311\33Z\10\234\16%\375m\23t9\263\242\363\312r\311\307\21\317\rQ\302\216\251Bo\376\237\311<\324\320\222\226\206\0048x\316\303$\35\330\213\31\300\271o\224\252\223\331\16\370$\35\306l\221\202\340\377\345\362\366\251nJn \264\3719xi\306A\245\34\335JO\4\377\"\t\17\364\330\36\274\362>\341\n<\247\370P\255\324\332\374p\202\202\314\263nt\237~I&!R\233\34\247\24\300}\rEA\372\2212\356\3\32M+C\246\307:$'\30=\235}*\204_\276\273b\230\340", 224, 0, NULL, NULL) = 224 <0.000021>
823   00:09:58.742402 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.742743 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2\0\242\206H\362]D\355\203\234\337\276=\f\215\345kM>\5H\302\f\234TV^\251\274:\226\254\332\246\363\33\32!\344N\256 \346\275k\35\177\307J\265\245\23\215\200\267\1&\252\366\244N\270\307a\347\354_\210\337'(\177;o\231>\212_\327\310S\1-\361fL\313\317\350PI\212K\341\262\25|\t'\221N\33\2126Y{C\23\304{\351\34qW\363G\353\256\262q\"*az\326\212\370\275\5w\257x3u\247\304\321\357\34\245\316\225\317\260\316\374<)#3EJ{\275J-h>!Q}\312\230F\240\23\n\22\305\22 \226\330E\370X+!\247_7\250T\235Qa\2764\332,D\223\23R\305m\34\222\202\2031z\330\2\211\240r,?\30\307\252\371\352\347\r\225\311\26m~\"y\260a\332-O\346!\2358\343sC\f\320\25\354\222\330/\1\326\346\3622\\\217\345X\332\27\265\221\232*&|\303\224\35\340p\367\332\5\376\221B\320\332R\\\253ICX\241lq\202sn\252>7\244N)F\340\3M\32\252U\234Z:\3634\25\327\333\21\34\276\210\352?B\316\255\311\4\336\217O\247\233\330\226\23jv\\,.\213G\330:\0241qP^\346%f\226r\262\266\347\302\241\237])\220\364C\322\315\277-xz]2\220\0300/\330\363\367$\207\311\255\7ZK\373\367\242T\254I\334\254#0\27\276\203\35w\267c\255\232y\277b\266\365(\33516Wg\261\351\337\37\271\327R\247\303\5\331?W\30\366\vw\236\tu\270\316\271\273\320\374\305\274\204~\330{\3503@\272\256-\312!k>.^\372H\273\272\v\3121\205\262\331\343\335\345\345\206\342\274\334dP\3\3i\306=,\311\0266 Ba\237r\262X\211\227-\210\4\361\2020\316\273\351\361\1V]\17\204<\205z\32\214\275/\250\35\255", 517, MSG_NOSIGNAL, NULL, 0) = 517 <0.000040>
823   00:09:58.743081 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.743390 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000149>
823   00:09:58.743845 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\2~", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.744151 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30p\231\210\351g\215\353\352\307\344\203N/\357+\354\227\221w\264\3102DK'4\256W\32\204L\317\17\274\326\237\216\177!E\356\236\30\307+\326'\330\311\34\364\260>\21!\206\361\376R\240\234\211~{\205Zb\302\205\263\256u\321\340\340\310\1@(\337|\354\347eDc\305pS>9gN\240\0*\5f\35\351\20\203\205z9L&g\320\364<\230A&u\361\34\354e\222\237\312t\304\343rU7Vra\300\331\335\35\323Pi\224\36\222\327\255\356\261\31\225\31w\340\214a\335\361Vz\340\352\216|Z3G\361\304\315F\260\271\213<\315\3603\354\f6u(!\350_\235\35Q\252;nrA\361!#\t\1\215\354\t\257U\23TM\263a\230kj\203j\341;\244\220\300\243\27^\206\1cs\17e\337\233\204\347n\16\346H\35ni\275\347\236S\317_\266P?D\244\30R\6<\325\243e\275\200v^\307\215\362>\326[\237v\364\33\357\36\251\306\r\201\265!\324\20\330\223vPp\332\233\25{\260\200\353\226\223\317J-/c\301C\225\346#B\v\235\f\23A7L\37@\321\331\3263e\2713(\32\232\34o\247\31\372\361AK\311\2325\225\304\305\354\255\247\342\25o\213?M5\265\2418jV\361\253\321\332\270\347\7\327\207\17P\234\354\334\"\306z\301\203\314P\376\371-\326\372<\2\333\2619\326Dv\217C!\346\216\311\271W\336\371\326\264\370\204\332d!\306\304\214\343\2\10 \352\241\222\312\265\305\10\356\373S\263\312\301$\261W,Q%\323\1\231m\232\35\207C\2704\220\2\212\352\364\254\306\225Ks\26,\374\273\265\353\227\226\360/6\10\317h\203\254\372\241\2125\205:\252u\351\360I|\4J\235\24\212\352K\32\273\325(\3\30\307\305k\232Or\336\362Q\374\371B6\10\324;\vjp<\234\nL\345\310\21\r\211IP\361P\233SP\337Z\10qj2\350\260\t\34c\216\342\261\33\272\303\313zY\307Z\343\345yS\371;\237\253\372\377N*\376$\5g\215\366P\265h\252/\n#\265\3342Y\202[\213\346\305\6U\246y\232P\207g\n`D&\274\25g\300/\2532\377\246\354zshW\305\256\370\2648\344\3\354S\37\306\222\350K\10:\5C\36\n\225\4\376\303\25\7", 638, 0, NULL, NULL) = 638 <0.000021>
823   00:09:58.745187 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.745524 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\327\242\206H\362]D\355\204\315D\264d\3\236\216MI}\207\264e\271\320\230>\34\301\227j;b[\220m6)\331\363\260S\312\224\31\215\245\3179M/2\26`H\301\356\22691\264\355\311\221\0i%\272g\360\25\337\3142\246w\301[c*\374\202-\222SF2;VB\321\372\307wq\226\222\267\206_\363Zj\376(\252\34\307/\0057\335\272\23 \314\201\204\304\35202P\27E z]\0\321\274gRh\375\321F\253/\316\376n,^W\310 Yu\373,\373\245<\266\t\331\4)9\240\35i\362\266\314\344\316/;'~\241!\372\ra \331\327wb\262!B\330\266[\365\353\3075u\31E!\260ZP-<\354\335\342\267\237+\214\255\260U\376\356\221\256\323\201", 220, MSG_NOSIGNAL, NULL, 0) = 220 <0.000039>
823   00:09:58.745857 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.746168 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000118>
823   00:09:58.746576 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\341", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.746881 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30qwH\0\305\335Y\321\225\360&\345\nhoD\241\252'{\360\36\303mF\273\251\277\"t6C\16\304L\200p3Cs\366\234U\27\233\354\32!\275V\236\274\256\v\360\210\352 \346\223\213\352\36\354\1\256\263b\5^\267<\323l\235VY\256\fT\341\10\371\34O\3579\306\235#\"\21R=\211\207\355\226\213\7^\230Q\236\r\25\200!?sP|\311r\276\206\345^z\204_\343\371\222\21\307\6\32\232\222\n\235\16\345\376[\3024\344\201\275SH\250i\321v\215Y\205\202\301H\272\10\361\3615\314\356\307Y\30+m\20\30\4\306\35\327\5\227\250\354\35\347_y\251I\270\5R\221\232_\276c\366\272\262\3528\316\365PQ\241\205IC\203:L\371\364@M\325N\261\304\344\321\246\312T", 225, 0, NULL, NULL) = 225 <0.000021>
823   00:09:58.751400 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000019>
823   00:09:58.751749 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\334\242\206H\362]D\355\205cV71B+/\352\363\210Wsc\301\270.\310=\24\255\211\30\372\25\257y\335z\251\204\266H0\350\340\227\255\21\2153\353E\242k\253t\201\232I\317\325\2022\241\213{\347\177\37\324\262;\23z\01654\261\251\35_\310*\341\200S[(_?'S@\226\37\177\235\275\230\35\22\340`\252\247\345\34]\213\27\371\210\253F=\301%\261M\234G\275'\3321(V\255\217\10\235\214N\251\262\370\334\375\373x\30\37\377;A\336\334\362\n\34'\215w\351^\353\234\367Y\362\v\305\222\23yN\26\260\354v\253\246\243+\212S\376\2<9\rR\263}^\272\205\237\257C\366n\16{\23\277\25\314%0\5\301]\22\27\243\34\337\3\316E^E!\350\237-\32\372\6\272\7", 225, MSG_NOSIGNAL, NULL, 0) = 225 <0.000038>
823   00:09:58.752079 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:58.752380 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000017>
823   00:09:58.752704 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\340", 5, 0, NULL, NULL) = 5 <0.000017>
823   00:09:58.753020 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30r\251X\246\347\265\21\203$\377qC\21K1\212\204\256\367W4jJ[\217Rr \262\310\177\257\214\310\313\243\315\32\360@O\360\340\243i3_\341\265@\247\v\255\f\247\5\373m\301\250V\364l\266\242F\214\371\201\r\320\321%\271\27@\216\354\345\367\\ \226\304\327\344\261F\n\254g\235\375\377\34.`\241?\364)\36m\206\251O\210\371u<\230\333I\232\351\273\202;~%T\275\265T\373\344rt{g\02436x\334^\206\271\20\276\f_\340)\320\257\333X\237\367\363\244i\216\234\204`\224\261i\237\226p\231\271/\231\317M\35\207\366 w\236W\344\206\377xk\r\347\254u\246\177\202 \260\36>\360\301\320$\344\36\242\v\244\300\3363\2\240\315hD\373\247\243\20\325\236\225\340", 224, 0, NULL, NULL) = 224 <0.000015>
823   00:09:58.757395 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.757743 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\321\242\206H\362]D\355\2066\210\303\35\252sV\31\200\361#\255\373\274\257e;\252\311@Yt\222*\306%M6\247\345F\26\365\236-\366\247-K\343\350\356RwI\32\350\244\333\6\246E\361\34}\341T\26\321\21\211\\2s=\r\2018\237\5\201sVU|\323\307\365\345[\221\261\240\251J\341\377\354\327\30\251de3ed\251jMBAA\350\233r\345\276\215\225\243 \276\241\2250\30\325\307\316\2529.\235\355\10~\270\250=8\6y\325Y\343\221\r\342\356\231\360\313\334|w@\362V\33\2078$Y\27\274'd\264a\362\202\25^\310\342\354d\313\233\232\227\354\322\352K\177N\265\36o\340O\3217\311\275\251\351i_3\2709\275\5\261-\367:<(", 214, MSG_NOSIGNAL, NULL, 0) = 214 <0.000041>
823   00:09:58.758082 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.758392 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000023>
823   00:09:58.758726 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\245", 5, 0, NULL, NULL) = 5 <0.000021>
823   00:09:58.759031 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30s$\264\305\2\32Q\324\221\276\372\"\234\231dy&\17\307\30\365\26\36\262\300\361\3034\315\270\325\20j\26\20\16\373\276I\377\333\373\357%\r\265\210cyl\271Z;\343\213\346\325\242\211\6<<\232\236\362:\354\364\223wM\16Z!\"\311\25f@\215(\20\232S\374T\243\336\355\230HW\31\22~\21Ou\321\263M\237g\201\267#E\317\321Hp\221\36\205\244\21#\341\2112\2542\260AH\6qYh\364\313n\33\334CTc\36\204\207\257\251][\336\331\362-|\247'\214\324\307.\205Z\250*\313y\217\363\210\266\316\2530\f\251!q\340\365\302\234\347\322S*\200\377\3404\323\25?\332R\325q\356\243r\221\257FJ>M\320\364\376\20\303\305E_\353y\21\333\223\225\355W\264\325\251;\22y\310k\375\25\235\n=|\271\361<\311)S|\354<\251\4T\n\307.\354\376W\362K\352\0051X\343\2303\376\7\357:\363\322\207\305)\7\2568}6\205L:f[\23`\273PS8?\363\212\237\263.'R\\\301\375\353\332\"\306\220\207\241B\253$\210\221\4\22\v\2172\355\222\"i\346\213\327\3457\1tV\375\212\212n\223m\31\214\373=Z\253\337\3761\365XZy[\226\10\205G8BN9\21,hn2\345\335\1_\362\30\210UV \327\336%\272w\272\250\274\5O\353\20\265E\t\220\370;\t$\372\362{\367{\372\252vN\343o|\3529\367\305o\304S1\206\365\4<\260~\377\370\306", 421, 0, NULL, NULL) = 421 <0.000021>
823   00:09:58.759700 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.760031 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\\\242\206H\362]D\355\207\217\355T\217a\366\301\211*I\355\271Vi=\351\326h\\D:\316\1\3562q\302\270\226\0362sV\342<\347V<\316\3\375\225\332\216\246\311\346\0\215<\202\20\357\336F'\345\345\23z&p\240fb\266\177|\370SE\210\227\310$\313\203\214\236\370\377[\247\244r\367Y\374?\221A\321\362T\34^%y\376\36\315\n\317\351m\33\271\265\206\30\274< ~\22\315u\336\213\376\2623\213\35h\213\216\225$\240\272]\210~l\16\264k$\271\30\222\351\322\351\335\200\301\3769\221\251\213\254\200\350p\212\345j\33\201id\352G\366\353\220\353\31\312\201\304\365\322\253\313h}HDlu`KX+\37\5\373\230\33\256\220'\246\10 \346\325\316JK.\254\34\253\6\231aK\20\24\313\26\260\305\336\310}f\25:\20\244@\260\223\7\214\353\217\206\334r\201\333\v\300\252U\343\302\357\275D\205Li\341</\337j\363\376\21u:/\363\224v de\17\272U\\nz\370B\266\26\370u\354qP\260\343s\205A<\245\17zy#\307}~t\321~9Z\275(\244`\367i\316\270\272\222\226\264|\31n\261\372\16\225\357\264\200\362\305?\274h\r\327\334\224\205\266\315\25\306)\303\342", 353, MSG_NOSIGNAL, NULL, 0) = 353 <0.000039>
823   00:09:58.760375 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.760684 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000024>
823   00:09:58.761016 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0d", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.761320 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30t\2611\371\17<\17\225'\n\212\373\27UV\314-\353Y\343\374x\217\230`\24\240~\350\303\325C\301\215\312\225\0\266\27\337\214\263L\306\6p\334\31J\377\300/\355\31D\264\277\247\17\\\v\275\2361\230KM\355\243e\373\200\351*\347\240\201\237\361\220;A~\337\356\246\4>[p'\234j", 100, 0, NULL, NULL) = 100 <0.000021>
823   00:09:58.764002 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000032>
823   00:09:58.764084 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/finders/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000020>
823   00:09:58.764136 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/helpers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764184 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/mailers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764231 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764278 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/policies/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764325 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/presenters/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764372 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/serializers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764419 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/services/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764466 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/uploaders/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764513 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/validators/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764560 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/workers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764607 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/controllers/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764654 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764700 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/lib/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764747 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/hooks/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764794 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/project_services/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764848 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/workers/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000022>
823   00:09:58.764898 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/services/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.764945 stat("/opt/gitlab/embedded/service/gitlab-rails/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.764993 stat("/opt/gitlab/embedded/service/gitlab-rails/app/finders/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765041 stat("/opt/gitlab/embedded/service/gitlab-rails/app/graphql/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.765087 stat("/opt/gitlab/embedded/service/gitlab-rails/app/helpers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765134 stat("/opt/gitlab/embedded/service/gitlab-rails/app/mailers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.765188 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000022>
823   00:09:58.765237 stat("/opt/gitlab/embedded/service/gitlab-rails/app/policies/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765304 stat("/opt/gitlab/embedded/service/gitlab-rails/app/presenters/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765352 stat("/opt/gitlab/embedded/service/gitlab-rails/app/serializers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765399 stat("/opt/gitlab/embedded/service/gitlab-rails/app/services/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765446 stat("/opt/gitlab/embedded/service/gitlab-rails/app/uploaders/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.765493 stat("/opt/gitlab/embedded/service/gitlab-rails/app/validators/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765539 stat("/opt/gitlab/embedded/service/gitlab-rails/app/workers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765587 stat("/opt/gitlab/embedded/service/gitlab-rails/app/controllers/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765633 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000020>
823   00:09:58.765681 stat("/opt/gitlab/embedded/service/gitlab-rails/lib/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765729 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/badges/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.765775 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/hooks/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.765821 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/members/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.765868 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/project_services/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765916 stat("/opt/gitlab/embedded/service/gitlab-rails/app/workers/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.765969 stat("/opt/gitlab/embedded/service/gitlab-rails/app/policies/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766016 stat("/opt/gitlab/embedded/service/gitlab-rails/app/services/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766062 stat("/opt/gitlab/embedded/service/gitlab-rails/app/serializers/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766108 stat("/opt/gitlab/embedded/service/gitlab-rails/app/finders/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766154 stat("/opt/gitlab/embedded/service/gitlab-rails/app/graphql/resolvers/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766201 stat("/opt/gitlab/embedded/service/gitlab-rails/app/graphql/mutations/concerns/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766248 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/peek-rblineprof-0.2.0/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000021>
823   00:09:58.766297 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/peek-1.0.1/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000020>
823   00:09:58.766345 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/peek-1.0.1/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766392 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/font-awesome-rails-4.7.0.1/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000020>
823   00:09:58.766439 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/font-awesome-rails-4.7.0.1/app/helpers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766485 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/mousetrap-rails-1.4.6/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766533 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/bootstrap_form-2.7.0/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000020>
823   00:09:58.766580 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/dropzonejs-rails-0.7.2/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766627 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/graphiql-rails-1.4.10/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766675 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/graphiql-rails-1.4.10/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766721 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-openid_connect-1.5.0/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766768 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/assets/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766815 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766862 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/helpers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.766909 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/validators/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.766958 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/devise-4.4.3/app/controllers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000019>
823   00:09:58.767006 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/devise-4.4.3/app/helpers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.767052 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/devise-4.4.3/app/mailers/approver_group/group.rb", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000018>
823   00:09:58.767103 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767148 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/finders/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.767193 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/helpers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767237 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/mailers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767281 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767325 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/policies/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767370 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/presenters/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767414 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/serializers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767458 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/services/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767502 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/uploaders/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767589 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/validators/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.767636 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/workers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767681 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/controllers/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.767725 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767770 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/lib/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767819 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/hooks/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767864 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/models/project_services/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767908 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/workers/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.767952 stat("/opt/gitlab/embedded/service/gitlab-rails/ee/app/services/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768000 stat("/opt/gitlab/embedded/service/gitlab-rails/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768045 stat("/opt/gitlab/embedded/service/gitlab-rails/app/finders/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768089 stat("/opt/gitlab/embedded/service/gitlab-rails/app/graphql/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768133 stat("/opt/gitlab/embedded/service/gitlab-rails/app/helpers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768176 stat("/opt/gitlab/embedded/service/gitlab-rails/app/mailers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768220 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768264 stat("/opt/gitlab/embedded/service/gitlab-rails/app/policies/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768307 stat("/opt/gitlab/embedded/service/gitlab-rails/app/presenters/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768351 stat("/opt/gitlab/embedded/service/gitlab-rails/app/serializers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768394 stat("/opt/gitlab/embedded/service/gitlab-rails/app/services/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768438 stat("/opt/gitlab/embedded/service/gitlab-rails/app/uploaders/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768483 stat("/opt/gitlab/embedded/service/gitlab-rails/app/validators/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.768527 stat("/opt/gitlab/embedded/service/gitlab-rails/app/workers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768570 stat("/opt/gitlab/embedded/service/gitlab-rails/app/controllers/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768614 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768658 stat("/opt/gitlab/embedded/service/gitlab-rails/lib/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768702 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/badges/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768747 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/hooks/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768792 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/members/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.768836 stat("/opt/gitlab/embedded/service/gitlab-rails/app/models/project_services/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768880 stat("/opt/gitlab/embedded/service/gitlab-rails/app/workers/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768924 stat("/opt/gitlab/embedded/service/gitlab-rails/app/policies/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.768968 stat("/opt/gitlab/embedded/service/gitlab-rails/app/services/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769012 stat("/opt/gitlab/embedded/service/gitlab-rails/app/serializers/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769060 stat("/opt/gitlab/embedded/service/gitlab-rails/app/finders/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769105 stat("/opt/gitlab/embedded/service/gitlab-rails/app/graphql/resolvers/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769149 stat("/opt/gitlab/embedded/service/gitlab-rails/app/graphql/mutations/concerns/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769193 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/peek-rblineprof-0.2.0/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769238 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/peek-1.0.1/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769282 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/peek-1.0.1/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769326 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/font-awesome-rails-4.7.0.1/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769371 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/font-awesome-rails-4.7.0.1/app/helpers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769416 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/mousetrap-rails-1.4.6/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769461 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/bootstrap_form-2.7.0/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769505 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/dropzonejs-rails-0.7.2/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769549 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/graphiql-rails-1.4.10/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769594 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/graphiql-rails-1.4.10/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769653 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-openid_connect-1.5.0/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769697 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/assets/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769742 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769786 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/helpers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769831 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/doorkeeper-4.3.2/app/validators/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769875 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/devise-4.4.3/app/controllers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.769919 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/devise-4.4.3/app/helpers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000016>
823   00:09:58.769963 stat("/opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/devise-4.4.3/app/mailers/approver_group/group", 0x7ffc6d3c2df0) = -1 ENOENT (No such file or directory) <0.000017>
823   00:09:58.771165 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000025>
823   00:09:58.771508 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\271\242\206H\362]D\355\210\246\2356\7\204'YZ\361\376\344\223\264\221.\255t\202;\345\340E:\266\200\311\355\236\325\17\vt\330\376\330\243WV=\364\16\334l\206\336\316h\233y\362\352\264[\301\346\33P\216\246]\356\fG\247eZ \274k\362Dh\342sQ\4\221T\373\3670x\2\21q\256\4X8t6g@+\21\376\314d\256&\0370\351j\177\335E\261,Ti\233\307\34\267\244\216\f\1\232a\260\364\31+\241\0314\372\205\22!\3F\335v\343\303\27v\347Y\303\34755n\1w\232\310\244\351\224d\272\357\300d\3355\212\2666\232\374^~f.\371\344\370\r\4\f\227", 190, MSG_NOSIGNAL, NULL, 0) = 190 <0.000038>
823   00:09:58.771860 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000015>
823   00:09:58.772161 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000219>
823   00:09:58.772667 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\5\255", 5, 0, NULL, NULL) = 5 <0.000031>
823   00:09:58.772981 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30u\10:F\236\310\243\214z\246\346\266\357\310\\I\322\361\234X\305nX\2443V\346=\224\t\305\276\223\n~\205\260\360\271\325\307\3570\245\260\375\357\256\352.\301\212\vt\272\350q\354\23!\372\3037\3215\227|\327\322\353efK\331\0\"|\2722\37\311\355\2\27\243\3601\322$\17Z\360\374V\224a\242\361M&u\355\261\33\305<\264f\230y\227\342\0079\"\231\1\377\17\256\217\223?\225\263,\26\217\272\342\342\363\323\334\332\351\37Jl\332\n\23\336\344\215\376\374\"v\226p\244\26\322\36c\317#<\347\216\254\3214\232\264\212\\\376.\5\347\f\26\223F\354w\344\332\212\346M\261\233\322v!\221%\"\373\n\312\232\2>\367{\30\372\253\301\324\211\370\2\377\332Id\214\260\250F\266\246\372\201\234\275\30*3\325P\356\225D\244\203\363\342\331N\370\23\210\233!\245q\335\343\f\341`\2352\375.\363\n%t\7\32\246\362\361w\3436\301r\35480}\350\t3\217\211\313\304Z\342\214\27\7Z<\262\357\277-\353kg\372\265C\254\224\210=g\254\343\315v\3167\5\363\241\210\200\342\250Rq{\340 \33\370=\214\356F\310\276g\21g&B\316.\366\302d\317\240G{q?#&\216\r\213\37\344\276x`m7\26\302\354!\2729\33\2347X\22*\201\\\315%\231\334|\332\323\0100\244\353\360\332\200[?\364\332\340'\332I\350zjs\203\10\272&\252\30\322\277g\355\240\311\253\17\35\214[wF9\224\r\36\360yh\37d\315/\375f\377\366\312\233\301`\303UDl8\246\20\r\2454\336c\16\213\227sV\\^>\330\376\262@\257\371\266\36\t\315\31\232F\261'\2278\240\n\3\345C\227\200\30\350\10\371\346:\274\222\376tI\261\22\6V\311\206\244\275\243\37\0226\365\252\322\262F-\242\203o\347\244#0\306\275\23\327&\224+\354U\0033\340\321\343\261\320s\7\255\306\227\366\230.\357Z\321dy:\nlb=\361j\270\312!P\252]\0212\270Q4S\343\347\245\211Y\254|P\224\266k\256\244\227\363\360\373o\266\327F\230\331\365\304n\3\32\321\363D\260\323\226(\200K\6Y\215\276}\6\313\342\211'\33Z|$\207\272\372\\7+\361$\211\312\f\321\33\265v\212M}\346\255/ea\264\232E\214se\252\301~\0108\352/s\237t\32\7\214\356\250>\2\366=*\334\0164\252W!2\5~\261=\357\265@Jp\276\371r\3747\304\304\t\371H\373mj\360\225\357\240N\203Y\n\6\247\367\257\fn]:|\301.\322xn\253\305^O\325i%\t\241J\255\244/\253\271\201&B\t\256$\326\314\252\377k\311:\241Za\262\314\251\341\246\273\267\347\271\330&C\276\332\302\314 \346\21\21\35\21wwd\332\354\274\356\206\vi\255\322\227k}\256g\326nKX\341v\335I\243Y\310\212\201\244}\335\343F1\202M\211\r\364L\260\325\\\30U|\240QK\214\273\375\314\303ha\341\214f\37\vY\300\277j\10e\304j\21\20\217\317\306\260\1\326m\33~\2y2bN\212p\207\264\235Uh\236\307@\30\325y\262\16\236\0\214\201\263x\214t\217\356\3341\364\22p\305:\362\352\214\4\252\314\245\360C\375>\312zh\376\343\242\212%\235\367\264\233M\32\v\\\241n\363v\36Kvm?\367\241\325K\205\211u;\310\242D\236\"*\23\\6j\330\351\323\253\262\257/\301\6E\346O\337\260\332;|\327\360>\273-\247Z\211\213\245\230(-\260\307\210\330bd,\332\331\243o\204\246b\374\306\313,\321\226\252\255\213A\257:\17\340J\353\306\313\3M\\\235\377\10\220\213g\313}\255>\355K\330\323\210\352\321"..., 1453, 0, NULL, NULL) = 1453 <0.000019>
823   00:09:58.781846 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000023>
823   00:09:58.782202 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\1\370\242\206H\362]D\355\211\237\261\312DCL\36\372\207\206\0X!5\312X\35\311\211\236\220\271\241X\1C\225\303\3526!c\7*\266f\4\306{\236\210y}\5A\222\204\34_\227o\256\234\227\306\177\214\227\321o\206\233N\372Se\312\260\354\0320\236i\333\376\330\210\273H\375\35\22]\2465Y\326\334 \n\267\35aj\330}\24\211\310 \36\321\254\235\23\241\235\275\303w>g\266\25\214\26\37_\16\363\355\357\3622n\373\250j\317\211\260;\376\6q\304QP\376Y&s\201\335)\32k&\241\3700Zgt\273\241\0\36\371\343\321\273\215\260\7Q\3\341SM\375\3725\253\231%\211\303<\335v\21\267\34\360jR\252E\245\205Y\370\256\217\210\223\177\332\357\252\313\2410\214\301\f%\v\330\30\330\37\33}H\272u\343\233>%\301\"\270\4\364\6\364Z\177VgV\225\fD\207\4\263\234\301\375\362[\251~\31Zt\305[\236b\0257\22&\355v\26\253oVU^\212\211ZUW\204\340m0\326\21<\366{\315\240D\277\365e\222\255.\22\200\20\241{\231<\220\273\24\352\273:x\272\352\363\370\7v\354.\373\7\341\212\30\200\277\1\367\273\363C\377\361\325r\275\32\226\244\24\206\365\243\235\375\366\327\206s\204'\376 T\34\241\213\4\254\375U\367\260\355\5qk\r\3419\371\2317R\221\261\262\224\27qa!\353\f\274\212f\327\312PN\257-(2\":o\250\363x\322X\0335\31NK\276\226\31\330\241\327\310\37~X\207YZ\252\252$\222\367\36\353\322-\n\253~\251\4e\315\234\225\323\254\330\361\17\247#577\232\216\355\274y\202\31[\2Fk\265\325\347\302\240;\264\1z3o\211\23\357\312\16\354\327\3\320\24\344\363b2\177\273)\24\313\261\342\344\272\f\7W\37PO\231\305\365+", 509, MSG_NOSIGNAL, NULL, 0) = 509 <0.000044>
823   00:09:58.782549 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000021>
823   00:09:58.782860 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000642>
823   00:09:58.783794 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\5#", 5, 0, NULL, NULL) = 5 <0.000020>
823   00:09:58.784100 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\354JY\3[\2\30v\234n\273\30o \376R1;\226/u\207\330\205\366\247q\236\302\262>\327^$*1V\365\305%\260Z\366\341#\245Q\301\253\nF\324\254\213Mp;v?\225\343C\307$\223\260\312\276\16\256t\271\342\252m:\262@\247Y?\360\217\23\221\372\340\334\236\"\261\263\217\22\326\274\315&n\222\273|z}\263\254\232\310\214W\237\361]-yhQz\201\211/\r\302\362Z\272l\250{5)\242a\232\5k\34\202\34j\223\332\304\227&r\35\4\362x\304`Z7G9\306\250]]c\321\264\36\330\213\7\206\341K\36\306\350?\342\215\302-\367j\23\227e\237\360\340)\277\245M\22513\330_\374\373x\3\36\327\301ce\235\214\366\336)\216\30bWn\271\370_\7\257\222\0\\<\354\244\245\377\326\251t\355m|e}\21L]P\207j\266\373\35\366\223\330\33\326\335\366\275\34\2069\260[\3007\364&\2017\311\35<\221B'6qc)\325^\7\26\241\10\314\265e\n\310iCh\337\7\300\33\3_)(\370\213\32\256\227\214\246\326\t\327\250\372\327\274\232!_\355\277\224\205\262r\26\37{8\206:\337\375\212TE@M5}\33\324\320\240\325^\276S\r\346,\2039\352\"\342\367C\22\214\204\337\225\357|\2024@2PQ\233\\\364w\204'Q\354\255Z\320U\213w\325U\21\237\235\245\226$s*\355\26D1\321\275(2\365\241A\211\254\274\340J\355\316\236/\34\10F\232\205_\22\235.\0371E\277S\364\254\17F0\232{\233U]\366\230\262\32\10\211\351\217\262H1\273\"\244,\262\271\233\32f\364\357\24\00183\6x`J\250\241\333\t\272\266\3765V\20\224\325\370h\267&\314\204\274\242\30\7\335\303\31\\\300\35\367\200u\317\214\233E\0351\241\214+\202\0322\373\0*O\30Y\254\365\226SR\303_\225-a\335\4m8s\312z\235\25;&\272}\376\250\\f\351\3444\\\372\34\273_2H\3\235\356\332+\274'=\355\315h\vx&\240\320\230\tH!\274<\360\363\177\1\3036\312\363@\1Fr\247\225\221\324\330\36\35\253:\16J\261!IEV\23R\00672 \337\354~\304\333j\245\37\266\336P\377p\210\354O!\336\1\254`\t@\377X\277-7Tt\303,\2453\7\210\300\312\35\304A{\376\212\377\335\37L{\271C\370\37S_\2+\264!\32X\27\342\372\23ph,\256EMJy\353\371{\6^x\26\10\355\203\226l\266\5D\345.$\200\375\rv\251+\325\363\372\306f-c\23[\226\264\361(\252%\364\351\360\254\352WR\2202\254\27i\275xX\24\345\0L\f\353\363\361\343\222\251\207\264\376\340\337\276v0\363<\272) \213\304\324\0075\211\364'\20A\" \227\234ZWs\3604\2\357\305\10\5\22L\363\221h}\370E\225\354-X/\207\16w\213\331\225\256ff3\310\337vH\252i4~jqR\334\213\rGN,0\\\0\350\213@\235\3174\233\370P:\200hDL\37\252\377\22\3318\210\301v\35\244\347\273z\364]\2\233\6\372\255@Uax\215\36\217\375\266D\330\314\217\222{\301\327\203\0Y`O\222\364\236\273S4\313\340\226\337\225\200NN\353\271e\310\241\322p\0/\357\272\\\0\246\214w\360D\2\235\346\346\220aZ\20\354\330\266\270\333\326\1\326\302\347RI\262:\206\302\302\214\265\213>\356b<Nj;{\267i\33)y\335\211&\362#\315\277\2706l9p\337WE\311\366[g7yP\265\25\347\253\200\265\2_^\237^\1#\262`\373=u\272\216p\0\371\326ZR\363^\262\331!\326\271\23D9FL\nlN\307\337B.[d~n\25"..., 1315, 0, NULL, NULL) = 1315 <0.000020>
823   00:09:58.789033 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.789425 sendto(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\0\271\242\206H\362]D\355\212W}\237\213k<\221\fU\244\231\322\235#\vC.\345=[\22\332\tb\273\310\371\264K\267\343\276I\212\302\252\6\354\200V\37\37\226\17\203\316\262q\277\303\2\233\353\377\226k\257\17\316\374\23\366L\330\325\0304\304It\371\356\277\237z\30\f_\244\223\252\30=o\302\305P0\211p\337%\324\353s\206G\3D\270{\246\252\355&x \312}7\365*\265;\202\376\3\305]\250\273\320\303\225r\207\242)\16h@\16\26\322\342I\16\254T\337\31kZ+\315\212\30\261\257$q'0\255\260\5\270\323]\231M\260C\17l\305\314b(d\370w`\350o\264N", 190, MSG_NOSIGNAL, NULL, 0) = 190 <0.000040>
823   00:09:58.789763 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, 0x7f5ef66aae03, 5, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>
823   00:09:58.790072 select(33, [32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>], NULL, NULL, NULL) = 1 (in [32]) <0.000024>
823   00:09:58.790410 recvfrom(32<TCP:[172.17.0.2:33462->10.7.7.48:5432]>, "\27\3\3\5\321", 5, 0, NULL, NULL) = 5 <0.000035>
"##;
