#[macro_use]
extern crate criterion;
#[macro_use]
extern crate lazy_static;
extern crate rayon;
extern crate regex;

use criterion::Criterion;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::prelude::*;
type Pid = i32;

struct RawData<'a> {
    pid: Pid,
    syscall: &'a str,
    length: f32,
    error: Option<&'a str>,
    file: Option<&'a str>,
}

impl<'a> RawData<'a> {
    fn from_strs(
        pid_str: &'a str,
        syscall: &'a str,
        length_str: &'a str,
        error: Option<&'a str>,
        file: Option<&'a str>,
    ) -> Option<RawData<'a>> {
        match (pid_str.parse::<Pid>(), length_str.parse::<f32>()) {
            (Ok(pid), Ok(length)) => Some(RawData {
                pid,
                syscall,
                length,
                error,
                file,
            }),
            _ => None,
        }
    }
}
struct SyscallData<'a> {
    lengths: Vec<f32>,
    errors: BTreeMap<&'a str, Pid>,
}

impl<'a> SyscallData<'a> {
    fn new() -> SyscallData<'a> {
        SyscallData {
            lengths: Vec::new(),
            errors: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
struct SyscallStats<'a> {
    name: &'a str,
    count: i32,
    total: f32,
    max: f32,
    avg: f32,
    min: f32,
    errors: BTreeMap<&'a str, i32>,
}

impl<'a> SyscallStats<'a> {
    fn new(
        name: &'a str,
        count: i32,
        total: f32,
        max: f32,
        avg: f32,
        min: f32,
        errors: BTreeMap<&'a str, i32>,
    ) -> SyscallStats<'a> {
        SyscallStats {
            name,
            count,
            total,
            max,
            avg,
            min,
            errors,
        }
    }
}

struct PidData<'a> {
    syscall_data: HashMap<&'a str, SyscallData<'a>>,
    files: BTreeSet<&'a str>,
}

impl<'a> PidData<'a> {
    fn new() -> PidData<'a> {
        PidData {
            syscall_data: HashMap::new(),
            files: BTreeSet::new(),
        }
    }
}

#[derive(Clone)]
struct PidSummary<'a> {
    syscall_count: i32,
    active_time: f32,
    wait_time: f32,
    total_time: f32,
    syscall_stats: Vec<SyscallStats<'a>>,
    files: BTreeSet<&'a str>,
}

type PidSummaries<'a> = HashMap<Pid, PidSummary<'a>>;

lazy_static! {
    static ref ALL_RE: Regex = Regex::new(
        r#"(?x)
        ^(?P<pid>\d+)[^a-zA-Z]+
        (?P<syscall>\w+)(\("(?P<file>[^"]+)")?[^)]+\)\s+
        =\s+(-)?\d+(<[^>]+>)?\s+((?P<error_code>E[A-Z]+)\s\([^)]+\)\s+)?
        <(?P<length>\d+\.\d+)?>$
    "#
    )
    .unwrap();
}

fn parse_syscall_data<'a>(buffer: &'a str) -> HashMap<Pid, PidData<'a>> {
    let parsed_data: Vec<_> = buffer
        .par_lines()
        .filter_map(|line| ALL_RE.captures(line))
        .map(|caps| {
            match (
                caps.name("pid"),
                caps.name("syscall"),
                caps.name("length"),
                caps.name("error_code"),
                caps.name("file"),
            ) {
                (Some(pid), Some(syscall), Some(length), Some(error), Some(file)) => {
                    match syscall.as_str() {
                        "open" => RawData::from_strs(
                            pid.as_str(),
                            syscall.as_str(),
                            length.as_str(),
                            Some(error.as_str()),
                            Some(file.as_str()),
                        ),
                        _ => RawData::from_strs(
                            pid.as_str(),
                            syscall.as_str(),
                            length.as_str(),
                            Some(error.as_str()),
                            None,
                        ),
                    }
                }
                (Some(pid), Some(syscall), Some(length), Some(error), None) => RawData::from_strs(
                    pid.as_str(),
                    syscall.as_str(),
                    length.as_str(),
                    Some(error.as_str()),
                    None,
                ),
                (Some(pid), Some(syscall), Some(length), None, Some(file)) => {
                    match syscall.as_str() {
                        "open" => RawData::from_strs(
                            pid.as_str(),
                            syscall.as_str(),
                            length.as_str(),
                            None,
                            Some(file.as_str()),
                        ),
                        _ => RawData::from_strs(
                            pid.as_str(),
                            syscall.as_str(),
                            length.as_str(),
                            None,
                            None,
                        ),
                    }
                }
                (Some(pid), Some(syscall), Some(length), None, None) => {
                    RawData::from_strs(pid.as_str(), syscall.as_str(), length.as_str(), None, None)
                }
                _ => None,
            }
        })
        .collect();

    let mut syscall_data = HashMap::new();
    for event_data in parsed_data {
        if let Some(data) = event_data {
            let pid_entry = syscall_data.entry(data.pid).or_insert(PidData::new());
            let syscall_entry = pid_entry
                .syscall_data
                .entry(data.syscall)
                .or_insert(SyscallData::new());

            syscall_entry.lengths.push(data.length);
            if let Some(error) = data.error {
                let error_entry = syscall_entry.errors.entry(error).or_insert(0);
                *error_entry += 1;
            }

            if let Some(file) = data.file {
                pid_entry.files.insert(file);
            }
        }
    }

    syscall_data
}

fn build_syscall_stats<'a>(
    data: &HashMap<Pid, PidData<'a>>,
) -> HashMap<Pid, Vec<SyscallStats<'a>>> {
    let mut syscall_stats = HashMap::new();

    for (pid, pid_stats) in data {
        let mut event_stats: Vec<_> = pid_stats
            .syscall_data
            .par_iter()
            .map(|(syscall, raw_data)| {
                let total_secs: f32 = raw_data.lengths.par_iter().sum();
                let total = total_secs * 1000.0;
                let max = raw_data
                    .lengths
                    .par_iter()
                    .max_by(|x, y| x.partial_cmp(y).unwrap())
                    .unwrap()
                    * 1000.0;
                let min = raw_data
                    .lengths
                    .par_iter()
                    .min_by(|x, y| x.partial_cmp(y).unwrap())
                    .unwrap()
                    * 1000.0;
                let avg = total / raw_data.lengths.len() as f32;
                let errors = raw_data.errors.clone();

                SyscallStats::new(
                    syscall,
                    raw_data.lengths.len() as i32,
                    total,
                    max,
                    avg,
                    min,
                    errors,
                )
            })
            .collect();

        event_stats.par_sort_by(|x, y| (y.total).partial_cmp(&x.total).unwrap());

        syscall_stats.insert(*pid, event_stats);
    }

    syscall_stats
}

fn build_pid_summaries<'a>(syscall_data: &HashMap<Pid, PidData<'a>>) -> PidSummaries<'a> {
    let pid_stats = build_syscall_stats(&syscall_data);
    let mut pid_summaries = HashMap::new();

    for (pid, syscall_stats) in pid_stats {
        let syscall_count = syscall_stats
            .par_iter()
            .fold_with(0, |acc, event_stats| acc + event_stats.count)
            .sum();

        let active_time = syscall_stats
            .iter()
            .filter(|stat| match stat.name.as_ref() {
                "epoll_wait" | "futex" | "nanosleep" | "restart_syscall" | "poll" | "ppoll"
                | "select" | "wait4" => false,
                _ => true,
            })
            .fold(0.0, |acc, event_stats| acc + event_stats.total);

        let wait_time = syscall_stats
            .iter()
            .filter(|stat| match stat.name.as_ref() {
                "epoll_wait" | "futex" | "nanosleep" | "restart_syscall" | "poll" | "ppoll"
                | "select" | "wait4" => true,
                _ => false,
            })
            .fold(0.0, |acc, event_stats| acc + event_stats.total);

        let total_time = active_time + wait_time;

        pid_summaries.insert(
            pid,
            PidSummary {
                syscall_count,
                active_time,
                wait_time,
                total_time,
                syscall_stats,
                files: syscall_data[&pid].files.clone(),
            },
        );
    }

    pid_summaries
}

fn parse_strace() {
    let mut f = File::open("bench_set").unwrap();
    let mut buffer = String::new();
    f.read_to_string(&mut buffer).unwrap();
    let syscall_data = parse_syscall_data(&buffer);

    let pid_summaries = build_pid_summaries(&syscall_data);

    let all_time: f32 = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.total_time)
        .sum();

    let all_active_time: f32 = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.active_time)
        .sum();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse strace", |b| b.iter(|| parse_strace()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
