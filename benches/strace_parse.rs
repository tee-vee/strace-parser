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
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
type Pid = i32;

struct RawData<'a> {
    pid: Pid,
    syscall: &'a str,
    length: Option<f32>,
    error: Option<&'a str>,
    file: Option<&'a str>,
}

impl<'a> RawData<'a> {
    fn from_strs(
        pid_str: &'a str,
        syscall: &'a str,
        length_str: Option<&'a str>,
        error: Option<&'a str>,
        file: Option<&'a str>,
    ) -> Option<RawData<'a>> {
        if let Some(length) = length_str {
            match (pid_str.parse::<Pid>(), length.parse::<f32>()) {
                (Ok(pid), Ok(length)) => Some(RawData {
                    pid,
                    syscall,
                    length: Some(length),
                    error,
                    file,
                }),
                _ => None,
            }
        } else {
            match pid_str.parse::<Pid>() {
                (Ok(pid)) => Some(RawData {
                    pid,
                    syscall,
                    length: None,
                    error,
                    file,
                }),
                _ => None,
            }
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

impl<'a> fmt::Display for SyscallStats<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "  {0: <15}\t{1: >8}\t{2: >10.3}\t{3: >10.3}\t{4: >10.3}\t{5: >10.3}",
            self.name, self.count, self.total, self.max, self.avg, self.min
        )?;

        for (err, count) in self.errors.iter() {
            write!(f, "\t{}: {}", err, count)?;
        }

        Ok(())
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
struct SessionSummary<'a> {
    pid_summaries: HashMap<Pid, PidSummary<'a>>,
    all_time: f32,
    all_active_time: f32,
}

impl<'a> SessionSummary<'a> {
    fn new() -> SessionSummary<'a> {
        SessionSummary {
            pid_summaries: HashMap::new(),
            all_time: 0.0,
            all_active_time: 0.0,
        }
    }
}

lazy_static! {
    static ref ALL_RE: Regex = Regex::new(
        r#"(?x)
        ^(?P<pid>\d+)[^a-zA-Z]+
        (?P<syscall>\w+)(:?\("(?P<file>[^"]+)")?
        ([^)]+<unfinished\s[.]{3}>$|[^)]+\)\s+=\s+(-)?\d+(<[^>]+>)?
        \s+(:?(?P<error_code>E[A-Z]+)\s\([^)]+\)\s+)?
        <(?P<length>\d+\.\d+)?>$)
    "#
    )
    .unwrap();
}

fn parse_syscall_data<'a>(buffer: &'a str) -> HashMap<Pid, PidData<'a>> {
    let parsed_data: Vec<_> = buffer
        .par_lines()
        .filter_map(|line| ALL_RE.captures(line))
        .map(|caps| match caps.name("syscall") {
            Some(s) => {
                let syscall = s.as_str();
                if syscall == "open" {
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
                        ),
                        (Some(pid), Some(length), None, Some(file)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            Some(file.as_str()),
                        ),
                        (Some(pid), Some(length), None, None) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
                            None,
                            None,
                        ),
                        (Some(pid), None, None, Some(file)) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            None,
                            None,
                            Some(file.as_str()),
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
                        ),
                        (Some(pid), Some(length), None) => RawData::from_strs(
                            pid.as_str(),
                            syscall,
                            Some(length.as_str()),
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
                    .max_by(|x, y| {
                        x.partial_cmp(y)
                            .expect("Invalid comparison when finding max length")
                    })
                    .unwrap_or(&(0.0))
                    * 1000.0;
                let min = raw_data
                    .lengths
                    .par_iter()
                    .min_by(|x, y| {
                        x.partial_cmp(y)
                            .expect("Invalid comparison when finding min length")
                    })
                    .unwrap_or(&(0.0))
                    * 1000.0;
                let avg = if raw_data.lengths.len() > 0 {
                    total / raw_data.lengths.len() as f32
                } else {
                    0.0
                };
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

        event_stats.par_sort_by(|x, y| {
            (y.total)
                .partial_cmp(&x.total)
                .expect("Invalid comparison wben sorting event_stats")
        });

        syscall_stats.insert(*pid, event_stats);
    }

    syscall_stats
}
fn build_session_summary<'a>(syscall_data: &HashMap<Pid, PidData<'a>>) -> SessionSummary<'a> {
    let pid_stats = build_syscall_stats(&syscall_data);
    let mut session_summary = SessionSummary::new();

    for (pid, syscall_stats) in pid_stats {
        let syscall_count = syscall_stats
            .par_iter()
            .fold_with(0, |acc, event_stats| acc + event_stats.count)
            .sum();

        let active_time = syscall_stats
            .par_iter()
            .filter(|stat| match stat.name.as_ref() {
                "epoll_wait" | "futex" | "nanosleep" | "restart_syscall" | "poll" | "ppoll"
                | "select" | "wait4" => false,
                _ => true,
            })
            .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
            .sum();

        let wait_time = syscall_stats
            .par_iter()
            .filter(|stat| match stat.name.as_ref() {
                "epoll_wait" | "futex" | "nanosleep" | "restart_syscall" | "poll" | "ppoll"
                | "select" | "wait4" => true,
                _ => false,
            })
            .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
            .sum();

        let total_time = active_time + wait_time;

        session_summary.pid_summaries.insert(
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

    session_summary.all_time = session_summary
        .pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, pid_summary)| acc + pid_summary.total_time)
        .sum();

    session_summary.all_active_time = session_summary
        .pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, pid_summary)| acc + pid_summary.active_time)
        .sum();

    session_summary
}

fn parse_strace() {
    let mut f = File::open("bench_set").unwrap();
    let mut buffer = String::new();
    f.read_to_string(&mut buffer).unwrap();
    let syscall_data = parse_syscall_data(&buffer);

    let session_summary = build_session_summary(&syscall_data);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse strace", |b| b.iter(|| parse_strace()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
