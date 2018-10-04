#[macro_use]
extern crate lazy_static;
extern crate rayon;
extern crate regex;

use chrono::NaiveTime;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::prelude::*;

type Pid = i32;

struct RawData<'a> {
    pid: Pid,
    syscall: &'a str,
    length: f32,
    error: Option<&'a str>,
}

impl<'a> RawData<'a> {
    fn parse_new(
        pid_str: &'a str,
        syscall: &'a str,
        length_str: &'a str,
        error: Option<&'a str>,
    ) -> Option<RawData<'a>> {
        match (pid_str.parse::<Pid>(), length_str.parse::<f32>()) {
            (Ok(pid), Ok(length)) => Some(RawData {
                pid,
                syscall,
                length,
                error,
            }),
            _ => None,
        }
    }
}
struct SyscallData<'a> {
    times: Vec<f32>,
    errors: BTreeMap<&'a str, Pid>,
}

impl<'a> SyscallData<'a> {
    fn new() -> SyscallData<'a> {
        SyscallData {
            times: Vec::new(),
            errors: BTreeMap::new(),
        }
    }
}

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

#[derive(Clone)]
struct PidSummary {
    syscall_count: i32,
    active_time: f32,
    wait_time: f32,
    total_time: f32,
}

enum SortBy {
    ActiveTime,
    Pid,
    TotalTime,
}

lazy_static! {
    static ref ALL_RE: Regex = Regex::new(
        r"(?x)
        ^((?P<pid>\d+)\s+)
        \d{2}:\d{2}:\d{2}\.\d{6}\s+
        (<\.{3}\s+)?(?P<syscall>\w[\w_]+)(\(|\sresumed>).*
        (=\s+(-)?\d+\s+(?P<error_code>E[A-Z]+)?).*
        (<(?P<length>\d+\.\d+)>$)
    "
    )
    .unwrap();
}

lazy_static! {
    static ref TIME_RE: Regex = Regex::new(r"^\d+\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})").unwrap();
}

lazy_static! {
    static ref PID_RE: Regex = Regex::new(r"^((?P<pid>\d+)\s+)").unwrap();
}

fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: strace_parser file_name");
        std::process::exit(1);
    }

    let mut f = match File::open(&args[1]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let mut buffer = String::new();

    f.read_to_string(&mut buffer)
        .expect("Error: unable to read file to string");

    if buffer.len() == 0 {
        eprintln!("Error: {} is empty", args[1]);
        std::process::exit(1);
    }

    let syscall_data = parse_syscall_data(&buffer);

    let syscall_stats = build_syscall_stats(&syscall_data);

    let pid_summaries = build_pid_summaries(&syscall_stats);

    let all_time = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.total_time)
        .sum();

    let all_active_time = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.active_time)
        .sum();

    print_pid_details(
        &syscall_stats,
        &pid_summaries,
        all_active_time,
        all_time,
        SortBy::ActiveTime,
    );

    print_pid_summaries(
        &pid_summaries,
        all_active_time,
        Some(10),
        SortBy::ActiveTime,
    );

    println!("Total PIDs: {}", pid_summaries.len());
    println!("System Time: {0:.6}s", all_time / 1000.0);

    print_wall_clock_time(&buffer);
}

fn parse_syscall_data<'a>(buffer: &'a str) -> HashMap<Pid, HashMap<&'a str, SyscallData<'a>>> {
    let parsed_data: Vec<_> = buffer
        .par_lines()
        .filter_map(|line| ALL_RE.captures(line))
        .map(|caps| {
            match (
                caps.name("pid"),
                caps.name("syscall"),
                caps.name("length"),
                caps.name("error_code"),
            ) {
                (Some(pid), Some(syscall), Some(length), Some(error)) => RawData::parse_new(
                    pid.as_str(),
                    syscall.as_str(),
                    length.as_str(),
                    Some(error.as_str()),
                ),
                (Some(pid), Some(syscall), Some(length), None) => {
                    RawData::parse_new(pid.as_str(), syscall.as_str(), length.as_str(), None)
                }
                _ => None,
            }
        })
        .collect();

    let mut syscall_data = HashMap::new();
    for event_data in parsed_data {
        if let Some(data) = event_data {
            let pid_entry = syscall_data.entry(data.pid).or_insert(HashMap::new());
            let syscall_entry = pid_entry.entry(data.syscall).or_insert(SyscallData::new());

            syscall_entry.times.push(data.length);
            if let Some(error) = data.error {
                let error_entry = syscall_entry.errors.entry(error).or_insert(0);
                *error_entry += 1;
            }
        }
    }

    syscall_data
}

fn build_syscall_stats<'a>(
    data: &HashMap<Pid, HashMap<&'a str, SyscallData<'a>>>,
) -> BTreeMap<Pid, Vec<SyscallStats<'a>>> {
    let mut syscall_stats = BTreeMap::new();

    for (pid, syscalls) in data {
        let mut event_stats: Vec<_> = syscalls
            .par_iter()
            .map(|(syscall, raw_data)| {
                let total: f32 = raw_data.times.par_iter().sum();
                let max = raw_data
                    .times
                    .par_iter()
                    .max_by(|x, y| x.partial_cmp(y).unwrap())
                    .unwrap()
                    * 1000.0;
                let min = raw_data
                    .times
                    .par_iter()
                    .min_by(|x, y| x.partial_cmp(y).unwrap())
                    .unwrap()
                    * 1000.0;
                let avg = (total * 1000.0) / raw_data.times.len() as f32;
                let errors = raw_data.errors.clone();

                SyscallStats::new(
                    syscall,
                    raw_data.times.len() as i32,
                    total * 1000.0,
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

fn build_pid_summaries(
    syscall_stats: &BTreeMap<Pid, Vec<SyscallStats>>,
) -> HashMap<Pid, PidSummary> {
    let mut pid_summaries = HashMap::new();

    for (pid, stats) in syscall_stats {
        let syscall_count = stats
            .par_iter()
            .fold_with(0, |acc, event_stats| acc + event_stats.count)
            .sum();

        let active_time = stats
            .iter()
            .filter(|stat| match stat.name.as_ref() {
                "epoll_wait" | "futex" | "nanosleep" | "restart_syscall" | "poll" | "ppoll"
                | "select" | "wait4" => false,
                _ => true,
            })
            .fold(0.0, |acc, event_stats| acc + event_stats.total);

        let wait_time = stats
            .iter()
            .filter(|stat| match stat.name.as_ref() {
                "epoll_wait" | "futex" | "nanosleep" | "restart_syscall" | "poll" | "ppoll"
                | "select" | "wait4" => true,
                _ => false,
            })
            .fold(0.0, |acc, event_stats| acc + event_stats.total);

        let total_time = active_time + wait_time;

        pid_summaries.insert(
            *pid,
            PidSummary {
                syscall_count,
                active_time,
                wait_time,
                total_time,
            },
        );
    }

    pid_summaries
}

fn print_pid_details(
    syscall_stats: &BTreeMap<Pid, Vec<SyscallStats>>,
    pid_summaries: &HashMap<Pid, PidSummary>,
    all_active_time: f32,
    all_time: f32,
    sort_by: SortBy,
) {
    for (pid, summary) in sort_pid_summaries(&pid_summaries, sort_by).iter() {
        if summary.syscall_count == 0 {
            continue;
        };

        let perc_active_time = summary.active_time / all_active_time * 100.0;
        let perc_total_time = summary.total_time / all_time * 100.0;

        println!(
                "PID {0} - {1} syscalls, active {2:.3}ms, total {3:.3}ms, active {4:.2}%, total {5:.2}%\n",
                pid, summary.syscall_count, summary.active_time, summary.total_time, perc_active_time, perc_total_time
            );
        println!(
            "  {0: <15}\t{1: >8}\t{2: >10}\t{3: >10}\t{4: >10}\t{5: >10}\t{6: <8}",
            "syscall", "count", "total", "max", "avg", "min", "errors"
        );
        println!(
            "  {0: <15}\t{1: >8}\t{2: >10}\t{3: >10}\t{4: >10}\t{5: >10}\t{6: >4}",
            "", "", "(ms)", "(ms)", "(ms)", "(ms)", ""
        );
        println!(
            "  ---------------\t--------\t----------\t----------\t----------\t----------\t--------"
        );
        for s in &syscall_stats[pid] {
            print!(
                "  {0: <15}\t{1: >8}\t{2: >10.3}\t{3: >10.3}\t{4: >10.3}\t{5: >10.3}",
                s.name, s.count, s.total, s.max, s.avg, s.min
            );
            if !s.errors.is_empty() {
                for (err, count) in &s.errors {
                    print!("\t{}: {}", err, count);
                }
            }
            println!("");
        }
        println!("  ---------------\n\n");
    }
}

fn print_pid_summaries(
    pid_summaries: &HashMap<Pid, PidSummary>,
    all_active_time: f32,
    count: Option<i32>,
    sort_by: SortBy,
) {
    let count_to_print = match count {
        None => pid_summaries.len(),
        Some(i) => {
            if i as usize > pid_summaries.len() {
                pid_summaries.len()
            } else {
                i as usize
            }
        }
    };

    if let Some(n) = count {
        println!("Top {} PIDs\n-----------\n", n);
    }

    println!(
        "  {0: <10}\t{1: >10}\t{2: >10}\t{3: >10}\t{4: >9}\t{5: >9}",
        "pid", "active (ms)", "wait (ms)", "total (ms)", "% active", "calls"
    );
    println!("  ----------\t----------\t---------\t---------\t---------\t---------");

    for (pid, summary) in sort_pid_summaries(&pid_summaries, sort_by)
        .iter()
        .take(count_to_print)
    {
        println!(
            "  {0: <10}\t{1: >10.3}\t{2: >10.3}\t{3: >10.3}\t{4: >8.2}%\t{5: >9}",
            pid,
            summary.active_time,
            summary.wait_time,
            summary.total_time,
            summary.active_time / all_active_time * 100.0,
            summary.syscall_count
        );
    }
    println!("");
}

fn sort_pid_summaries(
    pid_summaries: &HashMap<Pid, PidSummary>,
    sort_by: SortBy,
) -> Vec<(Pid, PidSummary)> {
    let mut sorted_summaries: Vec<_> = pid_summaries
        .par_iter()
        .map(|(pid, summary)| (*pid, (*summary).clone()))
        .collect();

    match sort_by {
        SortBy::ActiveTime => {
            sorted_summaries
                .par_sort_by(|(_, x), (_, y)| (y.active_time).partial_cmp(&x.active_time).unwrap());
        }
        SortBy::Pid => {
            sorted_summaries
                .par_sort_by(|(pid_x, _), (pid_y, _)| (pid_y).partial_cmp(&pid_x).unwrap());
        }
        SortBy::TotalTime => {
            sorted_summaries
                .par_sort_by(|(_, x), (_, y)| (y.total_time).partial_cmp(&x.total_time).unwrap());
        }
    }

    sorted_summaries
}

fn print_wall_clock_time(buffer: &str) {
    let start_line = buffer.lines().next().unwrap();
    let start_time_cap = TIME_RE
        .captures(start_line)
        .and_then(|cap| cap.name("time"));

    let end_line = buffer.lines().next_back().unwrap();
    let end_time_cap = TIME_RE.captures(end_line).and_then(|cap| cap.name("time"));

    match (start_time_cap, end_time_cap) {
        (Some(start), Some(end)) => {
            let start_time = NaiveTime::parse_from_str(start.as_str(), "%H:%M:%S%.6f");
            let end_time = NaiveTime::parse_from_str(end.as_str(), "%H:%M:%S%.6f");
            match (start_time, end_time) {
                (Ok(start), Ok(end)) => {
                    let wall_clock_time = end - start;
                    println!(
                        "Real Time: {}.{}s",
                        wall_clock_time.num_seconds(),
                        wall_clock_time.num_milliseconds()
                    );
                }
                _ => (),
            }
        }
        _ => {}
    }
}
