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

enum FieldsPresent {
    All,
    PID,
    Time,
    Length,
    PIDTimeLength,
    PIDTime,
    PIDLength,
    TimeLength,
    Base,
}

type Pid = i32;

struct SyscallRawData {
    times: Vec<f32>,
    errors: BTreeMap<String, Pid>,
}

struct SyscallStats {
    name: String,
    count: i32,
    total: f32,
    max: f32,
    avg: f32,
    min: f32,
    errors: BTreeMap<String, i32>,
}

#[derive(Clone)]
struct PidSummary {
    syscall_count: i32,
    total_time: f32,
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
    ).unwrap();
}

lazy_static! {
    static ref TIME_RE: Regex = Regex::new(r"^\d+\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})").unwrap();
}

lazy_static! {
    static ref PID_RE: Regex = Regex::new(r"^((?P<pid>\d+)\s+)").unwrap();
}

lazy_static! {
    static ref CHECK_RE: Regex = Regex::new(
        r"(?x)
        ^((?P<pid>\d+)\s+)
        ?
        (?P<time>\d{2}:\d{2}:\d{2}(\.\d+)?)?\s+.*
        (<(?P<length>.+)>$)
    "
    ).unwrap();
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

    let _fields = determine_fields(&buffer);

    let mut pids: BTreeMap<_, _> = buffer
        .par_lines()
        .filter_map(|l| PID_RE.captures(&l).and_then(|cap| cap.name("pid")))
        .map(|c| c.as_str().parse::<Pid>().unwrap())
        .map(|c| (c, HashMap::new()))
        .collect();

    parse_syscall_details(&buffer, &mut pids);

    let syscall_stats = build_syscall_stats(&pids);

    let pid_summaries = build_pid_summaries(&syscall_stats);

    let all_time = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.total_time)
        .sum();

    print_syscall_stats(&syscall_stats, &pid_summaries, all_time);

    print_n_pid_summaries(&pid_summaries, all_time, Some(10));

    println!("Total PIDs: {}", pids.len());
    println!("System Time: {0:.6}s", all_time / 1000.0);

    print_wall_clock_time(&buffer);
}

fn determine_fields(buffer: &str) -> FieldsPresent {
    let mut has_pid = false;
    let mut has_time = false;
    let mut has_length = false;

    if let Some(caps) = CHECK_RE.captures(&buffer.lines().next().unwrap()) {
        if let Some(_) = caps.name("pid") {
            has_pid = true;
        }
        if let Some(_) = caps.name("time") {
            has_time = true;
        }
        if let Some(_) = caps.name("length") {
            has_length = true;
        }
    }

    match (has_pid, has_time, has_length) {
        (true, true, true) => FieldsPresent::All,
        (_, _, _) => FieldsPresent::Base,
    }
}

fn parse_syscall_details<'a>(
    buffer: &'a str,
    pids: &mut BTreeMap<Pid, HashMap<&'a str, SyscallRawData>>,
) {
    for line in buffer.lines() {
        if let Some(caps) = ALL_RE.captures(line) {
            match (caps.name("pid"), caps.name("syscall"), caps.name("length")) {
                (Some(pid), Some(syscall), Some(length)) => {
                    let pid_entry = pids
                        .get_mut(&pid.as_str().parse::<Pid>().unwrap())
                        .unwrap()
                        .entry(syscall.as_str())
                        .or_insert(SyscallRawData {
                            times: Vec::new(),
                            errors: BTreeMap::new(),
                        });

                    pid_entry
                        .times
                        .push(length.as_str().parse::<f32>().unwrap());

                    if let Some(error) = caps.name("error_code") {
                        let error_entry = pid_entry
                            .errors
                            .entry(error.as_str().to_string())
                            .or_insert(0);
                        *error_entry += 1;
                    }
                }
                _ => {}
            }
        }
    }
}

fn build_syscall_stats(
    pids: &BTreeMap<Pid, HashMap<&str, SyscallRawData>>,
) -> BTreeMap<Pid, Vec<SyscallStats>> {
    let mut syscall_stats = BTreeMap::new();

    for (pid, syscalls) in pids {
        let mut event_stats: Vec<_> = syscalls
            .par_iter()
            .map(|(syscall, raw_data)| {
                let total: f32 = raw_data.times.par_iter().sum();
                let total = total * 1000.0;
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
                let avg = total / raw_data.times.len() as f32;
                let errors = raw_data.errors.clone();

                SyscallStats {
                    name: syscall.to_string(),
                    count: raw_data.times.len() as i32,
                    total,
                    max,
                    avg,
                    min,
                    errors,
                }
            }).collect();

        event_stats.par_sort_by(|x, y| (y.total).partial_cmp(&x.total).unwrap());

        syscall_stats.insert(*pid, event_stats);
    }

    syscall_stats
}

fn build_pid_summaries(
    syscall_stats: &BTreeMap<Pid, Vec<SyscallStats>>,
) -> BTreeMap<Pid, PidSummary> {
    let mut pid_summaries = BTreeMap::new();

    for (pid, stats) in syscall_stats {
        let syscall_count = stats
            .par_iter()
            .fold_with(0, |acc, event_stats| acc + event_stats.count)
            .sum();
        let total_time = stats
            .par_iter()
            .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
            .sum();

        pid_summaries.insert(
            *pid,
            PidSummary {
                syscall_count,
                total_time,
            },
        );
    }

    pid_summaries
}

fn print_syscall_stats(
    syscall_stats: &BTreeMap<Pid, Vec<SyscallStats>>,
    pid_summaries: &BTreeMap<Pid, PidSummary>,
    all_time: f32,
) {
    for (pid, syscalls) in syscall_stats {
        let syscall_count = pid_summaries[pid].syscall_count;
        let total_time = pid_summaries[pid].total_time;
        let perc_time = total_time / all_time * 100.0;

        if syscall_count == 0 {
            continue;
        };

        println!(
            "PID {0} - {1} syscalls, {2:.3}ms, {3:.2}%\n",
            pid, syscall_count, total_time, perc_time
        );
        println!(
            "  {0: <15}\t{1: >8}\t{2: >10.6}\t{3: >10.6}\t{4: >10.6}\t{5: >10.6}\t{6: <8}",
            "syscall", "count", "total", "max", "avg", "min", "errors"
        );
        println!(
            "  {0: <15}\t{1: >8}\t{2: >10.6}\t{3: >10.6}\t{4: >10.6}\t{5: >10.6}\t{6: >4}",
            "", "", "(ms)", "(ms)", "(ms)", "(ms)", ""
        );
        println!(
            "  ---------------\t--------\t----------\t----------\t----------\t----------\t--------"
        );
        for s in syscalls {
            print!(
                "  {0: <15}\t{1: >8}\t{2: >10.6}\t{3: >10.6}\t{4: >10.6}\t{5: >10.6}",
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

fn print_n_pid_summaries(
    pid_summaries: &BTreeMap<Pid, PidSummary>,
    all_time: f32,
    count: Option<i32>,
) {
    let count_to_print = match count {
        None => pid_summaries.len(),
        Some(i) => i as usize,
    };

    if let Some(n) = count {
        println!("Top {} PIDs\n-----------\n", n);
    }

    println!(
        "  {0: <10}\t{1: >10}\t{2: >9}\t{3: >9}",
        "pid", "time (ms)", "% time", "calls"
    );
    println!("  ----------\t----------\t---------\t---------");

    for (pid, summary) in get_sorted_pid_summaries(&pid_summaries)
        .iter()
        .take(count_to_print)
    {
        println!(
            "  {0: <10}\t{1: >10.3}\t{2: >8.2}%\t{3: >9}",
            pid,
            summary.total_time,
            summary.total_time / all_time * 100.0,
            summary.syscall_count
        );
    }
    println!("");
}

fn get_sorted_pid_summaries(pid_summaries: &BTreeMap<Pid, PidSummary>) -> Vec<(Pid, PidSummary)> {
    let mut sorted_summaries: Vec<_> = pid_summaries
        .par_iter()
        .map(|(pid, summary)| (*pid, (*summary).clone()))
        .collect();

    sorted_summaries
        .par_sort_by(|(_, x), (_, y)| (y.total_time).partial_cmp(&x.total_time).unwrap());

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
            let start_time = NaiveTime::parse_from_str(start.as_str(), "%H:%M:%S%.6f").unwrap();
            let end_time = NaiveTime::parse_from_str(end.as_str(), "%H:%M:%S%.6f").unwrap();
            let wall_clock_time = end_time - start_time;
            println!(
                "Real Time: {}.{}s",
                wall_clock_time.num_seconds(),
                wall_clock_time.num_milliseconds()
            );
        }
        _ => {}
    }
}
