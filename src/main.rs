extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate rayon;
extern crate regex;

use chrono::NaiveTime;
use clap::{App, Arg};
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

enum SortBy {
    ActiveTime,
    Pid,
    TotalTime,
}

enum Print {
    Top,
    Stats,
    Pid(Pid),
}

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

lazy_static! {
    static ref TIME_RE: Regex = Regex::new(r"^\d+\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})").unwrap();
}

fn validate_pid(p: String) -> Result<(), String> {
    if let Ok(_) = p.parse::<Pid>() {
        return Ok(());
    }
    Err(String::from("PID must be an integer"))
}

fn validate_file_count(f: String) -> Result<(), String> {
    if let Ok(_) = f.parse::<usize>() {
        return Ok(());
    }
    Err(String::from("FILE_COUNT must be a non-negative integer"))
}

fn validate_count(c: String) -> Result<(), String> {
    if let Ok(_) = c.parse::<usize>() {
        return Ok(());
    }
    Err(String::from("COUNT must be a non-negative integer"))
}

fn main() {
    let matches = App::new("strace parser")
        .version("0.2.0")
        .author("Will Chandler <wchandler@gitlab.com")
        .about("Summarizes raw strace output")
        .arg(
            Arg::with_name("top")
                .short("t")
                .long("top")
                .help("Prints a summary of top COUNT PIDs. Default option")
                .display_order(1),
        )
        .arg(
            Arg::with_name("stats")
                .short("s")
                .long("stats")
                .help("Prints a breakdown of syscall stats for COUNT PIDs")
                .display_order(2)
                .conflicts_with("top"),
        )
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .value_name("PID")
                .validator(validate_pid)
                .help("Print details of a specific PID")
                .takes_value(true)
                .conflicts_with("summary")
                .conflicts_with("top"),
        )
        .arg(
            Arg::with_name("count")
                .short("c")
                .long("count")
                .value_name("COUNT")
                .default_value_ifs(&[("top", None, "25"), ("stats", None, "5")])
                .help("The number of PIDs to print")
                .validator(validate_count)
                .conflicts_with("pid")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sort_by")
                .short("S")
                .long("sort")
                .possible_values(&["active_time", "pid", "total_time"])
                .default_value_ifs(&[
                    ("top", None, "active_time"),
                    ("summary", None, "active_time"),
                ])
                .takes_value(true)
                .help("Field to sort results by")
                .conflicts_with("pid"),
        )
        .arg(
            Arg::with_name("file_count")
                .short("f")
                .long("file_count")
                .value_name("FILE_COUNT")
                .requires("stats")
                .default_value_if("stats", None, "5")
                .help("Number of opened files to print with stats")
                .validator(validate_file_count)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Sets file to be parsed")
                .required(true)
                .takes_value(true)
                .index(1),
        )
        .get_matches();

    let count_to_print = match matches.value_of("count") {
        Some(c) => c.parse::<usize>().unwrap(),
        _ => 25,
    };

    let pid_to_print = {
        if matches.is_present("pid") {
            matches.value_of("pid").unwrap().parse::<Pid>().unwrap()
        } else {
            0
        }
    };

    let print_mode = match (
        matches.is_present("top"),
        matches.is_present("stats"),
        matches.is_present("pid"),
    ) {
        (true, _, _) => Print::Top,
        (_, true, _) => Print::Stats,
        (_, _, true) => Print::Pid(pid_to_print),
        _ => Print::Top,
    };

    let sort_by = match matches.value_of("sort_by") {
        Some("active_time") => SortBy::ActiveTime,
        Some("pid") => SortBy::Pid,
        Some("total_time") => SortBy::TotalTime,
        _ => SortBy::ActiveTime,
    };

    let file_count = match matches.value_of("file_count") {
        Some(f) => f.parse::<usize>().unwrap(),
        _ => 5,
    };

    let file_name = matches.value_of("INPUT").unwrap();

    let mut f = match File::open(file_name) {
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
        eprintln!("Error: {} is empty", file_name);
        std::process::exit(1);
    }

    let syscall_data = parse_syscall_data(&buffer);

    let pid_summaries = build_pid_summaries(&syscall_data);

    let all_time = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.total_time)
        .sum();

    let all_active_time = pid_summaries
        .par_iter()
        .fold_with(0.0, |acc, (_, summary)| acc + summary.active_time)
        .sum();

    match print_mode {
        Print::Top => print_pid_summaries(&pid_summaries, all_active_time, count_to_print, sort_by),
        Print::Stats => print_pid_stats(
            &pid_summaries,
            all_active_time,
            all_time,
            count_to_print,
            sort_by,
            file_count,
        ),
        Print::Pid(pid_to_print) => print_pid_details(&pid_summaries, pid_to_print),
    }

    println!("Total PIDs: {}", pid_summaries.len());
    println!("System Time: {0:.6}s", all_time / 1000.0);

    print_wall_clock_time(&buffer);
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

fn print_pid_stats(
    pid_summaries: &PidSummaries,
    all_active_time: f32,
    all_time: f32,
    count_to_print: usize,
    sort_by: SortBy,
    file_count: usize,
) {
    let count = {
        if count_to_print > pid_summaries.len() {
            pid_summaries.len()
        } else {
            count_to_print
        }
    };

    for (pid, summary) in sort_pid_summaries(&pid_summaries, sort_by)
        .iter()
        .take(count)
    {
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
        for s in &summary.syscall_stats {
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
        println!("  ---------------\n");

        if !summary.files.is_empty() {
            println!("Files opened:");
            if summary.files.len() > file_count {
                for f in summary.files.iter().take(file_count) {
                    println!("{}", f);
                }
                println!("And {} more...", summary.files.len() - file_count);
            } else {
                for f in summary.files.iter() {
                    println!("{}", f);
                }
            }
            println!("");
        } else {
            println!("");
        }
    }
}

fn print_pid_summaries(
    pid_summaries: &PidSummaries,
    all_active_time: f32,
    count_to_print: usize,
    sort_by: SortBy,
) {
    let count = {
        if count_to_print > pid_summaries.len() {
            pid_summaries.len()
        } else {
            count_to_print
        }
    };

    println!("Top {} PIDs\n-----------\n", count);

    println!(
        "  {0: <10}\t{1: >10}\t{2: >10}\t{3: >10}\t{4: >9}\t{5: >9}",
        "pid", "active (ms)", "wait (ms)", "total (ms)", "% active", "calls"
    );
    println!("  ----------\t----------\t---------\t---------\t---------\t---------");

    for (pid, summary) in sort_pid_summaries(&pid_summaries, sort_by)
        .iter()
        .take(count)
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

fn sort_pid_summaries<'a>(
    pid_summaries: &PidSummaries<'a>,
    sort_by: SortBy,
) -> Vec<(Pid, PidSummary<'a>)> {
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
            sorted_summaries.par_sort_by(|(pid_x, _), (pid_y, _)| (pid_x).cmp(pid_y));
        }
        SortBy::TotalTime => {
            sorted_summaries
                .par_sort_by(|(_, x), (_, y)| (y.total_time).partial_cmp(&x.total_time).unwrap());
        }
    }

    sorted_summaries
}

fn print_pid_details(pid_summaries: &PidSummaries, pid_to_print: Pid) {
    if let Some(summary) = pid_summaries.get(&pid_to_print) {
        println!(
            "PID {0} - {1} syscalls, active {2:.3}ms, total {3:.3}ms",
            pid_to_print, summary.syscall_count, summary.active_time, summary.total_time,
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
        for s in &summary.syscall_stats {
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
        println!("  ---------------\n");

        if !summary.files.is_empty() {
            println!("{} files opened:", summary.files.len());
            for f in summary.files.iter() {
                println!("{}", f);
            }
            println!("");
        }
    } else {
        println!("PID {} not found", pid_to_print);
    }
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
                _ => {}
            }
        }
        _ => {}
    }
}
