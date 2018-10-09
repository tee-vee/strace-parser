extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate petgraph;
extern crate rayon;
extern crate regex;

use chrono::{Duration, NaiveTime};
use clap::{App, Arg};
use petgraph::prelude::*;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

type Pid = i32;

#[derive(Debug, PartialEq)]
struct RawData<'a> {
    pid: Pid,
    syscall: &'a str,
    length: Option<f32>,
    error: Option<&'a str>,
    file: Option<&'a str>,
    child_pid: Option<Pid>,
}

impl<'a> RawData<'a> {
    fn from_strs(
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

#[derive(Debug)]
struct PidData<'a> {
    syscall_data: HashMap<&'a str, SyscallData<'a>>,
    files: BTreeSet<&'a str>,
    child_pids: Vec<Pid>,
}

impl<'a> PidData<'a> {
    fn new() -> PidData<'a> {
        PidData {
            syscall_data: HashMap::new(),
            files: BTreeSet::new(),
            child_pids: Vec::new(),
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
    child_pids: Vec<Pid>,
}

impl<'a> fmt::Display for PidSummary<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{0} syscalls, active time: {1:.3}ms, total time: {2:.3}ms\n",
            self.syscall_count, self.active_time, self.total_time
        );
        writeln!(
            f,
            "  {0: <15}\t{1: >8}\t{2: >10}\t{3: >10}\t{4: >10}\t{5: >10}\t{6: <8}",
            "syscall", "count", "total", "max", "avg", "min", "errors"
        );
        writeln!(
            f,
            "  {0: <15}\t{1: >8}\t{2: >10}\t{3: >10}\t{4: >10}\t{5: >10}\t{6: >4}",
            "", "", "(ms)", "(ms)", "(ms)", "(ms)", ""
        );
        writeln!(
            f,
            "  ---------------\t--------\t----------\t----------\t----------\t----------\t--------"
        );
        for s in &self.syscall_stats {
            writeln!(f, "{}", s);
        }

        Ok(())
    }
}

struct SessionSummary<'a> {
    pid_summaries: HashMap<Pid, PidSummary<'a>>,
    pid_graph: GraphMap<Pid, i32, Directed>,
    all_time: f32,
    all_active_time: f32,
}

impl<'a> SessionSummary<'a> {
    fn new() -> SessionSummary<'a> {
        SessionSummary {
            pid_summaries: HashMap::new(),
            pid_graph: DiGraphMap::new(),
            all_time: 0.0,
            all_active_time: 0.0,
        }
    }

    fn len(&self) -> usize {
        self.pid_summaries.len()
    }

    fn to_sorted_summaries(&self, sort_by: SortBy) -> Vec<(Pid, PidSummary<'a>)> {
        let mut sorted_summaries: Vec<_> = self
            .pid_summaries
            .par_iter()
            .map(|(pid, summary)| (*pid, (*summary).clone()))
            .collect();

        match sort_by {
            SortBy::ActiveTime => {
                sorted_summaries.par_sort_by(|(_, x), (_, y)| {
                    (y.active_time)
                        .partial_cmp(&x.active_time)
                        .expect("Invalid comparison on active times")
                });
            }
            SortBy::Pid => {
                sorted_summaries.par_sort_by(|(pid_x, _), (pid_y, _)| (pid_x).cmp(pid_y));
            }
            SortBy::TotalTime => {
                sorted_summaries.par_sort_by(|(_, x), (_, y)| {
                    (y.total_time)
                        .partial_cmp(&x.total_time)
                        .expect("Invalid comparison on total times")
                });
            }
        }

        sorted_summaries
    }
}

enum SortBy {
    ActiveTime,
    Pid,
    TotalTime,
}

enum Print {
    Top,
    Stats,
    Pid,
}

static PRINT_FILE_COUNT: usize = 5;

lazy_static! {
    static ref ALL_RE: Regex = Regex::new(
        r##"(?x)
        ^(?P<pid>\d+)[^a-zA-Z]+
        (?P<syscall>\w+)(:?\("(?P<file>[^"]+)")?
        ([^)]+<unfinished\s[.]{3}>$|.+\)\s+=\s+(?P<return_code>(-)?\d+)(:?<[^>]+>)?
        \s+(:?(?P<error_code>E[A-Z]+)\s\([^)]+\)\s+)?
        <(?P<length>\d+\.\d+)?>$)
    "##
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
            Arg::with_name("stats")
                .short("s")
                .long("stats")
                .help("Prints a breakdown of syscall stats for COUNT PIDs")
                .display_order(1),
        )
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .value_name("PID")
                .validator(validate_pid)
                .help("Print details of one or more specific PIDs")
                .takes_value(true)
                .multiple(true)
                .conflicts_with("summary"),
        )
        .arg(
            Arg::with_name("count")
                .short("c")
                .long("count")
                .value_name("COUNT")
                .default_value_if("top", None, "25")
                .help("The number of PIDs to print")
                .validator(validate_count)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sort_by")
                .short("S")
                .long("sort")
                .possible_values(&["active_time", "pid", "total_time"])
                .default_value_ifs(&[("stats", None, "active_time")])
                .takes_value(true)
                .help("Field to sort results by"),
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

    let pids_to_print = {
        if matches.is_present("pid") {
            let pid_strs: Vec<_> = matches.values_of("pid").unwrap().collect();
            pid_strs
                .into_iter()
                .map(|p| p.parse::<Pid>().unwrap())
                .collect::<Vec<Pid>>()
        } else {
            vec![0]
        }
    };

    let print_mode = match (
        matches.is_present("top"),
        matches.is_present("stats"),
        matches.is_present("pid"),
    ) {
        (true, _, _) => Print::Top,
        (_, true, _) => Print::Stats,
        (_, _, true) => Print::Pid,
        _ => Print::Top,
    };

    let sort_by = match matches.value_of("sort_by") {
        Some("active_time") => SortBy::ActiveTime,
        Some("pid") => SortBy::Pid,
        Some("total_time") => SortBy::TotalTime,
        _ => SortBy::ActiveTime,
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

    let session_summary = build_session_summary(&syscall_data);

    let elapsed_time = parse_elapsed_real_time(&buffer);

    match print_mode {
        Print::Top => {
            print_session_summary(&session_summary, elapsed_time, count_to_print, sort_by)
        }
        Print::Stats => print_pid_stats(&session_summary, count_to_print, sort_by),
        Print::Pid => print_pid_details(&session_summary, &pids_to_print),
    }

    build_pid_graph(&session_summary);
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
                child_pids: syscall_data[&pid].child_pids.clone(),
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

    session_summary.pid_graph = build_pid_graph(&session_summary);

    session_summary
}

fn build_pid_graph(session: &SessionSummary) -> GraphMap<Pid, i32, Directed> {
    let mut pid_graph = DiGraphMap::new();

    for (pid, pid_summary) in &session.pid_summaries {
        if !pid_summary.child_pids.is_empty() {
            for child in &pid_summary.child_pids {
                pid_graph.add_edge(*pid, *child, 1);
            }
        }
    }

    pid_graph
}

fn print_session_summary(
    session_summary: &SessionSummary,
    elapsed_time: Option<Duration>,
    mut count: usize,
    sort_by: SortBy,
) {
    if count > session_summary.len() {
        count = session_summary.len()
    }

    println!("");
    println!("Top {} PIDs\n-----------\n", count);

    println!(
        "  {0: <10}\t{1: >10}\t{2: >10}\t{3: >10}\t{4: >9}\t{5: >9}",
        "pid", "active (ms)", "wait (ms)", "total (ms)", "% active", "calls"
    );
    println!("  ----------\t----------\t---------\t---------\t---------\t---------");

    for (pid, pid_summary) in session_summary
        .to_sorted_summaries(sort_by)
        .iter()
        .take(count)
    {
        println!(
            "  {0: <10}\t{1: >10.3}\t{2: >10.3}\t{3: >10.3}\t{4: >8.2}%\t{5: >9}",
            pid,
            pid_summary.active_time,
            pid_summary.wait_time,
            pid_summary.total_time,
            pid_summary.active_time / session_summary.all_active_time * 100.0,
            pid_summary.syscall_count
        );
    }
    println!("");
    println!("Total PIDs: {}", session_summary.len());
    println!("System Time: {0:.6}s", session_summary.all_time / 1000.0);
    if let Some(real_time) = elapsed_time {
        println!(
            "Real Time: {}.{}s",
            real_time.num_seconds(),
            real_time.num_milliseconds()
        );
    }
}

fn print_pid_stats(session_summary: &SessionSummary, mut count: usize, sort_by: SortBy) {
    if count > session_summary.len() {
        count = session_summary.len()
    }

    println!("");

    for (pid, pid_summary) in session_summary
        .to_sorted_summaries(sort_by)
        .iter()
        .take(count)
    {
        if pid_summary.syscall_count == 0 {
            continue;
        }

        println!("PID {}", pid);
        print!("{}", pid_summary);
        println!("  ---------------\n");

        let parent = session_summary
            .pid_graph
            .neighbors_directed(*pid, Incoming)
            .peekable();

        for p in parent {
            println!("Parent PID: {}", p);
        }

        if pid_summary.child_pids.is_empty() {
            println!("");
        } else {
            let mut children = session_summary
                .pid_graph
                .neighbors_directed(*pid, Outgoing)
                .enumerate()
                .peekable();

            print!("Child PIDs:  ");
            if pid_summary.child_pids.len() > 10 {
                for (i, p) in children.take(10) {
                    if i != 9 {
                        print!("{}, ", p);
                    } else {
                        println!("{}", p);
                    }
                }
                println!("And {} more...", pid_summary.child_pids.len() - 10);
            } else {
                while let Some((i, n)) = children.next() {
                    if i % 10 == 0 && i != 0 {
                        println!("");
                    }
                    if let Some(_) = children.peek() {
                        print!("{}, ", n);
                    } else {
                        print!("{}", n);
                    }
                }
            }
            println!("\n");
        }

        if !pid_summary.files.is_empty() {
            println!("Files opened:");
            if pid_summary.files.len() > PRINT_FILE_COUNT {
                for f in pid_summary.files.iter().take(PRINT_FILE_COUNT) {
                    println!("{}", f);
                }
                println!("And {} more...", pid_summary.files.len() - PRINT_FILE_COUNT);
            } else {
                for f in pid_summary.files.iter() {
                    println!("{}", f);
                }
            }
        }
        println!("\n");
    }
}

fn print_pid_details(session_summary: &SessionSummary, pids: &Vec<Pid>) {
    for pid in pids {
        if let Some(pid_summary) = session_summary.pid_summaries.get(&pid) {
            println!("");
            println!("PID {}", pid);
            print!("{}", pid_summary);
            println!("  ---------------\n");

            let parent = session_summary
                .pid_graph
                .neighbors_directed(*pid, Incoming)
                .peekable();
            for p in parent {
                println!("Parent PID: {}", p);
            }

            if !pid_summary.child_pids.is_empty() {
                let mut children = session_summary
                    .pid_graph
                    .neighbors_directed(*pid, Outgoing)
                    .enumerate()
                    .peekable();

                print!("{} Child PIDs:  ", pid_summary.child_pids.len());
                while let Some((i, n)) = children.next() {
                    if i % 10 == 0 {
                        println!("");
                    }
                    if let Some(_) = children.peek() {
                        print!("{}, ", n);
                    } else {
                        print!("{}", n);
                    }
                }
                println!("\n");
            }

            if !pid_summary.files.is_empty() {
                println!("{} files opened:", pid_summary.files.len());
                for f in pid_summary.files.iter() {
                    println!("{}", f);
                }
            }

            println!("");
        } else {
            println!("PID {} not found", pid);
        }
    }
}

fn parse_elapsed_real_time(buffer: &str) -> Option<chrono::Duration> {
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
                (Ok(start), Ok(end)) => Some(end - start),
                _ => None,
            }
        }
        _ => None,
    }
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

    #[test]
    fn syscall_stats_name_correct() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##
            .to_string();
        let pid_data_map = parse_syscall_data(&input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        assert_eq!(pid_stats[&477][0].name, "fcntl");
    }

    #[test]
    fn syscall_stats_count_correct() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##
            .to_string();
        let pid_data_map = parse_syscall_data(&input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].count, 4);
    }

    #[test]
    fn syscall_stats_max_correct() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##
            .to_string();
        let pid_data_map = parse_syscall_data(&input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].max, 1500.0);
    }

    #[test]
    fn syscall_stats_min_correct() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##
            .to_string();
        let pid_data_map = parse_syscall_data(&input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].min, 500.0);
    }

    #[test]
    fn syscall_stats_avg_correct() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##
            .to_string();
        let pid_data_map = parse_syscall_data(&input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].avg, 1000.0);
    }

    #[test]
    fn syscall_stats_errors_correct() {
        let input = r##"477   00:09:57.959706 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000014>"##
            .to_string();
        let pid_data_map = parse_syscall_data(&input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].errors["ECHILD"], 1);
    }

    #[test]
    fn pid_summary_count_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let summary = build_session_summary(&pid_data_map);
        assert_eq!(summary.pid_summaries[&566].syscall_count, 5);
    }

    #[test]
    fn pid_summary_active_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let summary = build_session_summary(&pid_data_map);
        assert_eq!(summary.pid_summaries[&566].active_time, 3000.0);
    }

    #[test]
    fn pid_summary_wait_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let summary = build_session_summary(&pid_data_map);
        assert_eq!(summary.pid_summaries[&566].wait_time, 2000.0);
    }

    #[test]
    fn pid_summary_total_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let summary = build_session_summary(&pid_data_map);
        assert_eq!(summary.pid_summaries[&566].total_time, 5000.0);
    }

    #[test]
    fn pid_summary_files_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let summary = build_session_summary(&pid_data_map);
        assert!(summary.pid_summaries[&566].files.contains("/proc/net/unix"));
    }

    #[test]
    fn pid_summary_child_pids_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>
566   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let summary = build_session_summary(&pid_data_map);
        assert!(summary.pid_summaries[&566].child_pids.contains(&7390));
    }
}
