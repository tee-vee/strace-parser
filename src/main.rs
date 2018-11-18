use self::pid_summary::PidSummary;
use self::session_summary::SessionSummary;
use self::sort_by::SortBy;
use clap::{App, Arg};
use fnv::FnvBuildHasher;
use rayon_hash::{HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;

mod file_data;
mod histogram;
mod parser;
mod pid_summary;
mod real_time;
mod session_summary;
mod sort_by;
mod syscall_data;
mod syscall_stats;

type Pid = i32;
type RayonFnvHashMap<K, V> = HashMap<K, V, FnvBuildHasher>;
type RayonFnvHashSet<T> = HashSet<T, FnvBuildHasher>;

pub enum PrintMode {
    Top,
    Stats,
    Pid(PidsToPrint),
    Histogram((String, Option<Vec<Pid>>)),
}

pub enum PidsToPrint {
    Listed(Vec<Pid>),
    Related(Vec<Pid>),
}

fn validate_pid(p: String) -> Result<(), String> {
    if p.parse::<Pid>().is_ok() {
        return Ok(());
    }
    Err(String::from("PID must be an integer"))
}

fn validate_count(c: String) -> Result<(), String> {
    if c.parse::<usize>().is_ok() {
        return Ok(());
    }
    Err(String::from("COUNT must be a non-negative integer"))
}

fn main() {
    let matches = App::new("strace parser")
        .version("0.2.7")
        .author("Will Chandler <wchandler@gitlab.com>")
        .about("Summarizes raw strace output")
        .arg(
            Arg::with_name("stats")
                .short("s")
                .long("stats")
                .help("Prints a breakdown of syscall stats for <COUNT> PIDs"),
        )
        .arg(
            Arg::with_name("histogram")
                .short("h")
                .long("histogram")
                .takes_value(true)
                .value_name("SYSCALL")
                .help("Prints a log\u{2082} scale histogram of the execution times for <SYSCALL>")
                .conflicts_with("stats"),
        )
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .takes_value(true)
                .value_name("PID")
                .validator(validate_pid)
                .help("Print details of one or more specific PIDs")
                .multiple(true)
                .conflicts_with("stats"),
        )
        .arg(
            Arg::with_name("related")
                .short("r")
                .long("related")
                .help("With `--pid`, will print details of parent and child PIDs of <PID>")
                .conflicts_with("stats")
                .requires("pid"),
        )
        .arg(
            Arg::with_name("count")
                .short("c")
                .long("count")
                .takes_value(true)
                .value_name("COUNT")
                .default_value_if("stats", None, "5")
                .help("The number of PIDs to print")
                .validator(validate_count),
        )
        .arg(
            Arg::with_name("sort_by")
                .short("S")
                .long("sort")
                .value_name("SORT_BY")
                .possible_values(&["active_time", "children", "pid", "syscalls", "total_time"])
                .takes_value(true)
                .help("Field to sort results by"),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("File to be parsed")
                .required(true)
                .takes_value(true)
                .index(1),
        )
        .get_matches();

    let count_to_print = match matches.value_of("count") {
        Some(c) => c.parse::<usize>().unwrap(),
        _ => 25,
    };

    let print_mode = {
        if matches.is_present("pid") {
            let pid_strs: RayonFnvHashSet<_> = matches.values_of("pid").unwrap().collect();
            let pids: Vec<_> = pid_strs
                .into_iter()
                .map(|p| p.parse::<Pid>().unwrap())
                .collect();
            if matches.is_present("related") {
                PrintMode::Pid(PidsToPrint::Related(pids))
            } else if matches.is_present("histogram") {
                PrintMode::Histogram((
                    matches.value_of("histogram").unwrap().to_string(),
                    Some(pids),
                ))
            } else {
                PrintMode::Pid(PidsToPrint::Listed(pids))
            }
        } else {
            if matches.is_present("stats") {
                PrintMode::Stats
            } else if matches.is_present("histogram") {
                PrintMode::Histogram((matches.value_of("histogram").unwrap().to_string(), None))
            } else {
                PrintMode::Top
            }
        }
    };

    let sort_by = match matches.value_of("sort_by") {
        Some("active_time") => SortBy::ActiveTime,
        Some("children") => SortBy::ChildPids,
        Some("pid") => SortBy::Pid,
        Some("syscalls") => SortBy::SyscallCount,
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

    if buffer.is_empty() {
        eprintln!("Error: {} is empty", file_name);
        std::process::exit(1);
    }

    let syscall_data = syscall_data::build_syscall_data(&buffer);

    let syscall_stats = syscall_stats::build_syscall_stats(&syscall_data);

    let session_summary = SessionSummary::from_syscall_stats(&syscall_stats, &syscall_data);

    let elapsed_time = real_time::parse_elapsed_real_time(&buffer);

    match print_mode {
        PrintMode::Top => session_summary.print_summary(elapsed_time, count_to_print, sort_by),
        PrintMode::Stats => session_summary.print_pid_stats(count_to_print, sort_by),
        PrintMode::Pid(pids) => session_summary.print_pid_details(pids, &syscall_data),
        PrintMode::Histogram((syscall, pids)) => {
            if let Some(pids) = pids {
                histogram::print_histogram(&syscall, &pids, &syscall_data);
            } else {
                histogram::print_histogram(&syscall, &session_summary.pids(), &syscall_data);
            }
        }
    }
}
