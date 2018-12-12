use self::pid_summary::PidSummary;
use self::session_summary::SessionSummary;
use self::sort_by::SortBy;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use fxhash::FxBuildHasher;
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
type RayonFxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
type RayonFxHashSet<T> = HashSet<T, FxBuildHasher>;

enum SubCmd<'a> {
    Pid(&'a ArgMatches<'a>),
    Summary(&'a ArgMatches<'a>),
}

pub enum PrintMode {
    Summary,
    Stats,
    Pid,
    Histogram(String),
    Exec,
    Open,
}

pub enum PidPrintAmt {
    All,
    Listed,
    Related,
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
    let app_matches = App::new("strace parser")
        .version("0.3.0")
        .author("Will Chandler <wchandler@gitlab.com>")
        .about("Summarizes raw strace output")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommands(vec![SubCommand::with_name("pid")
            .arg(
                Arg::with_name("PIDS")
                    .help("PID(s) to analyze")
                    .required(true)
                    .takes_value(true)
                    .number_of_values(1)
                    .multiple(true)
                    .validator(validate_pid)
                    .index(1),
            )
            .arg(
                Arg::with_name("INPUT")
                    .help("File to be parsed")
                    .required(true)
                    .takes_value(true)
                    .number_of_values(1)
                    .index(2),
            )
            .arg(
                Arg::with_name("exec")
                    .help("List program executed via 'execve', 'fork', and 'vfork'")
                    .short("e")
                    .long("exec")
                    .conflicts_with("histogram"),
            )
            .arg(
                Arg::with_name("histogram")
                    .short("h")
                    .long("histogram")
                    .takes_value(true)
                    .number_of_values(1)
                    .value_name("SYSCALL")
                    .help(
                        "Prints a log\u{2082} scale histogram of the execution times for <SYSCALL>",
                    ),
            )
            .arg(
                Arg::with_name("files")
                    .help("List files opened via 'open' and 'openat'")
                    .short("f")
                    .long("files")
                    .conflicts_with("histogram")
                    .conflicts_with("exec"),
            )
            .arg(
                Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include details of parent and child PIDs of <PID> in results")
            ),
        SubCommand::with_name("summary")
            .arg(
                Arg::with_name("INPUT")
                    .help("File to be parsed")
                    .required(true)
                    .takes_value(true)
                    .index(1),
            )
            .arg(
                Arg::with_name("details")
                    .short("d")
                    .long("details")
                    .help("Prints detailed stats for syscalls made by top <COUNT> PIDs"),
            )
            .arg(
                Arg::with_name("exec")
                    .help("List program executed via 'execve'")
                    .short("e")
                    .long("exec")
                    .conflicts_with("histogram"),
            )
            .arg(
                Arg::with_name("histogram")
                    .short("h")
                    .long("histogram")
                    .takes_value(true)
                    .number_of_values(1)
                    .value_name("SYSCALL")
                    .help(
                        "Prints a log\u{2082} scale histogram of the execution times for <SYSCALL>",
                    ),
            )
            .arg(
                Arg::with_name("files")
                    .help("List files opened via 'open' and 'openat'")
                    .short("f")
                    .long("files")
                    .conflicts_with("details")
                    .conflicts_with("histogram")
                    .conflicts_with("exec"),
            )
            .arg(
                Arg::with_name("count")
                    .short("c")
                    .long("count")
                    .takes_value(true)
                    .value_name("COUNT")
                    .default_value_if("detail", None, "5")
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
        ])
        .get_matches();

    let sub_matches = match app_matches.subcommand() {
        ("pid", Some(pid_m)) => SubCmd::Pid(pid_m),
        ("summary", Some(summ_m)) => SubCmd::Summary(summ_m),
        _ => unreachable!(),
    };

    let print_mode = match sub_matches {
        SubCmd::Pid(pid_m) => {
            if pid_m.is_present("exec") {
                PrintMode::Exec
            } else if pid_m.is_present("files") {
                PrintMode::Open
            } else if let Some(hist) = pid_m.value_of("histogram") {
                PrintMode::Histogram(hist.to_string())
            } else {
                PrintMode::Pid
            }
        }
        SubCmd::Summary(summ_m) => {
            if summ_m.is_present("details") {
                PrintMode::Stats
            } else if summ_m.is_present("exec") {
                PrintMode::Exec
            } else if summ_m.is_present("files") {
                PrintMode::Open
            } else if let Some(hist) = summ_m.value_of("histogram") {
                PrintMode::Histogram(hist.to_string())
            } else {
                PrintMode::Summary
            }
        }
    };

    let file_name = match sub_matches {
        SubCmd::Pid(pid_m) => pid_m.value_of("INPUT").unwrap(),
        SubCmd::Summary(summ_m) => summ_m.value_of("INPUT").unwrap(),
    };

    let mut f = match File::open(file_name) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("File: {} -- {}", file_name, e);
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

    let print_status = match sub_matches {
        SubCmd::Pid(pid_m) => {
            let pid_strs: RayonFxHashSet<_> = pid_m.values_of("PIDS").unwrap().collect();
            let pids: Vec<_> = pid_strs
                .into_iter()
                .map(|p| p.parse::<Pid>().unwrap())
                .collect();
            let checked_pids = session_summary.validate_pids(&pids).unwrap();

            let (pids_to_print, print_type) = if pid_m.is_present("related") {
                let related_pids = session_summary.related_pids(&checked_pids);
                (related_pids, PidPrintAmt::Related)
            } else {
                (checked_pids, PidPrintAmt::Listed)
            };

            match print_mode {
                PrintMode::Exec => session_summary.print_exec_list(&pids_to_print, print_type),
                PrintMode::Open => {
                    session_summary.print_opened_files(&pids_to_print, &syscall_data)
                }
                PrintMode::Histogram(syscall) => {
                    histogram::print_histogram(&syscall, &pids_to_print, &syscall_data)
                }
                _ => session_summary.print_pid_details(&pids_to_print, &syscall_data),
            }
        }
        SubCmd::Summary(summ_m) => {
            let sort_by = match summ_m.value_of("sort_by") {
                Some("active_time") => SortBy::ActiveTime,
                Some("children") => SortBy::ChildPids,
                Some("pid") => SortBy::Pid,
                Some("syscalls") => SortBy::SyscallCount,
                Some("total_time") => SortBy::TotalTime,
                _ => SortBy::ActiveTime,
            };

            let count_to_print = if let Some(count) = summ_m.value_of("count") {
                count.parse::<usize>().unwrap()
            } else {
                25
            };

            match print_mode {
                PrintMode::Stats => session_summary.print_pid_stats(count_to_print, sort_by),
                PrintMode::Exec => {
                    session_summary.print_exec_list(&session_summary.pids(), PidPrintAmt::All)
                }
                PrintMode::Open => {
                    session_summary.print_opened_files(&session_summary.pids(), &syscall_data)
                }
                PrintMode::Histogram(syscall) => {
                    histogram::print_histogram(&syscall, &session_summary.pids(), &syscall_data)
                }
                _ => session_summary.print_summary(elapsed_time, count_to_print, sort_by),
            }
        }
    };

    if print_status.is_err() {
        std::process::exit(1);
    }
}
