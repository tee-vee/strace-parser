#![cfg_attr(feature = "nightly", feature(split_ascii_whitespace))]

use clap::ArgMatches;
use memmap::MmapOptions;
use std::error::Error;
use std::fs::File;
use std::str;
use strace_parse::histogram;
use strace_parse::session_summary::SessionSummary;
use strace_parse::sort_by::{SortBy, SortEventsBy};
use strace_parse::syscall_data;
use strace_parse::syscall_stats;
use strace_parse::time;
use strace_parse::HashSet;
use strace_parse::Pid;

mod check_flags;
mod cli;

#[derive(Clone, Copy, Debug)]
enum SubCmd {
    Details,
    Exec,
    Files,
    Io,
    Histogram,
    List,
    Summary,
}

fn main() {
    let app_matches = cli::cli_args();

    match execute(app_matches) {
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
        _ => {}
    };
}


fn execute(app_matches: ArgMatches) -> Result<(), Box<dyn Error>> {
    let file_name = app_matches.value_of("INPUT").ok_or("Missing filename")?;
    let file = File::open(file_name)?;
    let mmap = unsafe { MmapOptions::new().map(&file) }?;
    let buffer = str::from_utf8(&mmap)?;

    if buffer.is_empty() {
        eprintln!("Error: {} is empty", file_name);
        std::process::exit(1);
    }

    match check_flags::correct_strace_flags(&buffer.lines().nth(0).unwrap_or_default()) {
        Ok(true) => {}
        _ => std::process::exit(0),
    }

    let syscall_data = syscall_data::build_syscall_data(&buffer);
    let syscall_stats = syscall_stats::build_syscall_stats(&syscall_data);
    let session_summary = SessionSummary::from_syscall_stats(&syscall_stats, &syscall_data);
    let elapsed_time = time::parse_elapsed_real_time(&buffer);

    let (subcmd, args) = parse_subcmd(&app_matches);

    // ignore result as we expect failures when piping to head
    let _result = match subcmd {
        SubCmd::Details => {
            let pids_to_print = select_pids(args, &session_summary)?;
            session_summary.print_pid_details(&pids_to_print, &syscall_data)
        }
        SubCmd::Io => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            let sort_by = args
                .value_of("sort_by")
                .unwrap_or_default()
                .parse::<SortEventsBy>()
                .unwrap_or_default();
            session_summary.print_io(&pids_to_print, &syscall_data, sort_by)
        }
        SubCmd::Files => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            let sort_by = args
                .value_of("sort_by")
                .unwrap_or_default()
                .parse::<SortEventsBy>()
                .unwrap_or_default();
            session_summary.print_opened_files(&pids_to_print, &syscall_data, sort_by)
        }
        SubCmd::Exec => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            session_summary.print_exec_list(&pids_to_print)
        }
        SubCmd::Histogram => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            let syscall = args.value_of("syscall").unwrap_or_default();
            histogram::print_histogram(&syscall, &pids_to_print, &syscall_data)
        }
        SubCmd::List => {
            let count_to_print = if let Some(count) = args.value_of("count") {
                count.parse::<usize>()?
            } else {
                25
            };

            let sort_by = args
                .value_of("sort_by")
                .unwrap_or_default()
                .parse::<SortBy>()
                .unwrap_or_default();
            session_summary.print_pid_list(count_to_print, sort_by)
        }
        SubCmd::Summary => {
            let count_to_print = if let Some(count) = args.value_of("count") {
                count.parse::<usize>()?
            } else {
                25
            };

            let sort_by = args
                .value_of("sort_by")
                .unwrap_or_default()
                .parse::<SortBy>()
                .unwrap_or_default();
            session_summary.print_summary(elapsed_time, count_to_print, sort_by)
        }
    };

    Ok(())

}

fn parse_subcmd<'a>(app_matches: &'a ArgMatches<'a>) -> (SubCmd, &'a ArgMatches<'a>) {
    match app_matches.subcommand() {
        ("pid", Some(args)) => (SubCmd::Details, args),
        ("exec", Some(args)) => (SubCmd::Exec, args),
        ("files", Some(args)) => (SubCmd::Files, args),
        ("io", Some(args)) => (SubCmd::Io, args),
        ("histogram", Some(args)) => (SubCmd::Histogram, args),
        ("list_pids", Some(args)) => (SubCmd::List, args),
        ("summary", Some(args)) => (SubCmd::Summary, args),
        _ => unreachable!(),
    }
}

fn select_pids(
    args: &ArgMatches,
    session_summary: &SessionSummary,
) -> Result<Vec<Pid>, Box<dyn Error>> {
    if args.value_of("pid").is_some() {
        let pid_strs: HashSet<_> = args.values_of("pid").ok_or("No pids entered")?.collect();

        let pids: Vec<_> = pid_strs
            .into_iter()
            .filter_map(|p| p.parse::<Pid>().ok())
            .collect();

        let checked_pids = session_summary.validate_pids(&pids)?;

        if args.is_present("related") {
            let related_pids = session_summary.related_pids(&checked_pids);
            Ok(related_pids)
        } else {
            Ok(checked_pids)
        }
    } else {
        Ok(session_summary.pids())
    }
}