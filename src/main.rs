use bstr::ByteSlice;
use clap::ArgMatches;
use memmap::MmapOptions;
use parser::histogram;
use parser::session_summary::SessionSummary;
use parser::sort_by::{SortBy, SortEventsBy};
use parser::syscall_data;
use parser::syscall_stats;
use parser::time;
use parser::HashSet;
use parser::Pid;
use std::error::Error;
use std::fs::File;

mod check_flags;
mod cli;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Clone, Copy, Debug)]
enum SubCmd {
    Details,
    Exec,
    Files,
    Directories,
    Io,
    List,
    Quantize,
    Summary,
    Tree,
}

fn main() {
    let app_matches = cli::cli_args().get_matches();

    if let Err(e) = execute(app_matches) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn execute(app_matches: ArgMatches) -> Result<(), Box<dyn Error>> {
    let file_name = app_matches.value_of("INPUT").ok_or("Missing filename")?;
    let file = File::open(file_name)?;
    let mmap = unsafe { MmapOptions::new().map(&file) }?;
    let bytes = mmap.as_ref();

    if bytes.is_empty() {
        eprintln!("Error: {} is empty", file_name);
        std::process::exit(1);
    }

    match check_flags::correct_strace_flags(
        bytes.lines().next().unwrap_or_default().to_str().unwrap(),
    ) {
        Ok(true) => {}
        _ => std::process::exit(0),
    }

    let syscall_data = syscall_data::build_syscall_data(bytes);
    let syscall_stats = syscall_stats::build_syscall_stats(&syscall_data);
    let session_summary = SessionSummary::from_syscall_stats(&syscall_stats, &syscall_data);
    let elapsed_time = time::parse_elapsed_real_time(bytes);

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
                .unwrap_or(SortEventsBy::Time);
            session_summary.print_io(&pids_to_print, &syscall_data, sort_by)
        }
        SubCmd::Files => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            let sort_by = args
                .value_of("sort_by")
                .unwrap_or_default()
                .parse::<SortEventsBy>()
                .unwrap_or(SortEventsBy::Time);
            session_summary.print_opened_files(&pids_to_print, &syscall_data, sort_by)
        }
        SubCmd::Directories => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            let sort_by = args
                .value_of("sort_by")
                .unwrap_or_default()
                .parse::<SortEventsBy>()
                .unwrap_or(SortEventsBy::Time);
            session_summary.print_opened_directories(&pids_to_print, &syscall_data, sort_by)
        }
        SubCmd::Exec => {
            let mut pids_to_print = select_pids(&args, &session_summary)?;
            pids_to_print.sort();
            session_summary.print_exec_list(&pids_to_print)
        }
        SubCmd::Quantize => {
            let pids_to_print = select_pids(&args, &session_summary)?;
            let syscall = args.value_of("syscall").unwrap_or_default();
            histogram::print_histogram(syscall.as_bytes(), &pids_to_print, &syscall_data)
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
                .unwrap_or(SortBy::ActiveTime);
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
                .unwrap_or(SortBy::ActiveTime);
            session_summary.print_summary(elapsed_time, count_to_print, sort_by)
        }
        SubCmd::Tree => {
            let truncate = args.is_present("truncate");
            session_summary.print_pid_tree(truncate)
        }
    };

    Ok(())
}

fn parse_subcmd<'a>(app_matches: &'a ArgMatches<'a>) -> (SubCmd, &'a ArgMatches<'a>) {
    match app_matches.subcommand() {
        ("pid", Some(args)) => (SubCmd::Details, args),
        ("exec", Some(args)) => (SubCmd::Exec, args),
        ("files", Some(args)) => (SubCmd::Files, args),
        ("directories", Some(args)) => (SubCmd::Directories, args),
        ("io", Some(args)) => (SubCmd::Io, args),
        ("quantize", Some(args)) => (SubCmd::Quantize, args),
        ("list-pids", Some(args)) => (SubCmd::List, args),
        ("summary", Some(args)) => (SubCmd::Summary, args),
        ("tree", Some(args)) => (SubCmd::Tree, args),
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
        } else if args.is_present("threads") {
            let threads = session_summary.threads(&checked_pids);
            Ok(threads)
        } else {
            Ok(checked_pids)
        }
    } else {
        Ok(session_summary.pids())
    }
}
