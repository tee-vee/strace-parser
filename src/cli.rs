use clap::{App, AppSettings, Arg, SubCommand};
use parser::Pid;

pub fn cli_args() -> App<'static, 'static> {
    App::new("strace parser")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about("Summarizes raw strace output")
        .setting(AppSettings::SubcommandRequired)
        .setting(AppSettings::InferSubcommands)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("INPUT")
                .help("File to be parsed")
                .required(true)
                .takes_value(true)
                .number_of_values(1),
        )
        .subcommand(SubCommand::with_name("exec")
            .about("List programs executed")
            .arg(
                Arg::with_name("pid")
                    .short("p")
                    .long("pid")
                    .help("PID(s) to analyze")
                    .takes_value(true)
                    .value_name("PIDS")
                    .multiple(true)
                    .validator(validate_pid),
            )
            .arg(
                Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include parent and child PIDs of <PIDS> in results")
                    .requires("pid"),
            ).arg(
                Arg::with_name("threads")
                    .short("t")
                    .long("threads")
                    .help("Include sibling threads of <PIDS> in results")
                    .requires("pid"),
            ))
        .subcommand(SubCommand::with_name("files")
            .about("List files opened")
            .arg(
                Arg::with_name("pid")
                    .short("p")
                    .long("pid")
                    .help("PID(s) to analyze")
                    .takes_value(true)
                    .value_name("PIDS")
                    .multiple(true)
                    .validator(validate_pid),
            )
            .arg( Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include parent and child PIDs of <PIDS> in results")
                    .requires("pid"),
            )
            .arg(
                Arg::with_name("sort_by")
                    .short("s")
                    .long("sort")
                    .help("Field to sort results by")
                    .takes_value(true)
                    .value_name("SORT_BY")
                    .possible_values(&[
                        "duration",
                        "pid",
                        "time",
                    ]),
            ).arg(
                Arg::with_name("threads")
                    .short("t")
                    .long("threads")
                    .help("Include sibling threads of <PIDS> in results")
                    .requires("pid"),
        ))
        .subcommand(SubCommand::with_name("directories")
            .about("List total duration of 'open' and 'openat' calls performed in a directory and its children")
            .arg(
                Arg::with_name("pid")
                    .short("p")
                    .long("pid")
                    .help("PID(s) to analyze")
                    .takes_value(true)
                    .value_name("PIDS")
                    .multiple(true)
                    .validator(validate_pid),
            )
            .arg( Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include parent and child PIDs of <PIDS> in results")
                    .requires("pid"),
            )
            .arg(
                Arg::with_name("sort_by")
                    .short("s")
                    .long("sort")
                    .help("Field to sort results by")
                    .takes_value(true)
                    .value_name("SORT_BY")
                    .possible_values(&[
                        "count",
                        "duration",
                        "pid",
                        "time",
                    ]),
            ).arg(
                Arg::with_name("threads")
                    .short("t")
                    .long("threads")
                    .help("Include sibling threads of <PIDS> in results")
                    .requires("pid"),
        ))
        .subcommand(SubCommand::with_name("io")
            .about("Show details of I/O syscalls: read, recv, recvfrom, recvmsg, send, sendmsg, sendto, and write")
            .arg(
                Arg::with_name("pid")
                    .short("p")
                    .long("pid")
                    .help("PID(s) to analyze")
                    .takes_value(true)
                    .value_name("PIDS")
                    .multiple(true)
                    .validator(validate_pid),
            ).arg( Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include parent and child PIDs of <PIDS> in results")
                  .requires("pid"),
            ).arg(
                Arg::with_name("sort_by")
                    .short("s")
                    .long("sort")
                    .help("Field to sort results by")
                    .takes_value(true)
                    .value_name("SORT_BY")
                    .possible_values(&[
                        "duration",
                        "pid",
                        "time",
                    ]),
            ).arg(
                Arg::with_name("threads")
                    .short("t")
                    .long("threads")
                    .help("Include sibling threads of <PIDS> in results")
                    .requires("pid"),
            ))
        .subcommand(SubCommand::with_name("list-pids")
            .about("List of PIDs and their syscall stats")
            .arg(
                Arg::with_name("count")
                    .short("c")
                    .long("count")
                    .help("The number of PIDs to print")
                    .takes_value(true)
                    .value_name("COUNT")
                    .default_value_if("detail", None, "5")
                    .validator(validate_count),
            )
            .arg(
                Arg::with_name("sort_by")
                    .short("s")
                    .long("sort")
                    .help("Field to sort results by")
                    .takes_value(true)
                    .value_name("SORT_BY")
                    .possible_values(&[
                        "active_time",
                        "children",
                        "pid",
                        "syscalls",
                        "total_time",
                        "user_time",
                    ]),
            ))
        .subcommand(SubCommand::with_name("pid")
            .about("Details of PID(s) including syscalls stats, exec'd process, and slowest 'open' calls")
            .arg(
                Arg::with_name("pid")
                    .help("PID(s) to analyze")
                    .required(true)
                    .takes_value(true)
                    .value_name("PIDS")
                    .multiple(true)
                    .validator(validate_pid),
            )
            .arg(
                Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include parent and child PIDs of <PIDS> in results")
                    .requires("pid"),
            ).arg(
                Arg::with_name("threads")
                    .short("t")
                    .long("threads")
                    .help("Include sibling threads of <PIDS> in results")
                    .requires("pid"),
            ))
        .subcommand(SubCommand::with_name("quantize")
            .about("Prints a log\u{2082} scale histogram of the quantized execution times in \u{03BC}secs for <SYSCALL>")
            .arg(
                Arg::with_name("syscall")
                    .help("Syscall to analyze")
                    .required(true)
                    .value_name("SYSCALL")
                    .takes_value(true)
                    .number_of_values(1),
            )
            .arg(
                Arg::with_name("pid")
                    .short("p")
                    .long("pid")
                    .help("PID(s) to analyze")
                    .takes_value(true)
                    .value_name("PIDS")
                    .multiple(true)
                    .validator(validate_pid),
            )
            .arg(
                Arg::with_name("related")
                    .short("r")
                    .long("related")
                    .help("Include parent and child PIDs of <PIDS> in results")
                    .requires("pid"),
            ).arg(
                Arg::with_name("threads")
                    .short("t")
                    .long("threads")
                    .help("Include sibling threads of <PIDS> in results")
                    .requires("pid"),
            ))
        .subcommand(SubCommand::with_name("summary")
            .about("Overview of PIDs in session")
            .arg(
                Arg::with_name("count")
                    .short("c")
                    .long("count")
                    .help("The number of PIDs to print")
                    .takes_value(true)
                    .value_name("COUNT")
                    .default_value_if("detail", None, "5")
                    .validator(validate_count),
            )
            .arg(
                Arg::with_name("sort_by")
                    .short("s")
                    .long("sort")
                    .help("Field to sort results by")
                    .takes_value(true)
                    .value_name("SORT_BY")
                    .possible_values(&[
                        "active_time",
                        "children",
                        "pid",
                        "syscalls",
                        "total_time",
                        "user_time",
                    ]),
            ))
        .subcommand(SubCommand::with_name("tree")
            .about("pstree-style view of traced processes")
            .arg(
                Arg::with_name("truncate")
                    .short("t")
                    .long("truncate")
                    .help("Truncate commands to 50 characters")
                    ))
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
