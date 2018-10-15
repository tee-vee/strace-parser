use chrono::Duration;
use crate::file_data::FileData;
use crate::{syscall_data::PidData, Pid, PidSummary};
use crate::{syscall_stats::SyscallStats, SortBy};
use petgraph::prelude::*;
use rayon::prelude::*;
use std::collections::HashMap;

static PRINT_FILE_COUNT: usize = 5;

pub struct SessionSummary<'a> {
    pid_summaries: HashMap<Pid, PidSummary<'a>>,
    all_time: f32,
    all_active_time: f32,
}

impl<'a> SessionSummary<'a> {
    pub fn from_syscall_stats(
        session_stats: HashMap<Pid, Vec<SyscallStats<'a>>>,
        mut pid_data: HashMap<Pid, PidData<'a>>,
    ) -> SessionSummary<'a> {
        let mut summary = SessionSummary {
            pid_summaries: HashMap::new(),
            all_time: 0.0,
            all_active_time: 0.0,
        };

        for (pid, syscall_stats) in session_stats {
            let syscall_count = syscall_stats
                .par_iter()
                .fold_with(0, |acc, event_stats| acc + event_stats.count)
                .sum();

            let active_time = syscall_stats
                .par_iter()
                .filter(|stat| match stat.name.as_ref() {
                    "epoll_ctl" | "epoll_wait" | "epoll_pwait" | "futex" | "nanosleep"
                    | "restart_syscall" | "poll" | "ppoll" | "pselect" | "select" | "wait4" => {
                        false
                    }
                    _ => true,
                })
                .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
                .sum();

            let wait_time = syscall_stats
                .par_iter()
                .filter(|stat| match stat.name.as_ref() {
                    "epoll_ctl" | "epoll_wait" | "epoll_pwait" | "futex" | "nanosleep"
                    | "restart_syscall" | "poll" | "ppoll" | "pselect" | "select" | "wait4" => true,
                    _ => false,
                })
                .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
                .sum();

            let total_time = active_time + wait_time;

            let extracted_pid_data = pid_data.remove(&pid).expect("Pid not found in pid_data");
            let files = extracted_pid_data.files;
            let child_pids = extracted_pid_data.child_pids;

            summary.pid_summaries.insert(
                pid,
                PidSummary {
                    syscall_count,
                    active_time,
                    wait_time,
                    total_time,
                    syscall_stats,
                    files,
                    parent_pid: None,
                    child_pids,
                },
            );
        }

        summary.all_time = summary
            .pid_summaries
            .par_iter()
            .fold_with(0.0, |acc, (_, pid_summary)| acc + pid_summary.total_time)
            .sum();

        summary.all_active_time = summary
            .pid_summaries
            .par_iter()
            .fold_with(0.0, |acc, (_, pid_summary)| acc + pid_summary.active_time)
            .sum();

        let pid_graph = summary.build_pid_graph();

        for (pid, pid_summary) in summary.pid_summaries.iter_mut() {
            let mut parent_graph = pid_graph.neighbors_directed(*pid, Incoming);

            if let Some(parent) = parent_graph.next() {
                pid_summary.parent_pid = Some(parent);
            }
        }

        summary
    }

    fn to_sorted(&self, sort_by: SortBy) -> Vec<(Pid, PidSummary<'a>)> {
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
            SortBy::ChildPids => {
                sorted_summaries
                    .par_sort_by(|(_, x), (_, y)| (y.child_pids.len().cmp(&x.child_pids.len())));
            }
            SortBy::Pid => {
                sorted_summaries.par_sort_by(|(pid_x, _), (pid_y, _)| (pid_x).cmp(pid_y));
            }
            SortBy::SyscallCount => {
                sorted_summaries
                    .par_sort_by(|(_, x), (_, y)| (y.syscall_count).cmp(&x.syscall_count));
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

    fn build_pid_graph(&self) -> GraphMap<Pid, i32, Directed> {
        let mut pid_graph = DiGraphMap::new();

        for (pid, pid_summary) in self.pid_summaries.iter() {
            if !pid_summary.child_pids.is_empty() {
                for child in &pid_summary.child_pids {
                    pid_graph.add_edge(*pid, *child, 1);
                }
            }
        }

        pid_graph
    }

    pub fn related_pids(&self, pids: &[Pid]) -> Vec<Pid> {
        let mut related_pids = Vec::new();

        for pid in pids {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                related_pids.push(*pid);
                if let Some(parent) = pid_summary.parent_pid {
                    related_pids.push(parent);
                }

                for child in &pid_summary.child_pids {
                    related_pids.push(*child);
                }
            }
        }

        related_pids
    }

    pub fn print_summary(&self, elapsed_time: Option<Duration>, mut count: usize, sort_by: SortBy) {
        if count > self.pid_summaries.len() {
            count = self.pid_summaries.len()
        }

        println!("");
        println!("Top {} PIDs\n-----------\n", count);

        println!(
            "  {0: <10}\t{1: >10}\t{2: >10}\t{3: >10}\t{4: >9}\t{5: >9}",
            "pid", "active (ms)", "wait (ms)", "total (ms)", "% active", "syscalls"
        );
        println!("  ----------\t----------\t---------\t---------\t---------\t---------");

        for (pid, pid_summary) in self.to_sorted(sort_by).iter().take(count) {
            println!(
                "  {0: <10}\t{1: >10.3}\t{2: >10.3}\t{3: >10.3}\t{4: >8.2}%\t{5: >9}",
                pid,
                pid_summary.active_time,
                pid_summary.wait_time,
                pid_summary.total_time,
                pid_summary.active_time / self.all_active_time * 100.0,
                pid_summary.syscall_count
            );
        }
        println!("");
        println!("Total PIDs: {}", self.pid_summaries.len());
        println!("System Time: {0:.6}s", self.all_time / 1000.0);
        if let Some(real_time) = elapsed_time {
            println!(
                "Real Time: {}.{}s",
                real_time.num_seconds(),
                real_time.num_milliseconds()
            );
        }
    }

    pub fn print_pid_stats(&self, mut count: usize, sort_by: SortBy) {
        if count > self.pid_summaries.len() {
            count = self.pid_summaries.len()
        }

        let sorted_by = match sort_by {
            SortBy::ActiveTime => "Active Time",
            SortBy::ChildPids => "# of Child Processes",
            SortBy::Pid => "PID #",
            SortBy::SyscallCount => "Syscall Count",
            SortBy::TotalTime => "Total Time",
        };

        println!("");
        println!(
            "Details of Top {} PIDs by {}\n-----------\n",
            count, sorted_by
        );

        for (pid, pid_summary) in self.to_sorted(sort_by).iter().take(count) {
            if pid_summary.syscall_count == 0 {
                continue;
            }

            println!("PID {}", pid);
            print!("{}", pid_summary);
            println!("  ---------------\n");

            if let Some(p) = pid_summary.parent_pid {
                println!("Parent PID: {}", p);
            }

            if !pid_summary.child_pids.is_empty() {
                print!("Child PIDs:  ");
                if pid_summary.child_pids.len() > 10 {
                    for (i, p) in pid_summary.child_pids.iter().enumerate().take(10) {
                        if i != 9 {
                            print!("{}, ", p);
                        } else {
                            println!("{}", p);
                        }
                    }
                    println!("And {} more...", pid_summary.child_pids.len() - 10);
                } else {
                    let mut child_pid_iter = pid_summary.child_pids.iter().enumerate().peekable();
                    while let Some((i, n)) = child_pid_iter.next() {
                        if i % 10 == 0 && i != 0 {
                            println!("");
                        }
                        if let Some(_) = child_pid_iter.peek() {
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

    pub fn print_pid_details(&self, pids: &[Pid], file_lines: &HashMap<Pid, Vec<FileData>>) {
        for pid in pids {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                println!("");
                println!("PID {}", pid);
                print!("{}", pid_summary);
                println!("  ---------------\n");

                if let Some(p) = pid_summary.parent_pid {
                    println!("  Parent PID: {}", p);
                }

                if !pid_summary.child_pids.is_empty() {
                    print!("  Child PIDs:  ");

                    let mut child_pid_iter = pid_summary.child_pids.iter().enumerate().peekable();
                    while let Some((i, n)) = child_pid_iter.next() {
                        if i % 10 == 0 && i != 0 {
                            print!("\n    ");
                        }
                        if let Some(_) = child_pid_iter.peek() {
                            print!("{}, ", n);
                        } else {
                            print!("{}", n);
                        }
                    }
                    println!("\n  ");
                } else {
                    println!("");
                }

                if let Some(pid_files) = file_lines.get(&pid) {
                    println!("  Slowest file access times for PID {}:\n", pid);
                    println!(
                        "  {0: >12}\t{1: >15}\t   {2: >15}\t{3: <30}",
                        "open (ms)", "timestamp", "error", "   file name"
                    );
                    println!("  -----------\t---------------\t   ---------------\t   ----------");

                    for file in pid_files.iter().take(10) {
                        println!("{}", file);
                    }
                }

                println!("");
            } else {
                println!("PID {} not found", pid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_data::*;
    use crate::syscall_stats::*;

    #[test]
    fn pid_summary_count_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = parse_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(syscall_stats, pid_data_map);
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
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(syscall_stats, pid_data_map);
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
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(syscall_stats, pid_data_map);
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
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(syscall_stats, pid_data_map);
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
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(syscall_stats, pid_data_map);
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
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(syscall_stats, pid_data_map);
        assert!(summary.pid_summaries[&566].child_pids.contains(&7390));
    }
}
