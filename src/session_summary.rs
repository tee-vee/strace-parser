use chrono::Duration;
use crate::file_data;
use crate::pid_summary::{PrintAmt, PrintOptions};
use crate::syscall_data::PidData;
use crate::syscall_stats::SyscallStats;
use crate::{Pid, PidSummary, PidsToPrint, SortBy};
use fnv::{FnvHashMap, FnvHashSet};
use lazy_static::lazy_static;
use petgraph::prelude::*;
use rayon::prelude::*;

static PRINT_COUNT: usize = 10;

lazy_static! {
    static ref WAIT_SYSCALLS: FnvHashSet<&'static str> = {
        let mut s = FnvHashSet::default();
        s.insert("epoll_ctl");
        s.insert("epoll_wait");
        s.insert("epoll_pwait");
        s.insert("futex");
        s.insert("nanosleep");
        s.insert("restart_syscall");
        s.insert("poll");
        s.insert("ppoll");
        s.insert("pselect");
        s.insert("pselect6");
        s.insert("select");
        s.insert("wait4");
        s.insert("waitid");
        s
    };
}

pub struct SessionSummary<'a> {
    pid_summaries: FnvHashMap<Pid, PidSummary<'a>>,
    all_time: f32,
    all_active_time: f32,
}

impl<'a> SessionSummary<'a> {
    pub fn from_syscall_stats(
        session_stats: &FnvHashMap<Pid, Vec<SyscallStats<'a>>>,
        pid_data: &'a FnvHashMap<Pid, PidData<'a>>,
    ) -> SessionSummary<'a> {
        let mut summary = SessionSummary {
            pid_summaries: FnvHashMap::default(),
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
                .filter(|stat| !WAIT_SYSCALLS.contains(stat.name))
                .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
                .sum();

            let wait_time = syscall_stats
                .par_iter()
                .filter(|stat| WAIT_SYSCALLS.contains(stat.name))
                .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
                .sum();

            let total_time = active_time + wait_time;

            summary.pid_summaries.insert(
                *pid,
                PidSummary {
                    syscall_count,
                    active_time,
                    wait_time,
                    total_time,
                    syscall_stats: syscall_stats.clone(),
                    parent_pid: None,
                    child_pids: pid_data[&pid].child_pids.clone(),
                    execve: pid_data[&pid].execve.clone(),
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

    fn related_pids(&self, pids: &[Pid]) -> Vec<Pid> {
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

    fn validate_pids(&self, pids: &[Pid]) -> Vec<Pid> {
        let (valid_pids, invalid_pids): (Vec<Pid>, Vec<Pid>) = pids
            .iter()
            .cloned()
            .partition(|p| self.pid_summaries.get(p).is_some());

        for pid in invalid_pids {
            println!("No data found for PID {}", pid);
        }

        valid_pids
    }

    pub fn print_summary(&self, elapsed_time: Option<Duration>, mut count: usize, sort_by: SortBy) {
        if count > self.pid_summaries.len() {
            count = self.pid_summaries.len()
        }

        println!("\nTop {} PIDs by {}\n-----------\n", count, sort_by);

        println!(
            "  {: <7}\t{: >10}\t{: >10}\t{: >10}\t{: >9}\t{: >9}\t{: >9}",
            "", "active", "wait", "total", "% of", "", ""
        );
        println!(
            "  {: <7}\t{: >10}\t{: >10}\t{: >10}\t{: >9}\t{: >9}\t{: >9}",
            "pid", "(ms)", "(ms)", "(ms)", "actv time", "syscalls", "children"
        );
        println!("  -------\t----------\t----------\t----------\t---------\t---------\t---------");

        for (pid, pid_summary) in self.to_sorted(sort_by).iter().take(count) {
            println!(
                "  {: <7}\t{: >10.3}\t{: >10.3}\t{: >10.3}\t{: >8.2}%\t{: >9}\t{: >9}",
                pid,
                pid_summary.active_time,
                pid_summary.wait_time,
                pid_summary.total_time,
                pid_summary.active_time / self.all_active_time * 100.0,
                pid_summary.syscall_count,
                pid_summary.child_pids.len(),
            );
        }
        println!("\nTotal PIDs: {}", self.pid_summaries.len());
        println!("System Time: {:.6}s", self.all_time / 1000.0);
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

        println!(
            "\nDetails of Top {} PIDs by {}\n-----------\n",
            count, sort_by
        );

        for (pid, pid_summary) in self.to_sorted(sort_by).iter().take(count) {
            if pid_summary.syscall_count == 0 {
                continue;
            }

            println!("PID {}", pid);
            pid_summary.print(PrintOptions {
                execve: Some(PrintAmt::All),
                related_pids: Some(PrintAmt::Some(PRINT_COUNT)),
            });
        }
    }

    pub fn print_pid_details(
        &self,
        pids_to_print: PidsToPrint,
        raw_data: &FnvHashMap<Pid, PidData<'a>>,
    ) {
        let pids = match pids_to_print {
            PidsToPrint::Listed(unchecked_pids) => self.validate_pids(&unchecked_pids),
            PidsToPrint::Related(unchecked_pids) => {
                let valid_pids = self.validate_pids(&unchecked_pids);
                self.related_pids(&valid_pids)
            }
        };

        let file_times = file_data::files_opened(raw_data, &pids);

        for pid in pids {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                println!("\nPID {}", pid);
                pid_summary.print(PrintOptions {
                    execve: Some(PrintAmt::All),
                    related_pids: Some(PrintAmt::All),
                });

                if let Some(pid_files) = file_times.get(&pid) {
                    if !pid_files.is_empty() {
                        if pid_summary.parent_pid.is_some() || !pid_summary.child_pids.is_empty() {
                            println!();
                        }
                        println!("  Slowest file access times for PID {}:\n", pid);
                        println!(
                            "  {:>10}\t{: >15}\t   {: >15}\t{: <30}",
                            "open (ms)", "timestamp", "error", "   file name"
                        );
                        println!("  ----------\t---------------\t   ---------------\t   ---------");

                        for file in pid_files.iter().take(10) {
                            println!("{}", file);
                        }
                    }
                }
                println!();
            } else {
                println!("PID {} not found", pid);
            }
        }
    }

    pub fn pids(&self) -> Vec<Pid> {
        let pids: Vec<_> = self.pid_summaries.keys().cloned().collect();
        pids
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
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].syscall_count, 5);
    }

    #[test]
    fn pid_summary_active_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].active_time, 3000.0);
    }

    #[test]
    fn pid_summary_wait_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].wait_time, 2000.0);
    }

    #[test]
    fn pid_summary_total_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].total_time, 5000.0);
    }

    #[test]
    fn pid_summary_child_pids_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>
566   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000000>"##.to_string();
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert!(summary.pid_summaries[&566].child_pids.contains(&7390));
    }
}
