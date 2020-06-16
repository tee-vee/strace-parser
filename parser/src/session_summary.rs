use crate::exec::Execs;
use crate::pid_summary::PrintAmt;
use crate::syscall_data::PidData;
use crate::syscall_stats::SyscallStats;
use crate::{file_data, file_data::SortFilesBy, io_data, pid_tree};
use crate::{HashMap, HashSet, Pid, PidSummary, SortBy, SortEventsBy};
use chrono::Duration;
use petgraph::prelude::*;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::io::{prelude::*, stdout, Error};

static PRINT_COUNT: usize = 10;

#[derive(Default)]
pub struct SessionSummary<'a> {
    pid_summaries: HashMap<Pid, PidSummary<'a>>,
    all_time: f32,
    all_active_time: f32,
    all_user_time: f32,
}

impl<'a> SessionSummary<'a> {
    pub fn from_syscall_stats(
        session_stats: &HashMap<Pid, Vec<SyscallStats<'a>>>,
        pid_data: &'a HashMap<Pid, PidData<'a>>,
    ) -> SessionSummary<'a> {
        let mut summary = SessionSummary::default();

        for (pid, syscall_stats) in session_stats {
            summary.pid_summaries.insert(
                *pid,
                PidSummary::from((syscall_stats.as_slice(), &pid_data[pid])),
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
            .fold_with(0.0, |acc, (_, pid_summary)| {
                acc + pid_summary.system_active_time
            })
            .sum();

        summary.all_user_time = summary
            .pid_summaries
            .par_iter()
            .fold_with(0.0, |acc, (_, pid_summary)| acc + pid_summary.user_time)
            .sum();

        let pid_graph = summary.build_pid_graph();

        for (&pid, pid_summary) in summary.pid_summaries.iter_mut() {
            let mut parent_graph = pid_graph.neighbors_directed(pid, Incoming);

            if let Some(parent) = parent_graph.next() {
                pid_summary.parent_pid = Some(parent);
            }
        }

        summary.populate_threads();

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
                    (y.system_active_time)
                        .partial_cmp(&x.system_active_time)
                        .expect("Invalid comparison on active times")
                });
            }
            SortBy::ChildPids => {
                sorted_summaries
                    .par_sort_by(|(_, x), (_, y)| (y.child_pids.len()).cmp(&x.child_pids.len()));
            }
            SortBy::Pid => {
                sorted_summaries.par_sort_by(|(pid_x, _), (pid_y, _)| (pid_x).cmp(pid_y));
            }
            SortBy::StartTime => {
                sorted_summaries.par_sort_by(|(_, x), (_, y)| (x.start_time).cmp(&y.start_time));
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
            SortBy::UserTime => {
                sorted_summaries.par_sort_by(|(_, x), (_, y)| {
                    (y.user_time)
                        .partial_cmp(&x.user_time)
                        .expect("Invalid comparison on user times")
                });
            }
        }

        sorted_summaries
    }

    fn build_pid_graph(&self) -> GraphMap<Pid, Pid, Directed> {
        let mut pid_graph = DiGraphMap::new();

        for (&pid, pid_summary) in self.pid_summaries.iter() {
            if !pid_summary.child_pids.is_empty() {
                for &child in &pid_summary.child_pids {
                    pid_graph.add_edge(pid, child, 1);
                }
            }
        }

        pid_graph
    }

    fn populate_threads(&mut self) {
        let mut thread_map = HashMap::new();

        for (&pid, pid_summary) in &self.pid_summaries {
            for &thread in &pid_summary.threads {
                let thread_entry = thread_map.entry(thread).or_insert_with(Vec::new);
                thread_entry.push(pid);
                thread_entry.extend(pid_summary.threads.iter().filter(|&&t| t != thread));
            }
        }

        for (pid, threads) in thread_map.into_iter() {
            if let Some(pid_summary) = self.pid_summaries.get_mut(&pid) {
                pid_summary.threads.extend(threads);
            }
        }

        let futex_map = self.calc_futex_threads();
        for (pid, threads) in futex_map.into_iter() {
            if let Some(pid_summary) = self.pid_summaries.get_mut(&pid) {
                pid_summary.threads.extend(threads);
            }
        }
    }

    fn calc_futex_threads(&self) -> HashMap<Pid, HashSet<Pid>> {
        let mut addr_map = HashMap::new();
        for (&pid, pid_summary) in &self.pid_summaries {
            for addr in &pid_summary.pvt_futex {
                let addr_entry = addr_map.entry(addr).or_insert_with(HashSet::new);
                addr_entry.insert(pid);
            }
        }

        let mut addr_graph: UnGraphMap<&str, i8> = UnGraphMap::new();
        for (&&addr, pids) in &addr_map {
            for (inr_addr, inr_pids) in addr_map.iter().filter(|(&&a, _)| a != addr) {
                if !pids.is_disjoint(inr_pids) {
                    addr_graph.add_edge(addr, inr_addr, 1);
                }
            }
        }

        let mut thread_map: HashMap<Pid, HashSet<Pid>> = HashMap::new();
        for (addr, pids) in &addr_map {
            let mut dfs = Dfs::new(&addr_graph, addr);

            while let Some(relative) = dfs.next(&addr_graph) {
                for &pid in pids.iter() {
                    let entry = thread_map.entry(pid).or_insert_with(HashSet::new);
                    entry.extend(pids.iter().filter(|&&p| p != pid));

                    if let Some(more_pids) = addr_map.get(&relative) {
                        entry.extend(more_pids.iter().filter(|&&p| p != pid));
                    }
                }
            }
        }

        thread_map
    }

    pub fn related_pids(&self, pids: &[Pid]) -> Vec<Pid> {
        let mut related_pids = BTreeSet::new();

        for pid in pids {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                related_pids.insert(*pid);
                if let Some(parent) = pid_summary.parent_pid {
                    related_pids.insert(parent);
                }

                related_pids.extend(&pid_summary.threads);
                related_pids.extend(&pid_summary.child_pids);
            }
        }

        related_pids.into_iter().collect::<Vec<_>>()
    }

    pub fn threads(&self, pids: &[Pid]) -> Vec<Pid> {
        let mut threads = BTreeSet::new();

        for &pid in pids {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                threads.insert(pid);
                threads.extend(&pid_summary.threads);
            }
        }

        threads.into_iter().collect::<Vec<_>>()
    }

    pub fn validate_pids(&self, pids: &[Pid]) -> Result<Vec<Pid>, Error> {
        let (valid_pids, invalid_pids): (BTreeSet<Pid>, BTreeSet<Pid>) = pids
            .iter()
            .copied()
            .partition(|p| self.pid_summaries.get(p).is_some());

        for pid in invalid_pids {
            writeln!(stdout(), "No data found for PID {}", pid)?;
        }

        Ok(valid_pids.into_iter().collect::<Vec<_>>())
    }

    pub fn print_summary(
        &self,
        elapsed_time: Option<Duration>,
        mut count: usize,
        sort_by: SortBy,
    ) -> Result<(), Error> {
        if count > self.pid_summaries.len() {
            count = self.pid_summaries.len()
        }

        writeln!(
            stdout(),
            "\nTop {} PIDs by {}\n-----------\n",
            count,
            sort_by
        )?;

        writeln!(
            stdout(),
            "  {: <7}    {: >10}    {: >10}    {: >10}    {: >10}    {: >9}    {: >9}    {: >9}",
            "pid",
            "actv (ms)",
            "wait (ms)",
            "user (ms)",
            "total (ms)",
            "% of actv",
            "syscalls",
            "children"
        )?;
        writeln!(
            stdout(),
            "  -------    ----------    ----------    ----------    ----------    ---------    ---------    ---------"
        )?;

        for (pid, pid_summary) in self.to_sorted(sort_by).iter().take(count) {
            writeln!(
                stdout(),
                "  {: <7}    {: >10.3}    {: >10.3}    {: >10.3}    {: >10.3}    {: >8.2}%    {: >9}    {: >9}",
                pid,
                pid_summary.system_active_time,
                pid_summary.system_wait_time,
                pid_summary.user_time,
                pid_summary.total_time,
                pid_summary.system_active_time / self.all_active_time * 100.0,
                pid_summary.syscall_count,
                pid_summary.child_pids.len(),
            )?;
        }
        writeln!(stdout(), "\nPIDs   {}", self.pid_summaries.len())?;
        if let Some(real_time) = elapsed_time {
            writeln!(
                stdout(),
                "real   {}",
                SessionSummary::format_duration(real_time.num_milliseconds()),
            )?;
        }
        writeln!(
            stdout(),
            "user   {}",
            SessionSummary::format_duration(self.all_user_time as i64)
        )?;
        writeln!(
            stdout(),
            "sys    {}",
            SessionSummary::format_duration(self.all_active_time as i64)
        )?;

        Ok(())
    }

    pub fn print_pid_list(&self, mut count: usize, sort_by: SortBy) -> Result<(), Error> {
        if count > self.pid_summaries.len() {
            count = self.pid_summaries.len()
        }

        writeln!(
            stdout(),
            "\nDetails of Top {} PIDs by {}\n-----------\n",
            count,
            sort_by
        )?;

        for (pid, pid_summary) in self.to_sorted(sort_by).iter().take(count) {
            writeln!(stdout(), "PID {}\n", pid)?;
            writeln!(stdout(), "{}  ---------------", pid_summary)?;

            match (&pid_summary.execve, &pid_summary.exit_code) {
                (Some(exec), Some(exit)) => {
                    writeln!(stdout())?;
                    writeln!(stdout(), "{}", exec)?;
                    writeln!(stdout(), "  Exit code: {}", exit)?;
                    writeln!(stdout())?;
                }
                (Some(exec), None) => {
                    writeln!(stdout())?;
                    writeln!(stdout(), "{}", exec)?;
                    writeln!(stdout())?;
                }
                (None, Some(exit)) => {
                    writeln!(stdout())?;
                    writeln!(stdout(), "  Exit code: {}", exit)?;
                    writeln!(stdout())?;
                }
                (None, None) => {
                    if pid_summary.parent_pid.is_some()
                        || pid_summary.threads.is_empty()
                        || pid_summary.child_pids.is_empty()
                        || pid_summary.exit_code.is_none()
                    {
                        writeln!(stdout())?;
                    }
                }
            }

            pid_summary.print_related_pids(PrintAmt::Some(PRINT_COUNT))?;

            writeln!(stdout(), "\n")?;
        }

        Ok(())
    }

    pub fn print_pid_details(
        &self,
        pids: &[Pid],
        raw_data: &HashMap<Pid, PidData<'a>>,
    ) -> Result<(), Error> {
        let file_times = file_data::files_opened(&pids, raw_data, SortFilesBy::Duration);

        for pid in pids {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                writeln!(stdout(), "\nPID {}\n", pid)?;
                writeln!(stdout(), "{}  ---------------\n", pid_summary)?;

                if let Some(exec) = &pid_summary.execve {
                    writeln!(stdout(), "{}", exec)?;
                }
                if let Some(exit) = &pid_summary.exit_code {
                    writeln!(stdout(), "  Exit code: {}", exit)?;
                }
                if pid_summary.execve.is_some() || pid_summary.exit_code.is_some() {
                    writeln!(stdout())?;
                }

                pid_summary.print_related_pids(PrintAmt::All)?;

                if let Some(pid_files) = file_times.get(&pid) {
                    if !pid_files.is_empty() {
                        if pid_summary.parent_pid.is_some() || !pid_summary.child_pids.is_empty() {
                            writeln!(stdout())?;
                        }
                        writeln!(stdout(), "  Slowest file open times for PID {}:\n", pid)?;
                        writeln!(
                            stdout(),
                            "  {:>10}    {: ^15}    {: ^15}    {: <30}",
                            "dur (ms)",
                            "timestamp",
                            "error",
                            "file name"
                        )?;
                        writeln!(
                            stdout(),
                            "  ----------    ---------------    ---------------    ---------"
                        )?;

                        for file in pid_files.iter().take(10) {
                            writeln!(stdout(), "  {}", file)?;
                        }
                    }
                }
                writeln!(stdout())?;
            }
        }

        Ok(())
    }

    pub fn print_exec_list(&self, pids_to_print: &[Pid]) -> Result<(), Error> {
        writeln!(stdout(), "\nPrograms Executed\n")?;
        writeln!(
            stdout(),
            "  {: <6}    {: >4}    {: <16}    {: <}",
            "pid",
            "exit",
            "time",
            "program",
        )?;
        writeln!(stdout(), "  ------    ----    ---------------     -------")?;

        for pid in pids_to_print.iter() {
            if let Some(pid_summary) = self.pid_summaries.get(&pid) {
                if let Some(exec) = &pid_summary.execve {
                    let exit = match pid_summary.exit_code {
                        Some(e) => e.to_string(),
                        None => "n/a".to_string(),
                    };

                    for (cmd, time) in exec.iter() {
                        writeln!(
                            stdout(),
                            "  {: <6}    {: >4}    {: <16}    {: <}",
                            pid,
                            exit,
                            time,
                            Execs::replace_newlines(cmd, 35)
                        )?;
                    }
                }
            }
        }
        writeln!(stdout())?;

        Ok(())
    }

    pub fn print_opened_files(
        &self,
        pids_to_print: &[Pid],
        raw_data: &HashMap<Pid, PidData<'a>>,
        sort_by: SortEventsBy,
    ) -> Result<(), Error> {
        let open_calls = file_data::files_opened(&pids_to_print, raw_data, SortFilesBy::Time);

        writeln!(stdout(), "\nFiles Opened")?;
        writeln!(
            stdout(),
            "\n  {: >7}    {: >10}    {: ^15}    {: ^15}    {: <30}",
            "pid",
            "dur (ms)",
            "timestamp",
            "error",
            "file name"
        )?;
        writeln!(
            stdout(),
            "  -------    ----------    ---------------    ---------------    ---------"
        )?;

        let mut open_events: Vec<_> = pids_to_print
            .iter()
            .filter_map(|pid| open_calls.get(pid))
            .flatten()
            .collect();

        match sort_by {
            SortEventsBy::Duration => {
                open_events.par_sort_by(|x, y| {
                    (y.duration)
                        .partial_cmp(&x.duration)
                        .expect("Invalid comparison on io durations")
                });
            }
            SortEventsBy::Pid => {
                open_events.par_sort_by(|x, y| (x.pid).cmp(&y.pid));
            }
            SortEventsBy::Time => {
                open_events.par_sort_by(|x, y| (x.time).cmp(y.time));
            }
        }

        for event in open_events {
            writeln!(stdout(), "  {: >7}    {}", event.pid, event,)?;
        }

        writeln!(stdout())?;

        Ok(())
    }

    pub fn print_io(
        &self,
        pids_to_print: &[Pid],
        raw_data: &HashMap<Pid, PidData<'a>>,
        sort_by: SortEventsBy,
    ) -> Result<(), Error> {
        let io_calls = io_data::io_calls(pids_to_print, raw_data);

        writeln!(stdout(), "\nI/O Performed")?;
        writeln!(
            stdout(),
            "\n  {: >7}    {: >10}    {: ^15}    {: <8}    {: >8}    {: ^15}     {: <30}",
            "pid",
            "dur (ms)",
            "timestamp",
            "syscall",
            "bytes",
            "error",
            "file name"
        )?;
        writeln!(
            stdout(),
            "  -------    ----------    ---------------    --------    --------    ---------------     ---------"
        )?;

        let mut io_events: Vec<_> = pids_to_print
            .iter()
            .filter_map(|pid| io_calls.get(pid))
            .flatten()
            .collect();

        match sort_by {
            SortEventsBy::Duration => {
                io_events.par_sort_by(|x, y| {
                    (y.duration)
                        .partial_cmp(&x.duration)
                        .expect("Invalid comparison on io durations")
                });
            }
            SortEventsBy::Pid => {
                io_events.par_sort_by(|x, y| (x.pid).cmp(&y.pid));
            }
            SortEventsBy::Time => {
                io_events.par_sort_by(|x, y| (x.time).cmp(y.time));
            }
        }

        for event in io_events {
            writeln!(stdout(), "{}", event)?;
        }

        writeln!(stdout())?;

        Ok(())
    }

    pub fn print_pid_tree(&self, truncate: bool) -> Result<(), Error> {
        let pids: Vec<_> = self
            .to_sorted(SortBy::StartTime)
            .iter()
            .map(|(p, _)| p)
            .cloned()
            .collect();
        let mut done = Vec::new();
        let mut filled_cols = BTreeSet::new();

        let mut pid_iter = pids.iter().peekable();
        while let Some(&pid) = pid_iter.next() {
            let position = match pid_iter.peek().is_some() {
                true => pid_tree::PidPosition::NotLast,
                false => pid_tree::PidPosition::Last,
            };

            pid_tree::print_tree(
                pid,
                &self.pid_summaries,
                &mut done,
                &mut filled_cols,
                truncate,
                pid_tree::TreePrint::new(pid_tree::FanOut::All, 0, position),
            )?;
        }

        Ok(())
    }

    pub fn pids(&self) -> Vec<Pid> {
        self.pid_summaries.keys().cloned().collect()
    }

    fn format_duration(millis: i64) -> String {
        let dur = Duration::milliseconds(millis);

        let mins = dur.num_minutes();
        let secs = dur.num_seconds() - mins * 60;
        let ms = dur.num_milliseconds() - secs * 1000 - mins * 60 * 1000;

        format!("{}m{}.{:03}s", mins, secs, ms)
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
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
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
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].system_active_time, 3000.0);
    }

    #[test]
    fn pid_summary_wait_time_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].system_wait_time, 2000.0);
    }

    #[test]
    fn pid_summary_total_time_correct() {
        let input = r##"566   00:09:49.000000 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:50.000000 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:51.000000 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:52.000000 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].total_time, 4000.0);
    }

    #[test]
    fn pid_summary_total_time_syscall_starts_pre_strace_correct() {
        let input = r##"566   00:09:48.000000 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <100.000000>
566   00:09:52.000000 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].total_time, 101_000.0);
    }

    #[test]
    fn pid_summary_child_pids_correct() {
        let input = r##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>
566   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000000>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert!(summary.pid_summaries[&566].child_pids.contains(&7390));
    }

    #[test]
    fn pid_summary_threads_symetrical() {
        let input = r##"1875  1546841132.010874 clone(child_stack=0x7f3f8dffef70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f3f8dfff9d0, tls=0x7f3f8dfff700, child_tidptr=0x7f3f8dfff9d0) = 20222 <0.000037>
1875  1546841132.011524 clone(child_stack=0x7f3f8d5fdf70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f3f8d5fe9d0, tls=0x7f3f8d5fe700, child_tidptr=0x7f3f8d5fe9d0) = 20223 <0.000031>
20222 1546841132.017849 set_robust_list(0x7f3f8dfff9e0, 24) = 0 <0.000009>
20223 1546841132.016568 set_robust_list(0x7f3f8d5fe9e0, 24) = 0 <0.000010>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert!(summary.pid_summaries[&1875].threads.contains(&20222));
        assert!(summary.pid_summaries[&1875].threads.contains(&20223));
        assert!(summary.pid_summaries[&20222].threads.contains(&1875));
        assert!(summary.pid_summaries[&20222].threads.contains(&20223));
        assert!(summary.pid_summaries[&20223].threads.contains(&1875));
        assert!(summary.pid_summaries[&20223].threads.contains(&20222));
    }

    #[test]
    fn pid_summary_futex_threads_traced() {
        let input = r##"17038 11:36:25.284840 futex(0x7ff622820044, FUTEX_WAIT_PRIVATE, 30825, NULL <unfinished ...>
24685 11:36:25.736368 futex(0x7ff622820044, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7ff622820040, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1} <unfinished ...>
17041 11:36:27.818916 futex(0x7ff62282007c, FUTEX_WAIT_PRIVATE, 9057, NULL <unfinished ...>
17041 11:36:27.821480 futex(0x7ff622820010, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
17043 11:36:31.261304 futex(0x7ff62282007c, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7ff622820078, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1}) = 1 <0.000012>
24518 11:36:31.463766 futex(0x7ff622820044, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7ff622820040, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1}) = 1 <0.000146>
24518 11:36:31.462456 futex(0x7ff622820010, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(&input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        let mut all_pids = BTreeSet::new();
        all_pids.extend(&[17038, 17041, 17043, 24518, 24685]);

        let isect: BTreeSet<_> = summary.pid_summaries[&17038]
            .threads
            .intersection(&all_pids)
            .collect();
        assert_eq!(isect, [17041, 17043, 24518, 24685].iter().collect());

        let isect: BTreeSet<_> = summary.pid_summaries[&17041]
            .threads
            .intersection(&all_pids)
            .collect();
        assert_eq!(isect, [17038, 17043, 24518, 24685].iter().collect());

        let isect: BTreeSet<_> = summary.pid_summaries[&17043]
            .threads
            .intersection(&all_pids)
            .collect();
        assert_eq!(isect, [17038, 17041, 24518, 24685].iter().collect());

        let isect: BTreeSet<_> = summary.pid_summaries[&24518]
            .threads
            .intersection(&all_pids)
            .collect();
        assert_eq!(isect, [17038, 17041, 17043, 24685].iter().collect());

        let isect: BTreeSet<_> = summary.pid_summaries[&24685]
            .threads
            .intersection(&all_pids)
            .collect();
        assert_eq!(isect, [17038, 17041, 17043, 24518].iter().collect());
    }
}
