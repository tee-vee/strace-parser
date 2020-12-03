use crate::exec::Execs;
use crate::pid_summary::PrintAmt;
use crate::syscall_data::PidData;
use crate::syscall_stats::SyscallStats;
use crate::{directories, directories::SortDirectoriesBy};
use crate::{file_data, file_data::SortFilesBy, io_data, pid_tree};
use crate::{HashMap, HashSet, Pid, PidSummary, SortBy, SortEventsBy};

use chrono::Duration;
use petgraph::prelude::*;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::io::{prelude::*, stdout, Error};

static PRINT_COUNT: usize = 10;

#[derive(Debug, Default)]
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

        summary.populate_children();
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
            // We don't know the true order for any process not forked during the trace
            // Assume that these start from lowest pid, then sort the pids forked
            // during trace by start time
            SortBy::StartTime => {
                let (mut existing, mut forked): (Vec<_>, Vec<_>) = sorted_summaries
                    .into_iter()
                    .partition(|(_, s)| s.parent_pid.is_none());
                existing.sort_by(|(pid_x, _), (pid_y, _)| pid_x.cmp(&pid_y));
                forked.sort_by(|(_, x), (_, y)| (x.start_time).cmp(&y.start_time));
                existing.extend(forked);

                sorted_summaries = existing
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

    fn populate_children(&mut self) {
        let mut pid_graph = DiGraphMap::new();
        for (&pid, pid_summary) in self.pid_summaries.iter() {
            if !pid_summary.child_pids.is_empty() {
                for &child in &pid_summary.child_pids {
                    pid_graph.add_edge(pid, child, 1);
                }
            }
        }

        for (&pid, pid_summary) in self.pid_summaries.iter_mut() {
            let mut parent_graph = pid_graph.neighbors_directed(pid, Incoming);

            if let Some(parent) = parent_graph.next() {
                pid_summary.parent_pid = Some(parent);
            }
        }
    }

    fn populate_threads(&mut self) {
        let execve_threads = self.clone_threads();
        self.convert_execve_threads_to_children(execve_threads);
        self.futex_threads();
        self.mirror_threads_to_siblings();
        self.remove_self_from_threads();
    }

    fn clone_threads(&mut self) -> HashMap<Pid, Vec<Pid>> {
        let mut execve_threads = HashMap::new();
        let mut thread_graph = UnGraphMap::new();

        for (&pid, pid_summary) in &self.pid_summaries {
            for &thread in &pid_summary.threads {
                // Threads that execute execve are promoted to separate processes and
                // should not treat the threads of its parent as siblings.
                // For simplicity we assume that any threads spawned by the process
                // that eventually uses execve occur after the exec
                match self
                    .pid_summaries
                    .get(&thread)
                    .and_then(|s| s.execve.as_ref())
                {
                    Some(_) => {
                        let pid_entry = execve_threads.entry(pid).or_insert_with(Vec::new);
                        pid_entry.push(thread);
                        //let thread_entry = execve_threads.entry(thread).or_insert_with(Vec::new);
                        //thread_entry.push(pid);
                    }
                    _ => {
                        thread_graph.add_edge(pid, thread, 1);
                    }
                }
                if self
                    .pid_summaries
                    .get(&thread)
                    .and_then(|s| s.execve.as_ref())
                    .is_none()
                {
                    thread_graph.add_edge(pid, thread, 1);
                }
            }
        }

        let mut thread_map = HashMap::new();
        for (&pid, pid_summary) in self.pid_summaries.iter_mut() {
            let mut dfs = Dfs::new(&thread_graph, pid);
            while let Some(related) = dfs.next(&thread_graph) {
                pid_summary.threads.insert(related);
                let thread_entry = thread_map.entry(related).or_insert_with(Vec::new);
                thread_entry.push(pid);
            }
        }

        for (pid, threads) in thread_map {
            if let Some(summary) = self.pid_summaries.get_mut(&pid) {
                summary.threads.extend(threads);
            }
        }

        execve_threads
    }

    fn convert_execve_threads_to_children(&mut self, execve_threads: HashMap<Pid, Vec<Pid>>) {
        for (pid, threads) in execve_threads {
            if let Some(summary) = self.pid_summaries.get_mut(&pid) {
                for thread in threads {
                    summary.threads.remove(&thread);
                    summary.child_pids.insert(thread);
                }
            }
        }
    }

    fn mirror_threads_to_siblings(&mut self) {
        let mut symmetric_threads = HashMap::new();
        for (&pid, summary) in &self.pid_summaries {
            for &thread in &summary.threads {
                let thread_entry = symmetric_threads.entry(thread).or_insert_with(Vec::new);
                thread_entry.push(pid);
                thread_entry.extend(summary.threads.iter().copied());
            }
        }

        for (pid, threads) in symmetric_threads {
            if let Some(summary) = self.pid_summaries.get_mut(&pid) {
                summary.threads.extend(threads);
            }
        }
    }

    fn futex_threads(&mut self) {
        let mut addr_map = HashMap::new();

        // Only perform the futex linking on pids that existed prior to the trace
        // The threads of anything forked during tracing are already captured.
        for (&pid, pid_summary) in self
            .pid_summaries
            .iter()
            .filter(|(_, summary)| summary.parent_pid.is_none())
        {
            for addr in &pid_summary.pvt_futex {
                let addr_entry = addr_map.entry(addr).or_insert_with(HashSet::new);
                addr_entry.insert(pid);
            }
        }

        let mut addr_graph: UnGraphMap<&[u8], i8> = UnGraphMap::new();
        for (&&addr, pids) in &addr_map {
            for (inner_addr, inner_pids) in addr_map.iter().filter(|(&&a, _)| a != addr) {
                if !pids.is_disjoint(inner_pids) {
                    addr_graph.add_edge(addr, inner_addr, 1);
                }
            }
        }

        let mut thread_map: HashMap<Pid, HashSet<Pid>> = HashMap::new();
        for (addr, pids) in &addr_map {
            let mut dfs = Dfs::new(&addr_graph, addr);

            while let Some(relative) = dfs.next(&addr_graph) {
                for &pid in pids.iter() {
                    let entry = thread_map.entry(pid).or_insert_with(HashSet::new);
                    entry.extend(pids.iter());

                    if let Some(more_pids) = addr_map.get(&relative) {
                        entry.extend(more_pids.iter());
                    }
                }
            }
        }

        for (pid, threads) in thread_map.into_iter() {
            if let Some(pid_summary) = self.pid_summaries.get_mut(&pid) {
                pid_summary.threads.extend(threads);
            }
        }
    }

    fn remove_self_from_threads(&mut self) {
        for (pid, threads) in self
            .pid_summaries
            .iter_mut()
            .map(|(pid, summary)| (pid, &mut summary.threads))
        {
            threads.remove(pid);
        }
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

            match (&pid_summary.execve, pid_summary.exit) {
                (Some(exec), Some(exit)) => {
                    writeln!(stdout())?;
                    writeln!(stdout(), "{}", exec)?;
                    writeln!(stdout(), "  Exit: {}", exit)?;
                    writeln!(stdout())?;
                }
                (Some(exec), None) => {
                    writeln!(stdout())?;
                    writeln!(stdout(), "{}", exec)?;
                    writeln!(stdout())?;
                }
                (None, Some(exit)) => {
                    writeln!(stdout())?;
                    writeln!(stdout(), "  Exit: {}", exit)?;
                    writeln!(stdout())?;
                }
                (None, None) => {
                    if pid_summary.parent_pid.is_some()
                        || pid_summary.threads.is_empty()
                        || pid_summary.child_pids.is_empty()
                        || pid_summary.exit.is_none()
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
                if let Some(exit) = pid_summary.exit {
                    writeln!(stdout(), "  Exit: {}", exit)?;
                }
                if pid_summary.execve.is_some() || pid_summary.exit.is_some() {
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
                    for (cmd, time) in exec.iter() {
                        writeln!(
                            stdout(),
                            "  {: <6}    {: >4}    {: <16}    {: <}",
                            pid,
                            pid_summary
                                .exit
                                .map(|e| e.to_string())
                                .unwrap_or("n/a".to_string()),
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

    pub fn print_opened_directories(
        &self,
        pids_to_print: &[Pid],
        raw_data: &HashMap<Pid, PidData<'a>>,
        sort_by: SortEventsBy,
    ) -> Result<(), Error> {
        let open_calls =
            directories::directories_opened(&pids_to_print, raw_data, SortDirectoriesBy::Time);

        writeln!(stdout(), "\nDirectories accessed for files")?;
        writeln!(
            stdout(),
            "\n  {: >7}    {: >10}    {: ^15}    {: <30}",
            "pid",
            "dur (ms)",
            "timestamp",
            "directory name"
        )?;
        writeln!(
            stdout(),
            "  -------    ----------    ---------------    ---------------"
        )?;

        let mut open_events: Vec<_> = pids_to_print
            .iter()
            .filter_map(|pid| open_calls.get(pid))
            .flatten()
            .collect();

        match sort_by {
            SortEventsBy::Duration => {
                open_events.par_sort_by(|(_, x), (_, y)| {
                    (y.duration)
                        .partial_cmp(&x.duration)
                        .expect("Invalid comparison on io durations")
                });
            }
            SortEventsBy::Pid => {
                open_events.par_sort_by(|(_, x), (_, y)| (x.pid).cmp(&y.pid));
            }
            SortEventsBy::Time => {
                open_events.par_sort_by(|(_, x), (_, y)| (x.time).cmp(y.time));
            }
        }

        for (fullpath, dir) in open_events {
            writeln!(
                stdout(),
                "  {: >7}    {}    {: <30}",
                dir.pid,
                dir,
                fullpath.display(),
            )?;
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
        let mut filled_cols = HashSet::new();

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
        let input = br##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].syscall_count, 5);
    }

    #[test]
    fn pid_summary_active_time_correct() {
        let input = br##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].system_active_time, 3000.0);
    }

    #[test]
    fn pid_summary_wait_time_correct() {
        let input = br##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].system_wait_time, 2000.0);
    }

    #[test]
    fn pid_summary_total_time_correct() {
        let input = br##"566   00:09:49.000000 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:50.000000 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:51.000000 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:52.000000 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].total_time, 4000.0);
    }

    #[test]
    fn pid_summary_total_time_syscall_starts_pre_strace_correct() {
        let input = br##"566   00:09:48.000000 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <100.000000>
566   00:09:52.000000 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert_eq!(summary.pid_summaries[&566].total_time, 101_000.0);
    }

    #[test]
    fn pid_summary_child_pids_correct() {
        let input = br##"566   00:09:48.145068 <... restart_syscall resumed> ) = -1 ETIMEDOUT (Connection timed out) <1.000000>
566   00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>
566   00:09:48.145182 socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG) = 221<NETLINK:[3604353]> <1.000000>
566   00:09:48.145264 fstat(221<NETLINK:[3604353]>, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0 <1.000000>
566   00:09:48.145929 open("/proc/net/unix", O_RDONLY|O_CLOEXEC) = 222</proc/495/net/unix> <1.000000>
566   00:09:47.914797 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe5648a69d0) = 7390 <0.000000>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        assert!(summary.pid_summaries[&566].child_pids.contains(&7390));
    }

    #[test]
    fn pid_summary_threads_symetrical() {
        let input = br##"1875  1546841132.010874 clone(child_stack=0x7f3f8dffef70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f3f8dfff9d0, tls=0x7f3f8dfff700, child_tidptr=0x7f3f8dfff9d0) = 20222 <0.000037>
1875  1546841132.011524 clone(child_stack=0x7f3f8d5fdf70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f3f8d5fe9d0, tls=0x7f3f8d5fe700, child_tidptr=0x7f3f8d5fe9d0) = 20223 <0.000031>
20222 1546841132.017849 set_robust_list(0x7f3f8dfff9e0, 24) = 0 <0.000009>
20223 1546841132.016568 set_robust_list(0x7f3f8d5fe9e0, 24) = 0 <0.000010>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);

        assert_eq!(
            vec![&20222, &20223],
            summary.pid_summaries[&1875]
                .threads
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![&1875, &20223],
            summary.pid_summaries[&20222]
                .threads
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![&1875, &20222],
            summary.pid_summaries[&20223]
                .threads
                .iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn pid_summary_futex_threads_traced() {
        let input = br##"17038 11:36:25.284840 futex(0x7ff622820044, FUTEX_WAIT_PRIVATE, 30825, NULL <unfinished ...>
24685 11:36:25.736368 futex(0x7ff622820044, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7ff622820040, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1} <unfinished ...>
17041 11:36:27.818916 futex(0x7ff62282007c, FUTEX_WAIT_PRIVATE, 9057, NULL <unfinished ...>
17041 11:36:27.821480 futex(0x7ff622820010, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
17043 11:36:31.261304 futex(0x7ff62282007c, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7ff622820078, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1}) = 1 <0.000012>
24518 11:36:31.463766 futex(0x7ff622820044, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7ff622820040, {FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 1}) = 1 <0.000146>
24518 11:36:31.462456 futex(0x7ff622820010, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);

        assert_eq!(
            summary.pid_summaries[&17038]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&17041, &17043, &24518, &24685]
        );
        assert_eq!(
            summary.pid_summaries[&17041]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&17038, &17043, &24518, &24685]
        );
        assert_eq!(
            summary.pid_summaries[&17043]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&17038, &17041, &24518, &24685]
        );
        assert_eq!(
            summary.pid_summaries[&24518]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&17038, &17041, &17043, &24685]
        );
        assert_eq!(
            summary.pid_summaries[&24685]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&17038, &17041, &17043, &24518]
        );
    }

    #[test]
    fn pid_summary_execve_convert_thread_to_child() {
        let input = br##"8442  02:21:10.759733 futex(0xcccee86f48, FUTEX_WAIT_PRIVATE, 3, NULL <unfinished ...>
8357  02:21:10.760083 futex(0xc000084848, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>
8355  02:21:10.760103 futex(0x7f79a8c0d22c, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>
8346  02:21:10.760204 futex(0xc000084848, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>
8355  02:21:10.781726 futex(0xc000084848, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>
8346  02:21:12.681318 clone(child_stack=0x7ff9b45d7ff0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID <unfinished ...>
8346  02:21:15.002646 <... clone resumed>, parent_tid=[9154], tls=0x7ff9b4a0ea15, child_tidptr=0x7ff9b45d49d0) = 9154 <0.000078>
9154  02:21:14.985520 execve("/opt/gitlab/embedded/service/gitaly-ruby/git-hooks/post-receive", ["/opt/gitlab/embedded/service/gitaly-ruby/git-hooks/post-receive"], 0x7f797c047ff0 /* 39 vars */ <unfinished ...>
9154  02:21:15.002560 clone(child_stack=0x7ff9b45d7ff0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID <unfinished ...>
9154  02:21:15.002646 <... clone resumed>, parent_tid=[9157], tls=0x7ff9b45d8700, child_tidptr=0x7ff9b45d89d0) = 9157 <0.000078>
9157  02:21:15.003408 clone(child_stack=0x7ff9b31d5ff0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID <unfinished ...>
9157  02:21:15.003498 <... clone resumed>, parent_tid=[9159], tls=0x7ff9b31d6700, child_tidptr=0x7ff9b31d69d0) = 9159 <0.000082>
9154  02:21:15.013127 futex(0xcccee86f48, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
9159  02:21:15.026908 futex(0xcccee86f48, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);

        assert_eq!(
            summary.pid_summaries[&8346]
                .child_pids
                .iter()
                .collect::<Vec<_>>(),
            vec![&9154],
        );

        assert_eq!(
            summary.pid_summaries[&8346]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&8355, &8357]
        );
        assert_eq!(
            summary.pid_summaries[&8355]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&8346, &8357]
        );
        assert_eq!(
            summary.pid_summaries[&8357]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&8346, &8355]
        );

        assert_eq!(
            summary.pid_summaries[&9154]
                .child_pids
                .iter()
                .collect::<Vec<_>>(),
            vec![&9157]
        );
        assert_eq!(
            summary.pid_summaries[&9157]
                .child_pids
                .iter()
                .collect::<Vec<_>>(),
            vec![&9159]
        );

        assert_eq!(
            summary.pid_summaries[&9154]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&9157, &9159]
        );
        assert_eq!(
            summary.pid_summaries[&9157]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&9154, &9159]
        );
        assert_eq!(
            summary.pid_summaries[&9159]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&9154, &9157]
        );

        assert!(summary.pid_summaries[&8442].threads.is_empty());
    }

    #[test]
    fn pid_summary_futex_thread_check_excludes_children() {
        let input = br##"2979 11:34:25.556415 futex(0x7ffa5fbf9f24, FUTEX_WAIT_PRIVATE, 27, NULL <unfinished ...>
2989  11:34:25.557272 futex(0x7ffa5fbf9f24, FUTEX_WAIT_PRIVATE, 861, NULL <unfinished ...>
2979  11:34:27.679833 <... vfork resumed> ) = 11608 <0.141899>
11608 11:34:27.539786 futex(0x7ffa5fbf9f24, FUTEX_WAIT_BITSET_PRIVATE, 1, {2975525, 987165583}, ffffffff <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);

        assert_eq!(
            summary.pid_summaries[&2979]
                .child_pids
                .iter()
                .collect::<Vec<_>>(),
            vec![&11608]
        );
        assert_eq!(summary.pid_summaries[&11608].parent_pid, Some(2979));

        assert_eq!(
            summary.pid_summaries[&2979]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&2989]
        );
        assert_eq!(
            summary.pid_summaries[&2989]
                .threads
                .iter()
                .collect::<Vec<_>>(),
            vec![&2979]
        );
    }

    #[test]
    fn pid_summary_pid_start_time_sort() {
        let input = br##"32766  07:55:04.273462 <... clone resumed> child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 26124 <0.002655>
26124 07:55:04.270880 rt_sigaction(SIGHUP, {sa_handler=SIG_DFL, sa_mask=~[], sa_flags=SA_RESTORER|SA_ONSTACK|SA_RESTART|SA_SIGINFO, sa_restorer=0x462ca0}, NULL, 8) = 0 <0.000016>
9746  07:55:15.336457 <... clone resumed> child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 412 <0.002946>
412 07:55:15.336879 close(3</etc/ld.so.cache> <unfinished ...>"##;
        let pid_data_map = build_syscall_data(input);
        let syscall_stats = build_syscall_stats(&pid_data_map);
        let summary = SessionSummary::from_syscall_stats(&syscall_stats, &pid_data_map);
        let sorted: Vec<_> = summary
            .to_sorted(SortBy::StartTime)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(sorted, &[9746, 32766, 26124, 412]);
    }
}
