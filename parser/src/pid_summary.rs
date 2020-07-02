use crate::exec::Execs;
use crate::parser::ExitType;
use crate::syscall_data::PidData;
use crate::syscall_stats::SyscallStats;
use crate::time::parse_unix_timestamp;
use crate::HashSet;
use crate::Pid;
use chrono::NaiveTime;
use lazy_static::lazy_static;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fmt;
use std::io::{prelude::*, stdout, Error};

lazy_static! {
    static ref WAIT_SYSCALLS: HashSet<&'static str> = {
        let mut s = HashSet::default();
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

#[derive(Clone, Debug)]
pub struct PidSummary<'a> {
    pub syscall_count: i32,
    pub system_active_time: f32,
    pub system_wait_time: f32,
    pub user_time: f32,
    pub total_time: f32,
    pub start_time: &'a str,
    pub end_time: &'a str,
    pub syscall_stats: Vec<SyscallStats<'a>>,
    pub pvt_futex: HashSet<&'a str>,
    pub parent_pid: Option<Pid>,
    pub threads: BTreeSet<Pid>,
    pub child_pids: BTreeSet<Pid>,
    pub execve: Option<Execs>,
    pub exit: Option<ExitType<'a>>,
    pub proc_name: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrintAmt {
    All,
    Some(usize),
}

impl<'a> fmt::Display for PidSummary<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(name) = self.proc_name {
            writeln!(f, "  process: {}", name)?;
        }
        writeln!(
            f,
            "  {} syscalls, active time: {:.3}ms, user time: {:.3}ms, total time: {:.3}ms",
            self.syscall_count, self.system_active_time, self.user_time, self.total_time
        )?;
        writeln!(
            f,
            "  start time: {}    end time: {}\n",
            self.start_time, self.end_time
        )?;
        writeln!(
            f,
            "  {: <17}    {: >8}    {: >10}    {: >10}    {: >10}    {: >10}    {: >4}",
            "syscall", "count", "total (ms)", "max (ms)", "avg (ms)", " min (ms)", "errors"
        )?;
        writeln!(
            f,
            "  -----------------    --------    ----------    ----------    ----------    ----------    --------"
        )?;
        for s in &self.syscall_stats {
            writeln!(f, "  {}", s)?;
        }

        Ok(())
    }
}

impl<'a> From<(&[SyscallStats<'a>], &PidData<'a>)> for PidSummary<'a> {
    fn from(input: (&[SyscallStats<'a>], &PidData<'a>)) -> Self {
        let (syscall_stats, pid_data) = input;

        let syscall_count = syscall_stats
            .par_iter()
            .fold_with(0, |acc, event_stats| acc + event_stats.count)
            .sum();

        let system_active_time = syscall_stats
            .par_iter()
            .filter(|stat| !WAIT_SYSCALLS.contains(stat.name))
            .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
            .sum();

        let system_wait_time = syscall_stats
            .par_iter()
            .filter(|stat| WAIT_SYSCALLS.contains(stat.name))
            .fold_with(0.0, |acc, event_stats| acc + event_stats.total)
            .sum();

        let start_time = pid_data.start_time;
        let end_time = pid_data.end_time;

        let total_time =
            PidSummary::calc_total_time(start_time, end_time, system_active_time, system_wait_time);

        let user_time = total_time - system_active_time - system_wait_time;

        let execve = match &pid_data.execve {
            Some(e) => Some(Execs::new(e.clone())),
            None => None,
        };

        PidSummary {
            syscall_count,
            system_active_time,
            system_wait_time,
            user_time,
            total_time,
            start_time,
            end_time,
            syscall_stats: syscall_stats.to_vec(),
            pvt_futex: pid_data.pvt_futex.clone(),
            parent_pid: None, // parent is calculated later on
            threads: pid_data.threads.iter().cloned().collect(),
            child_pids: pid_data.child_pids.iter().cloned().collect(),
            execve,
            exit: pid_data.exit,
            proc_name: None, // populated from proc/status where available
        }
    }
}

impl<'a> PidSummary<'a> {
    pub fn print_related_pids(&self, print_amt: PrintAmt) -> Result<(), Error> {
        if let Some(p) = self.parent_pid {
            writeln!(stdout(), "  Parent PID:  {}", p)?;
        }

        PidSummary::print_pids(self.threads.iter().cloned(), "Threads", print_amt)?;
        PidSummary::print_pids(self.child_pids.iter().cloned(), "Child PIDs", print_amt)?;

        Ok(())
    }

    fn print_pids(
        pids: impl ExactSizeIterator<Item = Pid>,
        name: &str,
        print_amt: PrintAmt,
    ) -> Result<(), Error> {
        let len = pids.len();

        if len > 0 {
            let print_ct = match print_amt {
                PrintAmt::All => pids.len(),
                PrintAmt::Some(c) => c,
            };

            write!(stdout(), "  {}:  ", name)?;
            if pids.len() > print_ct {
                for (i, p) in pids.enumerate().take(print_ct) {
                    if i % 10 == 0 && i != 0 {
                        write!(stdout(), "\n               ")?;
                    }
                    if i != print_ct - 1 {
                        write!(stdout(), "{}, ", p)?;
                    } else {
                        write!(stdout(), "{} ", p)?;
                    }
                }
                writeln!(stdout(), "and {} more...", len - print_ct)?;
            } else {
                let mut pid_iter = pids.enumerate().peekable();
                while let Some((i, n)) = pid_iter.next() {
                    if i % 10 == 0 && i != 0 {
                        write!(stdout(), "\n               ")?;
                    }
                    if pid_iter.peek().is_some() {
                        write!(stdout(), "{}, ", n)?;
                    } else {
                        write!(stdout(), "{}", n)?;
                    }
                }
                writeln!(stdout())?;
            }
        }

        Ok(())
    }

    fn calc_total_time(start: &str, end: &str, active_time: f32, wait_time: f32) -> f32 {
        let st = NaiveTime::parse_from_str(start, "%H:%M:%S%.6f");
        let et = NaiveTime::parse_from_str(end, "%H:%M:%S%.6f");

        let timestamp_time = if let (Some(s), Some(e)) = (st.ok(), et.ok()) {
            (e - s).num_microseconds().unwrap() as f32 / 1000.0
        } else if let (Some(s), Some(e)) = (parse_unix_timestamp(start), parse_unix_timestamp(end))
        {
            (e - s).num_microseconds().unwrap() as f32 / 1000.0
        } else {
            0.0
        };

        // In some cases a syscall begun before strace may report
        // a run time greater than the timestamp span of the trace
        // In this case we just use the timestamp span
        if timestamp_time > active_time + wait_time {
            timestamp_time
        } else {
            active_time + wait_time
        }
    }
}
