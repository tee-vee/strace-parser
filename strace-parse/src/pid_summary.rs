use crate::syscall_data::PidData;
use crate::syscall_stats::SyscallStats;
use crate::time::parse_unix_timestamp;
use crate::HashSet;
use crate::Pid;
use chrono::NaiveTime;
use lazy_static::lazy_static;
use rayon::prelude::*;
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

#[derive(Clone)]
pub struct PidSummary<'a> {
    pub syscall_count: i32,
    pub system_active_time: f32,
    pub system_wait_time: f32,
    pub user_time: f32,
    pub total_time: f32,
    pub start_time: &'a str,
    pub end_time: &'a str,
    pub syscall_stats: Vec<SyscallStats<'a>>,
    pub parent_pid: Option<Pid>,
    pub child_pids: Vec<Pid>,
    pub execve: Option<Vec<&'a str>>,
}

pub enum PrintAmt {
    All,
    Some(usize),
}

impl<'a> fmt::Display for PidSummary<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

        PidSummary {
            syscall_count,
            system_active_time,
            system_wait_time,
            user_time,
            total_time,
            start_time,
            end_time,
            syscall_stats: syscall_stats.to_vec(),
            parent_pid: None,
            child_pids: pid_data.child_pids.clone(),
            execve: pid_data.execve.clone(),
        }
    }
}

impl<'a> PidSummary<'a> {
    pub fn format_execve(&self) -> Option<(String, String)> {
        if let Some(execve) = &self.execve {
            let mut args_iter = execve.iter();

            let cmd = args_iter
                .next()
                .and_then(|c| c.get(1..c.len() - 2))
                .unwrap_or_default()
                .to_string();

            let mut args = args_iter
                .skip(1)
                .map(|a| a.trim_end_matches(','))
                .fold(String::new(), |s, arg| s + arg + " ");

            if execve.iter().any(|s| s.ends_with("],")) && args.len() > 1 {
                args.insert(0, '[');
            }

            Some((cmd, args))
        } else {
            None
        }
    }

    pub fn print_exec(&self) -> Result<(), Error> {
        if let Some((cmd, args)) = self.format_execve() {
            writeln!(stdout(), "  Program Executed: {}", cmd)?;
            writeln!(stdout(), "  Args: {}\n", args)?;
        }

        Ok(())
    }

    pub fn print_related_pids(&self, print_amt: PrintAmt) -> Result<(), Error> {
        if let Some(p) = self.parent_pid {
            writeln!(stdout(), "  Parent PID:  {}", p)?;
        }

        if !self.child_pids.is_empty() {
            let print_ct = match print_amt {
                PrintAmt::All => self.child_pids.len(),
                PrintAmt::Some(c) => c,
            };
            write!(stdout(), "  Child PIDs:  ")?;
            if self.child_pids.len() > print_ct {
                for (i, p) in self.child_pids.iter().enumerate().take(print_ct) {
                    if i % 10 == 0 && i != 0 {
                        write!(stdout(), "\n               ")?;
                    }
                    if i != print_ct - 1 {
                        write!(stdout(), "{}, ", p)?;
                    } else {
                        write!(stdout(), "{} ", p)?;
                    }
                }
                writeln!(stdout(), "and {} more...", self.child_pids.len() - print_ct)?;
            } else {
                let mut child_pid_iter = self.child_pids.iter().enumerate().peekable();
                while let Some((i, n)) = child_pid_iter.next() {
                    if i % 10 == 0 && i != 0 {
                        write!(stdout(), "\n               ")?;
                    }
                    if child_pid_iter.peek().is_some() {
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
        if timestamp_time > active_time + wait_time {
            timestamp_time
        } else {
            active_time + wait_time
        }
    }
}
