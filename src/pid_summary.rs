use crate::syscall_stats::SyscallStats;
use crate::Pid;
use std::fmt;
use std::io::{prelude::*, stdout, Error};

#[derive(Clone)]
pub struct PidSummary<'a> {
    pub syscall_count: i32,
    pub active_time: f32,
    pub wait_time: f32,
    pub total_time: f32,
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
            "{} syscalls, active time: {:.3}ms, total time: {:.3}ms\n",
            self.syscall_count, self.active_time, self.total_time
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
                .map(|a| a.trim_end_matches(","))
                .fold(String::new(), |s, arg| s + arg + " ");

            if execve.iter().any(|s| s.ends_with("],")) {
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
}
