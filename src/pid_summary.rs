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

pub struct PrintOptions {
    pub execve: Option<PrintAmt>,
    pub related_pids: Option<PrintAmt>,
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
            "  {: <15}\t{: >8}\t{: >10}\t{: >10}\t{: >10}\t{: >10}\t{: <8}",
            "", "", "total", "max", "avg", "min", ""
        )?;
        writeln!(
            f,
            "  {: <15}\t{: >8}\t{: >10}\t{: >10}\t{: >10}\t{: >10}\t{: >4}",
            "syscall", "count", "(ms)", "(ms)", "(ms)", "(ms)", "errors"
        )?;
        writeln!(
            f,
            "  ---------------\t--------\t----------\t----------\t----------\t----------\t--------"
        )?;
        for s in &self.syscall_stats {
            writeln!(f, "{}", s)?;
        }

        Ok(())
    }
}

impl<'a> PidSummary<'a> {
    pub fn print(&self, print_options: PrintOptions) -> Result<(), Error> {
        if self.syscall_count == 0 {
            return Ok(());
        }

        write!(stdout(), "{}", self)?;
        writeln!(stdout(), "  ---------------\n")?;

        if print_options.execve.is_some() {
            self.print_execve()?;
        }

        if let Some(p) = print_options.related_pids {
            self.print_related_pids(p)?;
        }
        Ok(())
    }

    fn print_execve(&self) -> Result<(), Error> {
        if let Some(execve) = &self.execve {
            let cmd_quoted = if let Some(c) = execve.get(0) {
                let mut raw_cmd = c.to_string();
                raw_cmd.pop();
                raw_cmd
            } else {
                return Ok(());
            };
            let cmd = cmd_quoted.replace("\"", "");

            let args = if execve.iter().skip(2).any(|s| s.ends_with("],")) {
                execve
                    .iter()
                    .skip(2)
                    .fold("[".to_string(), |s, a| s + a + " ")
            } else {
                execve
                    .iter()
                    .skip(2)
                    .fold(String::new(), |s, a| s + a + " ")
            };

            writeln!(stdout(), "  Program Executed: {}", cmd)?;
            writeln!(stdout(), "  Args: {}\n", args)?;
        }
        Ok(())
    }

    fn print_related_pids(&self, print_amt: PrintAmt) -> Result<(), Error> {
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
