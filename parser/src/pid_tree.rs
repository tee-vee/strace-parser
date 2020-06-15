use crate::pid_summary::PidSummary;
use crate::HashMap;
use crate::Pid;
use std::collections::BTreeSet;
use std::io;
use std::io::prelude::*;

#[derive(Clone, Copy, Debug)]
pub enum FanOut {
    All,
    NoThreads,
}

#[derive(Clone, Copy, Debug)]
pub enum PidPosition {
    Last,
    NotLast,
}

#[derive(Clone, Debug)]
pub struct TreePrint {
    fan_out: FanOut,
    indent: usize,
    position: PidPosition,
}

impl TreePrint {
    pub fn new(fan_out: FanOut, indent: usize, position: PidPosition) -> TreePrint {
        TreePrint {
            fan_out,
            indent,
            position,
        }
    }
}

const ELL: &str = "  └";
const EMPTY: &str = "   ";
const HORIZ: &str = "─";
const VERT: &str = "  │";
const TEE: &str = "  ├";

pub fn print_tree(
    pid: Pid,
    pid_summaries: &HashMap<Pid, PidSummary>,
    done: &mut Vec<Pid>,
    filled_cols: &mut BTreeSet<usize>,
    truncate: bool,
    print_info: TreePrint,
) -> Result<(), io::Error> {
    use PidPosition::*;

    if done.contains(&pid) {
        return Ok(());
    }

    if let Some(pid_summary) = pid_summaries.get(&pid) {
        done.push(pid);

        let mut header = String::new();
        for i in 1..print_info.indent {
            if filled_cols.contains(&i) {
                header += VERT;
            } else {
                header += EMPTY;
            }
        }

        let mut line = match (print_info.indent, print_info.position) {
            (0, _) => header,
            (_, NotLast) => format!("{}{}{}", header, TEE, HORIZ),
            (_, Last) => format!("{}{}{}", header, ELL, HORIZ),
        };

        match print_info.fan_out {
            FanOut::All => line += &pid.to_string(),
            FanOut::NoThreads => line += &format!("{{{}}}", pid),
        }

        let exec = pid_summary
            .execve
            .as_ref()
            .and_then(|e| e.cmds().last())
            .map(|last| match (truncate, last.len() > 50) {
                (true, true) => format!("{}...", &last[..50]),
                (true, false) => last.clone(),
                (false, _) => last.clone(),
            });

        match (print_info.fan_out, pid_summary.exit_code, exec) {
            (FanOut::All, Some(exit), Some(cmd)) => {
                line += format!(" - exit: {}, cmd: {}", exit, cmd).as_str();
            }
            (FanOut::NoThreads, None, Some(cmd)) => {
                line += format!(" - cmd: {}", cmd).as_str();
            }
            (_, None, Some(cmd)) => {
                line += format!(" - cmd: {}", cmd).as_str();
            }
            (FanOut::All, Some(exit), None) => {
                line += format!(" - exit: {}", exit).as_str();
            }
            _ => {}
        }

        writeln!(io::stdout(), "{}", line)?;

        match print_info.position {
            NotLast => {
                filled_cols.insert(print_info.indent);
            }
            Last => {
                filled_cols.remove(&print_info.indent);
            }
        }

        if let FanOut::All = print_info.fan_out {
            let mut thread_iter = pid_summary.threads.iter().peekable();
            while let Some(&thread) = thread_iter.next() {
                let last_thread = match (
                    thread_iter.peek().is_none(),
                    pid_summary.child_pids.is_empty(),
                ) {
                    (true, true) => Last,
                    _ => NotLast,
                };

                print_tree(
                    thread,
                    pid_summaries,
                    done,
                    filled_cols,
                    truncate,
                    TreePrint::new(FanOut::NoThreads, print_info.indent + 1, last_thread),
                )?;
            }
        }

        let mut child_iter = pid_summary.child_pids.iter().peekable();
        while let Some(&child) = child_iter.next() {
            let last_child = match child_iter.peek().is_none() {
                true => Last,
                false => NotLast,
            };

            print_tree(
                child,
                pid_summaries,
                done,
                filled_cols,
                truncate,
                TreePrint::new(FanOut::All, print_info.indent + 1, last_child),
            )?;
        }
    }

    Ok(())
}
