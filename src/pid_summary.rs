use crate::syscall_stats::SyscallStats;
use crate::Pid;
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone)]
pub struct PidSummary<'a> {
    pub syscall_count: i32,
    pub active_time: f32,
    pub wait_time: f32,
    pub total_time: f32,
    pub syscall_stats: Vec<SyscallStats<'a>>,
    pub files: BTreeSet<&'a str>,
    pub parent_pid: Option<Pid>,
    pub child_pids: Vec<Pid>,
    pub execve: Option<Vec<&'a str>>,
}

impl<'a> fmt::Display for PidSummary<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{} syscalls, active time: {:.3}ms, total time: {:.3}ms\n",
            self.syscall_count, self.active_time, self.total_time
        );
        writeln!(
            f,
            "  {: <15}\t{: >8}\t{: >10}\t{: >10}\t{: >10}\t{: >10}\t{: <8}",
            "", "", "total", "max", "avg", "min", ""
        );
        writeln!(
            f,
            "  {: <15}\t{: >8}\t{: >10}\t{: >10}\t{: >10}\t{: >10}\t{: >4}",
            "syscall", "count", "(ms)", "(ms)", "(ms)", "(ms)", "errors"
        );
        writeln!(
            f,
            "  ---------------\t--------\t----------\t----------\t----------\t----------\t--------"
        );
        for s in &self.syscall_stats {
            writeln!(f, "{}", s);
        }

        Ok(())
    }
}
