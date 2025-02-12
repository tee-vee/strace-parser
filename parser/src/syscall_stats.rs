use crate::syscall_data::PidData;
use crate::HashMap;
use crate::Pid;

use bstr::ByteSlice;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug)]
pub struct SyscallStats<'a> {
    pub name: &'a [u8],
    pub count: i32,
    pub total: f32,
    max: f32,
    avg: f32,
    min: f32,
    errors: HashMap<&'a [u8], i32>,
}

impl<'a> fmt::Display for SyscallStats<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.count > 0 {
            write!(
                f,
                "{0: <17}    {1: >8}    {2: >10.3}    {3: >10.3}    {4: >10.3}    {5: >10.3}    ",
                self.name.to_str_lossy(),
                self.count,
                self.total,
                self.max,
                self.avg,
                self.min
            )?;
        } else {
            write!(
                f,
                "{0: <17}    {1: >8}    {2: >10}    {3: >10}    {4: >10}    {5: >10}    ",
                self.name.to_str_lossy(),
                "1",
                "n/a",
                "n/a",
                "n/a",
                "n/a"
            )?;
        }

        let sorted_errs: BTreeMap<_, _> = self.errors.iter().collect();

        for (err, count) in sorted_errs.iter() {
            write!(f, "{}: {}   ", err.to_str_lossy(), count)?;
        }

        Ok(())
    }
}

pub fn build_syscall_stats<'a>(
    data: &HashMap<Pid, PidData<'a>>,
) -> HashMap<Pid, Vec<SyscallStats<'a>>> {
    let mut syscall_stats = HashMap::default();

    for (pid, pid_stats) in data {
        let mut event_stats: Vec<_> = pid_stats
            .syscall_data
            .par_iter()
            .map(|(syscall, raw_data)| {
                let total = raw_data.lengths.par_iter().sum::<f32>() * 1000.0;
                let max = *raw_data
                    .lengths
                    .par_iter()
                    .max_by(|x, y| {
                        x.partial_cmp(y)
                            .expect("Invalid comparison when finding max length")
                    })
                    .unwrap_or(&(0.0))
                    * 1000.0;
                let min = *raw_data
                    .lengths
                    .par_iter()
                    .min_by(|x, y| {
                        x.partial_cmp(y)
                            .expect("Invalid comparison when finding min length")
                    })
                    .unwrap_or(&(0.0))
                    * 1000.0;
                let avg = if !raw_data.lengths.is_empty() {
                    total / raw_data.lengths.len() as f32
                } else {
                    0.0
                };
                let errors = raw_data.errors.clone();

                SyscallStats {
                    name: syscall,
                    count: raw_data.lengths.len() as i32,
                    total,
                    max,
                    avg,
                    min,
                    errors,
                }
            })
            .collect();

        event_stats.par_sort_by(|x, y| {
            (y.total)
                .partial_cmp(&x.total)
                .expect("Invalid comparison when sorting event_stats")
        });

        syscall_stats.insert(*pid, event_stats);
    }

    syscall_stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_data::build_syscall_data;

    #[test]
    fn syscall_stats_name_correct() {
        let input = br##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##;
        let pid_data_map = build_syscall_data(input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        assert_eq!(pid_stats[&477][0].name, b"fcntl");
    }

    #[test]
    fn syscall_stats_count_correct() {
        let input = br##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##;
        let pid_data_map = build_syscall_data(input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].count, 4);
    }

    #[test]
    fn syscall_stats_max_correct() {
        let input = br##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##;
        let pid_data_map = build_syscall_data(input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].max, 1500.0);
    }

    #[test]
    fn syscall_stats_min_correct() {
        let input = br##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##;
        let pid_data_map = build_syscall_data(input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].min, 500.0);
    }

    #[test]
    fn syscall_stats_avg_correct() {
        let input = br##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##;
        let pid_data_map = build_syscall_data(input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].avg, 1000.0);
    }

    #[test]
    fn syscall_stats_errors_correct() {
        let input = br##"477   00:09:57.959706 wait4(-1, 0x7ffe09dbae50, WNOHANG, NULL) = -1 ECHILD (No child processes) <0.000014>"##;
        let pid_data_map = build_syscall_data(input);
        let pid_stats = build_syscall_stats(&pid_data_map);
        let syscall_stats = &pid_stats[&477];
        assert_eq!(syscall_stats[0].errors[b"ECHILD".as_ref()], 1);
    }
}
