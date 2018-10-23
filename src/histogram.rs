use crate::syscall_data::PidData;
use crate::Pid;
use std::collections::{BTreeMap, HashMap};

pub fn print_histogram(syscall: &str, pids: &[Pid], syscall_data: &HashMap<Pid, PidData>) {
    let distribution = build_distribution(syscall, pids, syscall_data);

    let pid_str = build_pid_str(pids);

    let max = match distribution.values().max() {
        Some(m) => *m,
        None => {
            println!("No data found for histogram");
            return;
        }
    };

    println!("\n  syscall: {}\n  pids: {}\n", syscall, pid_str);
    println!(
        "    {0: >10}   {1: <10}\t: {2: <}\t\t {3: <10}",
        "\u{03BC}secs", "", "count", "distribution",
    );

    for (pow, count) in distribution.iter() {
        println!(
            "    {0: >10} -> {1: <10}\t: {2: <}\t\t|{3: <40}|",
            if *pow == 0 { 0 } else { 2u64.pow(*pow as u32) },
            2u64.pow(*pow + 1 as u32) - 1,
            *count,
            dist_marker((*count as f32 / max as f32) * 40.0),
        );
    }
    println!("");
}

fn build_distribution(
    syscall: &str,
    pids: &[Pid],
    syscall_data: &HashMap<Pid, PidData>,
) -> BTreeMap<u32, i32> {
    let mut distribution = BTreeMap::new();
    let mut max_pow = 0;

    for pid in pids {
        if let Some(pid_data) = syscall_data.get(pid) {
            if let Some(data) = pid_data.syscall_data.get(syscall) {
                for x in data.lengths.iter() {
                    let u_secs = *x * 1000.0 * 1000.0;

                    if u_secs < 1.0 {
                        let entry = distribution.entry(0).or_insert(0);
                        *entry += 1;
                    } else {
                        let pow = u_secs.log2() as u32;
                        let entry = distribution.entry(pow).or_insert(0);
                        *entry += 1;

                        if pow > max_pow {
                            max_pow = pow;
                        }
                    }
                }
            }
        }
    }

    fill_empty_pows(&mut distribution, max_pow);

    distribution
}

fn fill_empty_pows(distribution: &mut BTreeMap<u32, i32>, max_pow: u32) {
    for pow in 0..max_pow {
        if let None = distribution.get(&pow) {
            distribution.insert(pow, 0);
        }
    }
}

fn build_pid_str(pids: &[Pid]) -> String {
    let mut pid_list: String = pids
        .iter()
        .take(10)
        .map(|p| {
            let mut s = p.to_string();
            s.push_str(" ");
            s
        })
        .collect();

    if pids.len() > 10 {
        let addendum = format!("and {} more...", pids.len() - 10);
        pid_list += &addendum;
    }

    pid_list
}

fn dist_marker(perc: f32) -> String {
    let mut marker = String::new();
    let count = perc as i32;
    for _ in 0..count {
        marker += "*";
    }
    marker
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use crate::syscall_data::*;

    #[test]
    fn histogram_handles_empty_pids() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.500000>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <1.000000>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <1.000000>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <1.500000>"##
            .to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        assert_eq!(
            build_distribution("open", &Vec::new(), &pid_data_map),
            BTreeMap::new()
        );
    }

    #[test]
    fn histogram_finds_max_pow_2() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000100>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000100>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000100>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.001500>"##
            .to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        let dist = build_distribution("fcntl", &vec![477], &pid_data_map);
        assert_eq!(dist.keys().last(), Some(&10));
    }

    #[test]
    fn histogram_fills_empty_pows() {
        let input = r##"477   00:09:56.954410 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000100>
477   00:09:56.954448 fcntl(1<pipe:[3578440]>, F_DUPFD, 10) = 10<pipe:[3578440]> <0.000100>
477   00:09:56.954488 fcntl(1<pipe:[3578440]>, F_GETFD) = 0 <0.000100>
477   00:09:56.954525 fcntl(10<pipe:[3578440]>, F_SETFD, FD_CLOEXEC) = 0 <0.001500>"##
            .to_string();
        let raw_data = parse(&input);
        let pid_data_map = build_syscall_data(&raw_data);
        let dist = build_distribution("fcntl", &vec![477], &pid_data_map);
        assert_eq!(dist.get(&9), Some(&0));
    }
}