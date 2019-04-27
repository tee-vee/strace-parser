use chrono::NaiveTime;
use std::io::{prelude::*, stdout, Error};
use strace_parse::time;
use strace_parse::Pid;

pub fn correct_strace_flags(line: &str) -> Result<bool, Error> {
    let mut tokens = line.split_whitespace();

    let pid = tokens.next().and_then(|p| p.parse::<Pid>().ok()).is_some();

    let time_str = tokens
        .next()
        .filter(|time_token| {
            time_token
                .chars()
                .next()
                .filter(|c| c.is_numeric())
                .is_some()
        })
        .unwrap_or_default();

    let iso_time_ok =
        NaiveTime::parse_from_str(time_str, "%H:%M:%S%.6f").is_ok() && time_str.contains('.');
    let unix_time_ok = time_str.chars().next().filter(|c| *c != '0').is_some() && time::parse_unix_timestamp(time_str).is_some();
    let time = iso_time_ok || unix_time_ok;

    let duration = tokens.next_back().filter(|s| s.ends_with('>')).is_some();

    if pid && time && duration {
        Ok(true)
    } else {
        write!(
            stdout(),
            "  Error: strace command must include '-f', '-T' and '-tt' OR '-ttt'\
             \n    '-yyy' is also recommended to obtain all file names in 'io'\
             \n\n  The following required flag(s) were missing when strace was run: "
        )?;

        if !pid {
            write!(stdout(), "-f ")?;
        }

        if !time {
            write!(stdout(), "[-tt OR -ttt] ")?;
        }

        if !duration {
            write!(stdout(), "-T ")?;
        }

        writeln!(stdout())?;

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_pid_caught() {
        let input =
            r###"00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }

    #[test]
    fn present_pid_found() {
        let input =
            r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }
    #[test]
    fn missing_time_wo_pid_caught() {
        let input = r###"futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }

    #[test]
    fn missing_time_w_pid_caught() {
        let input = r###"123 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }

    #[test]
    fn present_time_found() {
        let input = r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }

    #[test]
    fn short_time_rejected() {
        let input =
            r###"123 00:09:48 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }

    #[test]
    fn unix_time_found() {
        let input = r###"123 1546409294.931558 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }

    #[test]
    fn relative_time_rejected() {
        let input =
            r###"123 0.000615 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }

    #[test]
    fn missing_execution_caught() {
        let input = r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }
    #[test]
    fn present_execution_found() {
        let input = r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }

    #[test]
    fn present_execution_unfinished_found() {
        let input = r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <unfinished ...>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }
}
