use crate::Pid;
use chrono::NaiveTime;
use std::io::{prelude::*, stdout, Error};

pub fn correct_strace_flags(line: &str) -> Result<bool, Error> {
    let tokens: Vec<_> = line.split_whitespace().collect();

    let pid = tokens
        .get(0)
        .cloned()
        .unwrap_or_default()
        .parse::<Pid>()
        .is_ok();

    let time = if pid {
        NaiveTime::parse_from_str(tokens.get(1).cloned().unwrap_or_default(), "%H:%M:%S%.6f")
            .is_ok()
    } else {
        NaiveTime::parse_from_str(tokens.get(0).cloned().unwrap_or_default(), "%H:%M:%S%.6f")
            .is_ok()
    };

    let execution = tokens
        .last()
        .cloned()
        .filter(|s| s.ends_with('>'))
        .is_some();

    if pid && time && execution {
        Ok(true)
    } else {
        write!(
            stdout(),
            "Unable to analyze file, the following flags need to be included when running strace: "
        )?;

        if !pid {
            write!(stdout(), "-f ")?;
        }

        if !time {
            write!(stdout(), "-tt ")?;
        }

        if !execution {
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
        let input =
            r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }
    #[test]
    fn missing_execution_caught() {
        let input = r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), false);
    }
    #[test]
    fn present_execution_found() {
        let input =
            r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <1.000000>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }

    #[test]
    fn present_execution_unfinished_found() {
        let input =
            r###"123 00:09:48.145114 futex(0x7f5efea4bd28, FUTEX_WAKE_PRIVATE, 1) = 0 <unfinished ...>"###;
        assert_eq!(correct_strace_flags(&input).unwrap(), true);
    }
}
