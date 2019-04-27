use crate::Pid;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: &'a str,
    pub syscall: &'a str,
    pub duration: Option<f32>,
    pub file: Option<&'a str>,
    pub error: Option<&'a str>,
    pub rtn_cd: Option<i32>,
    pub execve: Option<Vec<&'a str>>,
    pub call_status: CallStatus,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CallStatus {
    Complete,
    Resumed,
    Started,
}

pub fn parse_line(line: &str) -> Option<RawData> {
    let tokens = split_line(line);
    parse_tokens(tokens)
}

#[cfg(feature = "nightly")]
fn split_line(line: &str) -> std::str::SplitAsciiWhitespace {
    line.split_ascii_whitespace()
}

#[cfg(not(feature = "nightly"))]
fn split_line(line: &str) -> std::str::SplitWhitespace {
    line.split_whitespace()
}

fn parse_tokens<'a, I>(mut tokens: I) -> Option<RawData<'a>>
where
    I: DoubleEndedIterator<Item = &'a str>,
{
    let pid = tokens.next().and_then(|p| p.parse::<Pid>().ok())?;

    let time = tokens.next().filter(|time_token| {
        time_token
            .chars()
            .next()
            .filter(|c| c.is_numeric())
            .is_some()
    })?;

    let duration_token = tokens.next_back()?;

    let syscall_token = tokens.next()?;

    let call_status = if syscall_token.starts_with('<') {
        CallStatus::Resumed
    } else if duration_token.starts_with('<') {
        CallStatus::Complete
    } else {
        CallStatus::Started
    };

    let syscall;
    let mut file = None;
    let mut execve = None;

    match call_status {
        CallStatus::Resumed => {
            syscall = tokens.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;
        }
        CallStatus::Complete | CallStatus::Started => {
            let mut syscall_split = syscall_token.split('(');

            syscall = syscall_split.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;

            match syscall {
                "open" => {
                    file = syscall_split.next().and_then(|f| f.get(1..f.len() - 2));
                }
                "openat" => {
                    file = tokens.next().and_then(|f| f.get(1..f.len() - 2));
                }
                "execve" => {
                    if let Some(t) = syscall_split.next() {
                        let mut v = vec![t];
                        tokens
                            .by_ref()
                            .take_while(|s| *s != "[/*" && *s != "/*")
                            .for_each(|arg| v.push(arg));

                        execve = Some(v);
                    }
                }
                "read" | "recv" | "recvfrom" | "recvmsg" | "send" | "sendmsg" | "sendto"
                | "write" => {
                    file = syscall_split
                        .next()
                        .and_then(|s| s.splitn(2, '<').nth(1).and_then(|s| s.get(0..s.len() - 2)));
                }
                _ => {}
            }
        }
    }

    let duration = if duration_token.starts_with('<') {
        duration_token
            .get(1..duration_token.len() - 1)
            .and_then(|len| len.parse::<f32>().ok())
    } else {
        None
    };

    let mut rtn_cd = None;
    let mut error = None;

    if duration.is_some() {
        let mut end_tokens = tokens.rev().take_while(|t| *t != "=").peekable();

        while let Some(token) = end_tokens.next() {
            if token.starts_with('E') {
                error = Some(token);
            }

            if end_tokens.peek().is_none() {
                match syscall {
                    "clone" | "fork" | "vfork" | "read" | "recv" | "recvfrom" | "recvmsg"
                    | "send" | "sendmsg" | "sendto" | "write" => rtn_cd = token.parse::<i32>().ok(),
                    _ => {}
                }
            }
        }
    }

    Some(RawData {
        pid,
        time,
        syscall,
        duration,
        file,
        error,
        rtn_cd,
        execve,
        call_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_returns_none_invalid_pid() {
        let input = r##"16aaa 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_returns_none_missing_pid() {
        let input = r##"11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_captures_pid() {
        let input = r##" 16747 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 16747,
                time: "11:29:49.112721",
                syscall: "open",
                duration: Some(0.000030),
                file: Some("/dev/null"),
                error: None,
                rtn_cd: None,
                execve: None,
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_returns_none_missing_time() {
        let input = r##"16747 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_captures_time() {
        let input = r##"24009 09:07:12.773648 brk(NULL)         = 0x137e000 <0.000011>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 24009,
                time: "09:07:12.773648",
                syscall: "brk",
                duration: Some(0.000011),
                file: None,
                error: None,
                rtn_cd: None,
                execve: None,
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_returns_none_non_alpha_syscall() {
        let input = r##"27183 11:34:25.959907 +++ killed by SIGTERM +++"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_returns_some_invalid_length() {
        let input = r##"16747 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000aaa>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 16747,
                time: "11:29:49.112721",
                syscall: "open",
                duration: None,
                file: Some("/dev/null"),
                error: None,
                rtn_cd: None,
                execve: None,
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_captures_length() {
        let input = r##"16747 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 16747,
                time: "11:29:49.112721",
                syscall: "open",
                duration: Some(0.000030),
                file: Some("/dev/null"),
                error: None,
                rtn_cd: None,
                execve: None,
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_returns_some_invalid_child_pid() {
        let input = r##"16747 11:29:49.113885 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe42085c9d0) = 23aa <0.000118>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 16747,
                time: "11:29:49.113885",
                syscall: "clone",
                duration: Some(0.000118),
                file: None,
                error: None,
                rtn_cd: None,
                execve: None,
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_captures_child_pid() {
        let input = r##"16747 11:29:49.113885 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe42085c9d0) = 23151 <0.000118>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 16747,
                time: "11:29:49.113885",
                syscall: "clone",
                duration: Some(0.000118),
                file: None,
                error: None,
                rtn_cd: Some(23151),
                execve: None,
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_captures_execve_finished() {
        let input = r##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000229>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 13656,
                time: "10:53:02.442246",
                syscall: "execve",
                duration: Some(0.000229),
                file: None,
                error: None,
                rtn_cd: None,
                execve: Some(vec!["\"/bin/sleep\",", "[\"sleep\",", "\"1\"],",]),
                call_status: CallStatus::Complete,
            })
        );
    }

    #[test]
    fn parser_captures_execve_unfinished() {
        let input = r##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) <unfinished ...>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 13656,
                time: "10:53:02.442246",
                syscall: "execve",
                duration: None,
                file: None,
                error: None,
                rtn_cd: None,
                execve: Some(vec!["\"/bin/sleep\",", "[\"sleep\",", "\"1\"],",]),
                call_status: CallStatus::Started,
            })
        );
    }

}
