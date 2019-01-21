use crate::Pid;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: &'a str,
    pub syscall: &'a str,
    pub length: Option<f32>,
    pub file: Option<&'a str>,
    pub error: Option<&'a str>,
    pub child_pid: Option<Pid>,
    pub execve: Option<Vec<&'a str>>,
}

enum CallStatus {
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

    let syscall_token = tokens.next()?;

    let call_status = if syscall_token.starts_with('<') {
        CallStatus::Resumed
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
        CallStatus::Started => {
            let mut syscall_split = syscall_token.split('(');

            syscall = syscall_split.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;

            if syscall == "open" {
                file = syscall_split.next().and_then(|f| f.get(1..f.len() - 2));
            } else if syscall == "openat" {
                file = tokens.next().and_then(|f| f.get(1..f.len() - 2));
            } else if syscall == "execve" {
                if let Some(t) = syscall_split.next() {
                    let mut v = vec![t];
                    tokens
                        .by_ref()
                        .take_while(|s| *s != "[/*" && *s != "/*")
                        .for_each(|arg| v.push(arg));

                    execve = Some(v);
                }
            }
        }
    }

    let mut tokens_from_end = tokens.rev();

    let length = tokens_from_end
        .next()
        .filter(|t| t.starts_with('<'))
        .and_then(|t| t.get(1..t.len() - 1))
        .and_then(|len| len.parse::<f32>().ok());

    let mut child_pid = None;
    let mut error = None;

    if length.is_some() {
        let mut end_tokens = tokens_from_end.take_while(|t| *t != "=").peekable();

        while let Some(token) = end_tokens.next() {
            if token.starts_with('E') {
                error = Some(token);
            }

            if end_tokens.peek().is_none()
                && (syscall == "clone" || syscall == "vfork" || syscall == "fork")
            {
                child_pid = token.parse::<Pid>().ok();
            }
        }
    }

    Some(RawData {
        pid,
        time,
        syscall,
        length,
        file,
        error,
        child_pid,
        execve,
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
                length: Some(0.000030),
                file: Some("/dev/null"),
                error: None,
                child_pid: None,
                execve: None,
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
                length: Some(0.000011),
                file: None,
                error: None,
                child_pid: None,
                execve: None,
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
                length: None,
                file: Some("/dev/null"),
                error: None,
                child_pid: None,
                execve: None,
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
                length: Some(0.000030),
                file: Some("/dev/null"),
                error: None,
                child_pid: None,
                execve: None,
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
                length: Some(0.000118),
                file: None,
                error: None,
                child_pid: None,
                execve: None,
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
                length: Some(0.000118),
                file: None,
                error: None,
                child_pid: Some(23151),
                execve: None,
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
                length: Some(0.000229),
                file: None,
                error: None,
                child_pid: None,
                execve: Some(vec!["\"/bin/sleep\",", "[\"sleep\",", "\"1\"],",])
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
                length: None,
                file: None,
                error: None,
                child_pid: None,
                execve: Some(vec!["\"/bin/sleep\",", "[\"sleep\",", "\"1\"],",])
            })
        );
    }

}
