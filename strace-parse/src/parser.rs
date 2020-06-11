use crate::Pid;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: &'a str,
    pub syscall: &'a str,
    pub duration: Option<f32>,
    pub error: Option<&'a str>,
    pub rtn_cd: Option<i32>,
    pub call_status: CallStatus,
    pub other: Option<OtherFields<'a>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OtherFields<'a> {
    Execve(Vec<&'a str>),
    File(&'a str),
    Clone(ProcType),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CallStatus {
    Complete,
    Resumed,
    Started,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProcType {
    Thread,
    Process,
}

impl<'a> RawData<'a> {
    pub fn file(&self) -> Option<&'a str> {
        match self.other {
            Some(OtherFields::File(f)) => Some(f),
            _ => None,
        }
    }

    pub fn execve(&self) -> Option<&[&'a str]> {
        match &self.other {
            Some(OtherFields::Execve(v)) => Some(v),
            _ => None,
        }
    }

    pub fn proc_type(&self) -> Option<ProcType> {
        match self.other {
            Some(OtherFields::Clone(p)) => Some(p),
            _ => None,
        }
    }
}

const CLONE_THREAD: &str = "CLONE_THREAD";

pub fn parse_line(line: &str) -> Option<RawData> {
    let tokens = line.split_ascii_whitespace();
    parse_tokens(tokens)
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
    let mut other = None;

    match call_status {
        CallStatus::Resumed => {
            syscall = tokens.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;

            if syscall == "clone" {
                let flags = tokens.nth(2)?;
                if flags.contains(CLONE_THREAD) {
                    other = Some(OtherFields::Clone(ProcType::Thread))
                } else {
                    other = Some(OtherFields::Clone(ProcType::Process))
                }
            }
        }
        CallStatus::Complete | CallStatus::Started => {
            let mut syscall_split = syscall_token.splitn(2, '(');

            syscall = syscall_split.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;

            match syscall {
                "open" => {
                    if let Some(f) = syscall_split.next().and_then(|f| f.get(1..f.len() - 2)) {
                        other = Some(OtherFields::File(f));
                    }
                }
                "openat" => {
                    if let Some(f) = tokens.next().and_then(|f| f.get(1..f.len() - 2)) {
                        other = Some(OtherFields::File(f));
                    }
                }
                "execve" => {
                    if let Some(t) = syscall_split.next() {
                        let mut v = vec![t];
                        tokens
                            .by_ref()
                            .take_while(|&s| s != "[/*" && s != "/*")
                            .for_each(|arg| v.push(arg));

                        other = Some(OtherFields::Execve(v));
                    }
                }
                "read" | "recv" | "recvfrom" | "recvmsg" | "send" | "sendmsg" | "sendto"
                | "write" => {
                    if let Some(f) = syscall_split
                        .next()
                        .and_then(|s| s.splitn(2, '<').nth(1).and_then(|s| s.get(0..s.len() - 2)))
                    {
                        other = Some(OtherFields::File(f));
                    }
                }
                "clone" if matches!(call_status, CallStatus::Complete) => {
                    let flags = tokens.next()?;
                    if flags.contains(CLONE_THREAD) {
                        other = Some(OtherFields::Clone(ProcType::Thread));
                    } else {
                        other = Some(OtherFields::Clone(ProcType::Process));
                    }
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
        let mut end_tokens = tokens.rev().take_while(|&t| t != "=").peekable();

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
        error,
        rtn_cd,
        call_status,
        other,
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::File("/dev/null")),
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: None,
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::File("/dev/null")),
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::File("/dev/null")),
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Process)),
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
                error: None,
                rtn_cd: Some(23151),
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Process)),
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Execve(vec![
                    "\"/bin/sleep\",",
                    "[\"sleep\",",
                    "\"1\"],",
                ])),
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
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Started,
                other: Some(OtherFields::Execve(vec![
                    "\"/bin/sleep\",",
                    "[\"sleep\",",
                    "\"1\"],",
                ])),
            })
        );
    }

    #[test]
    fn parser_captures_complete_clone_thread() {
        let input = r##"98252 03:48:28.335770 clone(child_stack=0x7f202ac6bf70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f202ac6c9d0, tls=0x7f202ac6c700, child_tidptr=0x7f202ac6c9d0) = 98253 <0.000038>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 98252,
                time: "03:48:28.335770",
                syscall: "clone",
                duration: Some(0.000038),
                error: None,
                rtn_cd: Some(98253),
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Thread)),
            })
        );
    }

    #[test]
    fn parser_captures_complete_clone_proc() {
        let input = r##"98245 03:48:28.282463 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fc502200a50) = 98246 <0.000068>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 98245,
                time: "03:48:28.282463",
                syscall: "clone",
                duration: Some(0.000068),
                error: None,
                rtn_cd: Some(98246),
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Process)),
            })
        );
    }

    #[test]
    fn parser_captures_resumed_clone_thread() {
        let input = r##"111462 08:55:58.704022 <... clone resumed> child_stack=0x7f001bffdfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f001bffe9d0, tls=0x7f001bffe700, child_tidptr=0x7f001bffe9d0) = 103674 <0.000060>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 111462,
                time: "08:55:58.704022",
                syscall: "clone",
                duration: Some(0.000060),
                error: None,
                rtn_cd: Some(103674),
                call_status: CallStatus::Resumed,
                other: Some(OtherFields::Clone(ProcType::Thread)),
            })
        );
    }

    #[test]
    fn parser_captures_resumed_clone_proc() {
        let input = r##"98781 10:30:46.143570 <... clone resumed> child_stack=0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 56089 <0.004605>"##;
        assert_eq!(
            parse_line(input),
            Some(RawData {
                pid: 98781,
                time: "10:30:46.143570",
                syscall: "clone",
                duration: Some(0.004605),
                error: None,
                rtn_cd: Some(56089),
                call_status: CallStatus::Resumed,
                other: Some(OtherFields::Clone(ProcType::Process)),
            })
        );
    }
}
