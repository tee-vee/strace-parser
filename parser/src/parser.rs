use crate::Pid;

use bstr::ByteSlice;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: &'a [u8],
    pub syscall: &'a [u8],
    pub duration: Option<f32>,
    pub error: Option<&'a [u8]>,
    pub rtn_cd: Option<i32>,
    pub call_status: CallStatus,
    pub other: Option<OtherFields<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExitType<'a> {
    Exit(i32),
    Signal(&'a [u8]),
}

impl<'a> fmt::Display for ExitType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExitType::*;
        match self {
            Exit(code) => write!(f, "{}", code),
            Signal(sig) => write!(f, "{}", sig.to_str_lossy()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ExitData<'a> {
    pub pid: Pid,
    pub exit: ExitType<'a>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LineData<'a> {
    Syscall(RawData<'a>),
    Exit(ExitData<'a>),
}

impl<'a> LineData<'a> {
    pub fn pid(&self) -> Pid {
        match self {
            LineData::Syscall(data) => data.pid,
            LineData::Exit(data) => data.pid,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum OtherFields<'a> {
    Clone(ProcType),
    Execve(Vec<&'a [u8]>),
    File(&'a [u8]),
    Futex(&'a [u8]),
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
    pub fn file(&self) -> Option<&'a [u8]> {
        match self.other {
            Some(OtherFields::File(f)) => Some(f),
            _ => None,
        }
    }

    pub fn execve(&self) -> Option<&[&'a [u8]]> {
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

pub fn parse_line<'a>(bytes: &'a [u8]) -> Option<LineData<'a>> {
    let mut tokens = bytes.fields_with(|c| c.is_ascii_whitespace());
    let mut rev_tokens = match bytes.last() {
        // Handle CRLF newlines. We split lines '\n', which will leave a trailing
        // '\r' on each line. Since 'fields_with' isn't double-ended, we need
        // to use rsplit_str on ' ', which will not filter out '\r'
        Some(b'\r') if bytes.len() > 1 => bytes[..bytes.len() - 1].rsplit_str(" "),
        _ => bytes.rsplit_str(" "),
    };

    // 17819 13:43:39.888658 brk(NULL)         = 0x3213000 <0.000019>
    // ^^^^^
    let pid = tokens
        .next()
        .and_then(|s| s.to_str().ok())
        .and_then(|p| p.parse::<Pid>().ok())?;

    // 17819 13:43:39.888658 brk(NULL)         = 0x3213000 <0.000019>
    //       ^^^^^^^^^^^^^^^
    let time = tokens.next().filter(|time_token| {
        time_token
            .chars()
            .next()
            .filter(|c| c.is_ascii_digit())
            .is_some()
    })?;

    // 17819 13:43:39.888658 brk(NULL)         = 0x3213000 <0.000019>
    //                                                     ^^^^^^^^^^
    let duration_token = rev_tokens.next()?;

    // 17819 13:43:39.888658 brk(NULL)         = 0x3213000 <0.000019>
    //                       ^^^^^^^^^
    let syscall_token = tokens.next()?;

    // 17819 13:43:39.897107 <... rt_sigprocmask resumed>NULL, 8) = 0 <0.000016>
    //                       ^^^^
    let call_status = if let Some(b'<') = syscall_token.get(0) {
        CallStatus::Resumed
    // 17819 13:43:39.888658 brk(NULL)         = 0x3213000 <0.000019>
    //                                                     ^^^^^^^^^^
    } else if let Some(b'<') = duration_token.get(0) {
        CallStatus::Complete
    // 90718 13:48:58.423962 +++ exited with 0 +++
    //                       ^^^
    } else if syscall_token == b"+++" {
        // 13449 01:58:23.198334 +++ killed by SIGTERM +++
        //                           ^^^^^^
        let exit_kill = tokens.next()?;
        // 13449 01:58:23.198334 +++ killed by SIGTERM +++
        //                                     ^^^^^^^
        let signal_code = tokens.nth(1)?;
        return match exit_kill {
            b"exited" => {
                let code = signal_code
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse::<i32>().ok())?;
                Some(LineData::Exit(ExitData {
                    pid,
                    exit: ExitType::Exit(code),
                }))
            }
            b"killed" => Some(LineData::Exit(ExitData {
                pid,
                exit: ExitType::Signal(signal_code),
            })),
            _ => None,
        };
    } else {
        CallStatus::Started
    };

    let syscall;
    let mut other = None;

    match call_status {
        CallStatus::Resumed => {
            // 17819 13:43:39.897107 <... rt_sigprocmask resumed>NULL, 8) = 0 <0.000016>
            //                            ^^^^^^^^^^^^^^
            syscall = tokens.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;

            match syscall {
                b"clone" => {
                    // 17819 13:43:39.897681 <... clone resumed>, parent_tid=[17822], tls=0x7f1c6f753700, child_tidptr=0x7f1c6f7539d0) = 17822 <0.000041>
                    //                                  ^^^^^^^^^
                    if tokens
                        .next()
                        .map(|t| !t.ends_with_str(")"))
                        .unwrap_or_default()
                    {
                        // 10738 01:58:22.788361 <... clone resumed> child_stack=0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 13442 <0.002381>
                        //                                                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                        let flags = tokens.nth(1)?;
                        if flags.contains_str(CLONE_THREAD) {
                            other = Some(OtherFields::Clone(ProcType::Thread));
                        } else if flags.starts_with_str("flags") {
                            other = Some(OtherFields::Clone(ProcType::Process));
                        }
                    }
                }
                b"fork" | b"vfork" => other = Some(OtherFields::Clone(ProcType::Process)),
                _ => {}
            }
        }
        CallStatus::Complete | CallStatus::Started => {
            // 17819 13:43:39.892101 sigaltstack(NULL, {ss_sp=NULL, ss_flags=SS_DISABLE, ss_size=0}) = 0 <0.000012>
            //                       ^^^^^^^^^^^ ^^^^^
            let mut syscall_split = syscall_token.splitn_str(2, "(");

            // 17819 13:43:39.892101 sigaltstack(NULL, {ss_sp=NULL, ss_flags=SS_DISABLE, ss_size=0}) = 0 <0.000012>
            //                       ^^^^^^^^^^^
            syscall = syscall_split.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|&c| c.is_ascii_alphabetic() || c == '_')
                    .is_some()
            })?;

            match syscall {
                b"open" => {
                    // 17819 13:43:39.888967 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000014>
                    //                             ^^^^^^^^^^^^^^^^
                    if let Some(f) = syscall_split.next().and_then(|f| f.get(1..f.len() - 2)) {
                        other = Some(OtherFields::File(f));
                    }
                }
                b"openat" => {
                    // 17819 13:43:40.146677 openat(AT_FDCWD, "config.toml", O_RDONLY|O_CLOEXEC) = 3</var/opt/gitlab/gitaly/config.toml> <0.000026>
                    //                                         ^^^^^^^^^^^
                    if let Some(f) = tokens.next().and_then(|f| f.get(1..f.len() - 2)) {
                        other = Some(OtherFields::File(f));
                    }
                }
                b"execve" => {
                    // 17840 13:43:41.449433 execve("/bin/ps", ["ps", "-o", "rss=", "-p", "17838"], 0xc0001c2000 /* 22 vars */ <unfinished ...>
                    //                              ^^^^^^^^^^ ^^^^^^ ^^^^^ ^^^^^^^ ^^^^^ ^^^^^^^^^ ^^^^^^^^^^^^ ^^ ^^ ^^^^
                    if let Some(t) = syscall_split.next() {
                        let mut v = vec![t];
                        tokens
                            .by_ref()
                            .take_while(|&s| s != b"[/*" && s != b"/*")
                            .for_each(|arg| v.push(arg));

                        other = Some(OtherFields::Execve(v));
                    }
                }
                b"futex" => {
                    // 17826 13:43:41.450300 futex(0xc00005ef48, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
                    //                             ^^^^^^^^^^^^
                    if let Some(addr) = syscall_split.next().and_then(|a| a.get(..a.len() - 1)) {
                        // 17826 13:43:41.450300 futex(0xc00005ef48, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
                        //                                           ^^^^^^^^^^^^^^^^^^^
                        if tokens
                            .next()
                            .map(|t| t.contains_str("PRIVATE"))
                            .unwrap_or_default()
                        {
                            other = Some(OtherFields::Futex(addr))
                        }
                    }
                }
                b"read" | b"recv" | b"recvfrom" | b"recvmsg" | b"send" | b"sendmsg" | b"sendto"
                | b"write" => {
                    // 17819 13:43:41.450318 read(22<pipe:[879334396]>,  <unfinished ...>
                    //                               ^^^^^^^^^^^^^^^^
                    if let Some(f) = syscall_split.next().and_then(|s| {
                        s.splitn_str(2, "<")
                            .nth(1)
                            .and_then(|s| s.get(..s.len() - 2))
                    }) {
                        other = Some(OtherFields::File(f));
                    }
                }
                // Only set other when call is complete as new pid is not available on started
                b"fork" | b"vfork" if matches!(call_status, CallStatus::Complete) => {
                    other = Some(OtherFields::Clone(ProcType::Process))
                }
                b"clone" => {
                    // 17822 13:43:41.413034 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
                    //                                               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                    if let Some(flags) = tokens.next() {
                        if flags.contains_str(CLONE_THREAD) {
                            other = Some(OtherFields::Clone(ProcType::Thread));
                        } else {
                            other = Some(OtherFields::Clone(ProcType::Process));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 17819 13:43:39.888658 brk(NULL)         = 0x3213000 <0.000019>
    //                                                     ^^^^^^^^^^
    let duration = if let Some(b'<') = duration_token.get(0) {
        duration_token
            .get(1..duration_token.len() - 1)
            .and_then(|s| s.to_str().ok())
            .and_then(|len| len.parse::<f32>().ok())
    } else {
        None
    };

    let mut rtn_cd = None;
    let mut error = None;

    if duration.is_some() {
        // 17826 13:43:40.155194 <... epoll_ctl resumed>) = -1 EPERM (Operation not permitted) <0.000029>
        //                                                  ^^ ^^^^^ ^^^^^^^^^^ ^^^ ^^^^^^^^^^
        let mut end_tokens = rev_tokens.take_while(|&t| t != b"=").peekable();

        while let Some(token) = end_tokens.next() {
            // 17826 13:43:40.155194 <... epoll_ctl resumed>) = -1 EPERM (Operation not permitted) <0.000029>
            //                                                     ^^^^^
            if let Some(b'E') = token.get(0) {
                error = Some(token);
            }

            // 17819 13:43:40.149100 read(6</proc/sys/net/core/somaxconn>, "", 65531) = 0 <0.000013>
            //                                                                          ^
            if end_tokens.peek().is_none() {
                match syscall {
                    b"clone" | b"fork" | b"vfork" | b"read" | b"recv" | b"recvfrom"
                    | b"recvmsg" | b"send" | b"sendmsg" | b"sendto" | b"write" => {
                        rtn_cd = token.to_str().ok().and_then(|s| s.parse::<i32>().ok())
                    }
                    _ => {}
                }
            }
        }
    }

    Some(LineData::Syscall(RawData {
        pid,
        time,
        syscall,
        duration,
        error,
        rtn_cd,
        call_status,
        other,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_returns_none_invalid_pid() {
        let input = br##"16aaa 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_returns_none_missing_pid() {
        let input = br##"11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_captures_pid() {
        let input = br##" 16747 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 16747,
                time: b"11:29:49.112721",
                syscall: b"open",
                duration: Some(0.000030),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::File(b"/dev/null")),
            }))
        );
    }

    #[test]
    fn parser_returns_none_missing_time() {
        let input = br##"16747 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_captures_time() {
        let input = br##"24009 09:07:12.773648 brk(NULL)         = 0x137e000 <0.000011>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 24009,
                time: b"09:07:12.773648",
                syscall: b"brk",
                duration: Some(0.000011),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: None,
            }))
        );
    }

    #[test]
    fn parser_returns_none_non_alpha_syscall() {
        let input = br##"90718 13:48:58.423962 $!@*+-"##;
        assert_eq!(parse_line(input), None);
    }

    #[test]
    fn parser_returns_some_invalid_length() {
        let input = br##"16747 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000aaa>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 16747,
                time: b"11:29:49.112721",
                syscall: b"open",
                duration: None,
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::File(b"/dev/null")),
            }))
        );
    }

    #[test]
    fn parser_captures_length() {
        let input = br##"16747 11:29:49.112721 open("/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null> <0.000030>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 16747,
                time: b"11:29:49.112721",
                syscall: b"open",
                duration: Some(0.000030),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::File(b"/dev/null")),
            }))
        );
    }

    #[test]
    fn parser_returns_some_invalid_child_pid() {
        let input = br##"16747 11:29:49.113885 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe42085c9d0) = 23aa <0.000118>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 16747,
                time: b"11:29:49.113885",
                syscall: b"clone",
                duration: Some(0.000118),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Process)),
            }))
        );
    }

    #[test]
    fn parser_captures_child_pid() {
        let input = br##"16747 11:29:49.113885 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fe42085c9d0) = 23151 <0.000118>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 16747,
                time: b"11:29:49.113885",
                syscall: b"clone",
                duration: Some(0.000118),
                error: None,
                rtn_cd: Some(23151),
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Process)),
            }))
        );
    }

    #[test]
    fn parser_captures_execve_finished() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) = 0 <0.000229>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 13656,
                time: b"10:53:02.442246",
                syscall: b"execve",
                duration: Some(0.000229),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Execve(vec![
                    b"\"/bin/sleep\",",
                    b"[\"sleep\",",
                    b"\"1\"],",
                ])),
            }))
        );
    }

    #[test]
    fn parser_captures_execve_unfinished() {
        let input = br##"13656 10:53:02.442246 execve("/bin/sleep", ["sleep", "1"], [/* 12 vars */]) <unfinished ...>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 13656,
                time: b"10:53:02.442246",
                syscall: b"execve",
                duration: None,
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Started,
                other: Some(OtherFields::Execve(vec![
                    b"\"/bin/sleep\",",
                    b"[\"sleep\",",
                    b"\"1\"],",
                ])),
            }))
        );
    }

    #[test]
    fn parser_captures_private_futex_complete() {
        let input =
            br##"27820 20:26:33.949452 futex(0x535c890, FUTEX_WAKE_PRIVATE, 1) = 0 <0.000087>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 27820,
                time: b"20:26:33.949452",
                syscall: b"futex",
                duration: Some(0.000087),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Futex(b"0x535c890")),
            }))
        );
    }

    #[test]
    fn parser_captures_private_futex_started() {
        let input = br##"11638 11:34:25.556415 futex(0x7ffa50080ff4, FUTEX_WAIT_PRIVATE, 27, NULL <unfinished ...>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 11638,
                time: b"11:34:25.556415",
                syscall: b"futex",
                duration: None,
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Started,
                other: Some(OtherFields::Futex(b"0x7ffa50080ff4"))
            }))
        );
    }

    #[test]
    fn parser_skips_non_private_futex_complete() {
        let input = br##"2965  11:34:25.561897 futex(0x38e1c80, FUTEX_WAKE, 1) = 0 <0.000025>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 2965,
                time: b"11:34:25.561897",
                syscall: b"futex",
                duration: Some(0.000025),
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Complete,
                other: None,
            }))
        );
    }

    #[test]
    fn parser_skips_non_private_futex_started() {
        let input =
            br##"23740 11:34:25.556284 futex(0xc420061548, FUTEX_WAIT, 0, NULL <unfinished ...>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 23740,
                time: b"11:34:25.556284",
                syscall: b"futex",
                duration: None,
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Started,
                other: None,
            }))
        );
    }

    #[test]
    fn parser_captures_complete_clone_thread() {
        let input = br##"98252 03:48:28.335770 clone(child_stack=0x7f202ac6bf70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f202ac6c9d0, tls=0x7f202ac6c700, child_tidptr=0x7f202ac6c9d0) = 98253 <0.000038>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 98252,
                time: b"03:48:28.335770",
                syscall: b"clone",
                duration: Some(0.000038),
                error: None,
                rtn_cd: Some(98253),
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Thread)),
            }))
        );
    }

    #[test]
    fn parser_captures_complete_clone_proc() {
        let input = br##"98245 03:48:28.282463 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fc502200a50) = 98246 <0.000068>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 98245,
                time: b"03:48:28.282463",
                syscall: b"clone",
                duration: Some(0.000068),
                error: None,
                rtn_cd: Some(98246),
                call_status: CallStatus::Complete,
                other: Some(OtherFields::Clone(ProcType::Process)),
            }))
        );
    }

    #[test]
    fn parser_captures_started_clone_proc() {
        let input = br##"16093 04:37:37.662748 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 16093,
                time: b"04:37:37.662748",
                syscall: b"clone",
                duration: None,
                error: None,
                rtn_cd: None,
                call_status: CallStatus::Started,
                other: Some(OtherFields::Clone(ProcType::Process)),
            }))
        );
    }

    #[test]
    fn parser_captures_resumed_clone_immediate_end() {
        let input = br##"17826 13:43:48.972999 <... clone resumed>) = 17905 <0.008941>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 17826,
                time: b"13:43:48.972999",
                syscall: b"clone",
                duration: Some(0.008941),
                error: None,
                rtn_cd: Some(17905),
                call_status: CallStatus::Resumed,
                other: None,
            }))
        );
    }

    #[test]
    fn parser_captures_resumed_clone_no_flags() {
        let input = br##"17821 13:43:39.901584 <... clone resumed>, parent_tid=[17825], tls=0x7f1c6df50700, child_tidptr=0x7f1c6df509d0) = 17825 <0.000064>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 17821,
                time: b"13:43:39.901584",
                syscall: b"clone",
                duration: Some(0.000064),
                error: None,
                rtn_cd: Some(17825),
                call_status: CallStatus::Resumed,
                other: None,
            }))
        );
    }

    #[test]
    fn parser_captures_resumed_clone_thread() {
        let input = br##"111462 08:55:58.704022 <... clone resumed> child_stack=0x7f001bffdfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7f001bffe9d0, tls=0x7f001bffe700, child_tidptr=0x7f001bffe9d0) = 103674 <0.000060>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 111462,
                time: b"08:55:58.704022",
                syscall: b"clone",
                duration: Some(0.000060),
                error: None,
                rtn_cd: Some(103674),
                call_status: CallStatus::Resumed,
                other: Some(OtherFields::Clone(ProcType::Thread)),
            }))
        );
    }

    #[test]
    fn parser_captures_resumed_clone_proc() {
        let input = br##"98781 10:30:46.143570 <... clone resumed> child_stack=0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 56089 <0.004605>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 98781,
                time: b"10:30:46.143570",
                syscall: b"clone",
                duration: Some(0.004605),
                error: None,
                rtn_cd: Some(56089),
                call_status: CallStatus::Resumed,
                other: Some(OtherFields::Clone(ProcType::Process)),
            }))
        );
    }

    #[test]
    fn parser_captures_fork_proc() {
        let input = br##"2974  11:34:28.581144 <... vfork resumed> ) = 27367 <0.123110>"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Syscall(RawData {
                pid: 2974,
                time: b"11:34:28.581144",
                syscall: b"vfork",
                duration: Some(0.123110),
                error: None,
                rtn_cd: Some(27367),
                call_status: CallStatus::Resumed,
                other: Some(OtherFields::Clone(ProcType::Process)),
            }))
        );
    }

    #[test]
    fn parser_captures_zero_exit_code() {
        let input = br##"13513 01:58:50.823625 +++ exited with 0 +++"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Exit(ExitData {
                pid: 13513,
                exit: ExitType::Exit(0),
            }))
        );
    }

    #[test]
    fn parser_captures_nonzero_exit_code() {
        let input = br##"13454 01:58:23.149393 +++ exited with 128 +++"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Exit(ExitData {
                pid: 13454,
                exit: ExitType::Exit(128),
            }))
        );
    }

    #[test]
    fn parser_captures_signal_exit() {
        let input = br##"13350 01:58:19.443720 +++ killed by SIGTERM +++"##;
        assert_eq!(
            parse_line(input),
            Some(LineData::Exit(ExitData {
                pid: 13350,
                exit: ExitType::Signal(b"SIGTERM"),
            }))
        );
    }
}
