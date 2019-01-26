use crate::parser::CallStatus;
use crate::Pid;

enum LineData {
    Io(IoEvent),
    Clone(Pid),
    Other,
}

#[derive(Clone, Debug, PartialEq)]
struct IoEvent {
    pid: Pid,
    syscall: Syscall,
    bytes: Option<i64>,
    duration: Option<f32>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Syscall {
    Clone,
    Read,
    Recv,
    Recvfrom,
    Recvmsg,
    Send,
    SendTo,
    Sendmsg,
    Write,
}

pub fn io() {}

fn parser(line: &str) -> Option<LineData> {
    let mut tokens = line.split_whitespace();

    let pid = tokens.next().and_then(|p| p.parse::<Pid>().ok())?;

    tokens.next();

    let syscall_token = tokens.next()?;

    let call_status = if syscall_token.starts_with('<') {
        CallStatus::Resumed
    } else {
        CallStatus::Started
    };

    let syscall_str;
    match call_status {
        CallStatus::Resumed => {
            syscall_str = tokens.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;
        }
        CallStatus::Started => {
            let mut syscall_split = syscall_token.split('(');

            syscall_str = syscall_split.next().filter(|syscall_tok| {
                syscall_tok
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .is_some()
            })?;
        }
    }

    let syscall = match syscall_str {
        "read" => Syscall::Read,
        "write" => Syscall::Write,
        "clone" => Syscall::Clone,
        _ => return None,
    };

    let duration = tokens
        .next_back()
        .filter(|d| d.starts_with('<'))
        .and_then(|d| d.get(1..d.len() - 1))
        .and_then(|d| d.parse::<f32>().ok());

    let ret = tokens.next_back().and_then(|r| r.parse::<i64>().ok());

    if let Syscall::Clone = syscall {
        Some(LineData::Clone(pid))
    } else {
        Some(LineData::Io(IoEvent {
            pid,
            syscall,
            bytes: ret,
            duration,
        }))
    }
}
