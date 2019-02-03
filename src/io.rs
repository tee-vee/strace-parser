use crate::parser::{CallStatus, RawData};
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct IoCall<'a> {
    pid: Pid,
    time: &'a str,
    syscall: Syscall,
    fd: &'a str,
    bytes: i32,
    duration: f32,
    error: Option<&'a str>,
}

impl<'a> fmt::Display for IoCall<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let error = self.error.unwrap_or("-");
        let bytes = if self.bytes < 0 { 0 } else { self.bytes };
        let duration = self.duration * 1000.0;

        write!(
            f,
            "  {: >7}\t{: >10.3}\t{: ^17}\t{: ^5}\t{: >8}\t{: ^15}\t   {: <30}",
            self.pid, duration, self.time, self.syscall, bytes, error, self.fd
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Syscall {
    Read,
    Write,
    Other,
}

impl From<&str> for Syscall {
    fn from(syscall_name: &str) -> Syscall {
        match syscall_name {
            "read" | "recv" | "recvfrom" | "recvmsg" => Syscall::Read,
            "send" | "sendmsg" | "sendto" | "write" => Syscall::Write,
            _ => Syscall::Other,
        }
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Syscall::Read => write!(f, "read"),
            Syscall::Write => write!(f, "write"),
            Syscall::Other => write!(f, "other"),
        }
    }
}

pub fn io_calls<'a>(
    pids: &[Pid],
    raw_data: &HashMap<Pid, PidData<'a>>,
) -> BTreeMap<Pid, Vec<IoCall<'a>>> {
    pids.par_iter()
        .map(|pid| {
            let mut io_events = raw_data[pid].io_events.clone();
            io_events.par_sort_unstable_by(|x, y| (x.time).cmp(&y.time));

            let mut coalesced_data: Vec<_> = coalesce_io_events(&io_events);

            coalesced_data.par_sort_by(|x, y| (x.time).cmp(&y.time));
            (*pid, coalesced_data)
        })
        .collect()
}

fn coalesce_io_events<'a>(events: &[RawData<'a>]) -> Vec<IoCall<'a>> {
    let mut events_it = events.iter();
    let mut io_calls = Vec::new();

    while let Some(event) = events_it.next() {
        match event.call_status {
            CallStatus::Complete => io_calls.push(IoCall {
                pid: event.pid,
                time: event.time,
                syscall: Syscall::from(event.syscall),
                fd: event.file.unwrap_or_default(),
                bytes: event.rtn_cd.unwrap_or_default(),
                duration: event.duration.unwrap_or_default(),
                error: event.error,
            }),
            CallStatus::Started => {
                if let Some(next_event) = events_it.next() {
                    io_calls.push(IoCall {
                        pid: event.pid,
                        time: event.time,
                        syscall: Syscall::from(event.syscall),
                        fd: event.file.unwrap_or_default(),
                        bytes: next_event.rtn_cd.unwrap_or_default(),
                        duration: next_event.duration.unwrap_or_default(),
                        error: next_event.error,
                    })
                }
            }
            CallStatus::Resumed => {}
        }
    }
    io_calls
}
