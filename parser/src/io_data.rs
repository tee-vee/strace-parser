use crate::parser::{CallStatus, RawData, syscall::SyscallAtom};
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct IoCall<'a> {
    pub pid: Pid,
    pub time: &'a str,
    pub syscall: SyscallAtom,
    pub fd: &'a str,
    pub bytes: i32,
    pub duration: f32,
    pub error: Option<&'a str>,
}

impl<'a> fmt::Display for IoCall<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let error = self.error.unwrap_or("-");
        let bytes = if self.bytes < 0 { 0 } else { self.bytes };
        let duration = self.duration * 1000.0;

        write!(
            f,
            "  {: >7}    {: >10.3}    {: ^15}    {: <8}    {: >8}     {: ^15}    {: <30}",
            self.pid, duration, self.time, self.syscall, bytes, error, self.fd
        )
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
                syscall: event.syscall.clone(),
                fd: event
                    .file()
                    .unwrap_or("Unavailable: '-y' flag was not passed to strace"),
                bytes: event.rtn_cd.unwrap_or_default(),
                duration: event.duration.unwrap_or_default(),
                error: event.error,
            }),
            CallStatus::Started => {
                if let Some(next_event) = events_it.next() {
                    io_calls.push(IoCall {
                        pid: event.pid,
                        time: event.time,
                        syscall: event.syscall.clone(),
                        fd: event
                            .file()
                            .unwrap_or("Unavailable: '-y' flag was not passed to strace"),
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
