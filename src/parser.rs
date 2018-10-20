use chrono::NaiveTime;
use crate::Pid;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: NaiveTime,
    pub syscall: &'a str,
    pub length: Option<f32>,
    pub file: Option<&'a str>,
    pub error: Option<&'a str>,
    pub child_pid: Option<Pid>,
}

impl<'a> RawData<'a> {
    pub fn from_strs(
        pid_str: &'a str,
        time_str: &'a str,
        syscall: &'a str,
        length_str: Option<&'a str>,
        file: Option<&'a str>,
        error: Option<&'a str>,
        child_pid_str: Option<&'a str>,
    ) -> Option<RawData<'a>> {
        let pid = match pid_str.parse() {
            Ok(pid) => pid,
            Err(_) => return None,
        };

        let time = match NaiveTime::parse_from_str(time_str, "%H:%M:%S%.6f") {
            Ok(time) => time,
            Err(_) => return None,
        };

        let length = match length_str {
            Some(length) => match length.parse() {
                Ok(len) => Some(len),
                Err(_) => None,
            },
            None => None,
        };

        let child_pid = match child_pid_str {
            Some(child_pid) => match child_pid.parse() {
                Ok(c_pid) => Some(c_pid),
                Err(_) => None,
            },
            None => None,
        };

        Some(RawData {
            pid,
            time,
            syscall,
            length,
            file,
            error,
            child_pid,
        })
    }
}

enum CallStatus {
    Resumed,
    Started,
}

pub fn parse<'a>(buffer: &'a str) -> HashMap<Pid, Vec<RawData<'a>>> {
    let data = buffer.par_lines().filter_map(|l| parse_line(l)).collect();
    let sorted_data = sort_parsed_data(data);

    sorted_data
}

fn parse_line<'a>(line: &'a str) -> Option<RawData<'a>> {
    let tokens: SmallVec<[&str; 20]> = line.split_whitespace().collect();

    if tokens.len() < 5 {
        return None;
    }

    let pid = tokens[0];
    let time = tokens[1];

    let call_status = if tokens[2].starts_with('<') {
        CallStatus::Resumed
    } else {
        CallStatus::Started
    };

    let syscall;
    let mut file = None;

    match call_status {
        CallStatus::Started => {
            let split: SmallVec<[&str; 5]> = tokens[2].split('(').collect();

            if split.len() < 2 {
                return None;
            }

            syscall = split[0];
            if syscall == "open" {
                let file_quoted = split[1];
                file = Some(&file_quoted[1..file_quoted.len() - 2]);
            } else if syscall == "openat" {
                let file_quoted = tokens[3];
                file = Some(&file_quoted[1..file_quoted.len() - 2]);
            }
        }
        CallStatus::Resumed => {
            syscall = tokens[3];
        }
    }

    let length = match tokens.last() {
        Some(token) => {
            if token.starts_with('<') {
                Some(&token[1..token.len() - 1])
            } else {
                None
            }
        }
        None => None,
    };

    let mut child_pid = None;
    let mut error = None;

    let eq_pos = tokens.iter().rposition(|&t| t == "=");
    if let Some(pos) = eq_pos {
        if syscall == "clone" {
            if let Some(child_pid_str) = tokens.get(pos + 1).map(|t| *t) {
                child_pid = Some(child_pid_str);
            }
        }

        let err_pos = tokens.iter().skip(pos).position(|t| (*t).starts_with("E"));
        if let Some(e_pos) = err_pos {
            error = tokens.get(pos + e_pos).map(|t| *t);
        }
    }

    RawData::from_strs(pid, time, syscall, length, file, error, child_pid)
}

fn sort_parsed_data<'a>(parsed_data: Vec<RawData<'a>>) -> HashMap<Pid, Vec<RawData<'a>>> {
    let mut sorted_data = HashMap::new();

    for data in parsed_data.into_iter() {
        let pid_entry = sorted_data.entry(data.pid).or_insert(Vec::new());
        pid_entry.push(data);
    }

    sorted_data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_data_returns_none_invalid_pid() {
        assert_eq!(
            RawData::from_strs("123aaa", "00:09:47.790763", "test", None, None, None, None),
            None
        );
    }

    #[test]
    fn raw_data_returns_none_invalid_time() {
        assert_eq!(
            RawData::from_strs(
                "123aaa",
                "00:09:47.790763abcdefg",
                "test",
                None,
                None,
                None,
                None
            ),
            None
        );
    }

    #[test]
    fn raw_data_returns_some_invalid_length() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "00:09:47.790763",
                "test",
                Some("1.00000aaa"),
                None,
                None,
                None
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: None,
                file: None,
                error: None,
                child_pid: None,
            })
        );
    }

    #[test]
    fn raw_data_returns_some_invalid_child_pid() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "00:09:47.790763",
                "test",
                None,
                None,
                None,
                Some("123aaa"),
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: None,
                file: None,
                error: None,
                child_pid: None,
            })
        );
    }

    #[test]
    fn raw_data_constructed_pid_length_child_pid() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "00:09:47.790763",
                "test",
                Some("1.000000"),
                Some("/dev/null"),
                Some("EWAT"),
                Some("456")
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: Some(1.000000),
                file: Some("/dev/null"),
                error: Some("EWAT"),
                child_pid: Some(456),
            })
        );
    }

    #[test]
    fn raw_data_constructed_pid_length() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "00:09:47.790763",
                "test",
                Some("1.000000"),
                Some("/dev/null"),
                Some("EWAT"),
                None,
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: Some(1.000000),
                file: Some("/dev/null"),
                error: Some("EWAT"),
                child_pid: None,
            })
        );
    }
    #[test]
    fn raw_data_constructed_pid() {
        assert_eq!(
            RawData::from_strs(
                "123",
                "00:09:47.790763",
                "test",
                None,
                Some("/dev/null"),
                Some("EWAT"),
                None,
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: None,
                file: Some("/dev/null"),
                error: Some("EWAT"),
                child_pid: None,
            })
        );
    }
}
