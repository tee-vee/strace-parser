use chrono::NaiveTime;
use crate::Pid;
use smallvec::SmallVec;

#[derive(Clone, Debug, PartialEq)]
pub struct RawData<'a> {
    pub pid: Pid,
    pub time: NaiveTime,
    pub syscall: &'a str,
    pub length: Option<f32>,
    pub file: Option<&'a str>,
    pub error: Option<&'a str>,
    pub child_pid: Option<Pid>,
    pub execve: Option<Vec<&'a str>>,
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
        execve: Option<Vec<&'a str>>,
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
            execve,
        })
    }
}

enum CallStatus {
    Resumed,
    Started,
}

pub fn parse_line<'a>(line: &'a str) -> Option<RawData<'a>> {
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
    let mut execve = None;

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
            } else if syscall == "execve" {
                let v = vec![split[1]];
                execve = Some(v);
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

    if let Some(_) = length {
        let eq_pos = tokens.iter().rposition(|&t| t == "=");
        if let Some(pos) = eq_pos {
            if syscall == "clone" {
                if let Some(child_pid_str) = tokens.get(pos + 1).map(|t| *t) {
                    child_pid = Some(child_pid_str);
                }
            }

            if syscall == "execve" {
                let len_from_execve_to_eq = pos - 3;
                if let Some(ref mut v) = execve {
                    let mut cmds = tokens.iter().skip(3).take(len_from_execve_to_eq);
                    while let Some(cmd) = cmds.next() {
                        &v.push(cmd);
                    }
                }
            }

            let err_pos = tokens.iter().skip(pos).position(|t| (*t).starts_with("E"));
            if let Some(e_pos) = err_pos {
                error = tokens.get(pos + e_pos).map(|t| *t);
            }
        }
    } else if syscall == "execve" {
        if let CallStatus::Started = call_status {
            let len_from_execve_to_unfin = tokens.len() - 5;
            if let Some(ref mut v) = execve {
                let mut cmds = tokens.iter().skip(3).take(len_from_execve_to_unfin);
                while let Some(cmd) = cmds.next() {
                    v.push(cmd);
                }
            }
        }
    }

    RawData::from_strs(pid, time, syscall, length, file, error, child_pid, execve)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_data_returns_none_invalid_pid() {
        assert_eq!(
            RawData::from_strs(
                "123aaa",
                "00:09:47.790763",
                "test",
                None,
                None,
                None,
                None,
                None
            ),
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
                None,
                None,
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
                None,
                None,
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: None,
                file: None,
                error: None,
                child_pid: None,
                execve: None,
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
                None,
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: None,
                file: None,
                error: None,
                child_pid: None,
                execve: None,
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
                Some("456"),
                None,
            ),
            Some(RawData {
                pid: 123,
                time: NaiveTime::from_hms_micro(0, 9, 47, 790763),
                syscall: "test",
                length: Some(1.000000),
                file: Some("/dev/null"),
                error: Some("EWAT"),
                child_pid: Some(456),
                execve: None,
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
                execve: None,
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
                time: NaiveTime::from_hms_micro(10, 53, 02, 442246),
                syscall: "execve",
                length: Some(0.000229),
                file: None,
                error: None,
                child_pid: None,
                execve: Some(vec![
                    "\"/bin/sleep\",",
                    "[\"sleep\",",
                    "\"1\"],",
                    "[/*",
                    "12",
                    "vars",
                    "*/])"
                ])
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
                time: NaiveTime::from_hms_micro(10, 53, 02, 442246),
                syscall: "execve",
                length: None,
                file: None,
                error: None,
                child_pid: None,
                execve: Some(vec![
                    "\"/bin/sleep\",",
                    "[\"sleep\",",
                    "\"1\"],",
                    "[/*",
                    "12",
                    "vars",
                    "*/])"
                ])
            })
        );
    }
}
