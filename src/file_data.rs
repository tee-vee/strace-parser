use crate::Pid;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;

lazy_static! {
    static ref FILE_RE: Regex = Regex::new(
        r##"(?x)
    ^(?P<pid>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})
    \s+(?:<\.{3}\s)?(?:openat|open)(?:\((?:[A-Z_]+,\s+)?"(?P<file>[^"]+)")?.+
    (?:\s+=\s+((:?-)?[\d?]+(?:<[^>]+>)?\s+(?:(?P<error_code>E[A-Z_]+).+)?)
    <(?P<length>\d+\.\d{6})>|<unfinished\s+\.{3}>)$
    "##
    )
    .unwrap();
}

#[derive(Clone, Debug, PartialEq)]
pub struct FileData {
    time: String,
    name: Option<String>,
    error: Option<String>,
    length: Option<f32>,
}

impl fmt::Display for FileData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match &self.name {
            Some(n) => n,
            None => "",
        };
        let length = match self.length {
            Some(l) => l,
            None => 0.0,
        };
        let error = match &self.error {
            Some(e) => e,
            None => "",
        };

        write!(
            f,
            "  {0: >10.3}\t{1: >15}\t   {2: >15}\t   {3: <30}",
            length, self.time, error, name
        )
    }
}

pub fn parse_open_lines(buffer: &str, pids: &[Pid]) -> HashMap<Pid, Vec<FileData>> {
    let pid_lines: HashMap<_, _> = pids
        .iter()
        .map(|pid| {
            let mut lines: Vec<_> = buffer
                .par_lines()
                .filter(|line| {
                    FILE_RE
                        .captures(line)
                        .map(|cap| cap.name("pid").unwrap().as_str())
                        .and_then(|pid_str| pid_str.parse::<Pid>().ok())
                        .filter(|p| p == pid)
                        .is_some()
                })
                .filter_map(|l| {
                    FILE_RE.captures(l).map(|caps| {
                        match (
                            caps.name("file"),
                            caps.name("error_code"),
                            caps.name("length"),
                        ) {
                            (Some(file), Some(error_code), Some(length)) => FileData {
                                time: caps.name("time").unwrap().as_str().to_string(),
                                name: Some(file.as_str().to_string()),
                                error: Some(error_code.as_str().to_string()),
                                length: Some(length.as_str().parse::<f32>().unwrap() * 1000.0),
                            },
                            (Some(file), None, Some(length)) => FileData {
                                time: caps.name("time").unwrap().as_str().to_string(),
                                name: Some(file.as_str().to_string()),
                                error: None,
                                length: Some(length.as_str().parse::<f32>().unwrap() * 1000.0),
                            },
                            (Some(file), None, None) => FileData {
                                time: caps.name("time").unwrap().as_str().to_string(),
                                name: Some(file.as_str().to_string()),
                                error: None,
                                length: None,
                            },
                            (None, Some(error_code), Some(length)) => FileData {
                                time: caps.name("time").unwrap().as_str().to_string(),
                                name: None,
                                error: Some(error_code.as_str().to_string()),
                                length: Some(length.as_str().parse::<f32>().unwrap() * 1000.0),
                            },
                            (None, None, Some(length)) => FileData {
                                time: caps.name("time").unwrap().as_str().to_string(),
                                name: None,
                                error: None,
                                length: Some(length.as_str().parse::<f32>().unwrap() * 1000.0),
                            },
                            _ => FileData {
                                time: caps.name("time").unwrap().as_str().to_string(),
                                name: None,
                                error: None,
                                length: None,
                            },
                        }
                    })
                })
                .collect();

            lines.par_sort_unstable_by(|x, y| (x.time).cmp(&y.time));

            let mut coalesced_lines = coalesce_multi_line_opens(&lines);
            coalesced_lines.par_sort_by(|x, y| {
                (y.length)
                    .partial_cmp(&x.length)
                    .expect("Invalid comparison wben sorting event_stats")
            });

            (*pid, coalesced_lines)
        })
        .collect();

    pid_lines
}

fn coalesce_multi_line_opens(file_data: &[FileData]) -> Vec<FileData> {
    let mut iter = file_data.iter().peekable();

    let mut complete_entries = Vec::new();

    while let Some(entry) = iter.next() {
        match (&entry.name, entry.length) {
            (Some(_), Some(_)) => complete_entries.push(entry.clone()),
            (Some(f), None) => {
                if let Some(next) = iter.peek() {
                    complete_entries.push(FileData {
                        time: entry.time.clone(),
                        name: Some(f.clone()),
                        length: next.length,
                        error: next.error.clone(),
                    });
                    iter.next();
                } else {
                    complete_entries.push(entry.clone());
                }
            }
            _ => {}
        }
    }

    complete_entries
}
