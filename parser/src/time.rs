use bstr::ByteSlice;
use chrono::{Duration, NaiveDateTime, NaiveTime};

pub fn parse_elapsed_real_time(buffer: &[u8]) -> Option<Duration> {
    let start_token = buffer
        .lines()
        .next()
        .and_then(|line| line.fields().skip(1).next());

    let end_token = {
        // Skip the first newline which is the last character in the file
        if let Some(last_line_idx) = buffer.rfind_iter("\n").skip(1).next() {
            let last_line = &buffer[last_line_idx..];
            last_line.fields().skip(1).next()
        } else {
            None
        }
    };

    match (start_token, end_token) {
        (Some(start), Some(end)) => {
            let start_time;
            if let Ok(t) = NaiveTime::parse_from_str(start.to_str_lossy().as_ref(), "%H:%M:%S%.6f")
            {
                start_time = Some(t);
            } else if let Some(t) = parse_unix_timestamp(start) {
                start_time = Some(t.time());
            } else {
                start_time = None;
            }

            let end_time;
            if let Ok(t) = NaiveTime::parse_from_str(end.to_str_lossy().as_ref(), "%H:%M:%S%.6f") {
                end_time = Some(t);
            } else if let Some(t) = parse_unix_timestamp(end) {
                end_time = Some(t.time());
            } else {
                end_time = None;
            }
            match (start_time, end_time) {
                (Some(starting), Some(ending)) => Some(ending - starting),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn parse_unix_timestamp(time_bytes: &[u8]) -> Option<NaiveDateTime> {
    let time = time_bytes.to_str_lossy().to_string();
    let mut split_iter = time.split('.');

    let secs = match split_iter.next().and_then(|s| s.parse::<i64>().ok()) {
        Some(s) => s,
        None => return None,
    };
    let nanosecs = match split_iter.next().and_then(|n| n.parse::<u32>().ok()) {
        Some(n) => n * 1000, // strace provides usecs, convert to nsecs
        None => return None,
    };

    NaiveDateTime::from_timestamp_opt(secs, nanosecs)
}
