use chrono::{Duration, NaiveTime};

pub fn parse_elapsed_real_time(buffer: &str) -> Option<Duration> {
    let start_line = match buffer.lines().next() {
        Some(line) => line,
        None => return None,
    };
    let start_tokens: Vec<_> = start_line.split_whitespace().collect();

    let end_line = match buffer.lines().next_back() {
        Some(line) => line,
        None => return None,
    };
    let end_tokens: Vec<_> = end_line.split_whitespace().collect();

    match (start_tokens.get(1), end_tokens.get(1)) {
        (Some(start), Some(end)) => {
            let start_time = NaiveTime::parse_from_str(start, "%H:%M:%S%.6f");
            let end_time = NaiveTime::parse_from_str(end, "%H:%M:%S%.6f");
            match (start_time, end_time) {
                (Ok(start), Ok(end)) => Some(end - start),
                _ => None,
            }
        }
        _ => None,
    }
}
