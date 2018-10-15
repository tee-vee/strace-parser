use chrono::NaiveTime;
use regex::Regex;

lazy_static! {
    static ref TIME_RE: Regex = Regex::new(r"^\d+\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})").unwrap();
}

pub fn parse_elapsed_real_time(buffer: &str) -> Option<chrono::Duration> {
    let start_line = buffer.lines().next().unwrap();
    let start_time_cap = TIME_RE
        .captures(start_line)
        .and_then(|cap| cap.name("time"));

    let end_line = buffer.lines().next_back().unwrap();
    let end_time_cap = TIME_RE.captures(end_line).and_then(|cap| cap.name("time"));

    match (start_time_cap, end_time_cap) {
        (Some(start), Some(end)) => {
            let start_time = NaiveTime::parse_from_str(start.as_str(), "%H:%M:%S%.6f");
            let end_time = NaiveTime::parse_from_str(end.as_str(), "%H:%M:%S%.6f");
            match (start_time, end_time) {
                (Ok(start), Ok(end)) => Some(end - start),
                _ => None,
            }
        }
        _ => None,
    }
}
