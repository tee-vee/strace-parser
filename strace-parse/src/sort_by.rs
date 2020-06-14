use std::error;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub enum SortBy {
    ActiveTime,
    ChildPids,
    Pid,
    StartTime,
    SyscallCount,
    TotalTime,
    UserTime,
}

impl fmt::Display for SortBy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SortBy::ActiveTime => write!(f, "Active Time"),
            SortBy::ChildPids => write!(f, "# of Child Processes"),
            SortBy::Pid => write!(f, "PID #"),
            SortBy::StartTime => write!(f, "Start Time"),
            SortBy::SyscallCount => write!(f, "Syscall Count"),
            SortBy::TotalTime => write!(f, "Total Time"),
            SortBy::UserTime => write!(f, "User Time"),
        }
    }
}

impl FromStr for SortBy {
    type Err = ParseSortError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active_time" => Ok(SortBy::ActiveTime),
            "children" => Ok(SortBy::ChildPids),
            "pid" => Ok(SortBy::Pid),
            "syscalls" => Ok(SortBy::SyscallCount),
            "total_time" => Ok(SortBy::TotalTime),
            "user_time" => Ok(SortBy::UserTime),
            _ => Err(ParseSortError),
        }
    }
}

#[derive(Clone, Copy)]
pub enum SortEventsBy {
    Duration,
    Pid,
    Time,
}

impl fmt::Display for SortEventsBy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SortEventsBy::Duration => write!(f, "Duration"),
            SortEventsBy::Pid => write!(f, "PID #"),
            SortEventsBy::Time => write!(f, "Time"),
        }
    }
}

impl FromStr for SortEventsBy {
    type Err = ParseSortError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "duration" => Ok(SortEventsBy::Duration),
            "pid" => Ok(SortEventsBy::Pid),
            "time" => Ok(SortEventsBy::Time),
            _ => Err(ParseSortError),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ParseSortError;

impl fmt::Display for ParseSortError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid 'sort' value")
    }
}

impl error::Error for ParseSortError {
    fn description(&self) -> &str {
        "Invalid 'sort' value"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}
