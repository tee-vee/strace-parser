use std::fmt;

#[derive(Clone, Copy)]
pub enum SortBy {
    ActiveTime,
    ChildPids,
    Pid,
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
            SortBy::SyscallCount => write!(f, "Syscall Count"),
            SortBy::TotalTime => write!(f, "Total Time"),
            SortBy::UserTime => write!(f, "User Time"),
        }
    }
}
