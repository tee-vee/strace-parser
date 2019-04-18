#![cfg_attr(feature = "nightly", feature(split_ascii_whitespace))]

use self::pid_summary::PidSummary;
use self::sort_by::{SortBy, SortEventsBy};
use fxhash::FxBuildHasher;

pub mod file_data;
pub mod histogram;
pub mod io_data;
pub mod parser;
pub mod pid_summary;
pub mod session_summary;
pub mod sort_by;
pub mod syscall_data;
pub mod syscall_stats;
pub mod time;

pub type Pid = i32;
pub type HashMap<K, V> = rayon_hash::HashMap<K, V, FxBuildHasher>;
pub type HashSet<T> = rayon_hash::HashSet<T, FxBuildHasher>;

pub enum PidPrintAmt {
    All,
    Listed,
    Related,
}
