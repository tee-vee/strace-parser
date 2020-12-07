use crate::file_data::{self, FileData};
use crate::syscall_data::PidData;
use crate::{HashMap, Pid};

use bstr::ByteSlice;
use petgraph::prelude::*;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryData<'a> {
    pub pid: Pid,
    pub start_time: &'a [u8],
    pub end_time: &'a [u8],
    pub duration: f32,
    pub ct: usize,
}

impl<'a> DirectoryData<'a> {
    fn new(pid: Pid, start_time: &'a [u8], end_time: &'a [u8], duration: f32) -> DirectoryData<'a> {
        DirectoryData {
            pid,
            start_time,
            end_time,
            duration,
            ct: 1,
        }
    }
}

impl<'a> fmt::Display for DirectoryData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{: >10.3}    {: ^15}    {: ^15}    {: >10}",
            self.duration,
            self.start_time.to_str_lossy(),
            self.end_time.to_str_lossy(),
            self.ct,
        )
    }
}

// A naive iterator over path ancestors
// Does not attempt to normalize paths
struct PathSplit<'a> {
    path: &'a [u8],
}

impl<'a> PathSplit<'a> {
    pub fn new(path: &'a [u8]) -> PathSplit<'a> {
        PathSplit { path }
    }
}

impl<'a> Iterator for PathSplit<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.path.is_empty() {
            return None;
        }

        if self.path == b"/" {
            self.path = &*b"";
            return Some(b"/");
        }

        match self.path.rfind_byte(b'/') {
            Some(idx) if idx == 0 => {
                self.path = &*b"";
                Some(b"/")
            }
            Some(idx) => match self.path.get(..idx) {
                Some(rem) => {
                    self.path = rem;
                    Some(self.path)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

pub fn directories_opened<'a>(
    pids: &[Pid],
    raw_data: &HashMap<Pid, PidData<'a>>,
) -> HashMap<Pid, BTreeMap<&'a [u8], DirectoryData<'a>>> {
    let open_events = file_data::files_opened(&pids, raw_data, file_data::SortFilesBy::Time);

    pids.par_iter()
        .map(|pid| {
            let mut directory_data = BTreeMap::new();

            // Walking the full path for each event can be very
            // costly for pids with many open events on long paths.
            // Each path element will trigger an update/insert on
            // the map, so OPEN_CT * PATH_LEN inserts.
            // To minimize this cost, path relationships are
            // cached in a graph, which we can walk once to calculate
            // final totals after all events are processed,
            // OPEN_CT + PATH_LEN inserts.
            let mut directory_graph = DiGraphMap::new();

            open_events.get(pid).map(|files| {
                for event in files {
                    process_event(event, &mut directory_data, &mut directory_graph);
                }
            });

            walk_dir_graph(directory_graph, &mut directory_data);

            (*pid, directory_data)
        })
        .collect()
}

fn process_event<'a>(
    event: &FileData<'a>,
    directory_data: &mut BTreeMap<&'a [u8], DirectoryData<'a>>,
    directory_graph: &mut DiGraphMap<&'a [u8], u32>,
) {
    let mut splitter = PathSplit::new(event.file);
    if let Some(parent) = splitter.next() {
        directory_data
            .entry(parent)
            .and_modify(|entry: &mut DirectoryData| {
                if event.time < entry.start_time {
                    entry.start_time = event.time;
                }

                if event.time > entry.end_time {
                    entry.end_time = event.time;
                }

                entry.duration += event.duration;
                entry.ct += 1;
            })
            .or_insert(DirectoryData::new(
                event.pid,
                event.time,
                event.time,
                event.duration,
            ));

        let mut prev_path = parent;
        for path in splitter {
            // Stop parsing path once we find an existing edge
            if directory_graph.contains_edge(prev_path, path) {
                break;
            }

            directory_graph.add_edge(prev_path, path, 1);
            prev_path = path;
        }
    }
}

// Only directories directly accessed in the trace will be added
// by the initial pass, i.e. opening '/var/log/messages' will
// create an entry for '/var/log', but not for '/var' or '/'.
// Using the graph, walk all paths and sum up events as we go.
fn walk_dir_graph<'a>(
    dir_graph_map: DiGraphMap<&'a [u8], u32>,
    dir_data: &mut BTreeMap<&'a [u8], DirectoryData<'a>>,
) {
    let mut dir_graph = dir_graph_map.into_graph::<u32>();

    // The graph is initially directed from the leaf nodes
    // to root, creating creates multiple base paths which
    // would require complicated deduplication to handle.
    // We reverse the graph so it starts at a root and
    // branches out, allowing us to sum all branches with
    // a depth-first post-order search
    dir_graph.reverse();

    for root_node in dir_graph.externals(Incoming) {
        let mut dfs = DfsPostOrder::new(&dir_graph, root_node);
        while let Some(node) = dfs.next(&dir_graph) {
            let mut parents = dir_graph.neighbors_directed(node, Incoming);
            while let Some(parent_node) = parents.next() {
                process_node(node, parent_node, &dir_graph, dir_data);
            }
        }
    }
}

fn process_node<'a>(
    node: NodeIndex,
    parent_node: NodeIndex,
    graph: &Graph<&'a [u8], u32, Directed, u32>,
    data: &mut BTreeMap<&'a [u8], DirectoryData<'a>>,
) {
    // Copy data so we only have one ref when modifying the map
    let node_data = match data.get(graph[node]) {
        Some(d) => d.clone(),
        None => return,
    };

    data.entry(graph[parent_node])
        .and_modify(|entry: &mut DirectoryData| {
            if node_data.start_time < entry.start_time {
                entry.start_time = node_data.start_time;
            }

            if node_data.end_time > entry.end_time {
                entry.end_time = node_data.end_time;
            }

            entry.duration += node_data.duration;
            entry.ct += node_data.ct;
        })
        .or_insert(node_data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_data::build_syscall_data;
    use approx::assert_ulps_eq;
    use bstr::B;

    #[test]
    fn dirs_captures_pid() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map);
        assert_eq!(vec![&1070690], dir_data.keys().collect::<Vec<_>>());
    }

    #[test]
    fn dirs_captures_path_ancestors() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map);
        assert_eq!(
            vec![&B("/"), &B("/etc")],
            dir_data[&1070690].keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn dirs_sums_counts() {
        let input = br##"1070691 02:39:58.440106 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/tls/libruby.so.2.7", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000019>
1070691 02:39:58.440209 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/haswell/x86_64/libruby.so.2.7", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000019>
1070691 02:39:58.440313 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/haswell/libruby.so.2.7", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000019>
1070691 02:39:58.440424 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/x86_64/libruby.so.2.7", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000021>
1070691 02:39:58.440544 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/libruby.so.2.7", O_RDONLY|O_CLOEXEC) = 3</opt/gitlab/embedded/lib/libruby.so.2.7.2> <0.000024>
1070691 02:39:58.441186 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/libz.so.1", O_RDONLY|O_CLOEXEC) = 3</opt/gitlab/embedded/lib/libz.so.1.2.11> <0.000024>
1070691 02:39:58.441668 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/libpthread.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000022>
1070691 02:39:58.441728 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000022>
1070691 02:39:58.442002 openat(AT_FDCWD, "/lib64/libpthread.so.0", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libpthread-2.28.so> <0.000026>
1070691 02:39:58.442542 openat(AT_FDCWD, "/opt/gitlab/embedded/lib/librt.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000023>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070691], &pid_data_map);
        assert_eq!(10, dir_data[&1070691][B("/")].ct);
        assert_eq!(1, dir_data[&1070691][B("/etc")].ct);
        assert_eq!(
            8,
            dir_data[&1070691][b"/opt/gitlab/embedded/lib".as_ref()].ct
        );
    }

    #[test]
    fn dirs_sums_durations() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>
1070690 02:39:58.429716 openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.429788 openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3</usr/share/locale/locale.alias> <0.000020>
1070690 02:39:58.430142 openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.430197 openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3</usr/lib/locale/en_US.utf8/LC_IDENTIFICATION> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map);
        assert_ulps_eq!(
            (0.00002 * 1000.0) * 5.0,
            dir_data[&1070690][B("/")].duration
        );
        assert_ulps_eq!(
            (0.00002 * 1000.0) * 4.0,
            dir_data[&1070690][B("/usr")].duration
        );
        assert_ulps_eq!(
            (0.00002 * 1000.0) * 3.0,
            dir_data[&1070690][B("/usr/lib")].duration
        );
    }

    #[test]
    fn dirs_captures_start_end_time() {
        let input = br##"1070690 02:39:58.426334 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000020>
1070690 02:39:58.429716 openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.429788 openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3</usr/share/locale/locale.alias> <0.000020>
1070690 02:39:58.430142 openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.000020>
1070690 02:39:58.430197 openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3</usr/lib/locale/en_US.utf8/LC_IDENTIFICATION> <0.000020>"##;
        let pid_data_map = build_syscall_data(input);
        let dir_data = directories_opened(&[1070690], &pid_data_map);
        assert_eq!(
            B("02:39:58.426334"),
            dir_data[&1070690][B("/")].start_time.as_bstr(),
            "Start time"
        );
        assert_eq!(
            B("02:39:58.430197"),
            dir_data[&1070690][B("/")].end_time.as_bstr(),
            "End time"
        );
    }

    #[test]
    fn dirs_path_split_handles_absolute_path() {
        let path = b"/usr/lib/locale/locale-archive".as_ref();
        assert_eq!(
            vec![B("/usr/lib/locale"), B("/usr/lib"), B("/usr"), B("/"),],
            PathSplit::new(path)
                .into_iter()
                .map(|p| p.as_bstr())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn dirs_path_split_handles_relative_path() {
        let path = b"target/release/strace-parser".as_ref();
        assert_eq!(
            vec![b"target/release".as_bstr(), b"target".as_bstr(),],
            PathSplit::new(path)
                .into_iter()
                .map(|p| p.as_bstr())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn dirs_path_split_handles_double_dot() {
        let path = b"../target/release/../debug/strace-parser.tar.gz".as_ref();
        assert_eq!(
            vec![
                B("../target/release/../debug"),
                B("../target/release/.."),
                B("../target/release"),
                B("../target"),
                B(".."),
            ],
            PathSplit::new(path)
                .into_iter()
                .map(|p| p.as_bstr())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn dirs_path_split_handles_dot_slash() {
        let path = b"./target/release/strace-parser".as_ref();
        assert_eq!(
            vec![B("./target/release"), B("./target"), B("."),],
            PathSplit::new(path)
                .into_iter()
                .map(|p| p.as_bstr())
                .collect::<Vec<_>>(),
        );
    }
}
