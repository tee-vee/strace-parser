**Binaries can be downloaded via [Releases](https://gitlab.com/gitlab-com/support/toolbox/strace-parser/-/releases), or [Repository -> Tags](https://gitlab.com/gitlab-com/support/toolbox/strace-parser/-/tags)**

A tool to analyze raw `strace` data.

Similar to output provided by the `-c` flag, but with more detail and capable of handling multiple PIDs.

It can generate the following metrics:
   * A summary of the top processes, including total syscalls and time spent
   * Statistics on each type of syscall made for a given number of proccesses
   * Details of a process, including the statistics, files opened, and related PIDS
   * A list of all programs executed in session
   * A list of all files opened in session
   * A list of the duration spent opening files in a directory and its children
   * A list of all read/write calls made in session
   * A histogram showing the quantized distribution of execution times for a given syscall
   * A `pstree` style graph of traced processes

The parser will attempt to find all sibling threads of traced processes. For a command executed with or after
the start of the trace this will always be accurate. On existing processes some threads may not be found.
The parser checks for `futex` calls with a `*_PRIVATE` flag that share an `uaddr`; if these do not occur the
parser cannot relate the processes.

**NOTE**: `strace` must be run with the at least the `-tt -T -f -o <FILE>` flags for
required data to be captured. Including `-yyy` will provide file details in the `io` subcommand.

**WARNING:** Because `strace` may slow down the target system by up to 10x,
it is not recommended for use in a production environment
except as a last resort. See [this article](http://www.brendangregg.com/blog/2014-05-11/strace-wow-much-syscall.html)
for more information on the performance impacts of `strace`.

<details>
<summary>
I recommend using the following default flags:

```sh
strace -fttTyyy -s 1024 -o <FILE>
```
</summary>

| strace flag        | man's description |
| ------ | --- |
| `-f`        | Trace  child  processes as they are created by currently traced processes as a result of the fork(2), vfork(2) and clone(2) system calls.       |
| `-t`        | Prefix each line of the trace with the wall clock time. If given twice (`-tt`), the time printed will include the microseconds.                 |
| `-T`        | Show the time spent in system calls.  This records the time difference between the beginning and the end of each system call.                   |
| `-y`        | Print paths associated with file descriptor arguments.                                                                                          |
| `-yy`       | Print protocol specific information associated with socket file descriptors.                                                                    |
| `-s`        | Specify  the  maximum string size to print (the default is 32).  Note that filenames are not considered strings and are always printed in full. |
| `-o <FILE>` | Write the trace output to the file filename rather than to stderr.                                                                              |

</details>

Aside from these default flags, you will also want to attach `strace` to a `PID` with the `-p` flag.\
The `PID` to `strace` for depends on what you want to trace. For reference, you can use the following values:

| trace | `PID` |
| ----- | ----- |
| Sidekiq | `$(pgrep -fd, sidekiq)` |

For example:

```sh
# Strace Sidekiq
sudo strace -fttTyyy -s 1024 -o /tmp/sidekiq_trace -p $(pgrep -fd, sidekiq)
```

## Building from Source

You'll need the Rust compiler 1.42 or above, which can be obtained at [https://rustup.rs/](https://rustup.rs/).

Build with `cargo build --release`, the binary will be located at `target/release/strace-parser`.

## Usage

`strace-parser <INPUT> <SUBCOMMAND> [FLAGS] [OPTIONS]`

**Args**:
   * `<INPUT>` - strace output file to analyze

**Subcommands**:

  * `exec` - List programs executed
  * `files` - List files opened
  * `directories` - List total duration of `open` and `openat` calls performed in a directory and its children
  * `help` - Print a brief help message
  * `io` - Show details of I/O syscalls: `read`, `recv`, `recvfrom`, `recvmsg`, `send`, `sendmsg`, `sendto`, and `write`
  * `list-pids` - List of PIDs and their syscall stats
  * `pid` - Details of PID(s) including syscalls stats, exec'd process, and slowest `open` calls
  * `quantize` - Prints a log₂ scale histogram of the quantized execution times in μsecs for a syscall
  * `summary` - Overview of PIDs in session
  * `tree` - pstree-style view of traced processes

Note that all subcommands can be arbritrarily abbreviated.

For example, `strace-parser trace.txt s` goes to summary, while `strace-parser trace.txt fi` goes to files.

---

### Subcommand Details

#### summary

By default results are sorted by time the process was active, can be changed with `-s, --sort`

`strace-parser <INPUT> summary [OPTIONS]`

**Options**:

   * `-c, --count <COUNT>` - The number of PIDs to print, defaults to 25
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to active time. Options:
       * `active_time`
       * `children`
       * `pid` 
       * `syscalls`
       * `total_time`
       * `user_time`

```
$ strace-parser trace.txt summary --count 2

Top 2 PIDs by Active Time
-----------

  pid    	 actv (ms)	 wait (ms)	total (ms)	% of actv	 syscalls	 children
  -------	----------	----------	----------	---------	---------	---------
  18741  	   374.363	 10112.698	 10487.062	   65.85%	     4098	        0
  17021  	    67.277	 11131.771	 11199.049	   11.83%	     1473	        0

PIDs   101
real   1m0.609s
user   0m36.305s
sys    12m17.512s
```
---

#### list-pids

Print a list of the syscall stats of the top PIDs.

`strace-parser <INPUT> list-pids [OPTIONS]`

**Options**:

   * `-c, --count <COUNT>` - The number of PIDs to print, defaults to 25
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to active time. Options:
       * `active_time`
       * `children`
       * `pid` 
       * `syscalls`
       * `total_time`
       * `user_time`

```
$ strace-parser trace.txt list-pids --count 2 --sort syscalls
Details of Top 2 PIDs by Syscall Count
-----------

PID 18741
4098 syscalls, active time: 374.363ms, total time: 10487.062ms

  syscall        	   count	total (ms)	  max (ms)	  avg (ms)	  min (ms)	errors
  ---------------	--------	----------	----------	----------	----------	--------
  select         	      42	  9893.016	  4806.976	   235.548	     0.012
  clock_gettime  	    2550	   208.378	     3.959	     0.082	     0.008
  futex          	      79	   206.069	   101.633	     2.608	     0.009	EAGAIN: 3   ETIMEDOUT: 5

PID 17021
1473 syscalls, active time: 67.277ms, total time: 11199.049ms

  syscall        	   count	total (ms)	  max (ms)	  avg (ms)	  min (ms)	errors
  ---------------	--------	----------	----------	----------	----------	--------
  select         	      42	 11115.210	  4814.914	   264.648	     0.013
  clock_gettime  	     860	    20.842	     2.273	     0.024	     0.009
  fcntl          	     121	    13.360	     7.037	     0.110	     0.011
```

---

#### pid

Details of PID(s) including syscalls stats, processes executed, sibling threads, exit code, and slowest `open` and `openat` calls.

`strace-parser <INPUT> pid [FLAGS] <PIDS>...`

**Args**:
   * `<PIDS>...` - PID(s) to analyze

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results
   * `-t, --threads` - Include sibling threads of <PIDS> in results

```
$ strace-parser trace.txt pid 16747
PID 28912

  349 syscalls, active time: 5.746ms, user time: 10.892ms, total time: 66.577ms
  start time: 21:16:56.521660    end time: 21:16:56.588237

  syscall                 count    total (ms)      max (ms)      avg (ms)      min (ms)    errors
  -----------------    --------    ----------    ----------    ----------    ----------    --------
  wait4                       2        49.738        49.713        24.869         0.025
  fcntl                     265         2.447         0.060         0.009         0.008    EBADF: 252
  execve                      1         1.196         1.196         1.196         1.196
  clone                       3         0.543         0.325         0.181         0.092
  ---------------

  Program Executed: /bin/sh -c "/opt/gitlab/bin/gitlab-psql -d template1 -c 'SELECT datname FROM pg_database' -A | grep -x gitlabhq_production"
  Time: 21:16:56.533040
  Exit code: 0

  Parent PID:  28898
  Threads:  28914
  Child PIDs:  28915, 28916

  Slowest file open times for PID 28912:

    dur (ms)       timestamp            error         file name
  ----------    ---------------    ---------------    ---------
       0.026    21:16:56.534623           -           /etc/ld.so.cache
       0.024    21:16:56.534879           -           /lib/x86_64-linux-gnu/libc.so.6
       0.018    21:16:56.524736           -           /proc/self/status
```

---

#### directories

List sums of durations of `open` and `openat` calls in directories and their child directories.

For example, the row for `/` will sum all calls made in `/var` and `/opt`, as well as all calls
performed in `/` itself.

`strace-parser <INPUT> directories [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to timestamp. Options:
      * `count`
      * `duration`
      * `pid`
      * `time`

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results
   * `-t, --threads` - Include sibling threads of <PIDS> in results

```
Directories accessed for files

      pid      dur (ms)      first time          last time          open ct    directory name
  -------    ----------    ---------------    ---------------    ----------    --------------
  1071655     72399.930    02:43:35.288223    02:47:18.785449       1682782    /
  1071655         0.075    02:43:35.288223    02:43:35.355015             3    /proc
  1071655         0.052    02:43:35.288223    02:43:35.355015             2    /proc/self
  1071655         0.149    02:43:35.302629    02:46:54.763037             9    /etc
  1071655         0.255    02:43:35.302831    02:46:54.763379            15    /lib64
```

---

#### exec

Print a list of all programs executed in session via `execve`

`strace-parser <INPUT> exec [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results
   * `-t, --threads` - Include sibling threads of <PIDS> in results

```
$ strace-parser trace.txt exec --pid 28912 --related
Programs Executed

  pid       exit    time                program
  ------    ----    ---------------     -------
  28898        1    21:16:52.375031     /opt/gitlab/embedded/bin/omnibus-ctl gitlab /opt/gitlab/embedded/service/omnibus-ctl* replicate-geo-database --host=primary.geo.example.com --slot-name=secondary_geo_example_com --backup-timeout=21600
  28912        0    21:16:56.533040     /bin/sh -c "/opt/gitlab/bin/gitlab-psql -d template1 -c 'SELECT datname FROM pg_database' -A | grep -x gitlabhq_production"
  28915        0    21:16:56.537770     /opt/gitlab/bin/gitlab-psql -d template1 -c "SELECT datname FROM pg_database" -A
  28915        0    21:16:56.558860     /opt/gitlab/embedded/bin/chpst -u gitlab-psql -U gitlab-psql /usr/bin/env PGSSLCOMPRESSION=0 /opt/gitlab/embedded/bin/psql -p 5432 -h /var/opt/gitlab/postgresql -d gitlabhq_production -d template1 -c "SELECT datname FROM pg_database" -A
  28915        0    21:16:56.564387     /usr/bin/env PGSSLCOMPRESSION=0 /opt/gitlab/embedded/bin/psql -p 5432 -h /var/opt/gitlab/postgresql -d gitlabhq_production -d template1 -c "SELECT datname FROM pg_database" -A
  28915        0    21:16:56.566690     /opt/gitlab/embedded/bin/psql -p 5432 -h /var/opt/gitlab/postgresql -d gitlabhq_production -d template1 -c "SELECT datname FROM pg_database" -A
  28916        0    21:16:56.538270     /bin/grep -x gitlabhq_production
```

Processes with non-0 exits or terminated by a signal may indicate an error.

---

#### files

Print a list of all files opened in session via `open` and `openat`

`strace-parser <INPUT> files [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to timestamp. Options:
      * `duration`
      * `pid`
      * `time`

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results
   * `-t, --threads` - Include sibling threads of <PIDS> in results

```
$ strace-parser trace.txt files --pid 2913
Files Opened

      pid	 open (ms)  	   timestamp   	        error     	   file name
  -------	------------	---------------	   ---------------	   ---------
     2913	       0.553	11:35:02.902746	          -       	   /dev/null
     2913	       0.355	11:35:11.658594	          -       	   /proc/stat
```

---

#### io

Print details of all `read`, `write`, `recv`, `recvfrom`, `recvmsg`, `send`, `sendto`, and `sendmsg` calls in session

`strace-parser <INPUT> io [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to timestamp. Options:
      * `duration`
      * `pid`
      * `time`

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results
   * `-t, --threads` - Include sibling threads of <PIDS> in results

```
I/O Performed

      pid      dur (ms)       timestamp       syscall        bytes         error          file name
  -------    ----------    ---------------    --------    --------    ---------------     ---------
    20212         0.076    11:26:27.294812    read               0            -           pipe:[2645699502]
    20212         0.080    11:26:27.295020    read               0            -           pipe:[2645699502]
    20212         0.108    11:26:27.295187    read               0            -           pipe:[2645699502]
    20212         0.170    11:26:27.392784    write             30            -           UNIX:[2645216608->2645215442]
```

---

#### quantize

Prints a log₂ scale histogram of the quantized execution times in μsecs for a given syscall.

`strace-parser <INPUT> quantize [FLAGS] [OPTIONS] <SYSCALL>`

**Args**:
   * `<SYSCALL>` - Syscall to analyze

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results
   * `-t, --threads` - Include sibling threads of <PIDS> in results

```
$ strace-parser trace.txt quantize write --pid 2993 28861 --related
  syscall: write
  pids: 28861 27191 2993 27758 27569 28136 27947 28514 27222 27411 and 17 more...

    μsecs       	     count	 distribution
    ------------	  --------	 ----------------------------------------
      16 -> 31  	        10	|                                        |
      32 -> 63  	       206	|▇                                       |
      64 -> 127 	       992	|▇▇▇▇▇▇▇                                 |
     128 -> 255 	      3668	|▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇            |
     256 -> 511 	      5171	|▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇|
     512 -> 1K  	       765	|▇▇▇▇▇                                   |
      1K -> 2K  	        95	|                                        |
      2K -> 4K  	        32	|                                        |
      4K -> 8K  	        14	|                                        |
      8K -> 16K 	         2	|                                        |
     16K -> 32K 	         0	|                                        |
     32K -> 64K 	         1	|                                        |
```

---

#### tree

Print a `pstree` style graph of PIDs and their children. Sibling threads are surrounded by curly brackets.

**Note:** For processes already running when the trace began, the parser will attempt to guess thread
relationships using the addresses of private `futex` calls. Spurious relationships may occur rarely when
separate processes happen to use the same address for a `futex`. This method is not used for any processes
forked/cloned during the trace. The relationships of these will always be accurate.

`strace-parser <INPUT> tree [FLAGS]`

**Flags**:
   * `-t, --truncate` - Truncate commands to 50 characters to prevent line wrapping

```
$ strace-parser trace.txt tree --truncate
28897 - exit: 1, cmd: /usr/bin/gitlab-ctl replicate-geo-database --host=...
  └─28898 - exit: 1, cmd: /opt/gitlab/embedded/bin/omnibus-ctl gitlab /opt/g...
     ├─{28899}
     ├─{28906}
     ├─{28913}
     ├─{28920}
     ├─{28927}
     ├─28905 - exit: 0, cmd: /usr/bin/locale -a
     │  └─{28907}
     ├─28912 - exit: 0, cmd: /bin/sh -c "/opt/gitlab/bin/gitlab-psql -d templat...
     │  ├─{28914}
     │  ├─28915 - exit: 0, cmd: /opt/gitlab/embedded/bin/psql -p 5432 -h /var/opt/...
     │  │  └─28917 - exit: 0, cmd: /usr/bin/id -n -u
     │  └─28916 - exit: 0, cmd: /bin/grep -x gitlabhq_production
     ├─28919 - exit: 0, cmd: /bin/sh -c "/opt/gitlab/bin/gitlab-psql -d gitlabh...
     │  ├─{28921}
     │  ├─28922 - exit: 0, cmd: /opt/gitlab/embedded/bin/psql -p 5432 -h /var/opt/...
     │  │  └─28924 - exit: 0, cmd: /usr/bin/id -n -u
     │  └─28923 - exit: 0, cmd: /bin/grep -x projects
     └─28926 - exit: 0, cmd: /bin/sh -c "/opt/gitlab/bin/gitlab-psql -d gitlabh...
        ├─{28928}
        └─28929 - exit: 0, cmd: /opt/gitlab/embedded/bin/psql -p 5432 -h /var/opt/...
           └─28930 - exit: 0, cmd: /usr/bin/id -n -u
```

---

## Interpreting Output

`strace` will significantly slow down syscalls execution, so do not consider the times listed
as accurate when comparing to how a program performs normally.

That said, it is very useful for understanding what calls are made and their _relative_ cost.  

### Example 1

```
$ strace-parser trace1.txt pid 97266

PID 97266
303 syscalls, active time: 112.503ms, total time: 112.503ms

  syscall                 count    total (ms)      max (ms)      avg (ms)      min (ms)    errors
  -----------------    --------    ----------    ----------    ----------    ----------    --------
  read                       30        43.257        37.403         1.442         0.011    ERESTARTSYS: 1
  close                      24        27.824        12.166         1.159         0.012
  open                       29        19.730         5.053         0.680         0.013    ENOENT: 7
  access                     21         6.892         0.988         0.328         0.013    ENOENT: 13
  lstat                       5         2.974         1.142         0.595         0.019    ENOENT: 4
  stat                       15         2.862         0.575         0.191         0.013    ENOENT: 3
  openat                      2         2.486         1.872         1.243         0.614
  getdents                    4         2.150         1.796         0.538         0.011
  rt_sigaction               59         1.111         0.121         0.019         0.010
  mmap                       33         0.838         0.066         0.025         0.012
  fstat                      29         0.670         0.116         0.023         0.011
  mprotect                   14         0.432         0.100         0.031         0.014
  munmap                      8         0.212         0.089         0.026         0.014
  write                       6         0.181         0.036         0.030         0.023
  execve                      1         0.175         0.175         0.175         0.175
  brk                         4         0.157         0.085         0.039         0.015
  rt_sigprocmask              3         0.130         0.084         0.043         0.018
  lseek                       2         0.089         0.074         0.045         0.015
  fcntl                       4         0.083         0.032         0.021         0.015
  set_robust_list             1         0.065         0.065         0.065         0.065
  dup2                        3         0.061         0.035         0.020         0.011
  getrlimit                   2         0.044         0.027         0.022         0.017
  arch_prctl                  1         0.026         0.026         0.026         0.026
  set_tid_address             1         0.022         0.022         0.022         0.022
  getcwd                      1         0.020         0.020         0.020         0.020
  setpgid                     1         0.012         0.012         0.012         0.012
  ---------------

  Program Executed: /opt/gitlab/embedded/bin/git
  Args: ["--git-dir" "/gitlab-data/git-data/repositories/group_name/project.git" "cat-file" "--batch"]

  Parent PID:  118534

  Slowest file open times for PID 97266:

    dur (ms)       timestamp            error         file name
  ----------    ---------------    ---------------    ---------
       5.053    08:42:44.933863           -           /gitlab-data/git-data/repositories/group_name/project.git/config
       3.115    08:42:44.925575           -           /gitlab-data/git-data/repositories/group_name/project.git/config
       2.653    08:42:44.898632           -           /gitlab-data/git-data/repositories/group_name/project.git/config
       2.239    08:42:44.916090           -           /gitlab-data/home/.gitconfig
       1.972    08:42:44.983603           -           /gitlab-data/git-data/repositories/group_name/project.git/packed-refs
       1.921    08:42:44.891691           -           /gitlab-data/git-data/repositories/group_name/project.git/HEAD
       1.872    08:42:44.981307           -           /gitlab-data/git-data/repositories/group_name/project.git/refs/
       1.831    08:42:44.930141           -           /gitlab-data/home/.gitconfig
       0.614    08:42:44.987032           -           /gitlab-data/git-data/repositories/group_name/project.git/objects/pack
       0.342    08:42:44.997547        ENOENT         /gitlab-data/git-data/repositories/group_name/project.git/objects/info/alternates
```

### Example 2

```
$ strace-parser trace2.txt pid 64205

PID 64205
243 syscalls, active time: 120.542ms, total time: 120.542ms

  syscall                 count    total (ms)      max (ms)      avg (ms)      min (ms)    errors
  -----------------    --------    ----------    ----------    ----------    ----------    --------
  rt_sigaction               59        21.174         0.908         0.359         0.110
  open                       23        13.623         1.464         0.592         0.200    ENOENT: 6
  mmap                       27        12.203         1.116         0.452         0.163
  read                       23        11.897         0.998         0.517         0.221
  fstat                      24        11.276         0.770         0.470         0.155
  close                      19        11.176         1.024         0.588         0.234
  access                     11         8.197         1.492         0.745         0.247    ENOENT: 3
  lstat                       5         6.525         2.624         1.305         0.627    ENOENT: 4
  mprotect                   14         4.998         0.798         0.357         0.208
  munmap                      8         3.646         0.820         0.456         0.212
  stat                        7         2.997         0.629         0.428         0.155    ENOENT: 3
  getdents                    4         2.870         0.865         0.717         0.538
  brk                         4         1.784         0.597         0.446         0.351
  openat                      2         1.735         0.918         0.867         0.817
  dup2                        3         1.451         0.652         0.484         0.196
  execve                      1         1.301         1.301         1.301         1.301
  rt_sigprocmask              3         1.223         0.488         0.408         0.266
  getcwd                      1         0.557         0.557         0.557         0.557
  set_robust_list             1         0.466         0.466         0.466         0.466
  set_tid_address             1         0.452         0.452         0.452         0.452
  getrlimit                   1         0.419         0.419         0.419         0.419
  setpgid                     1         0.382         0.382         0.382         0.382
  arch_prctl                  1         0.190         0.190         0.190         0.190
  exit_group                  1           n/a           n/a           n/a           n/a
  ---------------

  Program Executed: /opt/gitlab/embedded/bin/git
  Args: ["--git-dir" "/var/opt/gitlab-data/git-data/repositories/group_name/project.git" "for-each-ref" "--format=%(refname)" "refs/tags"]

  Parent PID:  30154

  Slowest file open times for PID 64205:

    dur (ms)       timestamp            error         file name
  ----------    ---------------    ---------------    ---------
       1.464    14:38:21.803101           -           /var/opt/gitlab-data/git-data/repositories/group_name/project.git/packed-refs
       1.237    14:38:21.749569           -           /var/opt/gitlab-data/git-data/repositories/group_name/project.git/config
       1.166    14:38:21.711738           -           /var/opt/gitlab-data/git-data/repositories/group_name/project.git/config
       0.979    14:38:21.736315           -           /var/opt/gitlab-data/home/.gitconfig
       0.938    14:38:21.702572           -           /var/opt/gitlab-data/git-data/repositories/group_name/project.git/HEAD
       0.918    14:38:21.788967           -           /var/opt/gitlab-data/git-data/repositories/group_name/project.git/refs/
       0.836    14:38:21.664860           -           /lib64/librt.so.1
       0.817    14:38:21.796232           -           /var/opt/gitlab-data/git-data/repositories/group_name/project.git/refs/tags/
       0.739    14:38:21.775371           -           /var/opt/gitlab-data/home/.gitconfig
       0.598    14:38:21.663682        ENOENT         /opt/gitlab/embedded/lib/librt.so.1
```

Here's a comparison of two git processes on different infrastructure.

  * Example 1 spends ~90 out of 112ms on I/O operations `read`, `open`, and `close`.
  * Example 2 is not bound by a specific type of action, but syscalls in general are slower.
    * 59 calls to `rt_sigaction` take 1ms for example 1, but 21ms for example 2.
    * 33 calls to `mmap` take < 1ms for example 1, but 27 calls to it take 12ms for example 2.
    * Most other syscalls are significantly slower, with the exceptions of calls that rely on the filesystem.

Based on this, we can guess that example 1 is bottlenecked by block I/O, while example 2 is bound by general system performance - perhaps high load.

## Known Issues

* PID reuse is not handled; separate processes with the same PID will be tracked as a single entity.
* Existing thread relationships are not removed when from a process when it executes `execve`.
