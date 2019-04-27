**Binaries can be downloaded via [Releases](https://gitlab.com/gitlab-com/support/toolbox/strace-parser/releases), or [Repository -> Tags](https://gitlab.com/gitlab-com/support/toolbox/strace-parser/tags)**

A small tool to analyze raw `strace` data.

Similar to output provided by the `-c` flag, but with more details and capable of handling multiple PIDs.

It can generate the following metrics:
   * A summary of the top processes, including total syscalls and time spent
   * Statistics on each type of syscall made for a given number of proccesses
   * Details of a process, including the statistics, files opened, and related PIDS
   * A list of all programs executed in session
   * A list of all file opened in session
   * A list of all read/write calls made in session
   * A histogram showing the quantized distribution of execution times for a given syscall

**NOTE**: `strace` must be run with the `-tt -T -f` flags for the required data
to be captured. Including `-yyy` will provide file details in the `io` subcommand.

### Building

You'll need the Rust compiler, which can be obtained at [https://rustup.rs/](https://rustup.rs/).

On the stable compiler build with `cargo build --release`.  On nightly you can use `cargo build --release --features nightly` for a ~10% performance boost.

### Usage

`strace-parser <INPUT> <SUBCOMMAND> [FLAGS] [OPTIONS]`

**Args**:
   * `<INPUT>` - strace output file to analyze

Subcommands:

  * exec - List programs executed
  * files - List files opened
  * help - Print a brief help message
  * quantize - Prints a log₂ scale histogram of the quantized execution times in μsecs for a syscall
  * io - Show details of I/O syscalls: read, recv, recvfrom, recvmsg, send, sendmsg, sendto, and write
  * list_pids - List of PIDs and their syscall stats
  * pid - Details of PID(s) including syscalls stats, exec'd process, and slowest 'open' calls
  * summary - Overview of PIDs in session

Note that all subcommands can be arbritrarily abbreviated.

For example, `strace-parser trace.txt s` goes to summary, while `strace-parser trace.txt fi` goes to files.

---

#### Subcommand Details

##### summary

By default results are sorted by time the process was active, can be changed with `-s, --sort`

`strace-parser <INPUT> summary [OPTIONS]`

**Options**:

   * `-c, --count <COUNT>` - The number of PIDs to print, defaults to 25
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to active time. Options:
       * active_time
       * children
       * pid 
       * syscalls
       * total_time
       * user_time

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

##### pid

Details of PID(s) including syscalls stats, processes executed, and slowest `open` and `openat` calls

`strace-parser <INPUT> pid [FLAGS] <PIDS>...`

**Args**:
   * `<PIDS>...` - PID(s) to analyze

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results

```
$ strace-parser trace.txt pid 16747
PID 16747
408 syscalls, active time: 12.278ms, total time: 11375.831ms

                 	        	     total	       max	       avg	       min
  syscall        	   count	      (ms)	      (ms)	      (ms)	      (ms)	errors
  ---------------	--------	----------	----------	----------	----------	--------
  wait4          	      24	 11363.553	  1008.295	   473.481	     0.006	ECHILD: 12
  rt_sigprocmask 	      96	     6.760	     1.932	     0.070	     0.007
  ---------------

  Child PIDs:  23493, 23498, 23530, 23538, 23539

  Slowest file open times for PID 16747:

   open (ms)	      timestamp	        error     	   file name
  ----------	---------------	   ---------------	   ---------
       0.041	11:29:54.146422	          -       	   /dev/null
       0.030	11:29:49.112721	          -       	   /dev/null
```

---

##### list_pids

Print a list of the syscall stats of the top PIDs.

`strace-parser <INPUT> summary [OPTIONS]`

**Options**:

   * `-c, --count <COUNT>` - The number of PIDs to print, defaults to 25
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to active time. Options:
       * active_time
       * children
       * pid 
       * syscalls
       * total_time
       * user_time

```
$ strace-parser trace.txt list_pids --count 2 --sort syscalls
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

##### exec

Print a list of all programs executed in session via `execve`

`strace-parser <INPUT> exec [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results

```
$ strace-parser trace.txt exec --pid 27183 27184 --related

Programs Executed

      pid	           program            	args
  -------	          ---------            	--------
    27183	 /opt/gitlab/embedded/bin/git 	["--git-dir", "/var/opt/gitlab/git-data/repositories/root/project0.git", "cat-file", "--batch"], [/* 4 vars */]
    27184	 /opt/gitlab/embedded/bin/git 	["--git-dir", "/var/opt/gitlab/git-data/repositories/root/project1.git", "cat-file", "--batch"], [/* 4 vars */]
```

---

##### files

Print a list of all files opened in session via `open` and `openat`

`strace-parser <INPUT> files [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to timestamp. Options:
      * duration
      * pid
      * time

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results

```
$ strace-parser trace.txt files --pid 2913
Files Opened

      pid	 open (ms)  	   timestamp   	        error     	   file name
  -------	------------	---------------	   ---------------	   ---------
     2913	       0.553	11:35:02.902746	          -       	   /dev/null
     2913	       0.355	11:35:11.658594	          -       	   /proc/stat
```

---

##### io

Print details of all `read`, `write`, `recv`, `recvfrom`, `recvmsg`, `send`, `sendto`, and `sendmsg` calls in session

`strace-parser <INPUT> io [FLAGS] [OPTIONS]`

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs
   * `-s, --sort <SORT_BY>` - Field to sort results by, defaults to timestamp. Options:
      * duration
      * pid
      * time

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results

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

##### quantize

Prints a log₂ scale histogram of the quantized execution times in μsecs for a given syscall.

`strace-parser quantize [FLAGS] [OPTIONS] <SYSCALL>`

**Args**:
   * `<SYSCALL>` - Syscall to analyze

**Options**:
   * `-p, --pid <PIDS>...` - Limit results to one or more PIDs

**Flags**:
   * `-r, --related` - Include parent and child PIDs of <PIDS> in results

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


### Interpreting Output

`strace` will significantly slow down syscalls execution, so do not consider the times listed as accurate when comparing to how a program performs normally.

That said, it is very useful for understanding what calls are made and their _relative_ cost.  

#### Example 1

```
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

#### Example 2

```
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

Based on this, we can say that example 1 is bottlenecked by block I/O, while example 2 is bound by general system performance - perhaps high load.
