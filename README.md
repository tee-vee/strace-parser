**Binaries can be downloaded via [Repository -> Tags](https://gitlab.com/wchandler/strace-parser/tags)**

A small tool to analyze raw `strace` data.

It can generate the following metrics:
   * A summary of the top processes, including total syscalls and time spent
   * Statistics on each type of syscall made for a given number of proccesses
   * Details of a process, including the statistics, files opened, and related PIDS
   * A list of all programs executed in session
   * A list of all file opened in session
   * A list of all read/write calls made in session
   * A histogram showing the distribution of execution times for a given syscall

**NOTE**: `strace` must be run with the `-tt -T -f` flags for the required data
to be captured

### Commands

Usage: `strace-parser [FLAGS] [OPTIONS] <INPUT>`

When no flags/options are passed a base summary of the session is displayed

By default results are sorted by time the process was active, can be changed with `-s, --sort`

Output limited to the top 25 processes by default, can be changed with `-c, --count`

```
Top 2 PIDs by Active Time
-----------

  pid    	 actv (ms)	 wait (ms)	total (ms)	% of actv	 syscalls	 children
  -------	----------	----------	----------	---------	---------	---------
  18741  	   374.363	 10112.698	 10487.062	   65.85%	     4098	        0
  17021  	    67.277	 11131.771	 11199.049	   11.83%	     1473	        0

Total PIDs: 101
System Time: 1843.512939s
Real Time: 60.60968s
```

---

`-d, --details`

Print the details of the syscalls made by top processes

Sorted by active time by default, can be changed with `-s, --sort`

```
Details of Top 2 PIDs by Active Time
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

`-e, --exec`

Print a list of all programs executed in session via `execve`

```
Programs Executed

      pid	           program            	args
  -------	          ---------            	--------
    27183	 /opt/gitlab/embedded/bin/git 	["--git-dir", "/var/opt/gitlab/git-data/repositories/root/project0.git", "cat-file", "--batch"], [/* 4 vars */]
    27184	 /opt/gitlab/embedded/bin/git 	["--git-dir", "/var/opt/gitlab/git-data/repositories/root/project1.git", "cat-file", "--batch"], [/* 4 vars */]
```

---

`-f, --files`

Print a list of all files opened in session via `open` and `openat`

```
Files Opened

      pid	 open (ms)  	   timestamp   	        error     	   file name
  -------	------------	---------------	   ---------------	   ---------
     2913	       0.553	11:35:02.902746	          -       	   /dev/null
     2913	       0.355	11:35:11.658594	          -       	   /proc/stat
```

---

`-i, --io`

Print a list of all `read`, `write`, `recv`, `recvfrom`, `recvmsg`, `send`, `sendto`, and `sendmsg` calls in session

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

`-c, --count`

Number of processes to print on the base summary and in `-d/--details`

---

`-h, --histogram <SYSCALL>`

Print a chart of execution times for `<SYSCALL>`

```
  syscall: write
  pids: 28861 27191 2993 27758 27569 28136 27947 28514 27222 27411 and 1373 more...

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

`-p, --pid <PIDS>`

Limit output to the PIDs specified. Can be combined with `-r, --related` to pull in parent and child processes.

```
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

`-s, --sort <SORT_BY>`

Which field to sort base summary and `-d/--details` by

**Option for <SORT_BY>:**
```rb
   active_time   # Time spent by PID on active tasks
   children   # The number of child PIDs created by PID
   pid   # PID number
   syscalls   # The number of syscalls made by the PID
   total_time   # All time the PID was alive, includes waiting tasks
```