A small tool to analyze raw `strace` data.

It prints the following metrics:
   * A summary of the top processes, including total syscalls and time spent
   * A histogram showing the distribution of execution times for a given syscall
   * Statistics on each type of syscall made for a given number of proccesses
   * Details of a process, including the statistics above as well as slow
        file accesses and a list of child processes


**NOTE**: `strace` must be run with `-tt -T -f` flags for the required data
to be captured

Calls like nanosleep and futex can dominate the results, so they are broken 
out into the `wait` metric, and results are sorted by `active_time` by default.

**Example Summary**:

```
Top 10 PIDs
-----------

  pid       	active (ms)	 wait (ms)	total (ms)	 % active	 syscalls
  ----------	----------	---------	---------	---------	---------
  8795      	   689.073	 45773.832	 46462.906	   16.89%	    23018
  13408     	   679.432	 55910.887	 56590.320	   16.65%	    28593
  6423      	   554.822	 13175.485	 13730.308	   13.60%	    13735
  1814      	   473.893	 46394.922	 46868.816	   11.61%	    17162
  13620     	   400.984	 58957.699	 59358.684	    9.83%	    18600
  3756      	   386.442	 58050.078	 58436.520	    9.47%	    17518
  1588      	   382.861	 59836.238	 60219.098	    9.38%	    17314
  1570      	   182.843	  7667.887	  7850.729	    4.48%	     4880
  1567      	   177.168	 17091.062	 17268.230	    4.34%	     6328
  1198      	    58.053	 60733.664	 60791.719	    1.42%	     1952

Total PIDs: 101
System Time: 1843.512939s
Real Time: 60.60968s
```

**Example Histogram**:
```
  syscall: read
  pids: 8115 815 8128 8436 7438 7962 7490 8431 8286 8175 and 240 more...

    μsecs                  	     count	 distribution
    ------------------------	  --------	 ----------------------------------------
             0 -> 1         	         0	|                                        |
             2 -> 3         	         0	|                                        |
             4 -> 7         	        22	|                                        |
             8 -> 15        	      1285	|****************************************|
            16 -> 31        	      1150	|***********************************     |
            32 -> 63        	       319	|*********                               |
            64 -> 127       	        99	|***                                     |
           128 -> 255       	        58	|*                                       |
           256 -> 511       	        19	|                                        |
           512 -> 1023      	         4	|                                        |
          1024 -> 2047      	         5	|                                        |
          2048 -> 4095      	         3	|                                        |
```

**Example Statistics**:
```
Details of Top 2 PIDs by PID #
-----------

PID 1198
1952 syscalls, active time: 58.053ms, total time: 60791.719ms

  syscall        	   count	     total	       max	       avg	       min	errors
                 	        	      (ms)	      (ms)	      (ms)	      (ms)
  ---------------	--------	----------	----------	----------	----------	--------
  wait4          	     122	 60733.664	  1003.934	   497.817	     0.019	ECHILD: 61
  rt_sigprocmask 	     488	    14.359	     1.135	     0.029	     0.017
  fcntl          	     549	    13.189	     0.063	     0.024	     0.016
  clone          	      61	    11.288	     0.245	     0.185	     0.152
  dup2           	     244	     5.966	     0.040	     0.024	     0.017
  close          	     183	     4.365	     0.059	     0.024	     0.017
  rt_sigaction   	     122	     3.548	     0.405	     0.029	     0.020
  open           	      61	     2.245	     0.048	     0.037	     0.022
  kill           	      61	     1.587	     0.046	     0.026	     0.019
  rt_sigreturn   	      61	     1.506	     0.035	     0.025	     0.019
  ---------------

Child PIDs:  13656, 13665, 13666, 13667, 13676, 13678, 13681, 13690, 13691, 13696
And 51 more...


Files opened:
/dev/null


PID 1567
6328 syscalls, active time: 177.168ms, total time: 17268.230ms

  syscall        	   count	     total	       max	       avg	       min	errors
                 	        	      (ms)	      (ms)	      (ms)	      (ms)
  ---------------	--------	----------	----------	----------	----------	--------
  epoll_wait     	     814	 17091.062	    21.319	    20.996	     1.877
  clock_gettime  	    4899	   141.783	     1.548	     0.029	     0.011
  read           	     201	    16.749	     1.888	     0.083	     0.020	EAGAIN: 44
  getpid         	     166	     5.579	     0.235	     0.034	     0.018
  accept4        	      58	     3.882	     0.887	     0.067	     0.021	EAGAIN: 55
  getppid        	      55	     3.696	     1.933	     0.067	     0.017
  write          	      81	     3.615	     0.265	     0.045	     0.021
  recvfrom       	      33	     1.096	     0.097	     0.033	     0.021	EAGAIN: 12
  sendto         	       9	     0.367	     0.053	     0.041	     0.025
  close          	       5	     0.173	     0.040	     0.035	     0.029
  shutdown       	       4	     0.127	     0.037	     0.032	     0.027
  stat           	       1	     0.041	     0.041	     0.041	     0.041
  open           	       1	     0.033	     0.033	     0.033	     0.033
  ioctl          	       1	     0.027	     0.027	     0.027	     0.027	ENOTTY: 1
  ---------------

Files opened:
/proc/1567/smaps
```

**Example Details**:
```
PID 6423
13735 syscalls, active time: 554.822ms, total time: 13730.308ms

  syscall        	   count	     total	       max	       avg	       min	errors
                 	        	      (ms)	      (ms)	      (ms)	      (ms)
  ---------------	--------	----------	----------	----------	----------	--------
  epoll_wait     	     628	 13175.485	    21.259	    20.980	     0.020
  clock_gettime  	    7326	   199.500	     0.249	     0.027	     0.013
  stat           	    2101	   110.768	    19.056	     0.053	     0.017	ENOENT: 2076
  open           	      13	    60.174	    29.818	     4.629	     0.022
  getpid         	    1261	    37.016	     0.146	     0.029	     0.015
  fstat          	      16	    30.086	    10.279	     1.880	     0.018
  recvfrom       	     843	    26.753	     0.696	     0.032	     0.016	EAGAIN: 282
  read           	     451	    25.240	     2.417	     0.056	     0.018	EAGAIN: 127
  ftruncate      	       4	    19.214	     5.330	     4.804	     4.249
  write          	     266	    17.872	     3.472	     0.067	     0.021
  lstat          	     480	    12.355	     0.061	     0.026	     0.016	ENOENT: 473
  sendto         	     163	     7.095	     0.155	     0.044	     0.023
  close          	      33	     3.881	     1.115	     0.118	     0.020
  accept4        	      60	     2.100	     0.150	     0.035	     0.019	EAGAIN: 39
  getppid        	      39	     1.187	     0.075	     0.030	     0.017
  shutdown       	      20	     0.730	     0.056	     0.036	     0.022
  ioctl          	      13	     0.343	     0.031	     0.026	     0.022	ENOTTY: 13
  lseek          	      12	     0.305	     0.035	     0.025	     0.018
  sendmsg        	       1	     0.054	     0.054	     0.054	     0.054
  access         	       1	     0.036	     0.036	     0.036	     0.036
  geteuid        	       1	     0.029	     0.029	     0.029	     0.029
  getgid         	       1	     0.028	     0.028	     0.028	     0.028
  getegid        	       1	     0.028	     0.028	     0.028	     0.028
  getuid         	       1	     0.028	     0.028	     0.028	     0.028
  ---------------

  Parent PID: 495
  Child PIDs:  8383, 8418, 8419, 8420, 8421

  Slowest file access times for PID 6423:

     open (ms)	      timestamp	             error	   file name
  -----------	---------------	   ---------------	   ----------
      29.818	10:53:11.528954	                  	   /srv/gitlab-data/builds/2018_08/2123/421324.log
      12.309	10:53:46.708274	                  	   /srv/gitlab-data/builds/2018_08/3141/312521.log
       9.195	10:53:04.177982	                  	   /srv/gitlab-data/builds/2018_08/6863/512234.log
       8.560	10:53:40.664100	                  	   /srv/gitlab-data/builds/2018_08/1468/213984.log
       0.040	10:53:48.997537	                  	   /opt/gitlab/embedded/service/gitlab-rails/app/views/events/_events.html.haml
       0.039	10:53:49.037270	                  	   /opt/gitlab/embedded/lib/ruby/gems/2.4.0/gems/activesupport-4.2.10/lib/active_support/values/unicode_tables.dat
       0.039	10:53:49.222110	                  	   /opt/gitlab/embedded/service/gitlab-rails/app/views/events/event/_note.html.haml
       0.035	10:53:49.125115	                  	   /opt/gitlab/embedded/service/gitlab-rails/app/views/events/event/_push.html.haml
       0.033	10:53:49.153698	                  	   /opt/gitlab/embedded/service/gitlab-rails/app/views/events/_commit.html.haml
       0.030	10:53:49.009344	                  	   /opt/gitlab/embedded/service/gitlab-rails/app/views/events/_event.html.haml
```