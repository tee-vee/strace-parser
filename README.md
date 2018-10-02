A small tool to summarize raw `strace` data

It prints a summary of the syscalls performed in each PID in the `strace`
session and a list of the top 10 PIDs in terms of running time.

Currently calls like nanosleep and futex are included in the running time,
which can throw off the results.

Example output:


PID 13960 - 33 syscalls, 0.981ms, 0.00%

  syscall                  count             total             max             avg             min      errors
                                              (ms)            (ms)            (ms)            (ms)
  ---------------       --------        ----------      ----------      ----------      ----------      --------
  rt_sigaction                13          0.281000        0.026000        0.021615        0.021000      EINVAL: 1
  execve                       1          0.232000        0.232000        0.232000        0.232000
  mprotect                     4          0.100000        0.029000        0.025000        0.021000
  close                        3          0.074000        0.032000        0.024667        0.021000
  access                       3          0.069000        0.025000        0.023000        0.022000      ENOENT: 3
  open                         2          0.048000        0.025000        0.024000        0.023000
  fstat                        2          0.043000        0.022000        0.021500        0.021000
  getpid                       1          0.033000        0.033000        0.033000        0.033000
  munmap                       1          0.031000        0.031000        0.031000        0.031000
  read                         1          0.025000        0.025000        0.025000        0.025000
  rt_sigprocmask               1          0.024000        0.024000        0.024000        0.024000
  arch_prctl                   1          0.021000        0.021000        0.021000        0.021000
  ---------------


Top 10 PIDs
-----------

  pid            time (ms)         % time           calls
  ----------    ----------      ---------       ---------
  2247           60946.102          3.03%             258
  1198           60791.715          3.02%            1952
  3766           60769.699          3.02%             255
  13501          60669.969          3.01%             254
  6443           60580.656          3.01%             265
  2196           60410.234          3.00%             279
  2193           60398.492          3.00%              49
  8884           60352.805          3.00%             266
  1588           60221.812          2.99%           17322
  3756           60182.141          2.99%           17560

Total PIDs: 130
System Time: 2012.987183s
Real Time: 60.60968s