use crate::syscall_data::RawExec;
use std::fmt;
use std::iter::Zip;
use std::slice::Iter;

#[derive(Clone, Debug)]
pub struct Exec {
    cmds: Vec<String>,
    args: Vec<String>,
}

impl Exec {
    pub fn new(mut raw_execs: Vec<RawExec>) -> Exec {
        let mut cmds = Vec::new();
        let mut args = Vec::new();

        raw_execs.sort_by(|x, y| x.time.cmp(y.time));

        for raw_exec in raw_execs.iter() {
            let mut arg_iter = raw_exec.exec.iter().peekable();

            let cmd = arg_iter
                .next()
                .and_then(|c| c.get(1..c.len() - 2))
                .unwrap_or_default()
                .to_string();

            let mut arg = arg_iter
                .skip(1)
                .map(|a| a.trim_end_matches(','))
                .fold(String::new(), |s, arg| s + arg + " ");

            if arg.len() > 1 && raw_exec.exec.iter().any(|s| s.ends_with("],")) {
                arg.insert(0, '[');
                arg.truncate(arg.rfind("]").unwrap_or_default() + 1);
            }

            cmds.push(cmd);
            args.push(arg);
        }

        Exec { cmds, args }
    }

    pub fn iter(&self) -> Zip<Iter<String>, Iter<String>> {
        self.cmds.iter().zip(&self.args)
    }
}

impl fmt::Display for Exec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter().peekable();
        while let Some((cmd, arg)) = iter.next() {
            writeln!(f, "  Program Executed: {}", cmd)?;
            writeln!(f, "  Args: {}", arg)?;

            if iter.peek().is_some() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
