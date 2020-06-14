use crate::syscall_data::RawExec;
use std::fmt;
use std::iter::Zip;
use std::slice::Iter;

#[derive(Clone, Debug)]
pub struct Execs {
    cmds: Vec<String>,
    times: Vec<String>,
}

impl Execs {
    pub fn new(mut raw_execs: Vec<RawExec>) -> Execs {
        let mut cmds = Vec::new();
        let mut times = Vec::new();

        if raw_execs.is_empty() {
            panic!("empty exec");
        }

        raw_execs.sort_by(|x, y| x.time.cmp(y.time));

        for raw_exec in raw_execs.iter() {
            let end_idx = raw_exec
                .exec
                .iter()
                .position(|&a| a.ends_with("],"))
                .map(|i| i + 1)
                .unwrap_or(raw_exec.exec.len());
            let mut arg_iter = raw_exec.exec.iter().take(end_idx);

            let mut cmd = arg_iter
                .next()
                .map(|c| Execs::trim_arg(c))
                .unwrap_or_default()
                .to_string();

            cmd.push(' ');

            cmd.push_str(
                arg_iter
                    .nth(1) // skip argv[0] as this is a repeat of cmd 99% of the time
                    .map(|a| Execs::trim_arg(a))
                    .unwrap_or_default(),
            );

            cmd.push(' ');

            let full_cmd = arg_iter
                .map(|a| Execs::trim_arg(a))
                .fold(cmd, |s, arg| s + arg + " ");

            cmds.push(full_cmd.trim().to_string());
            times.push(raw_exec.time.to_string());
        }

        Execs { cmds, times }
    }

    pub fn iter(&self) -> Zip<Iter<String>, Iter<String>> {
        self.cmds.iter().zip(&self.times)
    }

    pub fn last_cmd(&self) -> &str {
        self.cmds.last().map(|c| c.as_str()).unwrap_or_default()
    }

    pub fn replace_newlines(cmd: &str, ct: usize) -> String {
        let mut whitespace = String::from("\n");
        whitespace.push_str(&" ".repeat(ct));

        cmd.replace(r#"\n"#, &whitespace)
    }

    fn trim_arg(arg: &str) -> &str {
        let initial_trim = arg
            .trim_start_matches(|c| c == '[')
            .trim_end_matches(|c| c == ',' || c == ']');

        // Only trim quotes if arg is fully quoted and not a standalone quote
        // otherwise it's part of a quoted command, e.g. 'sh -c "ls -la"'
        if initial_trim.starts_with('"') && initial_trim.ends_with('"') && initial_trim != r#"""# {
            initial_trim.trim_start_matches('"').trim_end_matches('"')
        } else {
            initial_trim
        }
    }
}

impl fmt::Display for Execs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter().peekable();
        while let Some((cmd, time)) = iter.next() {
            writeln!(
                f,
                "  Program Executed: {}",
                Execs::replace_newlines(cmd, 23)
            )?;
            writeln!(f, "  Time: {}", time)?;

            if iter.peek().is_some() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_data::build_syscall_data;

    #[test]
    fn exec_captures_args() {
        let input = r##"28898 21:16:52.375031 execve("/opt/gitlab/embedded/bin/omnibus-ctl", ["/opt/gitlab/embedded/bin/omnibus-ctl", "gitlab", "/opt/gitlab/embedded/service/omnibus-ctl*", "replicate-geo-database", "--host=primary.geo.example.com", "--slot-name=secondary_geo_example_com", "--backup-timeout=21600"], [/* 21 vars */]) = 0 <0.000297>"##.to_string();
        let mut pid_data_map = build_syscall_data(&input);
        let execs = Execs::new(pid_data_map.remove(&28898).unwrap().execve.unwrap());

        let cmd = execs.cmds.first().unwrap();
        assert_eq!(cmd, "/opt/gitlab/embedded/bin/omnibus-ctl gitlab /opt/gitlab/embedded/service/omnibus-ctl* replicate-geo-database --host=primary.geo.example.com --slot-name=secondary_geo_example_com --backup-timeout=21600");
    }

    #[test]
    fn exec_captures_time() {
        let input = r##"28926 21:16:56.676485 execve("/bin/sh", ["sh", "-c", "/opt/gitlab/bin/gitlab-psql -d gitlabhq_production -c 'SELECT 1 FROM projects LIMIT 1' -q -t"], [/* 22 vars */] <unfinished ...>"##.to_string();
        let mut pid_data_map = build_syscall_data(&input);
        let execs = Execs::new(pid_data_map.remove(&28926).unwrap().execve.unwrap());

        let time = execs.times.first().unwrap();
        assert_eq!(time, "21:16:56.676485");
    }

    #[test]
    fn exec_does_not_capture_addr() {
        let input = r##"12668 15:57:56.205465 execve("/bin/sleep", ["sleep", "1"], 0x1ae3c08 /* 15 vars */) = 0 <0.000176>"##.to_string();
        let mut pid_data_map = build_syscall_data(&input);
        let execs = Execs::new(pid_data_map.remove(&12668).unwrap().execve.unwrap());

        let cmd = execs.cmds.first().unwrap();
        assert_eq!(false, cmd.contains("0xae3c08"));
    }

    #[test]
    fn exec_captures_multiple_execs() {
        let input = r##"21038 17:07:44.594592 execve("/opt/gitlab/embedded/bin/bundle", ["bundle", "exec", "bin/ruby-cd", "/var/opt/gitlab/git-data/repositories/root/strace-parser.git", "git-linguist", "--commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b", "stats"], [/* 11 vars */] <unfinished ...>
21038 17:07:45.929391 execve("/opt/gitlab/embedded/bin/git-linguist", ["git-linguist", "--commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b", "stats"], [/* 29 vars */]) = 0 <0.001497>
21038 17:07:45.932139 execve("/opt/gitlab/embedded/lib/ruby/gems/2.5.0/bin/ruby", ["ruby", "/opt/gitlab/embedded/bin/git-linguist", "--commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b", "stats"], [/* 29 vars */]) = -1 ENOENT (No such file or directory) <0.000017>
21038 17:07:45.932215 execve("/opt/gitlab/bin/ruby", ["ruby", "/opt/gitlab/embedded/bin/git-linguist", "--commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b", "stats"], [/* 29 vars */]) = -1 ENOENT (No such file or directory) <0.000019>
21038 17:07:45.932289 execve("/opt/gitlab/embedded/bin/ruby", ["ruby", "/opt/gitlab/embedded/bin/git-linguist", "--commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b", "stats"], [/* 29 vars */]) = 0 <0.000211>"##.to_string();
        let mut pid_data_map = build_syscall_data(&input);
        let execs = Execs::new(pid_data_map.remove(&21038).unwrap().execve.unwrap());

        let first_cmd = execs.cmds.first().unwrap();
        let second_cmd = execs.cmds.get(1).unwrap();
        let third_cmd = execs.cmds.get(2).unwrap();
        let fourth_cmd = execs.cmds.get(3).unwrap();
        let fifth_cmd = execs.cmds.get(4).unwrap();
        assert_eq!(first_cmd, "/opt/gitlab/embedded/bin/bundle exec bin/ruby-cd /var/opt/gitlab/git-data/repositories/root/strace-parser.git git-linguist --commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b stats");
        assert_eq!(second_cmd, "/opt/gitlab/embedded/bin/git-linguist --commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b stats");
        assert_eq!(third_cmd, "/opt/gitlab/embedded/lib/ruby/gems/2.5.0/bin/ruby /opt/gitlab/embedded/bin/git-linguist --commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b stats");
        assert_eq!(fourth_cmd, "/opt/gitlab/bin/ruby /opt/gitlab/embedded/bin/git-linguist --commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b stats");
        assert_eq!(fifth_cmd, "/opt/gitlab/embedded/bin/ruby /opt/gitlab/embedded/bin/git-linguist --commit=95fd813967c6c18863ac4b1acb2ade9ba2c1c93b stats");
    }

    #[test]
    fn exec_keeps_quoted_group() {
        let input = r##"4135 14:08:51.762724 execve("/bin/bash", ["/bin/bash", "-c", "ls -la /etc | grep profile"], 0x7ffc1bafc638 /* 25 vars */) = 0 <0.000302>"##;
        let mut pid_data_map = build_syscall_data(&input);
        let execs = Execs::new(pid_data_map.remove(&4135).unwrap().execve.unwrap());

        let cmd = execs.cmds.first().unwrap();
        assert_eq!(cmd, r##"/bin/bash -c "ls -la /etc | grep profile""##);
    }

    #[test]
    fn exec_does_not_strip_escaped_quotes() {
        let input = r##"28919 21:16:56.608477 execve("/bin/sh", ["sh", "-c", "/opt/gitlab/bin/gitlab-psql -d gitlabhq_production -c \"SELECT table_name\n                 FROM information_schema.tables\n                WHERE table_catalog = 'gitlabhq_production'\n                  AND table_schema='public'\" -A | grep -x projects"], [/* 22 vars */] <unfinished ...>"##;
        let mut pid_data_map = build_syscall_data(&input);
        let execs = Execs::new(pid_data_map.remove(&28919).unwrap().execve.unwrap());

        let cmd = execs.cmds.first().unwrap();
        assert_eq!(
            cmd,
            r##"/bin/sh -c "/opt/gitlab/bin/gitlab-psql -d gitlabhq_production -c \"SELECT table_name\n FROM information_schema.tables\n WHERE table_catalog = 'gitlabhq_production'\n AND table_schema='public'\" -A | grep -x projects""##
        );
    }
}
