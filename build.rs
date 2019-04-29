use clap::Shell;
use std::env;

include!("src/cli.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };
    let mut app = cli_args();
    app.gen_completions("strace-parser", Shell::Bash, outdir);
}
