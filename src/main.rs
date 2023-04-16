use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use ptrace_inject::{Injector, Process};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::WarnLevel>,

    /// Name of a process to attach to.
    #[arg(short, long, group = "target")]
    name: Option<String>,

    /// PID of a process to attach to.
    #[arg(short, long, group = "target")]
    pid: Option<u32>,

    /// Path to the library to inject.
    #[arg(requires = "target")]
    library: std::path::PathBuf,
}

impl Args {
    fn run(self) -> Result<()> {
        pretty_env_logger::formatted_builder()
            .filter_level(self.verbose.log_level_filter())
            .init();
        let process = if let Some(name) = self.name {
            Process::by_name(&name)?
                .ok_or_else(|| eyre!("could not find process with name {name:?}"))?
        } else if let Some(pid) = self.pid {
            Process::get(pid)?
        } else {
            panic!("no target specified, but clap should have caught this");
        };
        Injector::attach(process)?.inject(&self.library)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    Args::parse().run()
}
