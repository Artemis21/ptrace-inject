//! A library for injecting shared libraries into running processes via ptrace.
//!
//! # Platform support
//!
//! This library currently only supports x64 \*nix systems, mainly because that's
//! what I have. Support for other architectures should be possible - the only
//! barrier being that I cannot test it. In theory though, it would just be
//! a matter of re-writing the shellcode for each architecture and selecting the
//! correct one with conditional compilation.
//!
//! For Windows, use other projects like [`dll-syringe`][1].
//!
//! # Example
//!
//! ```no_run
//! use std::{process::Command, path::PathBuf};
//! use ptrace_inject::{Injector, Process};
//!
//! # fn main() -> eyre::Result<()> {
//! let library = PathBuf::from("path/to/library.so");
//!
//! // Spawn a new process and inject the library into it.
//! let target = Command::new("target-process");
//! Injector::spawn(target)?.inject(&library)?;
//!
//! // Or attach to an existing process.
//! let proc = Process::by_name("target-process")?.expect("to find target process");
//! Injector::attach(proc)?.inject(&library)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Ptrace note
//!
//! This library was inspired by [`linux-inject`][2]. As noted by that project:
//!
//! > On many Linux distributions, the kernel is configured by default to
//! > prevent any process from calling ptrace() on another process that it did
//! > not create (e.g. via `fork()`). This is a security feature meant to prevent
//! > exactly the kind of mischief that this tool causes. You can temporarily
//! > disable it until the next reboot using the following command:
//! > ```text
//! > echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
//! > ```
//!
//! This library uses [`log`][3] for logging.
//!
//!  [1]: https://crates.io/crates/dll-syringe
//!  [2]: https://github.com/gaffe23/linux-inject
//!  [3]: https://crates.io/crates/log
#![warn(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]
#![allow(
    // Errors can happen for such a diverse set of reasons out of the user's
    // control that listing them all in a form other than the variants of `Error`
    // would not be feasible or useful.
    clippy::missing_errors_doc,
    // Register names like `rsi` and `rdi` break this.
    clippy::similar_names,
)]
use eyre::{eyre, Context, Result};
use injection::Injection;
pub(crate) use libc_addresses::LibcAddrs;
pub use process::Process;

mod injection;
mod libc_addresses;
mod process;
/*
/// Any error this library might encounter.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("couldn't read the procfs filesystem (`/proc`)")]
    ProcFs(#[from] procfs::ProcError),
    #[error("interacting with the traced process via ptrace failed")]
    Ptrace(#[from] pete::Error),
    #[error("failed to get information about the locally loaded libc via `dlopen` and related functions")]
    LocalDlopen(#[from] libloading::Error),
    #[error("couldn't get absolute path from given library path")]
    InvalidLibraryPath(#[source] std::io::Error),
    #[error("no executable region was found in the target process' address space")]
    NoExecutableRegionInTarget,
    #[error("the target process does not appear to have the libc library loaded")]
    TargetDoesNotHaveLibc,
    #[error("calling `malloc` in the target process failed")]
    InjectedMalloc,
    #[error("calling `dlopen` in the target process failed")]
    InjectedDlopen,
    #[error("the shellcode was meant to trap, but the target quietly exited instead")]
    ShellcodeDidntTrap,
    #[error("the target exited quietly as soon as we started tracing it")]
    TargetExitedImmediately,
    #[error("the target sent an unexpected signal while running the shellcode")]
    UnexpectedSignal(pete::Signal),
}

/// A type alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
*/
/// A type capable of loading libraries into a ptrace'd target process.
///
/// When this struct is dropped it will detach from the target process.
pub struct Injector {
    /// The PID of the process we are injecting into.
    proc: Process,
    /// The tracer that is controlling the tracee.
    tracer: pete::Ptracer,
}

impl Injector {
    /// Spawn a new process and begin tracing it.
    pub fn spawn(command: std::process::Command) -> Result<Self> {
        let mut tracer = pete::Ptracer::new();
        let child = tracer
            .spawn(command)
            .wrap_err("failed to spawn and trace command")?;
        let proc =
            Process::get(child.id()).wrap_err("failed to get newly spawned process by PID")?;
        log::info!("Spawned process with PID {}", proc);
        Ok(Self { proc, tracer })
    }

    /// Attach to an existing process and begin tracing it.
    pub fn attach(proc: Process) -> Result<Self> {
        let mut tracer = pete::Ptracer::new();
        tracer
            .attach((&proc).into())
            .wrap_err("failed to attach to given process")?;
        log::trace!("Attached to process with PID {}", proc);
        Ok(Self { proc, tracer })
    }

    /// Inject the given library into the traced process.
    pub fn inject(&mut self, library: &std::path::Path) -> Result<()> {
        let Some(tracee) = self.tracer.wait()? else {
            return Err(eyre!("the target exited quietly as soon as we started tracing it"));
        };
        let mut injection = Injection::inject(&self.proc, &mut self.tracer, tracee)
            .wrap_err("failed to inject shellcode")?;
        injection
            .execute(library)
            .wrap_err("failed to execute shellcode")?;
        injection.remove().wrap_err("failed to remove shellcode")?;
        log::info!(
            "Successfully injected library {} into process with PID {}",
            library.display(),
            self.proc
        );
        Ok(())
    }
}
