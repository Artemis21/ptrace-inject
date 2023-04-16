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

    /// Attach to all child threads of the process.
    fn attach_children(&mut self) -> Result<()> {
        let threads = self
            .proc
            .thread_ids()
            .wrap_err("couldn't get thread IDs of target to attach to them")?;
        log::trace!("Attaching to {} child threads of target", threads.len() - 1);
        threads
            .iter()
            .filter(|&tid| tid != &self.proc.pid())
            .try_for_each(|&tid| {
                self.tracer
                    .attach(pete::Pid::from_raw(tid))
                    .wrap_err_with(|| format!("failed to attach to child thread with TID {tid}"))?;
                // The order that the threads stop is not necessarily the same as the order
                // that they were attached to, so we don't know what tracee we're getting here.
                let actual_tid = self
                    .tracer
                    .wait()
                    .wrap_err("failed to wait for thread to stop")?
                    .ok_or_else(|| {
                        eyre!("a target thread exited quietly as soon as we started tracing it")
                    })?
                    .pid;
                log::trace!("Attached to thread ID {actual_tid} of target process");
                Ok(())
            })
    }

    /// Inject the given library into the traced process.
    pub fn inject(&mut self, library: &std::path::Path) -> Result<()> {
        self.attach_children()
            .wrap_err("failed to attach to child threads")?;
        let Some(tracee) = self.tracer.wait()? else {
            return Err(eyre!("the target exited quietly as soon as we started tracing it"));
        };
        log::trace!("Attached to process with ID {}", tracee.pid);
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
