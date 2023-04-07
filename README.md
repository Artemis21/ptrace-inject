# `ptrace-inject`

`ptrace-inject` is a tool for injecting code into a running process using
[ptrace][1]. It is a tool for \*nix systems - for Windows, see [`dll-syringe`][2].
Currently, only x64 is supported, but support for other architectures is planned
as soon as I can test them.

`ptrace-inject` is both a Rust library and a command line tool. Here's an example
of using the library:

```rust
use std::{process::Command, path::PathBuf};
use ptrace_inject::{Injector, Process};

let library = PathBuf::from("path/to/library.so");

// Spawn a new process and inject the library into it.
let target = Command::new("target-process");
Injector::spawn(target)?.inject(&library)?;

// Or attach to an existing process.
let proc = Process::by_name("target-process")?.expect("to find target process");
Injector::attach(proc)?.inject(&library)?;
```

See [the documentation][3] for more information.

The usage of the command line tool is as follows:

```
Usage: ptrace-inject [OPTIONS] <--name <NAME>|--pid <PID>> <LIBRARY>

Arguments:
  <LIBRARY>  Path to the library to inject

Options:
  -v, --verbose...   More output per occurrence
  -q, --quiet...     Less output per occurrence
  -n, --name <NAME>  Name of a process to attach to
  -p, --pid <PID>    PID of a process to attach to
  -h, --help         Print help
  -V, --version      Print version
```

You can install it with `cargo install ptrace-inject --features cli`.


 [1]: https://en.wikipedia.org/wiki/Ptrace
 [2]: https://crates.io/crates/dll-syringe
 [3]: https://docs.rs/ptrace-inject
