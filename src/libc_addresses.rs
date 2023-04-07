use crate::Process;
use eyre::{Context, Report, Result};
use libloading::os::unix::Library;

/// The address of the libc functions we need to call within a process.
#[derive(Debug, Clone, Copy)]
pub struct LibcAddrs {
    pub(crate) malloc: u64,
    pub(crate) dlopen: u64,
    pub(crate) free: u64,
}

impl LibcAddrs {
    /// Get the addresses of functions in the currently running process.
    fn for_current_process() -> Result<Self> {
        let addr_of = unsafe {
            let lib = Library::new("libc.so.6")
                .wrap_err("loading local libc to get function addresses failed")?;
            move |name: &str| {
                Ok::<_, Report>(
                    lib.get::<u64>(name.as_bytes())
                        .wrap_err(format!(
                            "getting address of symbol {name:?} from libc failed"
                        ))?
                        .into_raw() as u64,
                )
            }
        };
        let addrs = Self {
            malloc: addr_of("malloc")?,
            dlopen: addr_of("dlopen")?,
            free: addr_of("free")?,
        };
        log::debug!("Got libc addresses for current process: {addrs:x?}");
        Ok(addrs)
    }

    /// Given the offset of libc in the process that this struct has addresses
    /// for, and the offset of libc in another process, return the addresses of
    /// the same functions in the other process.
    const fn change_base(&self, old_base: u64, new_base: u64) -> Self {
        // We cannot calculate an offset as `new_base - old_base` because it
        // might be less than 0.
        Self {
            malloc: self.malloc - old_base + new_base,
            dlopen: self.dlopen - old_base + new_base,
            free: self.free - old_base + new_base,
        }
    }

    /// Get the addresses of functions in a given process - the whole point.
    pub(crate) fn for_process(process: &Process) -> Result<Self> {
        let our_libc = Process::current()
            .wrap_err("getting current process to find the local libc offset failed")?
            .libc_address()
            .wrap_err("getting the local libc offset failed")?;
        let their_libc = process
            .libc_address()
            .wrap_err("getting the target libc offset failed")?;
        log::debug!(
            "Calculating libc address given our offset {:x} and their offset {:x}",
            our_libc,
            their_libc
        );
        Ok(Self::for_current_process()?.change_base(our_libc, their_libc))
    }
}
