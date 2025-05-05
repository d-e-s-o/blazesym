use std::ops::Range;

use crate::maps;
use crate::Addr;
use crate::Pid;
use crate::Result;


/// Configuration determining how to symbolize vDSO addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Vdso {
    /// Don't handle vDSO addresses.
    None,
    /// Use the remote process' vDSO image.
    ///
    /// Use the vDSO image of the process whose addresses we attempt to
    /// symbolize. Doing so will result in the correct symbolization
    /// result, but it requires the capability for reading remote
    /// process memory via `/proc/<pid>/mem`.
    #[default]
    RemoteProcMem,
    /// Use the vDSO image of the process containing the library.
    ///
    /// Use the current process' vDSO image for symbolization. Use at your
    /// own risk and only for good reason. Conceptually, processes in a
    /// system are free to use a different libc and vDSO image and if that
    /// is the case symbolization may be wrong if this option is being
    /// used. However, by using this option the need for requiring the
    /// capability for reading `/proc/<pid>/mem` is eliminated.
    CurrentProcMem,
}


pub(crate) fn find_vdso() -> Result<Option<Range<Addr>>> {
    // TODO: Could use getauxval(3) with `AT_SYSINFO_EHDR` as well.

    let entries = maps::parse_filtered(Pid::Slf)?;
    for result in entries {
        let entry = result?;
        if matches!(entry.path_name, Some(maps::PathName::Component(c)) if c == "[vdso]") {
            return Ok(Some(entry.range))
        }
    }
    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Make sure that we can look up the address of the process' vDSO, if
    /// any.
    #[test]
    fn vdso_addr_finding() {}
}
