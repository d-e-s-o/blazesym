use std::ops::Range;

use libc::getauxval;
use libc::AT_PAGESZ;
use libc::AT_SYSINFO_EHDR;

use crate::maps;
use crate::Addr;
use crate::Pid;
use crate::Result;


#[cfg_attr(target_pointer_width = "64", allow(trivial_numeric_casts))]
fn find_vdso_auxval() -> Option<Range<Addr>> {
    // SAFETY: `getauxval` is always safe to call.
    let start = unsafe { getauxval(AT_SYSINFO_EHDR) } as Addr;
    if start == 0 {
        return None
    }

    // SAFETY: `getauxval` is always safe to call.
    let page_size = unsafe { getauxval(AT_PAGESZ) } as u64;
    if page_size == 0 {
        return None
    }

    // As per getauxval(3), the vDSO is one page in size.
    Some(start..start + page_size)
}

pub(crate) fn find_vdso_maps(pid: Pid) -> Result<Option<Range<Addr>>> {
    let entries = maps::parse_filtered(pid)?;
    for result in entries {
        let entry = result?;
        if matches!(entry.path_name, Some(maps::PathName::Component(c)) if c == "[vdso]") {
            return Ok(Some(entry.range))
        }
    }
    Ok(None)
}

pub(crate) fn find_vdso() -> Result<Option<Range<Addr>>> {
    if let r @ Some(..) = find_vdso_auxval() {
        return Ok(r)
    }

    if let r @ Some(..) = find_vdso_maps(Pid::Slf)? {
        return Ok(r)
    }

    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Make sure that we can look up the address of the process' vDSO
    /// using `getauxval(3)`.
    #[test]
    fn vdso_addr_finding_auxval() {
        let _range = find_vdso_auxval().unwrap();
    }

    /// Make sure that we can look up the address of the process' vDSO
    /// by parsing `/proc/self/maps`.
    #[test]
    fn vdso_addr_finding_maps() {
        let _range = find_vdso_maps(Pid::Slf).unwrap();
    }

    /// Make sure that we can look up the address of the process' vDSO.
    #[test]
    fn vdso_addr_finding() {
        let _range = find_vdso().unwrap();
    }
}
