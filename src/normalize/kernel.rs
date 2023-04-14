use std::error::Error as StdError;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read as _;
use std::io::Result;
use std::path::Path;
use std::str;
use std::str::FromStr;

use crate::Addr;

use super::meta::KernelAddrMeta;
use super::normalizer::NormalizedAddrs;


/// A type representing normalized kernel addresses.
pub type NormalizedKernelAddrs = NormalizedAddrs<KernelAddrMeta>;


#[derive(Debug)]
enum KaslrState {
    /// KASLR is known to be disabled.
    Disabled,
    /// KASLR is known to be enabled.
    Enabled,
    /// The state of KASLR on the system could not be determined.
    Unknown,
}

impl FromStr for KaslrState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let value =
            usize::from_str(s.trim()).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        match value {
            0 => Ok(KaslrState::Disabled),
            1 | 2 => Ok(KaslrState::Enabled),
            // It's unclear whether we should error out here or map anything
            // "unknown" to `Unknown`.
            x => Err(Error::new(
                ErrorKind::InvalidData,
                format!("/proc/sys/kernel/randomize_va_space node value {x} is not understood"),
            )),
        }
    }
}


fn read_proc_node_value<T>(path: &Path) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: StdError + Send + Sync + 'static,
{
    let result = File::open(path);
    let mut file = match result {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    // We don't want to blindly use Read::read_to_end or something like
    // that if we can avoid it. We don't anticipate this function to be
    // used for nodes with large content, so just stack allocate a 64KiB
    // buffer.
    let mut buffer = [0; u16::MAX as usize];
    let count = file.read(&mut buffer)?;
    if count >= u16::MAX.into() {
        // Error our if more data is present.
        return Err(Error::new(
            ErrorKind::InvalidData,
            "file content is larger than 64 KiB",
        ))
    }

    let s =
        str::from_utf8(&buffer[0..count]).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    let value = T::from_str(s).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    Ok(Some(value))
}


/// Try to determine the KASLR state of the system.
fn determine_kaslr_state() -> Result<KaslrState> {
    // https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space
    let kaslr =
        read_proc_node_value::<KaslrState>(Path::new("/proc/sys/kernel/randomize_va_space"))?
            .unwrap_or(KaslrState::Unknown);
    Ok(kaslr)
}


pub(super) fn normalize_kernel_addrs(_addrs: &[Addr]) -> Result<NormalizedKernelAddrs> {
    // No PID means that we can only resolve kernel addresses.

    // TODO: We'd need to take into account KASLR offsets here, for
    //       example.

    // The canonical source for getting its value is /proc/kcore.
    // But that file may not be present. Reference:
    // https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html#kerneloffset
    //
    // https://github.com/osandov/drgn/blob/c76f25b8525c9a80ee4b4f5ce3292c14125c9e1b/libdrgn/drgn_program_parse_vmcoreinfo.inc.strswitch#L51
    // has example logic

    // May have to check 'kernel.randomize_va_space' sysctl
    // Check System.map-<kernel version>
    // - discrepancy to /proc/kallsysms contents would be KASLR
    //   offset
    // - _head or _text symbol from /proc/kallsysms could point to
    //   kernel base address
    //
    // /sys/kernel/debug/kernel_page_tables could potentially be of
    // interest, too
    //
    // CONFIG_RANDOMIZE_BASE seems to be a necessity
    //
    // nokaslr would disable KASLR, kaslr would enable it
    // /proc/cmdline contains command line
    //
    // try lsmod or /proc/modules to access module address
    //
    // Could potentially parse dmesg:
    // > 505.654475:   <6> Kernel Offset: 0x2c28000000 from 0xffffff8008000000
    //
    // May be worth looking at
    // https://github.com/libvmi/libvmi/blob/0f832ebfc41bde5977be0547d9bfa9722891e631/libvmi/os/linux/core.c#L404
    // as well

    Err(Error::new(ErrorKind::Other, ""))
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Check that we can determine the system's KASLR state.
    #[test]
    fn kaslr_detection() {
        let _state = determine_kaslr_state().unwrap();
        println!("system KASLR state: {_state:?}");
    }
}
