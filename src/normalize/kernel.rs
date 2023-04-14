use std::error::Error as StdError;
use std::fs::File;
use std::io;
use std::io::Read as _;
use std::path::Path;
use std::str;
use std::str::FromStr;

use crate::elf;
use crate::elf::types::ElfN_Nhdr;
use crate::elf::BackendImpl;
use crate::elf::ElfParser;
use crate::util::align_up_u32;
use crate::util::from_radix_16;
use crate::util::split_bytes;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;

use super::meta::KernelAddrMeta;
use super::normalizer::Output;


/// A type representing normalized kernel addresses.
pub type KernelOutput<'src> = Output<KernelAddrMeta<'src>>;


/// The absolute path of the `randomize_va_space` `proc` node.
const PROC_RANDOMIZE_VA_SPACE: &str = "/proc/sys/kernel/randomize_va_space";
/// The absolute path to the `kcore` `proc` node.
const PROC_KCORE: &str = "/proc/kcore";
/// The name of the `VMCOREINFO` ELF note.
///
/// See https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html
const VMCOREINFO_NAME: &[u8] = b"VMCOREINFO\0";


/// The kernel address space layout randomization (KASLR) state of the
/// system.
#[derive(Debug, PartialEq)]
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
        let value = usize::from_str(s.trim()).map_err(Error::with_invalid_data)?;
        match value {
            0 => Ok(KaslrState::Disabled),
            1 | 2 => Ok(KaslrState::Enabled),
            // It's unclear whether we should error out here or map anything
            // "unknown" to `Unknown`.
            x => Err(Error::with_invalid_data(format!(
                "{PROC_RANDOMIZE_VA_SPACE} node value {x} is not understood"
            ))),
        }
    }
}


/// # Notes
/// Right now this function imposes an arbitrary limit on the maximum
/// node value content size.
fn read_proc_node_value<T>(path: &Path) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: StdError + Send + Sync + 'static,
{
    let result = File::open(path);
    let mut file = match result {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    // We don't want to blindly use Read::read_to_end or something like
    // that if we can avoid it.
    let mut buffer = [0; u8::MAX as usize];
    let count = file.read(&mut buffer)?;
    if count >= size_of_val(&buffer) {
        return Err(Error::with_invalid_data(format!(
            "file content is larger than {} bytes",
            size_of_val(&buffer)
        )))
    }

    let s = str::from_utf8(&buffer[0..count]).map_err(Error::with_invalid_data)?;
    let value = T::from_str(s).map_err(Error::with_invalid_data)?;
    Ok(Some(value))
}


/// Try to determine the KASLR state of the system.
fn determine_kaslr_state() -> Result<KaslrState> {
    // https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space
    let kaslr = read_proc_node_value::<KaslrState>(Path::new(PROC_RANDOMIZE_VA_SPACE))
        .with_context(|| {
            format!(
                "failed to determine KASLR state from {}",
                PROC_RANDOMIZE_VA_SPACE
            )
        })?
        .unwrap_or(KaslrState::Unknown);
    Ok(kaslr)
}

/// "Parse" the VMCOREINFO descriptor.
///
/// This underspecified blob roughly has the following format:
/// ```
/// OSRELEASE=6.2.15-100.fc36.x86_64
/// BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
/// PAGESIZE=4096
/// SYMBOL(init_uts_ns)=ffffffffb72b8160
/// OFFSET(uts_namespace.name)=0
/// [...]
/// ```
fn parse_vmcoreinfo_desc(desc: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    desc.split(|&b| b == b'\n')
        .filter_map(|line| split_bytes(line, |b| b == b'='))
}

/// Find and read the `KERNELOFFSET` note in a "kcore" file represented by
/// `parser` (i.e., already opened as an ELF).
fn find_kaslr_offset(parser: &ElfParser<File>) -> Result<Option<u64>> {
    let phdrs = parser.program_headers()?;
    for phdr in phdrs.iter(0) {
        if phdr.type_() != elf::types::PT_NOTE {
            continue
        }

        let file = parser.backend();
        let mut offset = phdr.offset();

        // Iterate through all available notes. See `elf(5)` for
        // details.
        while offset + (size_of::<ElfN_Nhdr>() as u64) <= phdr.file_size() {
            let nhdr = file
                .read_pod_obj::<ElfN_Nhdr>(offset)
                .context("failed to read kcore note header")?;
            offset += size_of::<ElfN_Nhdr>() as u64;

            let name = if nhdr.n_namesz > 0 {
                let name = file.read_pod_slice::<u8>(offset, nhdr.n_namesz as _)?;
                offset += u64::from(align_up_u32(nhdr.n_namesz, 4));
                Some(name)
            } else {
                None
            };

            // We are looking for the note named `VMCOREINFO`.
            if name.as_deref() == Some(VMCOREINFO_NAME) {
                if nhdr.n_descsz > 0 {
                    let desc = file.read_pod_slice::<u8>(offset, nhdr.n_descsz as _)?;
                    let offset = parse_vmcoreinfo_desc(&desc)
                        .find(|(key, _value)| key == b"KERNELOFFSET")
                        // The value is in hexadecimal format. Go figure.
                        .map(|(_key, value)| {
                            from_radix_16(value).ok_or_invalid_data(|| {
                                format!("failed to parse KERNELOFFSET value `{value:x?}`")
                            })
                        })
                        .transpose();
                    return offset
                }

                // There shouldn't be multiple notes with that name,
                // but I suppose it can't hurt to keep checking...?
            }

            offset += u64::from(align_up_u32(nhdr.n_descsz, 4));
        }
    }
    Ok(None)
}

pub(super) fn normalize_kernel_addrs(_addrs: &[Addr]) -> Result<KernelOutput<'static>> {
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
    // - discrepancy to /proc/kallsysms contents would be KASLR offset
    // - _head or _text symbol from /proc/kallsysms could point to kernel base
    //   address
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

    Err(Error::with_unsupported("not yet implemented"))
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::ErrorKind;


    /// Make sure that we can parse the KASLR state string correctly.
    #[test]
    fn kaslr_state_parsing() {
        assert_eq!(KaslrState::from_str("0").unwrap(), KaslrState::Disabled);
        assert_eq!(KaslrState::from_str("1").unwrap(), KaslrState::Enabled);
        assert_eq!(KaslrState::from_str("2").unwrap(), KaslrState::Enabled);
        assert!(KaslrState::from_str("3").is_err());
        assert!(KaslrState::from_str("!@&*()&#!@@#").is_err());
    }

    /// Check that we can parse a dummy VMCOREINFO descriptor.
    #[test]
    fn vmcoreinfo_desc_parsing() {
        let desc = b"OSRELEASE=6.2.15-100.fc36.x86_64
BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
SYMBOL(init_uts_ns)=ffffffffb72b8160
OFFSET(uts_namespace.name)=0
PAGESIZE=4096
";

        let page_size = parse_vmcoreinfo_desc(desc)
            .find(|(key, _value)| key == b"PAGESIZE")
            .map(|(_key, value)| value)
            .unwrap();
        assert_eq!(page_size, b"4096");
    }

    /// Check that we can determine the system's KASLR state.
    #[test]
    fn kaslr_detection() {
        let state = determine_kaslr_state().unwrap();

        // Always attempt reading the KASLR to exercise the VMCOREINFO
        // parsing path.
        // Note that we cannot use the regular mmap based ELF parser
        // backend for this file, as it cannot be mmap'ed. We have to
        // fall back to using regular I/O instead.
        let parser = match ElfParser::open_non_mmap(PROC_KCORE) {
            Ok(parser) => parser,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("{err}"),
        };
        let offset = find_kaslr_offset(&parser).unwrap();

        match state {
            KaslrState::Enabled => assert_ne!(offset, None),
            KaslrState::Disabled => {
                assert!(
                    offset.is_none() || matches!(offset, Some(0)),
                    "{offset:#x?}"
                );
            }
            KaslrState::Unknown => {
                // Anything is game.
            }
        }
    }
}
