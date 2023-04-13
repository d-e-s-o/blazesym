use std::ffi::OsStr;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::mem::transmute;
use std::num::NonZeroU32;
use std::ops::Deref as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Component;
use std::path::PathBuf;
use std::str;

use crate::mmap::Mmap;
use crate::Addr;


/// An enumeration identifying a process.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Pid {
    Slf,
    Pid(NonZeroU32),
}

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Slf => write!(f, "self"),
            Self::Pid(pid) => write!(f, "{pid}"),
        }
    }
}

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        NonZeroU32::new(pid).map(Pid::Pid).unwrap_or(Pid::Slf)
    }
}


pub(crate) struct MapsEntry {
    pub loaded_address: Addr,
    pub _end_address: Addr,
    pub mode: u8,
    pub _offset: u64,
    pub path: PathBuf,
}


// TODO: Use slice::trim_ascii_start once it stabilized.
fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    // Note: A pattern matching based approach (instead of indexing) allows
    // making the function const.
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break
        }
    }
    bytes
}

// TODO: Use slice::trim_ascii_end once it stabilized.
fn trim_ascii_end(mut bytes: &[u8]) -> &[u8] {
    // Note: A pattern matching based approach (instead of indexing) allows
    // making the function const.
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break
        }
    }
    bytes
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(bytes))
}


fn split_bytes<F>(bytes: &[u8], mut check: F) -> Option<(&[u8], &[u8])>
where
    F: FnMut(u8) -> bool,
{
    let (idx, _) = bytes.iter().enumerate().find(|(_idx, b)| check(**b))?;
    let (left, right) = bytes.split_at(idx);
    Some((left, &right[1..]))
}


/// Parse a line of a proc maps file.
fn parse_maps_line<'line>(line: &'line [u8], pid: Pid) -> Result<MapsEntry, Error> {
    let full_line = line;

    let split_once = |line: &'line [u8], component| -> Result<(&'line [u8], &'line [u8]), Error> {
        split_bytes(line, |b| b.is_ascii_whitespace()).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!(
                    "failed to find {component} in proc maps line: {}\n{}",
                    String::from_utf8_lossy(line),
                    String::from_utf8_lossy(full_line)
                ),
            )
        })
    };

    // Lines have the following format:
    // address           perms offset  dev   inode      pathname
    // 08048000-08049000 r-xp 00000000 03:00 8312       /opt/test
    // 0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
    // a7cb1000-a7cb2000 ---p 00000000 00:00 0
    // a7ed5000-a8008000 r-xp 00000000 03:00 4222       /lib/libc.so.6
    let (address_str, line) = split_once(line, "address range")?;
    let (loaded_str, end_str) = split_bytes(address_str, |b| b == b'-').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed address range in proc maps line: {}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;
    let loaded_str = str::from_utf8(loaded_str).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed start address in proc maps line: {}: {err}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;
    let loaded_address = Addr::from_str_radix(loaded_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed start address in proc maps line: {}: {err}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;
    let end_str = str::from_utf8(end_str).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed end address in proc maps line: {}: {err}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;
    let end_address = Addr::from_str_radix(end_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed end address in proc maps line: {}: {err}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;

    let (mode_str, line) = split_once(line, "permissions component")?;
    let mode = mode_str
        .iter()
        .fold(0, |mode, b| (mode << 1) | u8::from(*b != b'-'));

    let (offset_str, line) = split_once(line, "offset component")?;
    let offset_str = str::from_utf8(offset_str).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed offset component in proc maps line: {}: {err}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;

    let offset = u64::from_str_radix(offset_str, 16).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "encountered malformed offset component in proc maps line: {}: {err}",
                String::from_utf8_lossy(full_line)
            ),
        )
    })?;

    let (_dev, line) = split_once(line, "device component")?;
    // Note that by design, a path may not be present and so we may not be able
    // to successfully split.
    let path_str = split_once(line, "inode component")
        .map(|(_inode, line)| trim_ascii_start(line))
        .unwrap_or(b"");
    let path = if path_str.ends_with(b" (deleted)") {
        PathBuf::from(format!(
            "/proc/{pid}/map_files/{}",
            String::from_utf8_lossy(address_str)
        ))
    } else {
        PathBuf::from(OsStr::from_bytes(path_str).to_os_string())
    };

    let entry = MapsEntry {
        loaded_address,
        _end_address: end_address,
        mode,
        _offset: offset,
        path,
    };
    Ok(entry)
}

/// Parse a proc maps file from the provided reader.
///
/// `filter` is a filter function (similar to those usable on iterators)
/// that determines which entries we keep (those for which it returned
/// `true`) and which we discard (anything `false`).
fn parse_file(data: &[u8], pid: Pid) -> impl Iterator<Item = Result<MapsEntry, Error>> + '_ {
    data.split(|&b| b == b'\n' || b == b'\r')
        .filter_map(move |raw_line| {
            let raw_line = trim_ascii(raw_line);
            if !raw_line.is_empty() {
                Some(parse_maps_line(raw_line, pid))
            } else {
                None
            }
        })
}

#[derive(Debug)]
struct MapsEntryIter<I> {
    /// XXX
    iter: I,
    _mmap: Mmap,
}

impl<I> Iterator for MapsEntryIter<I>
where
    I: Iterator<Item = Result<MapsEntry, Error>>,
{
    type Item = Result<MapsEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// Parse the maps file for the process with the given PID.
pub(crate) fn parse(pid: Pid) -> Result<impl Iterator<Item = Result<MapsEntry, Error>>, Error> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(path).unwrap();
    let mmap = Mmap::map(&file).unwrap();
    // SAFETY: We keep `mmap` around for the duration that data (and the derived
    //         iterator below) lives, so the 'static lifetime is apt.
    let data = unsafe { transmute::<_, &'static [u8]>(mmap.deref()) };

    let iter = MapsEntryIter {
        iter: parse_file(data, pid),
        _mmap: mmap,
    };
    Ok(iter)
}

/// A helper function checking whether a `MapsEntry` has relevant to
/// symbolization efforts. If that is not the case, it may be possible to ignore
/// it altogether.
pub(crate) fn is_symbolization_relevant(entry: &MapsEntry) -> bool {
    // Only entries with actual paths are of relevance.
    if entry.path.as_path().components().next() != Some(Component::RootDir) {
        return false
    }

    // Only entries that are executable and readable (r-x-) are of relevance.
    if (entry.mode & 0b1010) != 0b1010 {
        return false
    }

    if let Ok(meta_data) = entry.path.metadata() {
        if !meta_data.is_file() {
            return false
        }
    } else {
        // TODO: We probably should handle errors more gracefully. It's not
        //       clear that silently ignoring them is the right thing to do.
        return false
    }

    true
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use test_log::test;


    /// Check that we can split a byte slice as expected.
    #[test]
    fn byte_slice_splitting() {
        let bytes = b"56156eb96000-56156ebf2000";
        let (left, right) = split_bytes(bytes, |b| b == b'-').unwrap();
        assert_eq!(left, b"56156eb96000");
        assert_eq!(right, b"56156ebf2000");
    }

    /// Check that we can parse `/proc/self/maps`.
    #[test]
    fn self_map_parsing() {
        let maps = parse(Pid::Slf).unwrap();
        assert_eq!(maps.count(), 0);
    }

    #[test]
    fn map_line_parsing() {
        let lines = r#"
55f4a95c9000-55f4a95cb000 r--p 00000000 00:20 41445                      /usr/bin/cat
55f4a95cb000-55f4a95cf000 r-xp 00002000 00:20 41445                      /usr/bin/cat
55f4a95cf000-55f4a95d1000 r--p 00006000 00:20 41445                      /usr/bin/cat
55f4a95d1000-55f4a95d2000 r--p 00007000 00:20 41445                      /usr/bin/cat
55f4a95d2000-55f4a95d3000 rw-p 00008000 00:20 41445                      /usr/bin/cat
55f4aa379000-55f4aa39a000 rw-p 00000000 00:00 0                          [heap]
7f1273b05000-7f1273b06000 r--s 00000000 00:13 19                         /sys/fs/selinux/status
7f2321e00000-7f2321e37000 r--p 00000000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2321e37000-7f2321f6f000 r-xp 00037000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2321f6f000-7f2322009000 r--p 0016f000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f2322009000-7f232201b000 r--p 00208000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7f232201b000-7f232201d000 rw-p 0021a000 00:20 1808269                    /usr/lib64/libgnutls.so.30.34.1 (deleted)
7fa7ade00000-7fa7bb3b7000 r--p 00000000 00:20 12022451                   /usr/lib/locale/locale-archive
7fa7bb400000-7fa7bb428000 r--p 00000000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb428000-7fa7bb59c000 r-xp 00028000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb59c000-7fa7bb5f4000 r--p 0019c000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5f4000-7fa7bb5f8000 r--p 001f3000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5f8000-7fa7bb5fa000 rw-p 001f7000 00:20 12023223                   /usr/lib64/libc.so.6
7fa7bb5fa000-7fa7bb602000 rw-p 00000000 00:00 0
7fa7bb721000-7fa7bb746000 rw-p 00000000 00:00 0
7fa7bb758000-7fa7bb75a000 rw-p 00000000 00:00 0
7fa7bb75a000-7fa7bb75c000 r--p 00000000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb75c000-7fa7bb783000 r-xp 00002000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb783000-7fa7bb78e000 r--p 00029000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb78f000-7fa7bb791000 r--p 00034000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7fa7bb791000-7fa7bb793000 rw-p 00036000 00:20 12023220                   /usr/lib64/ld-linux-x86-64.so.2
7ffd03212000-7ffd03234000 rw-p 00000000 00:00 0                          [stack]
7ffd033a7000-7ffd033ab000 r--p 00000000 00:00 0                          [vvar]
7ffd033ab000-7ffd033ad000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
"#;

        let entries = parse_file(lines.as_bytes(), Pid::Slf);
        let () = entries.for_each(|entry| {
            let _entry = entry.unwrap();
        });

        // Parse the first (actual) line.
        let entry = parse_maps_line(lines.lines().nth(1).unwrap().as_bytes(), Pid::Slf).unwrap();
        assert_eq!(entry.loaded_address, 0x55f4a95c9000);
        assert_eq!(entry._end_address, 0x55f4a95cb000);
        assert_eq!(entry.path, Path::new("/usr/bin/cat"));

        let entry = parse_maps_line(lines.lines().nth(8).unwrap().as_bytes(), Pid::Slf).unwrap();
        assert_eq!(
            entry.path,
            Path::new("/proc/self/map_files/7f2321e00000-7f2321e37000")
        );
    }
}
