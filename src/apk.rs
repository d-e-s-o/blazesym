use std::os::unix::ffi::OsStrExt as _;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;


pub(crate) struct ApkPath {
    /// The Android style APK path, including the member.
    path: PathBuf,
    /// The index of the APK portion of the path, without the separator or
    /// the APK member.
    apk_end: usize,
}

impl ApkPath {
    pub(crate) fn new(apk: &Path, elf: &Path) -> Self {
        let mut apk = apk.to_path_buf();
        let apk_end = apk.as_os_str().as_bytes().len();
        // Append '!' to indicate separation from archive internal contents
        // that follow. This is an Android convention.
        let () = apk.as_mut_os_string().push("!");
        let elf = {
            let mut it = elf.components();
            if let Some(first) = it.next() {
                match first {
                    Component::Prefix(_) | Component::RootDir => {
                        // We removed the root directory/prefix.
                        it.as_path()
                    }
                    _ => elf,
                }
            } else {
                elf
            }
        };
        let path = apk.join(elf);

        Self { path, apk_end }
    }

    #[cfg(unix)]
    pub(crate) fn filesystem_path(&self) -> &Path {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        Path::new(OsStr::from_bytes(
            &self.path.as_os_str().as_bytes()[0..self.apk_end],
        ))
    }

    #[cfg(not(unix))]
    pub(crate) fn filesystem_path(&self) -> &Path {
        // Shouldn't be needed for the time being. Not possible in
        // infallible fashion, it seems, so requires a bit of a rework
        // to implement properly.
        unimplemented!()
    }

    pub(crate) fn virtual_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_virtual_path(self) -> PathBuf {
        self.path
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = ApkPath::new(apk, elf);
        assert_eq!(
            path.virtual_path(),
            Path::new("/root/test.apk!/subdir/libc.so")
        );
        assert_eq!(path.filesystem_path(), Path::new("/root/test.apk"));

        let apk = Path::new("/root/test");
        let elf = Path::new("subdir/libc.so");
        let path = ApkPath::new(apk, elf);
        assert_eq!(path.virtual_path(), Path::new("/root/test!/subdir/libc.so"));
        assert_eq!(path.filesystem_path(), Path::new("/root/test"));

        let apk = Path::new("/root/test");
        let elf = Path::new("/subdir/libc.so");
        let path = ApkPath::new(apk, elf);
        assert_eq!(path.virtual_path(), Path::new("/root/test!/subdir/libc.so"));
        assert_eq!(path.filesystem_path(), Path::new("/root/test"));

        let path = ApkPath::new(Path::new(""), elf);
        assert_eq!(path.virtual_path(), Path::new("!/subdir/libc.so"));
        assert_eq!(path.filesystem_path(), Path::new(""));

        let path = ApkPath::new(apk, Path::new(""));
        assert_eq!(path.virtual_path(), Path::new("/root/test!/"));
        assert_eq!(path.filesystem_path(), Path::new("/root/test"));
    }
}
