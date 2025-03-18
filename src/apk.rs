use std::ffi::OsString;
use std::path::Component;
use std::path::Path;


pub(crate) fn create_apk_elf_path(apk: &Path, elf: &Path) -> OsString {
    let mut apk = apk.to_path_buf();
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
    path.into_os_string()
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf);
        assert_eq!(path, "/root/test.apk!/subdir/libc.so");

        let apk = Path::new("/root/test");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf);
        assert_eq!(path, "/root/test!/subdir/libc.so");

        let apk = Path::new("/root/test");
        let elf = Path::new("/subdir/libc.so");
        let path = create_apk_elf_path(apk, elf);
        assert_eq!(path, "/root/test!/subdir/libc.so");

        let path = create_apk_elf_path(Path::new(""), elf);
        assert_eq!(path, "!/subdir/libc.so");

        let path = create_apk_elf_path(apk, Path::new(""));
        assert_eq!(path, "/root/test!/");
    }
}
