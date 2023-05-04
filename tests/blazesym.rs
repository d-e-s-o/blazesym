#![allow(clippy::let_and_return, clippy::let_unit_value)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use std::ffi::CString;
use std::io::Error;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;

use coverage_helper::test;


/// Make sure that we fail symbolization when providing a non-existent source.
#[test_log::test(test)]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        symbolize::Source::Gsym(symbolize::Gsym::new(non_existent)),
        symbolize::Source::Elf(symbolize::Elf::new(non_existent)),
    ];
    let symbolizer = Symbolizer::new();

    for src in srcs {
        let err = symbolizer.symbolize(&src, &[0x2000100]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can correctly symbolize an address using GSYM.
#[test_log::test(test)]
fn symbolize_gsym() {
    let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test.gsym");

    let src = symbolize::Source::Gsym(symbolize::Gsym::new(test_gsym));
    let symbolizer = Symbolizer::new();

    let results = symbolizer
        .symbolize(&src, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}

/// Check that we can symbolize an address using DWARF.
#[test_log::test(test)]
fn symbolize_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &[0x2000100])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.symbol, "factorial");
}

/// Check that we can symbolize addresses inside our own process.
#[test_log::test(test)]
fn symbolize_process() {
    let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
    let addrs = [symbolize_process as Addr, Symbolizer::new as Addr];
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, &addrs)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);

    let result = &results[0];
    assert!(result.symbol.contains("symbolize_process"), "{result:x?}");

    let result = &results[1];
    assert!(result.symbol.contains("Symbolizer3new"), "{result:x?}");
}

/// Check that we can look up an address using DWARF.
#[test_log::test(test)]
fn lookup_dwarf() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .find_addrs(&src, &["factorial"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.address, 0x2000100);
}

/// Check that we can normalize user addresses in our own shared object.
#[test_log::test(test)]
fn normalize_user_addr() {
    fn test(so: &str) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data").join(so);
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = Normalizer::new();
        let norm_addrs = normalizer
            .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(norm_addrs.addrs.len(), 1);
        assert_eq!(norm_addrs.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let norm_addr = norm_addrs.addrs[0];
        let meta = &norm_addrs.meta[norm_addr.1];
        assert_eq!(meta.binary().unwrap().path, test_so);

        let mut elf = symbolize::Elf::new(test_so);
        // TODO: Fix our symbolizer. Base address should be 0.
        elf.base_address = 0x1000;

        let src = symbolize::Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let results = symbolizer
            .symbolize(&src, &[norm_addr.0])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.symbol, "the_answer");
    }

    test("libtest-so.so");
    test("libtest-so-no-separate-code.so");
}


/// Check that we can look up an address.
#[test_log::test(test)]
fn inspect() {
    fn test(src: inspect::Source) {
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&["factorial"], &src)
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.address, 0x2000100);
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-dwarf.bin");
    let src = inspect::Source::Elf(inspect::Elf::new(test_dwarf));
    let () = test(src);

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let mut elf = inspect::Elf::new(test_elf);
    assert!(elf.debug_info);
    elf.debug_info = false;
    let src = inspect::Source::Elf(elf);
    let () = test(src);
}
