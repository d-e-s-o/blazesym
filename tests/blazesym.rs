#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::collections::HashSet;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::copy;
use std::fs::metadata;
use std::fs::read as read_file;
use std::fs::set_permissions;
use std::io::Error;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use blazesym::helper::read_elf_build_id;
use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::ErrorExt as _;
use blazesym::ErrorKind;
use blazesym::IntoError as _;
use blazesym::Pid;
use blazesym::Result;

use libc::exit;
use libc::fork;
use libc::seteuid;
use libc::waitpid;
use libc::WEXITSTATUS;
use libc::WIFEXITED;

use tempfile::NamedTempFile;

use test_log::test;


/// Make sure that we fail symbolization when providing a non-existent source.
#[test]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        symbolize::Source::from(symbolize::GsymFile::new(non_existent)),
        symbolize::Source::Elf(symbolize::Elf::new(non_existent)),
    ];
    let symbolizer = Symbolizer::default();

    for src in srcs {
        let err = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can symbolize an address using ELF, DWARF, and GSYM.
#[test]
fn symbolize_elf_dwarf_gsym() {
    fn test(src: symbolize::Source, has_code_info: bool) {
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000100);
        assert_eq!(result.offset, 0);

        if has_code_info {
            let code_info = result.code_info.as_ref().unwrap();
            assert_ne!(code_info.dir, None);
            assert_eq!(code_info.file, OsStr::new("test-stable-addresses.c"));
            assert_eq!(code_info.line, Some(8));
        } else {
            assert_eq!(result.code_info, None);
        }

        let size = result.size.unwrap();
        assert_ne!(size, 0);

        // Now check that we can symbolize addresses at a positive offset from the
        // start of the function.
        let offsets = (1..size).collect::<Vec<_>>();
        let addrs = offsets
            .iter()
            .map(|offset| (0x2000100 + offset) as Addr)
            .collect::<Vec<_>>();
        let results = symbolizer
            .symbolize(&src, symbolize::Input::VirtOffset(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), addrs.len());

        for (i, symbolized) in results.into_iter().enumerate() {
            let result = symbolized.into_sym().unwrap();
            assert_eq!(result.name, "factorial");
            assert_eq!(result.addr, 0x2000100);
            assert_eq!(result.offset, offsets[i]);

            if has_code_info {
                let code_info = result.code_info.as_ref().unwrap();
                assert_ne!(code_info.dir, None);
                assert_eq!(code_info.file, OsStr::new("test-stable-addresses.c"));
                assert!(code_info.line.is_some());
            } else {
                assert_eq!(result.code_info, None);
            }
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    test(src, false);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    test(src, true);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(&path));
    test(src, true);

    let data = read_file(&path).unwrap();
    let src = symbolize::Source::from(symbolize::GsymData::new(&data));
    test(src, true);
}

/// Check that we fail symbolization as expected when we don't have the
/// permission to open the symbolization source.
#[test]
// This test uses fork() from a (likely) multi-threaded program and relies on
// a nobody user with UID 65534 being present. Ugh. The cfg_attr dance is
// necessary because the bencher benchmarking infrastructure doesn't work
// properly with the --include-ignored argument, at least not when invoked via
// cargo-llvm-cov. Ugh^2.
#[cfg_attr(
    not(feature = "nightly"),
    ignore = "test does some nasty things that could conceivably not pan out"
)]
fn symbolize_no_permission() {
    // We run as root. Even if we limit permissions for a root-owned file we can
    // still access it (unlike the behavior for regular users). As such, we have
    // to work as a different user to check handling of permission denied
    // errors. Because such a change is process-wide, though, we can't do that
    // directly but have to fork first.

    fn test() -> Result<()> {
        let src = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");

        let tmpfile = NamedTempFile::new()?;
        let path = tmpfile.path();
        let _bytes = copy(src, path)?;

        let mut permissions = metadata(path)?.permissions();
        // Clear all permissions.
        let () = permissions.set_mode(0o0);
        let () = set_permissions(path, permissions)?;

        let nobody = 65534;
        if unsafe { seteuid(nobody) } == -1 {
            return Err(
                Error::last_os_error().with_context(|| format!("failed to seteuid({nobody})"))
            )
        }

        let src = symbolize::Source::Elf(symbolize::Elf::new(tmpfile.path()));
        let symbolizer = Symbolizer::new();
        let result = symbolizer.symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100));

        if matches!(result, Err(ref err) if err.kind() == ErrorKind::PermissionDenied) {
            Ok(())
        } else {
            None.ok_or_invalid_data(|| {
                format!("received unexpected symbolization result: {result:?}")
            })
        }
    }

    let pid = unsafe { fork() };
    match pid {
        -1 => panic!("failed to fork: {}", Error::last_os_error()),
        0 => {
            // Run the actual test. Note that it is insufficient for us to rely
            // on panics to convey failures to the parent process. The test
            // binary ends up just exiting with 0 even if a panic occurred.
            // Hence, we force a hard exit here directly.
            if let Err(err) = test() {
                eprintln!("{}", err);
                unsafe { exit(1) };
            }
        }
        pid => {
            let mut status = 0;
            let options = 0;
            if unsafe { waitpid(pid, &mut status, options) } == -1 {
                panic!("failed to waitpid({pid}): {}", Error::last_os_error())
            }

            if WIFEXITED(status) {
                assert_eq!(WEXITSTATUS(status), 0, "{status:#x}");
            } else {
                panic!("child process {pid} terminated unexpectedly (status: {status:#x})")
            }
        }
    }
}

/// Make sure that we report (enabled) or don't report (disabled) inlined
/// functions with DWARF and Gsym sources.
#[test]
fn symbolize_dwarf_gsym_inlined() {
    fn test(src: symbolize::Source, inlined_fns: bool) {
        let symbolizer = Symbolizer::builder()
            .enable_inlined_fns(inlined_fns)
            .build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x200020a))
            .unwrap()
            .into_sym()
            .unwrap();

        let code_info = result.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test-stable-addresses.c"));
        // The Gsym format uses inline information to "refine" the
        // line information associated with an address. As a result,
        // when we ignore inline information we may end up with a
        // slightly misleading location, namely that of the deepest
        // inlined caller.
        assert_eq!(code_info.line, Some(if inlined_fns { 32 } else { 21 }));

        if inlined_fns {
            assert_eq!(result.inlined.len(), 2);

            let name = &result.inlined[0].name;
            assert_eq!(*name, "factorial_inline_wrapper");
            let frame = result.inlined[0].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addresses.c"));
            assert_eq!(frame.line, Some(26));

            let name = &result.inlined[1].name;
            assert_eq!(*name, "factorial_2nd_layer_inline_wrapper");
            let frame = result.inlined[1].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addresses.c"));
            assert_eq!(frame.line, Some(21));
        } else {
            assert!(result.inlined.is_empty(), "{:#?}", result.inlined);
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(path));
    test(src.clone(), true);
    test(src, false);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = symbolize::Source::from(symbolize::Elf::new(path));
    test(src.clone(), true);
    test(src, false);
}

/// Check that we can symbolize the `abort_creds` function inside a
/// kernel image properly. Inside of
/// vmlinux-5.17.12-100.fc34.x86_64.dwarf, this function's address range
/// and name are in separate attributes:
/// ```text
/// 0x01273e11: DW_TAG_subprogram
///               DW_AT_abstract_origin     (0x0126ff5d "abort_creds")
///               DW_AT_low_pc      (0xffffffff8110ecb0)
///               DW_AT_high_pc     (0xffffffff8110ecce)
///               DW_AT_frame_base  (DW_OP_call_frame_cfa)
///               DW_AT_call_all_calls      (true)
///               DW_AT_sibling     (0x01273f66)
///
/// 0x0110932c: DW_TAG_subprogram
///               DW_AT_external    (true)
///               DW_AT_name        ("abort_creds")
///               DW_AT_decl_file   ("<...>/include/linux/cred.h")
///               DW_AT_decl_line   (163)
///               DW_AT_decl_column (0x0d)
///               DW_AT_prototyped  (true)
///               DW_AT_declaration (true)
///               DW_AT_sibling     (0x0110933e)
/// ```
/// In the past we were unable to handle this case properly.
#[test]
#[cfg_attr(not(feature = "generate-large-test-files"), ignore)]
fn symbolize_dwarf_complex() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0xffffffff8110ecb0))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.addr, 0xffffffff8110ecb0);
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}


/// Symbolize an address inside a DWARF file, with and without auto-demangling
/// enabled.
#[test]
fn symbolize_dwarf_demangle() {
    fn test(test_dwarf: &Path, addr: Addr) -> Result<(), ()> {
        let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
        let symbolizer = Symbolizer::builder().enable_demangling(false).build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert!(
            result.name.contains("test13test_function"),
            "{}",
            result.name
        );

        if result.inlined.is_empty() {
            return Err(())
        }
        assert!(
            result.inlined[0].name.contains("test12inlined_call"),
            "{}",
            result.inlined[0].name
        );

        // Do it again, this time with demangling enabled.
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "test::test_function");
        assert_eq!(result.inlined.len(), 1, "{:#?}", result.inlined);
        assert_eq!(result.inlined[0].name, "test::inlined_call");
        Ok(())
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs.bin");
    let elf = inspect::Elf::new(&test_dwarf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&["_RNvCs69hjMPjVIJK_4test13test_function"], &src)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(!results.is_empty());

    let addr = results[0].addr;
    let src = symbolize::Source::Elf(symbolize::Elf::new(&test_dwarf));
    let symbolizer = Symbolizer::builder().enable_demangling(false).build();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
        .unwrap()
        .into_sym()
        .unwrap();

    let addr = result.addr;
    let size = result.size.unwrap() as u64;
    for inst_addr in addr..addr + size {
        if test(&test_dwarf, inst_addr).is_ok() {
            return
        }
    }

    panic!("failed to find inlined function call");
}

/// Check that we can symbolize addresses inside our own process.
#[test]
fn symbolize_process() {
    let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
    let addrs = [symbolize_process as Addr, Symbolizer::symbolize as Addr];
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, symbolize::Input::AbsAddr(&addrs))
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);

    let result = results[0].as_sym().unwrap();
    assert!(result.name.contains("symbolize_process"), "{result:x?}");

    let result = results[1].as_sym().unwrap();
    // It's not entirely clear why we have seen two different demangled
    // symbols, but they both seem legit.
    assert!(
        result.name == "blazesym::symbolize::symbolizer::Symbolizer::symbolize"
            || result.name == "<blazesym::symbolize::symbolizer::Symbolizer>::symbolize",
        "{}",
        result.name
    );
}

/// Check that we can normalize addresses in an ELF shared object.
#[test]
fn normalize_elf_addr() {
    fn test(so: &str) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data").join(so);
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        assert_eq!(meta.elf().unwrap().path, test_so);

        let elf = symbolize::Elf::new(test_so);
        let src = symbolize::Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::FileOffset(output.0))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");

        let results = symbolizer
            .symbolize(&src, symbolize::Input::FileOffset(&[output.0]))
            .unwrap();
        assert_eq!(results.len(), 1);

        let sym = results[0].as_sym().unwrap();
        assert_eq!(sym.name, "the_answer");
    }

    test("libtest-so.so");
    test("libtest-so-no-separate-code.so");
}


/// Check that we can enable/disable the reading of build IDs.
#[test]
fn normalize_build_id_rading() {
    fn test(read_build_ids: bool) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = Normalizer::builder()
            .enable_build_ids(read_build_ids)
            .build();
        let normalized = normalizer
            .normalize_user_addrs_sorted([the_answer_addr as Addr].as_slice(), Pid::Slf)
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        let elf = meta.elf().unwrap();
        assert_eq!(elf.path, test_so);
        if read_build_ids {
            let expected = read_elf_build_id(&test_so).unwrap().unwrap();
            assert_eq!(elf.build_id.as_deref().unwrap(), &expected);
        } else {
            assert_eq!(elf.build_id, None);
        }
    }

    test(true);
    test(false);
}


/// Check that we can look up an address.
#[test]
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

        let result = &results[0];
        assert_eq!(result.addr, 0x2000100);
        assert_ne!(result.file_offset, None);
        assert_eq!(
            result.obj_file_name.as_deref().unwrap(),
            src.path().unwrap()
        );
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = inspect::Source::Elf(inspect::Elf::new(test_dwarf));
    let () = test(src);

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let mut elf = inspect::Elf::new(test_elf);
    assert!(elf.debug_syms);
    elf.debug_syms = false;
    let src = inspect::Source::Elf(elf);
    let () = test(src);
}


/// Read four bytes at the given `offset` in the file identified by `path`.
fn read_4bytes_at(path: &Path, offset: u64) -> [u8; 4] {
    let offset = offset as usize;
    let content = read_file(path).unwrap();
    let slice = &content[offset..offset + 4];
    <[u8; 4]>::try_from(slice).unwrap()
}


/// Check that we can correctly retrieve the file offset in an ELF file.
#[test]
fn inspect_file_offset_elf() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&["dummy"], &src)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert_ne!(result.file_offset, None);
    let bytes = read_4bytes_at(src.path().unwrap(), result.file_offset.unwrap());
    assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
}


/// Check that we can iterate over all symbols in an ELF file.
#[test]
fn inspect_all_symbols() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let syms = inspector
        .for_each(&src, HashSet::<String>::new(), |mut syms, sym| {
            let _inserted = syms.insert(sym.name.to_string());
            syms
        })
        .unwrap();

    assert!(syms.contains("main"));
    assert!(syms.contains("factorial"));
    assert!(syms.contains("factorial_wrapper"));
    assert!(syms.contains("factorial_inline_test"));
}
