use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
#[cfg(test)]
use std::fs::File;
use std::io::BufRead as _;
use std::io::BufReader;
use std::io::Read;
use std::ops::ControlFlow;
use std::path::Path;
use std::path::PathBuf;

use crate::inspect::FindAddrOpts;
use crate::inspect::ForEachFn;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::once::OnceCell;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::symbolize::Symbolize;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Addr;
use crate::Result;
use crate::SymType;

pub const KALLSYMS: &str = "/proc/kallsyms";
const DFL_KSYM_CAP: usize = 200000;

#[derive(Debug)]
struct Kfunc {
    addr: Addr,
    name: Box<str>,
}

impl Kfunc {
    fn resolve(&self, _addr: Addr, _opts: &FindSymOpts) -> Result<ResolvedSym<'_>> {
        let Kfunc { name, addr } = self;
        let sym = ResolvedSym {
            name,
            addr: *addr,
            // There is no size information in kallsyms.
            size: None,
            // Kernel symbols don't carry any source code language
            // information.
            lang: SrcLang::Unknown,
            // kallsyms doesn't have source code location information.
            code_info: None,
            inlined: Box::new([]),
        };
        Ok(sym)
    }
}

impl<'kfunc> From<&'kfunc Kfunc> for SymInfo<'kfunc> {
    fn from(other: &'kfunc Kfunc) -> Self {
        let Kfunc { name, addr } = other;
        SymInfo {
            name: Cow::Borrowed(name),
            addr: *addr,
            size: 0,
            sym_type: SymType::Function,
            file_offset: None,
            obj_file_name: None,
        }
    }
}


/// The symbol resolver for /proc/kallsyms.
///
/// The users should provide the path of kallsyms, so you can provide
/// a copy from other devices.
pub(crate) struct KSymResolver {
    /// An index over `syms` that is sorted by name.
    by_name_idx: OnceCell<Box<[usize]>>,
    syms: Box<[Kfunc]>,
    file_name: PathBuf,
}

impl KSymResolver {
    #[cfg(test)]
    fn load_file_name(path: &Path) -> Result<Self> {
        let f = File::open(path)?;
        Self::load_from_reader(f, path)
    }

    pub fn load_from_reader<R>(reader: R, path: &Path) -> Result<Self>
    where
        R: Read,
    {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut syms = Vec::with_capacity(DFL_KSYM_CAP);

        loop {
            let () = line.clear();
            let sz = reader.read_line(&mut line)?;
            if sz == 0 {
                break
            }

            let mut tokens = line.split_ascii_whitespace();

            #[rustfmt::skip]
            let (addr, name) = {
                let addr = if let Some(token) = tokens.next() { token } else { continue };
                let _typ = if let Some(token) = tokens.next() { token } else { continue };
                let name = if let Some(token) = tokens.next() { token } else { continue };
                (addr, name)
            };

            if let Ok(addr) = Addr::from_str_radix(addr, 16) {
                if addr == 0 {
                    continue
                }
                syms.push(Kfunc {
                    addr,
                    name: Box::from(name),
                });
            }
        }

        syms.sort_by(|a, b| a.addr.cmp(&b.addr));

        let slf = Self {
            syms: syms.into_boxed_slice(),
            by_name_idx: OnceCell::new(),
            file_name: path.to_path_buf(),
        };
        Ok(slf)
    }

    fn find_ksym(&self, addr: Addr) -> Result<&Kfunc, Reason> {
        let result = find_match_or_lower_bound_by_key(&self.syms, addr, |kfunc: &Kfunc| kfunc.addr)
            .and_then(|idx| self.syms.get(idx));
        match result {
            Some(sym) => Ok(sym),
            None => {
                if self.syms.is_empty() {
                    Err(Reason::MissingSyms)
                } else {
                    Err(Reason::UnknownAddr)
                }
            }
        }
    }

    fn create_by_name_idx(syms: &[Kfunc]) -> Vec<usize> {
        let mut by_name_idx = (0..syms.len()).collect::<Vec<_>>();
        let () = by_name_idx.sort_by(|idx1, idx2| {
            let sym1 = &syms[*idx1];
            let sym2 = &syms[*idx2];
            sym1.name
                .cmp(&sym2.name)
                .then_with(|| sym1.addr.cmp(&sym2.addr))
        });

        by_name_idx
    }

    /// Retrieve the path to the kallsyms file used by this resolver.
    pub(crate) fn file_name(&self) -> &Path {
        &self.file_name
    }
}

impl Symbolize for KSymResolver {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        match self.find_ksym(addr) {
            Ok(ksym) => {
                let sym = ksym.resolve(addr, opts)?;
                Ok(Ok(sym))
            }
            Err(reason) => Ok(Err(reason)),
        }
    }
}

impl Inspect for KSymResolver {
    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        if let SymType::Variable = opts.sym_type {
            return Ok(Vec::new())
        }

        let by_name_idx = self.by_name_idx.get_or_init(|| {
            let by_name_idx = Self::create_by_name_idx(&self.syms);
            let by_name_idx = by_name_idx.into_boxed_slice();
            by_name_idx
        });

        let result =
            find_match_or_lower_bound_by_key(by_name_idx, name, |idx| &self.syms[*idx].name);
        let syms = if let Some(idx) = result {
            by_name_idx[idx..]
                .iter()
                .map(|idx| SymInfo::from(&self.syms[*idx]))
                .collect()
        } else {
            Vec::new()
        };
        Ok(syms)
    }

    fn for_each(&self, opts: &FindAddrOpts, f: &mut ForEachFn<'_>) -> Result<()> {
        if let SymType::Variable = opts.sym_type {
            return Ok(())
        }

        for ksym in self.syms.iter() {
            let sym = SymInfo::from(ksym);
            if let ControlFlow::Break(()) = f(&sym) {
                return Ok(())
            }
        }
        Ok(())
    }
}

impl Debug for KSymResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "KSymResolver")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nightly")]
    use test::Bencher;

    use test_log::test;
    use test_tag::tag;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[tag(miri)]
    #[test]
    fn debug_repr() {
        let resolver = KSymResolver {
            syms: Box::default(),
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };
        assert_ne!(format!("{resolver:?}"), "");

        let kfunc = Kfunc {
            addr: 0x1337,
            name: Box::from("3l33t"),
        };
        assert_ne!(format!("{kfunc:?}"), "");
    }

    /// Check that we can use a `KSymResolver` to find symbols.
    #[test]
    fn ksym_resolver_load_find() {
        let result = KSymResolver::load_file_name(Path::new(KALLSYMS));
        let resolver = match result {
            Ok(resolver) => resolver,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("failed to instantiate KSymResolver: {err}"),
        };

        assert!(
            resolver.syms.len() > 10000,
            "kallsyms seems to be unavailable or with all 0 addresses. (Check {KALLSYMS})"
        );

        let ensure_addr_for_name = |name, addr| {
            let opts = FindAddrOpts {
                offset_in_file: false,
                sym_type: SymType::Function,
            };
            let found = resolver.find_addr(name, &opts).unwrap();
            assert!(
                found.iter().any(|x| x.addr == addr),
                "{addr:#x} {found:#x?}"
            );
        };


        // Find the address of the symbol placed at the middle
        let sym = &resolver.syms[resolver.syms.len() / 2];
        let addr = sym.addr;
        let found = resolver
            .find_sym(addr, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        ensure_addr_for_name(found.name, addr);

        // 0 is an invalid address.  We remove all symbols with 0 as
        // their address from the list.
        assert!(resolver.find_sym(0, &FindSymOpts::Basic).unwrap().is_err());

        // Find the address of the last symbol
        let sym = &resolver.syms.last().unwrap();
        let addr = sym.addr;
        let found = resolver
            .find_sym(addr, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        ensure_addr_for_name(found.name, addr);

        let found = resolver
            .find_sym(addr + 1, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        // Should still find the previous symbol, which is the last one.
        ensure_addr_for_name(found.name, addr);
    }

    #[tag(miri)]
    #[test]
    fn find_ksym() {
        let resolver = KSymResolver {
            syms: vec![
                Kfunc {
                    addr: 0x123,
                    name: Box::from("1"),
                },
                Kfunc {
                    addr: 0x123,
                    name: Box::from("1.5"),
                },
                Kfunc {
                    addr: 0x1234,
                    name: Box::from("2"),
                },
                Kfunc {
                    addr: 0x12345,
                    name: Box::from("3"),
                },
            ]
            .into_boxed_slice(),
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };

        // The address is less than the smallest address of all symbols.
        assert!(resolver.find_ksym(1).is_err());

        // The address match symbols exactly (the first address.)
        let sym = resolver.find_ksym(0x123).unwrap();
        assert_eq!(sym.addr, 0x123);
        assert_eq!(&*sym.name, "1");

        // The address is in between two symbols (the first address.)
        let sym = resolver.find_ksym(0x124).unwrap();
        assert_eq!(sym.addr, 0x123);
        assert_eq!(&*sym.name, "1.5");

        // The address match symbols exactly.
        let sym = resolver.find_ksym(0x1234).unwrap();
        assert_eq!(sym.addr, 0x1234);
        assert_eq!(&*sym.name, "2");

        // The address is in between two symbols.
        let sym = resolver.find_ksym(0x1235).unwrap();
        assert_eq!(sym.addr, 0x1234);
        assert_eq!(&*sym.name, "2");

        // The address match symbols exactly (the biggest address.)
        let sym = resolver.find_ksym(0x12345).unwrap();
        assert_eq!(sym.addr, 0x12345);
        assert_eq!(&*sym.name, "3");

        // The address is bigger than the biggest address of all symbols.
        let sym = resolver.find_ksym(0x1234568).unwrap();
        assert_eq!(sym.addr, 0x12345);
        assert_eq!(&*sym.name, "3");
    }

    /// Check that we can correctly iterate over all symbols.
    #[tag(miri)]
    #[test]
    fn symbol_iteration() {
        let resolver = KSymResolver {
            syms: vec![
                Kfunc {
                    addr: 0x123,
                    name: Box::from("j"),
                },
                Kfunc {
                    addr: 0x123,
                    name: Box::from("b"),
                },
                Kfunc {
                    addr: 0x1234,
                    name: Box::from("a"),
                },
                Kfunc {
                    addr: 0x12345,
                    name: Box::from("z"),
                },
            ]
            .into_boxed_slice(),
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };

        let opts = FindAddrOpts::default();
        let mut syms = Vec::with_capacity(resolver.syms.len());
        let () = resolver
            .for_each(&opts, &mut |sym| {
                let () = syms.push(sym.name.to_string());
                ControlFlow::Continue(())
            })
            .unwrap();
        let () = syms.sort();
        assert_eq!(syms, vec!["a", "b", "j", "z"]);
    }

    /// Check that [`KSymResolver::find_addr`] and
    /// [`KSymResolver::for_each`] behave as expected for variable
    /// inquiries.
    #[tag(miri)]
    #[test]
    fn variable_operations() {
        let resolver = KSymResolver {
            syms: vec![
                Kfunc {
                    addr: 0x123,
                    name: Box::from("j"),
                },
                Kfunc {
                    addr: 0x123,
                    name: Box::from("b"),
                },
                Kfunc {
                    addr: 0x1234,
                    name: Box::from("a"),
                },
                Kfunc {
                    addr: 0x12345,
                    name: Box::from("z"),
                },
            ]
            .into_boxed_slice(),
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };

        let opts = FindAddrOpts {
            sym_type: SymType::Variable,
            ..Default::default()
        };
        let result = resolver.find_addr("a", &opts).unwrap();
        assert_eq!(result, Vec::new());

        let () = resolver
            .for_each(&opts, &mut |_sym| unreachable!())
            .unwrap();
    }

    /// Benchmark the parsing a kallsyms file.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_parse_kallsyms(b: &mut Bencher) {
        use std::fs::read;
        use std::hint::black_box;

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("kallsyms");
        let kallsyms = read(&path).unwrap();

        let () = b.iter(|| {
            let _resolver = black_box(
                KSymResolver::load_from_reader(black_box(&mut kallsyms.as_slice()), &path).unwrap(),
            );
        });
    }
}
