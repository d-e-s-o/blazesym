use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::ops::Deref as _;
use std::path::Path;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::file_cache::FileCache;
use crate::inspect::FindAddrOpts;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::once::OnceCell;
use crate::symbolize::FindSymOpts;
use crate::symbolize::IntSym;
use crate::symbolize::Reason;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::Error;
use crate::Result;

use super::ElfParser;

#[derive(Clone, Debug)]
enum ElfBackend {
    #[cfg(feature = "dwarf")]
    Dwarf(Rc<DwarfResolver>), // ELF w/ DWARF
    Elf(Rc<ElfParser>), // ELF w/o DWARF
}

#[derive(Clone, Debug)]
pub(crate) enum ResolverType<'res> {
    /// A DWARF resolver.
    #[cfg(feature = "dwarf")]
    Dwarf(&'res Rc<ElfResolver>),
    /// An ELF resolver.
    Elf(&'res Rc<ElfResolver>),
}

impl<'res> ResolverType<'res> {
    /// Retrieve the [`ElfParser`] underlying either of the resolvers.
    #[inline]
    pub fn elf_parser(&self) -> &ElfParser {
        match self {
            #[cfg(feature = "dwarf")]
            ResolverType::Dwarf(resolver) => resolver.parser(),
            ResolverType::Elf(resolver) => resolver.parser(),
        }
    }

    #[inline]
    pub fn to_owned(&self) -> Rc<dyn Symbolize> {
        match self {
            #[cfg(feature = "dwarf")]
            ResolverType::Dwarf(resolver) => Rc::clone(resolver) as Rc<dyn Symbolize>,
            ResolverType::Elf(resolver) => Rc::clone(resolver) as Rc<dyn Symbolize>,
        }
    }

    #[inline]
    pub fn as_symbolize(&self) -> &'res dyn Symbolize {
        match self {
            #[cfg(feature = "dwarf")]
            ResolverType::Dwarf(resolver) => Rc::deref(resolver) as &dyn Symbolize,
            ResolverType::Elf(resolver) => Rc::deref(resolver) as &dyn Symbolize,
        }
    }

    #[inline]
    pub fn as_inspect(&self) -> &'res dyn Inspect {
        match self {
            #[cfg(feature = "dwarf")]
            ResolverType::Dwarf(resolver) => Rc::deref(resolver) as &dyn Inspect,
            ResolverType::Elf(resolver) => Rc::deref(resolver) as &dyn Inspect,
        }
    }
}


/// Resolver data associated with a specific source.
#[derive(Clone, Debug)]
pub(crate) struct ElfResolverData {
    /// A bare-bones ELF resolver.
    pub elf: OnceCell<Rc<ElfResolver>>,
    /// An ELF resolver with debug information enabled.
    pub dwarf: OnceCell<Rc<ElfResolver>>,
}

impl FileCache<ElfResolverData> {
    pub(crate) fn elf_resolver<'slf>(
        &'slf self,
        path: &Path,
        debug_syms: bool,
    ) -> Result<ResolverType<'slf>> {
        let (file, cell) = self.entry(path)?;
        let resolver = if let Some(data) = cell.get() {
            if debug_syms {
                data.dwarf.get_or_try_init(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `dwarf` part of it, the
                    //         `elf` part *must* be present.
                    let parser = data.elf.get().unwrap().parser().clone();
                    let resolver = ElfResolver::from_parser(parser, debug_syms)?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?
            } else {
                data.elf.get_or_try_init(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `elf` part of it, the
                    //         `dwarf` part *must* be present.
                    let parser = data.dwarf.get().unwrap().parser().clone();
                    let resolver = ElfResolver::from_parser(parser, debug_syms)?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?
            }
            .clone()
        } else {
            let parser = Rc::new(ElfParser::open_file(file, path)?);
            let resolver = ElfResolver::from_parser(parser, debug_syms)?;
            Rc::new(resolver)
        };

        let data = cell.get_or_init(|| {
            if debug_syms {
                ElfResolverData {
                    dwarf: OnceCell::from(resolver),
                    elf: OnceCell::new(),
                }
            } else {
                ElfResolverData {
                    dwarf: OnceCell::new(),
                    elf: OnceCell::from(resolver),
                }
            }
        });

        let resolver = if debug_syms {
            // SANITY: We made sure to create the desired resolver above.
            ResolverType::Dwarf(data.dwarf.get().unwrap())
        } else {
            // SANITY: We made sure to create the desired resolver above.
            ResolverType::Elf(data.elf.get().unwrap())
        };
        Ok(resolver)
    }
}


/// The symbol resolver for a single ELF file.
pub struct ElfResolver {
    backend: ElfBackend,
}

impl ElfResolver {
    pub(crate) fn from_parser(parser: Rc<ElfParser>, _debug_syms: bool) -> Result<Self> {
        #[cfg(feature = "dwarf")]
        let backend = if _debug_syms {
            let dwarf = DwarfResolver::from_parser(parser)?;
            let backend = ElfBackend::Dwarf(Rc::new(dwarf));
            backend
        } else {
            ElfBackend::Elf(parser)
        };

        #[cfg(not(feature = "dwarf"))]
        let backend = ElfBackend::Elf(parser);

        let resolver = ElfResolver { backend };
        Ok(resolver)
    }

    pub(crate) fn parser(&self) -> &Rc<ElfParser> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.parser(),
            ElfBackend::Elf(parser) => parser,
        }
    }

    /// Retrieve the path to the ELF file represented by this resolver.
    pub(crate) fn path(&self) -> &Path {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.parser().path(),
            ElfBackend::Elf(parser) => parser.path(),
        }
    }
}

impl Symbolize for ElfResolver {
    #[cfg_attr(feature = "tracing", crate::log::instrument(fields(addr = format_args!("{addr:#x}"))))]
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<IntSym<'_>, Reason>> {
        #[cfg(feature = "dwarf")]
        if let ElfBackend::Dwarf(dwarf) = &self.backend {
            if let Ok(sym) = dwarf.find_sym(addr, opts)? {
                return Ok(Ok(sym))
            }
        }

        let parser = self.parser();
        let result = parser.find_sym(addr, opts)?;
        Ok(result)
    }
}

impl Inspect for ElfResolver {
    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        #[cfg(feature = "dwarf")]
        if let ElfBackend::Dwarf(dwarf) = &self.backend {
            let syms = dwarf.find_addr(name, opts)?;
            if !syms.is_empty() {
                return Ok(syms)
            }
        }

        let parser = self.parser();
        let syms = parser.find_addr(name, opts)?;
        Ok(syms)
    }

    fn for_each(&self, opts: &FindAddrOpts, f: &mut dyn FnMut(&SymInfo<'_>)) -> Result<()> {
        let parser = self.parser();
        parser.deref().for_each(opts, f)
    }
}

impl Debug for ElfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(_) => write!(f, "DWARF {}", self.path().display()),
            ElfBackend::Elf(_) => write!(f, "ELF {}", self.path().display()),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.bin");

        let parser = Rc::new(ElfParser::open(&path).unwrap());
        let resolver = ElfResolver::from_parser(parser.clone(), false).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("ELF"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addresses.bin"), "{dbg}");

        let resolver = ElfResolver::from_parser(parser, true).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("DWARF"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addresses.bin"), "{dbg}");
    }

    /// Check that we fail finding an offset for an address not
    /// representing a symbol in an ELF file.
    #[test]
    fn addr_without_offset() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");
        let parser = ElfParser::open(&path).unwrap();

        assert_eq!(parser.find_file_offset(0x0).unwrap(), None);
        assert_eq!(parser.find_file_offset(0xffffffffffffffff).unwrap(), None);
    }
}
