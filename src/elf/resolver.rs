use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

#[cfg(feature = "dwarf")]
use crate::dwarf::DwarfResolver;
use crate::file_cache::FileCache;
use crate::inspect::FindAddrOpts;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::log::debug;
use crate::log::warn;
use crate::once::OnceCell;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::Symbolize;
use crate::symbolize::TranslateFileOffset;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::Mmap;
use crate::Result;

use super::debug_link::debug_link_crc32;
use super::debug_link::read_debug_link;
use super::ElfParser;

#[derive(Clone, Debug)]
enum ElfBackend {
    #[cfg(feature = "dwarf")]
    Dwarf(Rc<DwarfResolver>), // ELF w/ DWARF
    Elf(Rc<ElfParser>), // ELF w/o DWARF
}


#[derive(Clone, Debug)]
pub(crate) enum Dwarf {
    /// A "direct" resolver.
    Resolver(Rc<ElfResolver>),
    /// A debug link.
    Link {
        /// The ELF parser of the linking entity.
        parser: Rc<ElfParser>,
        /// The ELF resolver for the link destination.
        resolver: Rc<ElfResolver>,
    },
}

impl Dwarf {
    #[inline]
    pub fn resolver(&self) -> &Rc<ElfResolver> {
        match self {
            Self::Resolver(resolver) | Self::Link { resolver, .. } => resolver,
        }
    }
}


/// Find a debug file in a list of default directories.
///
/// `linker` is the path to the file containing the debug link.
///
/// # Notes
/// This function ignores any errors encountered.
// TODO: Ideally this discovery functionality would be provided in the
//       form of an iterator for better testability.
fn find_debug_file(file: &OsStr, linker: &Path) -> Option<PathBuf> {
    macro_rules! return_if_exists {
        ($path:ident) => {
            if $path.exists() {
                debug!("found debug info at {}", $path.display());
                return Some($path)
            }
        };
    }

    // First check known fixed locations.
    let path = Path::new("/lib/debug/").join(file);
    return_if_exists!(path);

    let path = Path::new("/usr/lib/debug/").join(file);
    return_if_exists!(path);

    // Next check others that depend on the absolute `linker` (which may
    // not be retrievable).
    // TODO: Different heuristics may be possible here? Users
    //       could want to pass in a directory instead?
    if let Ok(mut path) = linker.canonicalize() {
        let () = path.set_file_name(file);
        return_if_exists!(path);

        let mut ancestors = path.ancestors();
        // Remove the file name, as we will always append it anyway.
        let _ = ancestors.next();

        for ancestor in ancestors {
            let mut components = ancestor.components();
            // Remove the root directory to make the path relative. That
            // allows for joining to work as expected.
            let _ = components.next();

            // If the remaining path is empty we'd basically just cover
            // one of the "fixed" cases above, so we can stop.
            if components.as_path().as_os_str().is_empty() {
                break
            }

            let path = Path::new("/usr/lib/debug/")
                .join(components.as_path())
                .join(file);
            return_if_exists!(path);
        }
    }
    None
}


fn create_debug_resolver(parser: Rc<ElfParser>) -> Result<Dwarf> {
    let debug_syms = true;

    if let Some((file, checksum)) = read_debug_link(&parser)? {
        match find_debug_file(file, parser.path()) {
            Some(path) => {
                let mmap = Mmap::builder().open(&path).with_context(|| {
                    format!("failed to open debug link destination `{}`", path.display())
                })?;
                let crc = debug_link_crc32(&mmap);
                if crc != checksum {
                    return Err(Error::with_invalid_data(format!(
                        "debug link destination `{}` checksum does not match \
                         expected one: {crc:x} (actual) != {checksum:x} (expected)",
                        path.display()
                    )))
                }

                let dst_parser = Rc::new(ElfParser::from_mmap(mmap, path));
                let resolver = ElfResolver::from_parser(dst_parser.clone(), debug_syms)?;
                let dwarf = Dwarf::Link {
                    parser,
                    resolver: Rc::new(resolver),
                };
                return Ok(dwarf)
            }
            None => warn!(
                "debug link references destination `{}` which was not found in any known location",
                Path::new(file).display(),
            ),
        }
    }

    let resolver = ElfResolver::from_parser(parser, debug_syms)?;
    let dwarf = Dwarf::Resolver(Rc::new(resolver));
    Ok(dwarf)
}


/// Resolver data associated with a specific source.
#[derive(Clone, Debug)]
pub(crate) struct ElfResolverData {
    /// A bare-bones ELF resolver.
    pub elf: OnceCell<Rc<ElfResolver>>,
    /// An ELF resolver with debug information enabled.
    pub dwarf: OnceCell<Dwarf>,
}

impl FileCache<ElfResolverData> {
    pub(crate) fn elf_resolver<'slf>(
        &'slf self,
        path: &Path,
        debug_syms: bool,
    ) -> Result<&'slf Rc<ElfResolver>> {
        let (file, cell) = self.entry(path)?;
        let data = if let Some(data) = cell.get() {
            if debug_syms {
                let _dwarf = data.dwarf.get_or_try_init(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `dwarf` part of it, the
                    //         `elf` part *must* be present.
                    let parser = data.elf.get().unwrap().parser().clone();
                    create_debug_resolver(parser)
                })?;
            } else {
                let _resolver = data.elf.get_or_try_init(|| {
                    // SANITY: We *know* a `ElfResolverData` object is
                    //         present and given that we are
                    //         initializing the `elf` part of it, the
                    //         `dwarf` part *must* be present.
                    let parser = match data.dwarf.get().unwrap() {
                        Dwarf::Resolver(resolver) => resolver.parser().clone(),
                        Dwarf::Link {
                            parser,
                            resolver: _,
                        } => parser.clone(),
                    };
                    let resolver = ElfResolver::from_parser(parser, debug_syms)?;
                    let resolver = Rc::new(resolver);
                    Result::<_, Error>::Ok(resolver)
                })?;
            };
            data
        } else {
            let parser = Rc::new(ElfParser::open_file(file, path)?);

            let data = if debug_syms {
                ElfResolverData {
                    dwarf: OnceCell::from(create_debug_resolver(parser)?),
                    elf: OnceCell::new(),
                }
            } else {
                let resolver = ElfResolver::from_parser(parser, debug_syms)?;
                ElfResolverData {
                    dwarf: OnceCell::new(),
                    elf: OnceCell::from(Rc::new(resolver)),
                }
            };
            cell.get_or_init(|| data)
        };

        let resolver = if debug_syms {
            data.dwarf.get().map(Dwarf::resolver)
        } else {
            data.elf.get()
        };
        // SANITY: We made sure to create the desired resolver above.
        Ok(resolver.unwrap())
    }

    /// Create a new [`ElfResolver`] given a shared [`ElfParser`].
    ///
    /// This functionality is a method (it doesn't have to be) on `FileCache`
    /// (it conceptually doesn't have to belong to it) in an attempt to force
    /// `ElfResolver` construction through `FileCache` objects, as that is the
    /// intended usage anywhere outside this module. This way, we make it a very
    /// intentional decision to create an `ElfResolver` circumventing the
    /// `FileCache` as it allows us to keep the [`ElfResolver::from_parser`]
    /// constructor as restricted as possible.
    #[inline]
    pub(crate) fn elf_resolver_from_parser(
        &self,
        parser: Rc<ElfParser>,
        debug_syms: bool,
    ) -> Result<ElfResolver> {
        ElfResolver::from_parser(parser, debug_syms)
    }
}


/// The symbol resolver for a single ELF file.
pub struct ElfResolver {
    backend: ElfBackend,
}

impl ElfResolver {
    /// Create a `ElfResolver` that loads data from the provided file.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let parser = Rc::new(ElfParser::open(path).unwrap());
        Self::from_parser(parser, true)
    }

    fn from_parser(parser: Rc<ElfParser>, _debug_syms: bool) -> Result<Self> {
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

    fn parser(&self) -> &Rc<ElfParser> {
        match &self.backend {
            #[cfg(feature = "dwarf")]
            ElfBackend::Dwarf(dwarf) => dwarf.parser(),
            ElfBackend::Elf(parser) => parser,
        }
    }

    /// Retrieve the path to the ELF file represented by this resolver.
    pub(crate) fn path(&self) -> Option<&Path> {
        self.parser().path()
    }
}

impl Symbolize for ElfResolver {
    #[cfg_attr(feature = "tracing", crate::log::instrument(fields(addr = format_args!("{addr:#x}"))))]
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
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

impl TranslateFileOffset for ElfResolver {
    fn file_offset_to_virt_offset(&self, file_offset: u64) -> Result<Option<Addr>> {
        let parser = self.parser();
        parser.file_offset_to_virt_offset(file_offset)
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
            ElfBackend::Dwarf(_) => write!(
                f,
                "DWARF {}",
                self.path().unwrap_or_else(|| Path::new("")).display()
            ),
            ElfBackend::Elf(_) => write!(
                f,
                "ELF {}",
                self.path().unwrap_or_else(|| Path::new("")).display()
            ),
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
            .join("test-stable-addrs.bin");

        let parser = Rc::new(ElfParser::open(&path).unwrap());
        let resolver = ElfResolver::from_parser(parser.clone(), false).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("ELF"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addrs.bin"), "{dbg}");

        let resolver = ElfResolver::from_parser(parser, true).unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.starts_with("DWARF"), "{dbg}");
        assert!(dbg.ends_with("test-stable-addrs.bin"), "{dbg}");
    }

    /// Check that we fail finding an offset for an address not
    /// representing a symbol in an ELF file.
    #[test]
    fn addr_without_offset() {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin");
        let parser = ElfParser::open(&path).unwrap();

        assert_eq!(parser.find_file_offset(0x0).unwrap(), None);
        assert_eq!(parser.find_file_offset(0xffffffffffffffff).unwrap(), None);
    }
}
