use std::cell::OnceCell;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::elf::ElfResolverData;
use crate::file_cache::FileCache;
use crate::inspect::Inspect;
use crate::insert_map::InsertMap;
use crate::pathlike::PathLike;
use crate::util::OnceCellExt as _;
use crate::ErrorExt as _;
use crate::Result;

use super::kaslr::derive_stext_kaslr_offset;
use super::kaslr::find_kcore_kaslr_offset;
use super::ksym::KsymResolver;
use super::DepmodIndex;
use super::ModMap;
use super::MODULES;


/// A cache for kernel related data.
#[derive(Debug)]
pub(crate) struct KernelCache {
    /// Cache of ELF files.
    elf_cache: FileCache<ElfResolverData>,
    /// `/proc/kallsyms` cache.
    ksym_cache: FileCache<Rc<KsymResolver>>,
    /// The system's module map (`/proc/modules`).
    modmap: OnceCell<ModMap>,
    /// The system's depmod index.
    depmod: OnceCell<DepmodIndex>,
    /// The system-wide KASLR offset as read from `/proc/kcore`'s
    /// `VMCOREINFO` note. `None` once initialized means kcore was
    /// unavailable or did not contain the note.
    kcore_kaslr_offset: OnceCell<Option<u64>>,
    /// KASLR offsets derived via `_stext` subtraction, keyed by the
    /// `(kallsyms, vmlinux)` path pair the derivation ran against. The
    /// stored value is `None` when derivation was attempted but `_stext`
    /// was missing from one of the inputs (cached so we don't redo the
    /// symbol lookups on the next call).
    derived_kaslr_offset: InsertMap<(PathBuf, PathBuf), Option<u64>>,
    #[cfg(feature = "dwarf")]
    debug_dirs: Rc<[PathBuf]>,
}

impl KernelCache {
    #[cfg(feature = "dwarf")]
    pub fn new(debug_dirs: Rc<[PathBuf]>) -> Self {
        Self {
            elf_cache: FileCache::default(),
            ksym_cache: FileCache::default(),
            modmap: OnceCell::default(),
            depmod: OnceCell::default(),
            kcore_kaslr_offset: OnceCell::default(),
            derived_kaslr_offset: InsertMap::new(),
            debug_dirs,
        }
    }

    #[cfg(not(feature = "dwarf"))]
    pub fn new() -> Self {
        Self {
            elf_cache: FileCache::default(),
            ksym_cache: FileCache::default(),
            modmap: OnceCell::default(),
            depmod: OnceCell::default(),
            kcore_kaslr_offset: OnceCell::default(),
            derived_kaslr_offset: InsertMap::new(),
        }
    }

    fn maybe_debug_dirs(&self, debug_syms: bool) -> Option<&[PathBuf]> {
        #[cfg(feature = "dwarf")]
        let debug_dirs = &self.debug_dirs;
        #[cfg(not(feature = "dwarf"))]
        let debug_dirs = &[];
        debug_syms.then_some(debug_dirs)
    }

    pub fn elf_resolver<'slf>(
        &'slf self,
        path: &dyn PathLike,
        debug_syms: bool,
    ) -> Result<&'slf Rc<ElfResolver>> {
        self.elf_cache
            .elf_resolver(path, self.maybe_debug_dirs(debug_syms))
    }

    fn create_ksym_resolver(&self, path: &Path, file: &File) -> Result<Rc<KsymResolver>> {
        let resolver = KsymResolver::load_from_reader(file, path)?;
        let resolver = Rc::new(resolver);
        Ok(resolver)
    }

    pub fn ksym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf Rc<KsymResolver>> {
        let (file, cell) = self.ksym_cache.entry(path)?;
        let resolver = cell.get_or_try_init_(|| self.create_ksym_resolver(path, file))?;
        Ok(resolver)
    }

    pub fn modmap(&self) -> Result<&ModMap> {
        self.modmap
            .get_or_try_init_(|| ModMap::new(Path::new(MODULES)))
    }

    #[cfg(linux)]
    pub fn depmod(&self) -> Result<&DepmodIndex> {
        self.depmod
            .get_or_try_init_(DepmodIndex::with_system_default)
            .context("failed to read system depmod information")
    }

    #[cfg(not(linux))]
    pub fn depmod(&self) -> Result<&DepmodIndex> {
        unimplemented!()
    }

    pub fn kaslr_offset(
        &self,
        kallsyms: Option<&Path>,
        vmlinux: Option<&Path>,
        ksym_resolver: Option<&dyn Inspect>,
        vmlinux_resolver: Option<&dyn Inspect>,
    ) -> Result<u64> {
        // The system-wide kcore offset always wins when present; it's the
        // authoritative value and doesn't depend on the input pair.
        let kcore = self
            .kcore_kaslr_offset
            .get_or_try_init_(find_kcore_kaslr_offset)
            .context("failed to query system KASLR offset")?;
        if let Some(offset) = kcore {
            return Ok(*offset)
        }

        // Fall back to deriving the offset from the (kallsyms, vmlinux) pair.
        // Cached keyed on that pair: different inputs can yield different
        // offsets, so a single OnceCell would be incorrect.
        let derived = match (kallsyms, vmlinux, ksym_resolver, vmlinux_resolver) {
            (Some(ksym_path), Some(vmlinux_path), Some(ksym), Some(vmlinux)) => self
                .derived_kaslr_offset
                .get_or_insert((ksym_path.to_path_buf(), vmlinux_path.to_path_buf()), || {
                    derive_stext_kaslr_offset(ksym, vmlinux)
                }),
            _ => &None,
        };
        Ok(derived.unwrap_or(0))
    }

    #[cfg(test)]
    pub fn set_modmap(&self, modmap: ModMap) {
        self.modmap.set(modmap).unwrap()
    }

    #[cfg(test)]
    pub fn set_depmod(&self, depmod: DepmodIndex) {
        self.depmod.set(depmod).unwrap()
    }

    #[cfg(test)]
    fn set_kcore_kaslr_offset(&self, offset: Option<u64>) {
        self.kcore_kaslr_offset.set(offset).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::borrow::Cow;
    use std::cell::Cell;

    use crate::inspect::FindAddrOpts;
    use crate::inspect::ForEachFn;
    use crate::inspect::SymInfo;
    use crate::Addr;
    use crate::SymType;


    /// Stub [`Inspect`] resolver that reports a single symbol at a fixed
    /// address and counts how many times `find_addr` is invoked.
    #[derive(Debug)]
    struct StubInspect {
        sym: &'static str,
        addr: Option<Addr>,
        find_addr_calls: Cell<usize>,
    }

    impl StubInspect {
        fn new(sym: &'static str, addr: Option<Addr>) -> Self {
            Self {
                sym,
                addr,
                find_addr_calls: Cell::new(0),
            }
        }
    }

    impl Inspect for StubInspect {
        fn find_addr(&self, name: &str, _opts: &FindAddrOpts) -> Result<Vec<SymInfo<'_>>> {
            self.find_addr_calls.set(self.find_addr_calls.get() + 1);
            if name != self.sym {
                return Ok(Vec::new())
            }
            let Some(addr) = self.addr else {
                return Ok(Vec::new())
            };
            Ok(vec![SymInfo {
                name: Cow::Borrowed(self.sym),
                addr,
                size: None,
                sym_type: SymType::Function,
                file_offset: None,
                module: None,
                _non_exhaustive: (),
            }])
        }

        fn for_each(&self, _opts: &FindAddrOpts, _f: &mut ForEachFn<'_>) -> Result<()> {
            unimplemented!()
        }
    }

    fn empty_cache() -> KernelCache {
        #[cfg(feature = "dwarf")]
        {
            KernelCache::new(Rc::new([]))
        }
        #[cfg(not(feature = "dwarf"))]
        {
            KernelCache::new()
        }
    }

    /// Two distinct `(kallsyms, vmlinux)` pairs should each get their own
    /// derived offset; the cache must not collapse them.
    #[test]
    fn derived_offset_keyed_per_pair() {
        let cache = empty_cache();
        cache.set_kcore_kaslr_offset(None);

        let ksym_a = StubInspect::new("_stext", Some(0x4000));
        let vmlinux_a = StubInspect::new("_stext", Some(0x1000));
        let ksym_b = StubInspect::new("_stext", Some(0x8000));
        let vmlinux_b = StubInspect::new("_stext", Some(0x2000));

        let offset_a = cache
            .kaslr_offset(
                Some(Path::new("/kallsyms-a")),
                Some(Path::new("/vmlinux-a")),
                Some(&ksym_a as &dyn Inspect),
                Some(&vmlinux_a as &dyn Inspect),
            )
            .unwrap();
        let offset_b = cache
            .kaslr_offset(
                Some(Path::new("/kallsyms-b")),
                Some(Path::new("/vmlinux-b")),
                Some(&ksym_b as &dyn Inspect),
                Some(&vmlinux_b as &dyn Inspect),
            )
            .unwrap();

        assert_eq!(offset_a, 0x3000);
        assert_eq!(offset_b, 0x6000);
        assert_eq!(cache.derived_kaslr_offset.len(), 2);
    }

    /// Repeated queries for the same pair must not re-run derivation.
    #[test]
    fn derived_offset_reused_for_same_pair() {
        let cache = empty_cache();
        cache.set_kcore_kaslr_offset(None);

        let ksym = StubInspect::new("_stext", Some(0x5000));
        let vmlinux = StubInspect::new("_stext", Some(0x1000));

        let kallsyms_path = Path::new("/kallsyms");
        let vmlinux_path = Path::new("/vmlinux");

        let first = cache
            .kaslr_offset(
                Some(kallsyms_path),
                Some(vmlinux_path),
                Some(&ksym as &dyn Inspect),
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();
        let second = cache
            .kaslr_offset(
                Some(kallsyms_path),
                Some(vmlinux_path),
                Some(&ksym as &dyn Inspect),
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();

        assert_eq!(first, 0x4000);
        assert_eq!(second, 0x4000);
        assert_eq!(ksym.find_addr_calls.get(), 1);
        assert_eq!(vmlinux.find_addr_calls.get(), 1);
        assert_eq!(cache.derived_kaslr_offset.len(), 1);
    }

    /// A populated kcore offset short-circuits derivation regardless of the
    /// pair, and the per-pair cache stays empty.
    #[test]
    fn kcore_offset_shared_across_pairs() {
        let cache = empty_cache();
        cache.set_kcore_kaslr_offset(Some(0xdead0000));

        let ksym = StubInspect::new("_stext", Some(0x5000));
        let vmlinux = StubInspect::new("_stext", Some(0x1000));

        let offset_a = cache
            .kaslr_offset(
                Some(Path::new("/k-a")),
                Some(Path::new("/v-a")),
                Some(&ksym as &dyn Inspect),
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();
        let offset_b = cache
            .kaslr_offset(
                Some(Path::new("/k-b")),
                Some(Path::new("/v-b")),
                Some(&ksym as &dyn Inspect),
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();

        assert_eq!(offset_a, 0xdead0000);
        assert_eq!(offset_b, 0xdead0000);
        assert_eq!(cache.derived_kaslr_offset.len(), 0);
        assert_eq!(ksym.find_addr_calls.get(), 0);
        assert_eq!(vmlinux.find_addr_calls.get(), 0);
    }

    /// Derivation that returns `None` (missing `_stext`) should still be
    /// cached so the symbol lookups aren't repeated.
    #[test]
    fn negative_derivation_cached() {
        let cache = empty_cache();
        cache.set_kcore_kaslr_offset(None);

        let ksym = StubInspect::new("_stext", Some(0x5000));
        let vmlinux = StubInspect::new("_stext", None);

        let kallsyms_path = Path::new("/kallsyms");
        let vmlinux_path = Path::new("/vmlinux");

        let first = cache
            .kaslr_offset(
                Some(kallsyms_path),
                Some(vmlinux_path),
                Some(&ksym as &dyn Inspect),
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();
        let second = cache
            .kaslr_offset(
                Some(kallsyms_path),
                Some(vmlinux_path),
                Some(&ksym as &dyn Inspect),
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();

        assert_eq!(first, 0);
        assert_eq!(second, 0);
        assert_eq!(cache.derived_kaslr_offset.len(), 1);
        // ksym is queried first; vmlinux short-circuits derivation to None,
        // so both are queried exactly once total.
        assert_eq!(ksym.find_addr_calls.get(), 1);
        assert_eq!(vmlinux.find_addr_calls.get(), 1);
    }

    /// Missing kallsyms means we have nothing to derive against; the call
    /// must return 0 without polluting the per-pair cache.
    #[test]
    fn missing_kallsyms_no_insert() {
        let cache = empty_cache();
        cache.set_kcore_kaslr_offset(None);

        let vmlinux = StubInspect::new("_stext", Some(0x1000));

        let offset = cache
            .kaslr_offset(
                None,
                Some(Path::new("/vmlinux")),
                None,
                Some(&vmlinux as &dyn Inspect),
            )
            .unwrap();

        assert_eq!(offset, 0);
        assert_eq!(cache.derived_kaslr_offset.len(), 0);
        assert_eq!(vmlinux.find_addr_calls.get(), 0);
    }
}
