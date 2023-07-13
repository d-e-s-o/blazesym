use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::Read as _;
use std::io::Seek as _;
use std::io::SeekFrom;
use std::mem;
use std::mem::MaybeUninit;
use std::ops::Deref as _;
use std::path::Path;
use std::slice;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::inspect::SymType;
use crate::mmap::Mmap;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;

use super::types::Elf64_Ehdr;
use super::types::Elf64_Phdr;
use super::types::Elf64_Shdr;
use super::types::Elf64_Sym;
use super::types::SHN_UNDEF;
#[cfg(test)]
use super::types::STT_FUNC;


fn symbol_name<'mmap>(strtab: &'mmap [u8], sym: &Elf64_Sym) -> Result<&'mmap str> {
    let name = strtab
        .get(sym.st_name as usize..)
        .ok_or_invalid_input(|| "string table index out of bounds")?
        .read_cstr()
        .ok_or_invalid_input(|| "no valid string found in string table")?
        .to_str()
        .map_err(Error::with_invalid_data)
        .context("invalid symbol name")?;

    Ok(name)
}


struct Cache<'mmap> {
    /// The cached ELF header.
    ehdr: Option<Cow<'mmap, Elf64_Ehdr>>,
    /// The cached ELF section headers.
    shdrs: Option<Cow<'mmap, [Elf64_Shdr]>>,
    shstrtab: Option<Cow<'mmap, [u8]>>,
    /// The cached ELF program headers.
    phdrs: Option<Cow<'mmap, [Elf64_Phdr]>>,
    symtab: Option<Box<[Cow<'mmap, Elf64_Sym>]>>, // in address order
    /// The cached ELF string table.
    strtab: Option<Cow<'mmap, [u8]>>,
    str2symtab: Option<Box<[(&'mmap str, usize)]>>, // strtab offset to symtab in the dictionary order
}

impl<'mmap> Cache<'mmap> {
    /// Create a new `Cache` using the provided raw ELF object data.
    fn new() -> Self {
        Self {
            ehdr: None,
            shdrs: None,
            shstrtab: None,
            phdrs: None,
            symtab: None,
            strtab: None,
            str2symtab: None,
        }
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`.
    fn section_data(
        &mut self,
        mut backend: &'mmap Backend,
        idx: usize,
    ) -> Result<Cow<'mmap, [u8]>> {
        let shdrs = self.ensure_shdrs(backend)?;
        let section = shdrs
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF section index ({idx}) out of bounds"))?;

        let data = backend
            .read_pod_slice::<u8>(section.sh_offset, section.sh_size as usize)
            .context("failed to read section data: invalid size")?;
        Ok(data)
    }

    fn ensure_ehdr(&mut self, mut backend: &'mmap Backend) -> Result<&'mmap Elf64_Ehdr> {
        if let Some(ehdr) = self.ehdr {
            return Ok(&ehdr)
        }

        let ehdr = backend
            .read_pod::<Elf64_Ehdr>(0)
            .context("failed to read Elf64_Ehdr")?;
        if !(ehdr.e_ident[0] == 0x7f
            && ehdr.e_ident[1] == b'E'
            && ehdr.e_ident[2] == b'L'
            && ehdr.e_ident[3] == b'F')
        {
            return Err(Error::with_invalid_data(format!(
                "encountered unexpected e_ident: {:x?}",
                &ehdr.e_ident[0..4]
            )))
        }
        self.ehdr = Some(ehdr);
        Ok(&ehdr)
    }

    fn ensure_shdrs(&mut self, mut backend: &'mmap Backend) -> Result<&'mmap [Elf64_Shdr]> {
        if let Some(shdrs) = self.shdrs {
            return Ok(&shdrs)
        }

        let ehdr = self.ensure_ehdr(backend)?;
        let shdrs = backend
            .read_pod_slice::<Elf64_Shdr>(ehdr.e_shoff, ehdr.e_shnum.into())
            .context("failed to read Elf64_Shdr")?;
        self.shdrs = Some(shdrs);
        Ok(&shdrs)
    }

    fn ensure_phdrs(&mut self, mut backend: &'mmap Backend) -> Result<&'mmap [Elf64_Phdr]> {
        if let Some(phdrs) = self.phdrs {
            return Ok(&phdrs)
        }

        let ehdr = self.ensure_ehdr(backend)?;
        let phdrs = backend
            .read_pod_slice::<Elf64_Phdr>(ehdr.e_phoff, ehdr.e_phnum.into())
            .context("failed to read Elf64_Phdr")?;
        self.phdrs = Some(phdrs);
        Ok(&phdrs)
    }

    fn ensure_shstrtab(&mut self, mut backend: &'mmap Backend) -> Result<&'mmap [u8]> {
        if let Some(shstrtab) = self.shstrtab {
            return Ok(&shstrtab)
        }

        let ehdr = self.ensure_ehdr(backend)?;
        let shstrndx = ehdr.e_shstrndx;
        let shstrtab = self.section_data(backend, shstrndx as usize)?;
        self.shstrtab = Some(shstrtab);
        Ok(&shstrtab)
    }

    /// Get the name of the section at a given index.
    fn section_name(&mut self, mut backend: &'mmap Backend, idx: usize) -> Result<&'mmap str> {
        let shdrs = self.ensure_shdrs(backend)?;
        let shstrtab = self.ensure_shstrtab(backend)?;

        let sect = shdrs
            .get(idx)
            .ok_or_invalid_input(|| "ELF section index out of bounds")?;
        let name = shstrtab
            .get(sect.sh_name as usize..)
            .ok_or_invalid_input(|| "string table index out of bounds")?
            .read_cstr()
            .ok_or_invalid_input(|| "no valid string found in string table")?
            .to_str()
            .map_err(Error::with_invalid_data)
            .context("invalid section name")?;
        Ok(name)
    }

    #[cfg(test)]
    fn symbol(&mut self, idx: usize) -> Result<&'mmap Elf64_Sym> {
        let () = self.ensure_symtab()?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = self.symtab.as_ref().unwrap();
        let symbol = symtab
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF symbol index ({idx}) out of bounds"))?;

        Ok(symbol)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    fn find_section(&mut self, mut backend: &'mmap Backend, name: &str) -> Result<Option<usize>> {
        let ehdr = self.ensure_ehdr(backend)?;
        for i in 1..ehdr.e_shnum.into() {
            if self.section_name(backend, i)? == name {
                return Ok(Some(i))
            }
        }
        Ok(None)
    }

    // Note: This function should really return a reference to
    //       `self.symtab`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_symtab(&mut self, mut backend: &'mmap Backend) -> Result<()> {
        if self.symtab.is_some() {
            return Ok(())
        }

        let idx = if let Some(idx) = self.find_section(backend, ".symtab")? {
            idx
        } else if let Some(idx) = self.find_section(backend, ".dynsym")? {
            idx
        } else {
            // Neither symbol table exists. Fake an empty one.
            self.symtab = Some(Box::new([]));
            return Ok(())
        };
        let mut symtab = self.section_data(backend, idx)?;

        if symtab.len() % mem::size_of::<Elf64_Sym>() != 0 {
            return Err(Error::with_invalid_data(
                "size of symbol table section is invalid",
            ))
        }

        let count = symtab.len() / mem::size_of::<Elf64_Sym>();

        let mut symtab = match symtab {
            Cow::Borrowed(symtab) => symtab
                .read_pod_slice_ref::<Elf64_Sym>(count)
                .ok_or_invalid_data(|| "failed to read symbol table contents")?
                .iter()
                .map(Cow::Borrowed)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            Cow::Owned(symtab) => {
                let raw = Box::into_raw(symtab.into_boxed_slice());
                unsafe { Vec::from_raw_parts(raw.cast::<Elf64_Sym>(), count, count) }
                    .into_iter()
                    .map(Cow::Owned)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }
        };
        // Order symbols by address and those with equal address descending by
        // size.
        let () = symtab.sort_by(|sym1, sym2| {
            sym1.st_value
                .cmp(&sym2.st_value)
                .then_with(|| sym1.st_size.cmp(&sym2.st_size).reverse())
        });

        self.symtab = Some(symtab);
        Ok(())
    }

    fn ensure_strtab(&mut self, mut backend: &'mmap Backend) -> Result<&'mmap [u8]> {
        if let Some(strtab) = self.strtab {
            return Ok(&strtab)
        }

        let strtab = if let Some(idx) = self.find_section(backend, ".strtab")? {
            self.section_data(backend, idx)?
        } else if let Some(idx) = self.find_section(backend, ".dynstr")? {
            self.section_data(backend, idx)?
        } else {
            Cow::Borrowed([].as_slice())
        };

        self.strtab = Some(strtab);
        Ok(&strtab)
    }

    // Note: This function should really return a reference to
    //       `self.str2symtab`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_str2symtab(&mut self, mut backend: &'mmap Backend) -> Result<()> {
        if self.str2symtab.is_some() {
            return Ok(())
        }

        let strtab = self.ensure_strtab(backend)?;
        let () = self.ensure_symtab(backend)?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = self.symtab.as_ref().unwrap();

        let mut str2symtab = symtab
            .iter()
            .enumerate()
            .map(|(i, sym)| {
                let name = strtab
                    .get(sym.st_name as usize..)
                    .ok_or_invalid_input(|| "string table index out of bounds")?
                    .read_cstr()
                    .ok_or_invalid_input(|| "no valid string found in string table")?
                    .to_str()
                    .map_err(Error::with_invalid_data)
                    .context("invalid symbol name")?;
                Ok((name, i))
            })
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();

        let () = str2symtab.sort_by_key(|&(name, _i)| name);

        self.str2symtab = Some(str2symtab);
        Ok(())
    }
}

impl Debug for Cache<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Cache")
    }
}


trait Backend<'r> {
    fn read_pod<T>(&mut self, offset: u64) -> Result<Cow<'r, T>, Error>
    where
        T: Clone + Pod;

    fn read_pod_slice<T>(&mut self, offset: u64, count: usize) -> Result<Cow<'r, [T]>, Error>
    where
        T: Clone + Pod;
}

impl<'r> Backend<'r> for &'r Mmap {
    fn read_pod<T>(&mut self, offset: u64) -> Result<Cow<'r, T>, Error>
    where
        T: Clone + Pod,
    {
        let value = self
            .get(offset as _..)
            .unwrap()
            .read_pod_ref::<T>()
            .ok_or_invalid_data(|| "failed to read value from mmap")?;
        Ok(Cow::Borrowed(value))
    }

    fn read_pod_slice<T>(&mut self, offset: u64, count: usize) -> Result<Cow<'r, [T]>, Error>
    where
        T: Clone + Pod,
    {
        let value = self
            .get(offset as _..)
            .unwrap()
            .read_pod_slice_ref::<T>(count)
            .ok_or_invalid_data(|| "failed to read slice from mmap")?;
        Ok(Cow::Borrowed(value))
    }
}

impl<'r> Backend<'r> for &'r File {
    fn read_pod<T>(&mut self, offset: u64) -> Result<Cow<'r, T>, Error>
    where
        T: Clone + Pod,
    {
        let _pos = self.seek(SeekFrom::Start(offset))?;

        let mut value = MaybeUninit::<T>::zeroed();
        // SAFETY: `value` is a buffer of `size_of::<T>` bytes.
        // TODO: Are we UB here because we create a mut reference?
        let slice = unsafe {
            slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), mem::size_of::<T>())
        };
        let () = self.read_exact(slice)?;
        // SAFETY: `T` is a `Pod` and hence valid for any bit pattern,
        //         including all zeroes.
        Ok(Cow::Owned(unsafe { value.assume_init() }))
    }

    fn read_pod_slice<T>(&mut self, offset: u64, count: usize) -> Result<Cow<'r, [T]>, Error>
    where
        T: Clone + Pod,
    {
        let _pos = self.seek(SeekFrom::Start(offset))?;
        let mut vec = Vec::<T>::new();
        // SAFETY: `T` is a `Pod` and hence valid for any bit pattern,
        //         including all zeroes.
        let () = vec.resize(count, unsafe { mem::zeroed() });

        // TODO: Are we UB here because we create a mut reference?
        let slice = unsafe {
            slice::from_raw_parts_mut(vec.as_mut_ptr().cast::<u8>(), count * mem::size_of::<T>())
        };
        let () = self.read_exact(slice)?;
        Ok(Cow::Owned(vec))
    }
}


/// A parser for ELF64 files.
#[derive(Debug)]
pub(crate) struct ElfParser<B = Mmap> {
    /// A cache for relevant parts of the ELF file.
    /// SAFETY: We must not hand out references with a 'static lifetime to
    ///         this member. Rather, they should never outlive `self`.
    ///         Furthermore, this member has to be listed before `mmap`
    ///         to make sure we never end up with a dangling reference.
    cache: RefCell<Cache<'static>>,
    /// The backend used.
    backend: B,
}

impl ElfParser<Mmap> {
    fn backend(&self) -> &'static Mmap {
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        unsafe { mem::transmute::<&Backend, &Backend>(&self.backend) }
    }

    /// Create an `ElfParser` from an open file.
    pub fn open_file(file: File) -> Result<ElfParser> {
        Mmap::map(&file).map(Self::from_mmap)
    }

    /// Create an `ElfParser` from mmap'ed data.
    pub fn from_mmap(mmap: Mmap) -> ElfParser {
        let parser = ElfParser {
            backend: mmap,
            cache: RefCell::new(Cache::new()),
        };
        parser
    }

    /// Create an `ElfParser` for a path.
    pub fn open(filename: &Path) -> Result<ElfParser> {
        let file = File::open(filename)?;
        let parser = Self::open_file(file);
        if let Ok(parser) = parser {
            Ok(parser)
        } else {
            parser
        }
    }
}

impl<B> ElfParser<B> {
    /// Retrieve the data corresponding to the ELF section at index `idx`.
    pub fn section_data(&self, idx: usize) -> Result<Cow<'_, [u8]>> {
        let mut cache = self.cache.borrow_mut();
        cache.section_data(self.backend(), idx)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    pub fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let mut cache = self.cache.borrow_mut();
        let index = cache.find_section(self.backend(), name)?;
        Ok(index)
    }

    pub fn find_sym(&self, addr: Addr, st_type: u8) -> Result<Option<(&str, Addr)>> {
        let mut cache = self.cache.borrow_mut();
        let strtab = cache.ensure_strtab(self.backend())?;
        let () = cache.ensure_symtab(self.backend())?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();

        match find_match_or_lower_bound_by_key(symtab, addr, |sym| sym.st_value as Addr) {
            None => Ok(None),
            Some(idx) => symtab[idx..]
                .iter()
                .find_map(|sym| {
                    if sym.st_shndx == SHN_UNDEF || sym.type_() != st_type {
                        return None
                    }

                    let addr = addr as u64;
                    if sym.contains(addr) {
                        let name = match symbol_name(strtab, sym) {
                            Ok(name) => name,
                            Err(err) => return Some(Err(err)),
                        };
                        let addr = sym.st_value as Addr;
                        Some(Ok((name, addr)))
                    } else {
                        None
                    }
                })
                .transpose(),
        }
    }

    pub(crate) fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo>> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported("Not implemented"))
        }

        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab(self.backend())?;
        let () = cache.ensure_str2symtab(self.backend())?;
        // SANITY: The above `ensure_symtab` ensures we have `symtab`
        //         available.
        let symtab = cache.symtab.as_ref().unwrap();
        // SANITY: The above `ensure_str2symtab` ensures we have
        //         `str2symtab` available.
        let str2symtab = cache.str2symtab.as_ref().unwrap();

        let r = find_match_or_lower_bound_by_key(str2symtab, name, |&(name, _i)| &name);
        match r {
            Some(idx) => {
                let mut found = vec![];
                for (name_visit, sym_i) in str2symtab.iter().skip(idx) {
                    if *name_visit != name {
                        break
                    }
                    let sym_ref = &symtab.get(*sym_i).ok_or_invalid_input(|| {
                        format!("symbol table index ({sym_i}) out of bounds")
                    })?;
                    if sym_ref.st_shndx != SHN_UNDEF {
                        found.push(SymInfo {
                            name: name.to_string(),
                            addr: sym_ref.st_value as Addr,
                            size: sym_ref.st_size as usize,
                            sym_type: SymType::Function,
                            file_offset: 0,
                            obj_file_name: None,
                        });
                    }
                }
                Ok(found)
            }
            None => Ok(vec![]),
        }
    }

    #[cfg(test)]
    fn get_symbol_name(&self, idx: usize) -> Result<&str> {
        let mut cache = self.cache.borrow_mut();
        let strtab = cache.ensure_strtab(self.backend())?;
        let sym = cache.symbol(idx)?;
        let name = symbol_name(strtab, sym)?;
        Ok(name)
    }

    pub(crate) fn section_headers(&self) -> Result<&[Elf64_Shdr]> {
        let mut cache = self.cache.borrow_mut();
        let phdrs = cache.ensure_shdrs(self.backend())?;
        Ok(phdrs)
    }

    pub(crate) fn program_headers(&self) -> Result<&[Elf64_Phdr]> {
        let mut cache = self.cache.borrow_mut();
        let phdrs = cache.ensure_phdrs(self.backend())?;
        Ok(phdrs)
    }

    #[cfg(test)]
    fn pick_symtab_addr(&self) -> (&str, Addr) {
        let mut cache = self.cache.borrow_mut();
        let () = cache.ensure_symtab(self.backend()).unwrap();
        let symtab = cache.symtab.as_ref().unwrap();

        let mut idx = symtab.len() / 2;
        while symtab[idx].type_() != STT_FUNC || symtab[idx].st_shndx == SHN_UNDEF {
            idx += 1;
        }
        let sym = &symtab[idx];
        let addr = sym.st_value;
        drop(cache);

        let sym_name = self.get_symbol_name(idx).unwrap();
        (sym_name, addr as Addr)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use test_log::test;


    #[test]
    fn test_elf64_parser() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());
    }

    #[test]
    fn test_elf64_symtab() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (sym_name, addr) = parser.pick_symtab_addr();

        let sym = parser.find_sym(addr, STT_FUNC).unwrap().unwrap();
        let (sym_name_ret, addr_ret) = sym;
        assert_eq!(addr_ret, addr);
        assert_eq!(sym_name_ret, sym_name);
    }

    #[test]
    fn elf64_lookup_symbol_random() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (sym_name, addr) = parser.pick_symtab_addr();

        println!("{sym_name}");
        let opts = FindAddrOpts::default();
        let addr_r = parser.find_addr(sym_name, &opts).unwrap();
        assert_eq!(addr_r.len(), 1);
        assert!(addr_r.iter().any(|x| x.addr == addr));
    }

    /// Make sure that we can look up a symbol in an ELF file.
    #[test]
    fn lookup_symbol() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-no-dwarf.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let opts = FindAddrOpts::default();
        let syms = parser.find_addr("factorial", &opts).unwrap();
        assert_eq!(syms.len(), 1);
        let sym = &syms[0];
        assert_eq!(sym.name, "factorial");
        assert_eq!(sym.addr, 0x2000100);

        let syms = parser.find_addr("factorial_wrapper", &opts).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "factorial_wrapper");
        assert_eq!(syms[1].name, "factorial_wrapper");
        assert_ne!(syms[0].addr, syms[1].addr);
    }
}
