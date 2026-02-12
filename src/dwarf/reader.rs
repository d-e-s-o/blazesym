use std::rc::Rc;

use gimli::EndianSlice;
use gimli::RelocateReader;
use gimli::SectionId;

use crate::elf::ElfParser;
use crate::Result;


#[cfg(target_endian = "little")]
pub(super) type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
pub(super) type Endianess = gimli::BigEndian;

/// A map of resolved relocations for a single ELF section.
///
/// Relocations are stored as `(offset, resolved_value)` pairs, sorted
/// by offset for efficient binary search lookup. This is used for
/// relocatable ELF objects (such as kernel modules) where DWARF
/// sections contain unresolved relocations.
#[derive(Debug, Clone, Default)]
pub(crate) struct RelocationMap {
    relocs: Rc<[(usize, u64)]>,
}

impl RelocationMap {
    fn new(mut relocs: Vec<(usize, u64)>) -> Self {
        let () = relocs.sort_by_key(|&(offset, _)| offset);
        Self {
            relocs: relocs.into(),
        }
    }

    fn lookup(&self, offset: usize) -> Option<u64> {
        self.relocs
            .binary_search_by_key(&offset, |&(o, _)| o)
            .ok()
            .map(|idx| self.relocs[idx].1)
    }
}

impl gimli::read::Relocate for RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.lookup(offset).unwrap_or(value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        match self.lookup(offset) {
            Some(relocated) => <usize as gimli::ReaderOffset>::from_u64(relocated),
            None => Ok(value),
        }
    }
}

/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
pub(crate) type R<'dat> = RelocateReader<EndianSlice<'dat, Endianess>, RelocationMap>;


/// Convert a reader's content to a UTF-8 string, preserving the
/// original data lifetime.
///
/// This mirrors `EndianSlice::to_string()` (an inherent method that
/// returns `Result<&'input str>`) for the `RelocateReader` wrapper,
/// which does not expose such a method.
pub(super) fn to_str<'dat>(reader: &R<'dat>) -> gimli::Result<&'dat str> {
    str::from_utf8(reader.inner().slice()).map_err(|_| gimli::Error::BadUtf8)
}


fn load_section_impl<'elf>(parser: &'elf ElfParser, name: Option<&str>) -> Result<R<'elf>> {
    let (data, relocs) = if let Some(name) = name {
        match parser.find_section(name)? {
            Some(idx) => {
                let data = parser.section_data(idx)?;
                let reloc_vec = parser.section_relocations(idx)?;
                (data, RelocationMap::new(reloc_vec))
            }
            // Make sure to return empty data if a section does not exist.
            None => (&[] as &[u8], RelocationMap::default()),
        }
    } else {
        (&[] as &[u8], RelocationMap::default())
    };

    let reader = RelocateReader::new(EndianSlice::new(data, Endianess::default()), relocs);
    Ok(reader)
}

pub(super) fn load_section(parser: &ElfParser, id: SectionId) -> Result<R<'_>> {
    load_section_impl(parser, Some(id.name()))
}

pub(super) fn load_dwo_section(parser: &ElfParser, id: SectionId) -> Result<R<'_>> {
    load_section_impl(parser, id.dwo_name())
}

pub(super) fn empty_reader() -> R<'static> {
    RelocateReader::new(
        EndianSlice::new(&[], Endianess::default()),
        RelocationMap::default(),
    )
}
