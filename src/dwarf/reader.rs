use gimli::read::EndianReader;
use gimli::CloneStableDeref;
use gimli::EndianSlice;
use gimli::SectionId;
use gimli::StableDeref;

use crate::elf::ElfParser;
use crate::mmap::Mmap;
use crate::Result;


/// SAFETY: `Mmap`, (unless [`constrain`][Mmap::constrain]ed) always
///         derefs to the same address.
unsafe impl StableDeref for Mmap {}
/// SAFETY: `Mmap`, if cloned, still derefs to the same address.
unsafe impl CloneStableDeref for Mmap {}


#[cfg(target_endian = "little")]
type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
type Endianess = gimli::BigEndian;


/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
pub(crate) type R = EndianReader<Endianess, Mmap>;


pub(super) fn load_section(parser: &ElfParser, id: SectionId) -> Result<R> {
    let result = parser.find_section(id.name())?;
    let data = match result {
        Some(idx) => parser.section_data(idx)?,
        // Make sure to return empty data if a section does not exist.
        None => &[],
    };

    #[cfg(target_endian = "little")]
    let reader = EndianSlice::new(data, gimli::LittleEndian);
    #[cfg(target_endian = "big")]
    let reader = EndianSlice::new(data, gimli::BigEndian);
    Ok(reader)
}
