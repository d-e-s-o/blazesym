use std::borrow::Cow;

use gimli::EndianSlice;
use gimli::Reader;
use gimli::ReaderOffsetId;
use gimli::Result;
use gimli::SectionId;

use crate::elf::ElfParser;


#[cfg(target_endian = "little")]
type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
type Endianess = gimli::BigEndian;


/// The gimli reader type we use.
#[derive(Clone, Debug)]
pub(crate) enum R<'dat> {
    Slice(EndianSlice<'dat, Endianess>),
}

impl<'dat> Reader for R<'dat> {
    type Endian = Endianess;
    type Offset = <EndianSlice<'dat, Endianess> as Reader>::Offset;

    #[inline]
    fn endian(&self) -> Self::Endian {
        match self {
            Self::Slice(slice) => slice.endian(),
        }
    }

    #[inline]
    fn len(&self) -> Self::Offset {
        match self {
            Self::Slice(slice) => slice.len(),
        }
    }

    #[inline]
    fn empty(&mut self) {
        match self {
            Self::Slice(slice) => slice.empty(),
        }
    }

    #[inline]
    fn truncate(&mut self, len: Self::Offset) -> Result<()> {
        match self {
            Self::Slice(slice) => Reader::truncate(slice, len),
        }
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> Self::Offset {
        match self {
            Self::Slice(slice) => slice.offset_from(base),
        }
    }

    #[inline]
    fn offset_id(&self) -> ReaderOffsetId {
        match self {
            Self::Slice(slice) => slice.offset_id(),
        }
    }

    #[inline]
    fn lookup_offset_id(&self, id: ReaderOffsetId) -> Option<Self::Offset> {
        match self {
            Self::Slice(slice) => slice.lookup_offset_id(id),
        }
    }

    #[inline]
    fn find(&self, byte: u8) -> Result<Self::Offset> {
        match self {
            Self::Slice(slice) => Reader::find(slice, byte),
        }
    }

    #[inline]
    fn skip(&mut self, len: Self::Offset) -> Result<()> {
        match self {
            Self::Slice(slice) => slice.skip(len),
        }
    }

    #[inline]
    fn split(&mut self, len: Self::Offset) -> Result<Self> {
        match self {
            Self::Slice(slice) => Reader::split(slice, len).map(Self::Slice),
        }
    }

    #[inline]
    fn to_slice(&self) -> Result<Cow<[u8]>> {
        match self {
            Self::Slice(slice) => Reader::to_slice(slice),
        }
    }

    #[inline]
    fn to_string(&self) -> Result<Cow<str>> {
        match self {
            Self::Slice(slice) => Reader::to_string(slice),
        }
    }

    #[inline]
    fn to_string_lossy(&self) -> Result<Cow<str>> {
        match self {
            Self::Slice(slice) => Reader::to_string_lossy(slice),
        }
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Slice(slice) => Reader::read_slice(slice, buf),
        }
    }
}


pub(super) fn load_section(parser: &ElfParser, id: SectionId) -> crate::Result<R<'_>> {
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
    Ok(R::Slice(reader))
}
