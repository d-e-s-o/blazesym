#[cfg(test)]
use std::env;

use gimli::read::EndianSlice;
use gimli::SectionId;
use gimli::UnitSectionOffset;

use crate::elf::ElfParser;
use crate::Result;


#[cfg(target_endian = "little")]
type Endianess = gimli::LittleEndian;
#[cfg(target_endian = "big")]
type Endianess = gimli::BigEndian;

/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
pub(super) type R<'dat> = EndianSlice<'dat, Endianess>;


fn format_offset(offset: UnitSectionOffset<usize>) -> String {
    match offset {
        UnitSectionOffset::DebugInfoOffset(o) => {
            format!(".debug_info+0x{:08x}", o.0)
        }
        UnitSectionOffset::DebugTypesOffset(o) => {
            format!(".debug_types+0x{:08x}", o.0)
        }
    }
}


pub(super) fn load_section(parser: &ElfParser, id: SectionId) -> Result<R<'_>> {
    let result = parser.find_section(id.name());
    let data = match result {
        Ok(Some(idx)) => parser.section_data(idx)?,
        // Make sure to return empty data if a section does not exist.
        Ok(None) => &[],
        Err(err) => return Err(err),
    };

    #[cfg(target_endian = "little")]
    let reader = EndianSlice::new(data, gimli::LittleEndian);
    #[cfg(target_endian = "big")]
    let reader = EndianSlice::new(data, gimli::BigEndian);
    Ok(reader)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nightly")]
    use std::hint::black_box;
    use std::path::Path;

    use gimli::Dwarf;

    use test_log::test;

    #[cfg(feature = "nightly")]
    use test::Bencher;


    #[test]
    fn xxxxxxxxxxxxxxxxxxxxxxxxx() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-dwarf-only.bin");
        let parser = ElfParser::open(&test_dwarf).unwrap();
        let mut load_section = |section| self::load_section(&parser, section);
        let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();

        let units = crate::dwarf::unit::Units::parse(dwarf).unwrap();
        let mut funcs = units.find_name("factorial");
        println!("FOUND: {:?}", funcs.next().unwrap());
        assert!(funcs.next().is_none());
    }

    /// Check that we can parse debug line information.
    #[test]
    fn debug_line_parsing() {
        let binaries = [
            "test-dwarf-v2.bin",
            "test-dwarf-v3.bin",
            "test-dwarf-v4.bin",
            "test-dwarf-v5.bin",
        ];

        for binary in binaries {
            let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(binary);

            let parser = ElfParser::open(bin_name.as_ref()).unwrap();
            let _lines = parse_debug_line_elf_parser(&parser).unwrap();
        }
    }

    /// Benchmark the [`parse_debug_line_elf_parser`] function.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_debug_line_parsing(b: &mut Bencher) {
        let bin_name = env::args().next().unwrap();
        let parser = ElfParser::open(bin_name.as_ref()).unwrap();

        let () = b.iter(|| parse_debug_line_elf_parser(black_box(&parser)).unwrap());
    }

    /// Check that we can parse debug information and extract relevant symbols.
    #[test]
    fn debug_info_parseing() {
        let binaries = [
            "test-dwarf-v2.bin",
            "test-dwarf-v3.bin",
            "test-dwarf-v4.bin",
            "test-dwarf-v5.bin",
        ];

        for binary in binaries {
            let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(binary);

            let parser = ElfParser::open(bin_name.as_ref()).unwrap();
            let syms = debug_info_parse_symbols(&parser).unwrap();
            assert!(syms.iter().any(|sym| sym.name == "fibonacci"))
        }
    }

    /// Benchmark the [`debug_info_parse_symbols`] function.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_debug_info_parsing(b: &mut Bencher) {
        let bin_name = env::args().next().unwrap();
        let parser = ElfParser::open(bin_name.as_ref()).unwrap();

        let () = b.iter(|| debug_info_parse_symbols(black_box(&parser)).unwrap());
    }
}
