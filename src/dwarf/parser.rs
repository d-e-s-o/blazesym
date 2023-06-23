#[cfg(test)]
use std::env;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use gimli::constants;
use gimli::read::AttributeValue;
use gimli::read::EndianSlice;
use gimli::DebuggingInformationEntry;
use gimli::Dwarf;
use gimli::IncompleteLineProgram;
use gimli::SectionId;
use gimli::Unit;
use gimli::UnitSectionOffset;

use crate::elf::ElfParser;
use crate::inspect::SymType;
use crate::log::warn;
use crate::Addr;
use crate::ErrorExt as _;
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


pub(crate) struct AddrSrcInfo<'dwarf> {
    pub addr: Addr,
    pub line: u32,
    pub _col: u32,
    pub dir: Option<&'dwarf Path>,
    pub file: Option<&'dwarf OsStr>,
}

fn parse_debug_line_program<'dwarf>(
    dwarf: &Dwarf<R<'dwarf>>,
    unit: &Unit<R<'dwarf>>,
    program: IncompleteLineProgram<R<'dwarf>, usize>,
    results: &mut Vec<AddrSrcInfo<'dwarf>>,
) -> Result<()> {
    let mut rows = program.rows();
    let mut last_file_idx = u64::MAX;
    let mut last_file = None;
    let mut last_dir = None;

    while let Some((header, row)) = rows
        .next_row()
        .context("failed to retrieve DWARF source location row")?
    {
        // End of sequence indicates a possible gap in addresses.
        if row.end_sequence() {
            continue
        }
        // Determine line/column. DWARF line/column is never 0.
        let line = match row.line() {
            Some(line) => line.get(),
            None => 0,
        };
        let col = match row.column() {
            gimli::ColumnType::Column(column) => column.get(),
            gimli::ColumnType::LeftEdge => 0,
        };

        (last_dir, last_file) = if last_file_idx != row.file_index() {
            last_file_idx = row.file_index();

            if let Some(file) = row.file(header) {
                let dir = if let Some(dir) = file.directory(header) {
                    let dir = dwarf
                        .attr_string(unit, dir)
                        .context("failed to retrieve DWARF directory attribute value string")?;
                    let dir = Path::new(OsStr::from_bytes(dir.slice()));
                    Some(dir)
                } else {
                    None
                };

                let file_name = dwarf
                    .attr_string(unit, file.path_name())
                    .context("failed to retrieve DWARF path name attribute value string")?;
                let file_name = OsStr::from_bytes(file_name.slice());

                (dir, Some(file_name))
            } else {
                // The file changed but no file information is available. Tough
                // luck.
                (None, None)
            }
        } else {
            (last_dir, last_file)
        };

        let src_info = AddrSrcInfo {
            addr: row.address() as Addr,
            line: line.try_into().unwrap_or(u32::MAX),
            _col: col.try_into().unwrap_or(u32::MAX),
            dir: last_dir,
            file: last_file,
        };
        let () = results.push(src_info);
    }

    Ok(())
}

/// Parse DWARF line information and return a full version of debug_line matrix.
pub(crate) fn parse_debug_line_elf_parser(parser: &ElfParser) -> Result<Vec<AddrSrcInfo>> {
    let mut results = Vec::new();
    let mut load_section = |section| self::load_section(parser, section);
    let dwarf = Dwarf::<R>::load(&mut load_section)?;

    let mut iter = dwarf.units();
    while let Some(header) = iter
        .next()
        .context("failed to iterate DWARF unit headers")?
    {
        let unit = dwarf.unit(header).with_context(|| {
            format!(
                "failed to retrieve DWARF unit for unit header @ {}",
                format_offset(header.offset())
            )
        })?;

        if let Some(program) = unit.line_program.clone() {
            parse_debug_line_program(&dwarf, &unit, program, &mut results)?;
        }
    }
    Ok(results)
}


/// The symbol information extracted out of DWARF.
#[derive(Clone, Debug)]
pub(crate) struct DWSymInfo<'a> {
    pub name: &'a str,
    pub addr: Addr,
    pub size: usize,
    pub sym_type: SymType, // A function or a variable.
}

impl DWSymInfo<'_> {
    /// Check whether this symbol contains the provided address.
    pub fn contains(&self, addr: Addr) -> bool {
        (self.size == 0 && self.addr == addr)
            || (self.size != 0 && (self.addr..self.addr + self.size).contains(&addr))
    }
}

/// Parse a DIE that declares a subprogram. (a function)
///
/// We already know the given DIE is a declaration of a subprogram.
/// This function tries to extract the address of the subprogram and
/// other information from the DIE.
// TODO: Having a single function for a single subprogram may not be
//       sufficient to get all relevant symbol information. See
//       https://stackoverflow.com/a/59674438
// TODO: We likely need to handle DW_AT_ranges; see
//       https://reviews.llvm.org/D78489
#[cfg_attr(feature = "tracing", crate::log::instrument(skip_all))]
fn parse_die_subprogram<'dat>(
    dwarf: &Dwarf<R<'dat>>,
    unit: &Unit<R<'dat>>,
    entry: &DebuggingInformationEntry<R<'dat>>,
) -> Result<Option<DWSymInfo<'dat>>> {
    let mut addr = None;
    let mut name = None;
    let mut size = None;
    let mut high_pc = None;
    let mut linkage_name = None;

    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next().context("failed to read next DIE attribute")? {
        match attr.name() {
            constants::DW_AT_linkage_name | constants::DW_AT_name => {
                let attr_name = || {
                    attr.name()
                        .static_string()
                        .unwrap_or("DW_AT_name/DW_AT_linkage_name")
                };

                let string = dwarf.attr_string(unit, attr.value()).with_context(|| {
                    format!(
                        "failed to retrieve DWARF {} attribute value string",
                        attr_name()
                    )
                })?;
                let name_ = string.to_string().with_context(|| {
                    format!("{} attribute does not contain valid string", attr_name())
                })?;
                if attr.name() == constants::DW_AT_name {
                    name = Some(name_);
                } else {
                    linkage_name = Some(name_);
                }
            }
            constants::DW_AT_low_pc => match attr.value() {
                AttributeValue::Addr(addr_) => {
                    addr = Some(addr_);
                }
                _ => {
                    warn!(
                        "encountered unexpected attribute for {}",
                        attr.name().static_string().unwrap_or("DW_AT_low_pc")
                    );
                }
            },
            constants::DW_AT_high_pc => match attr.value() {
                AttributeValue::Addr(addr) => {
                    high_pc = Some(addr);
                }
                _ => {
                    if let Some(udata) = attr.value().udata_value() {
                        // It's an offset from "low_pc", i.e., the size.
                        size = Some(udata)
                    } else {
                        warn!(
                            "encountered unexpected attribute for {}",
                            attr.name().static_string().unwrap_or("DW_AT_high_pc")
                        );
                    }
                }
            },
            _ => (),
        }
    }

    name = name.or(linkage_name);
    size = match (size, addr, high_pc) {
        (None, Some(low_pc), Some(high_pc)) => high_pc.checked_sub(low_pc),
        _ => size,
    };

    match (addr, name) {
        (Some(addr), Some(name)) => Ok(Some(DWSymInfo {
            name,
            addr: addr as Addr,
            // TODO: `size` really should be an `Option` inside
            //       `DWSymInfo`.
            size: size.unwrap_or(0) as usize,
            sym_type: SymType::Function,
        })),
        _ => Ok(None),
    }
}

/// Walk through all DIEs of a compile unit to extract symbols.
#[cfg_attr(feature = "tracing", crate::log::instrument(skip_all))]
fn debug_info_parse_symbols_cu<'dat>(
    dwarf: &Dwarf<R<'dat>>,
    unit: Unit<R<'dat>>,
    found_syms: &mut Vec<DWSymInfo<'dat>>,
) -> Result<()> {
    let mut entries = unit.header.entries(&unit.abbreviations);
    while let Some((_, entry)) = entries.next_dfs().context("failed to find next DIE")? {
        if entry.tag() == constants::DW_TAG_subprogram {
            if let Some(sym) = parse_die_subprogram(dwarf, &unit, entry)? {
                let () = found_syms.push(sym);
            }
        }
    }
    Ok(())
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


/// Parse the addresses of symbols from the `.debug_info` section.
///
/// # Arguments
///
/// * `parser` - is an ELF parser.
pub(crate) fn debug_info_parse_symbols(parser: &ElfParser) -> Result<Vec<DWSymInfo<'_>>> {
    let mut load_section = |section| self::load_section(parser, section);
    let dwarf = Dwarf::<R>::load(&mut load_section)?;

    let mut units = dwarf.units();
    let mut syms = Vec::new();

    while let Some(header) = units
        .next()
        .context("failed to iterate DWARF unit headers")?
    {
        let unit = dwarf.unit(header).with_context(|| {
            format!(
                "failed to retrieve DWARF unit for unit header @ {}",
                format_offset(header.offset())
            )
        })?;

        let () = debug_info_parse_symbols_cu(&dwarf, unit, &mut syms)?;
    }
    Ok(syms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nightly")]
    use std::hint::black_box;

    use test_log::test;

    #[cfg(feature = "nightly")]
    use test::Bencher;


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
