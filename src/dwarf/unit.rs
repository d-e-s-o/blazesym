// Based on gimli-rs/addr2line (https://github.com/gimli-rs/addr2line):
// > Copyright (c) 2016-2018 The gimli Developers
// >
// > Permission is hereby granted, free of charge, to any
// > person obtaining a copy of this software and associated
// > documentation files (the "Software"), to deal in the
// > Software without restriction, including without
// > limitation the rights to use, copy, modify, merge,
// > publish, distribute, sublicense, and/or sell copies of
// > the Software, and to permit persons to whom the Software
// > is furnished to do so, subject to the following
// > conditions:
// >
// > The above copyright notice and this permission notice
// > shall be included in all copies or substantial portions
// > of the Software.
// >
// > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// > ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// > TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// > PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// > SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// > CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// > OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// > IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// > DEALINGS IN THE SOFTWARE.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::path::Path;

use super::function::Function;
use super::function::Functions;
use super::lazy::LazyCell;
use super::line::LineSequence;
use super::line::Lines;
use super::range::RangeAttributes;


struct UnitRange {
    unit_id: usize,
    max_end: u64,
    range: gimli::Range,
}


/// A source location.
pub struct Location<'a> {
    /// The directory.
    pub dir: &'a Path,
    /// The file name.
    pub file: &'a OsStr,
    /// The line number.
    pub line: Option<u32>,
    /// The column number.
    pub column: Option<u32>,
}


struct LocationRangeUnitIter<'ctx> {
    lines: &'ctx Lines,
    seqs: &'ctx [LineSequence],
    seq_idx: usize,
    row_idx: usize,
    probe_high: u64,
}

impl<'ctx> LocationRangeUnitIter<'ctx> {
    fn new<R: gimli::Reader>(
        unit: &'ctx Unit<R>,
        sections: &gimli::Dwarf<R>,
        probe_low: u64,
        probe_high: u64,
    ) -> Result<Option<Self>, gimli::Error> {
        let lines = unit.parse_lines(sections)?;

        if let Some(lines) = lines {
            // Find index for probe_low.
            let seq_idx = lines.sequences.binary_search_by(|sequence| {
                if probe_low < sequence.start {
                    Ordering::Greater
                } else if probe_low >= sequence.end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            });
            let seq_idx = match seq_idx {
                Ok(x) => x,
                Err(0) => 0, // probe below sequence, but range could overlap
                Err(_) => lines.sequences.len(),
            };

            let row_idx = if let Some(seq) = lines.sequences.get(seq_idx) {
                let idx = seq.rows.binary_search_by(|row| row.address.cmp(&probe_low));
                match idx {
                    Ok(x) => x,
                    Err(0) => 0, // probe below sequence, but range could overlap
                    Err(x) => x - 1,
                }
            } else {
                0
            };

            Ok(Some(Self {
                lines,
                seqs: &*lines.sequences,
                seq_idx,
                row_idx,
                probe_high,
            }))
        } else {
            Ok(None)
        }
    }
}

impl<'ctx> Iterator for LocationRangeUnitIter<'ctx> {
    type Item = (u64, u64, Location<'ctx>);

    fn next(&mut self) -> Option<(u64, u64, Location<'ctx>)> {
        while let Some(seq) = self.seqs.get(self.seq_idx) {
            if seq.start >= self.probe_high {
                break;
            }

            match seq.rows.get(self.row_idx) {
                Some(row) => {
                    if row.address >= self.probe_high {
                        break;
                    }

                    // SANITY: We always have a file present for each
                    //         `file_index`.
                    let (dir, file) = self.lines.files.get(row.file_index as usize).unwrap();
                    let nextaddr = seq
                        .rows
                        .get(self.row_idx + 1)
                        .map(|row| row.address)
                        .unwrap_or(seq.end);

                    let item = (
                        row.address,
                        nextaddr - row.address,
                        Location {
                            dir,
                            file,
                            line: if row.line != 0 { Some(row.line) } else { None },
                            column: if row.column != 0 {
                                Some(row.column)
                            } else {
                                None
                            },
                        },
                    );
                    self.row_idx += 1;

                    return Some(item);
                }
                None => {
                    self.seq_idx += 1;
                    self.row_idx = 0;
                }
            }
        }
        None
    }
}


struct Unit<R: gimli::Reader> {
    offset: gimli::DebugInfoOffset<R::Offset>,
    dw_unit: gimli::Unit<R>,
    lang: Option<gimli::DwLang>,
    lines: LazyCell<Result<Lines, gimli::Error>>,
    funcs: LazyCell<Result<Functions<R>, gimli::Error>>,
}

impl<R: gimli::Reader> Unit<R> {
    fn parse_lines(&self, sections: &gimli::Dwarf<R>) -> Result<Option<&Lines>, gimli::Error> {
        // NB: line information is always stored in the main debug file so this does not need
        // to handle DWOs.
        let ilnp = match self.dw_unit.line_program {
            Some(ref ilnp) => ilnp,
            None => return Ok(None),
        };
        self.lines
            .borrow_with(|| Lines::parse(&self.dw_unit, ilnp.clone(), sections))
            .as_ref()
            .map(Some)
            .map_err(gimli::Error::clone)
    }

    fn find_location(
        &self,
        probe: u64,
        sections: &gimli::Dwarf<R>,
    ) -> Result<Option<Location<'_>>, gimli::Error> {
        if let Some(mut iter) = LocationRangeUnitIter::new(self, sections, probe, probe + 1)? {
            match iter.next() {
                None => Ok(None),
                Some((_addr, _len, loc)) => Ok(Some(loc)),
            }
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn find_location_range(
        &self,
        probe_low: u64,
        probe_high: u64,
        sections: &gimli::Dwarf<R>,
    ) -> Result<Option<LocationRangeUnitIter<'_>>, gimli::Error> {
        LocationRangeUnitIter::new(self, sections, probe_low, probe_high)
    }

    fn parse_functions_dwarf_and_unit(
        &self,
        unit: &gimli::Unit<R>,
        sections: &gimli::Dwarf<R>,
    ) -> Result<&Functions<R>, gimli::Error> {
        self.funcs
            .borrow_with(|| Functions::parse(unit, sections))
            .as_ref()
            .map_err(gimli::Error::clone)
    }

    fn parse_inlined_functions(
        &self,
        unit: &gimli::Unit<R>,
        sections: &gimli::Dwarf<R>,
    ) -> Result<&Functions<R>, gimli::Error> {
        self.funcs
            .borrow_with(|| {
              let funcs = Functions::parse(unit, sections)?;
              let () = funcs.parse_inlined_functions(unit, sections)?;
              Ok(funcs)
            })
            .as_ref()
            .map_err(gimli::Error::clone)
    }

    fn find_function_or_location<'unit>(
        &'unit self,
        probe: u64,
        sections: &gimli::Dwarf<R>,
    ) -> Result<(Option<&'unit Function<R>>, Option<Location<'unit>>), gimli::Error> {
        let unit = &self.dw_unit;
        let functions = self.parse_functions_dwarf_and_unit(unit, sections)?;
        let function = match functions.find_address(probe) {
            Some(address) => {
                let function_index = functions.addresses[address].function;
                let function = &functions.functions[function_index];
                // TODO: The original code parsed inline functions here. But
                //       it's not exactly clear why that is necessary?
                Some(function)
            }
            None => None,
        };
        let location = self.find_location(probe, sections)?;
        Ok((function, location))
    }

    fn find_name<'unit>(
        &'unit self,
        name: &str,
        sections: &gimli::Dwarf<R>,
    ) -> Result<Option<&'unit Function<R>>, gimli::Error> {
        let unit = &self.dw_unit;
        let functions = self.parse_functions_dwarf_and_unit(unit, sections)?;
        for func in functions.functions.iter() {
          let name = Some(Ok(Cow::Borrowed(name.as_bytes())));
          if func.name.as_ref().map(|r| r.to_slice()) == name {
            return Ok(Some(func))
          }
        }
        Ok(None)
    }
}


pub(crate) struct Units<R: gimli::Reader> {
    /// The DWARF data.
    dwarf: gimli::Dwarf<R>,
    /// The ranges of the units encountered.
    unit_ranges: Vec<UnitRange>,
    /// All units along with meta-data.
    units: Box<[Unit<R>]>,
}

impl<R: gimli::Reader> Units<R> {
    pub(crate) fn parse(sections: gimli::Dwarf<R>) -> Result<Self, gimli::Error> {
        // Find all the references to compilation units in .debug_aranges.
        // Note that we always also iterate through all of .debug_info to
        // find compilation units, because .debug_aranges may be missing some.
        let mut aranges = Vec::new();
        let mut headers = sections.debug_aranges.headers();
        while let Some(header) = headers.next()? {
            aranges.push((header.debug_info_offset(), header.offset()));
        }
        aranges.sort_by_key(|i| i.0);

        let mut unit_ranges = Vec::new();
        let mut res_units = Vec::new();
        let mut units = sections.units();
        while let Some(header) = units.next()? {
            let unit_id = res_units.len();
            let offset = match header.offset().as_debug_info_offset() {
                Some(offset) => offset,
                None => continue,
            };
            // We mainly want compile units, but we may need to follow references to entries
            // within other units for function names.  We don't need anything from type units.
            match header.type_() {
                gimli::UnitType::Type { .. } | gimli::UnitType::SplitType { .. } => continue,
                _ => {}
            }
            let dw_unit = match sections.unit(header) {
                Ok(dw_unit) => dw_unit,
                Err(_) => continue,
            };

            let mut lang = None;
            let mut have_unit_range = false;
            {
                let mut entries = dw_unit.entries_raw(None)?;

                let abbrev = match entries.read_abbreviation()? {
                    Some(abbrev) => abbrev,
                    None => continue,
                };

                let mut ranges = RangeAttributes::default();
                for spec in abbrev.attributes() {
                    let attr = entries.read_attribute(*spec)?;
                    match attr.name() {
                        gimli::DW_AT_low_pc => match attr.value() {
                            gimli::AttributeValue::Addr(val) => ranges.low_pc = Some(val),
                            gimli::AttributeValue::DebugAddrIndex(index) => {
                                ranges.low_pc = Some(sections.address(&dw_unit, index)?);
                            }
                            _ => {}
                        },
                        gimli::DW_AT_high_pc => match attr.value() {
                            gimli::AttributeValue::Addr(val) => ranges.high_pc = Some(val),
                            gimli::AttributeValue::DebugAddrIndex(index) => {
                                ranges.high_pc = Some(sections.address(&dw_unit, index)?);
                            }
                            gimli::AttributeValue::Udata(val) => ranges.size = Some(val),
                            _ => {}
                        },
                        gimli::DW_AT_ranges => {
                            ranges.ranges_offset =
                                sections.attr_ranges_offset(&dw_unit, attr.value())?;
                        }
                        gimli::DW_AT_language => {
                            if let gimli::AttributeValue::Language(val) = attr.value() {
                                lang = Some(val);
                            }
                        }
                        _ => {}
                    }
                }

                // Find the address ranges for the CU, using in order of preference:
                // - DW_AT_ranges
                // - .debug_aranges
                // - DW_AT_low_pc/DW_AT_high_pc
                //
                // Using DW_AT_ranges before .debug_aranges is possibly an arbitrary choice,
                // but the feeling is that DW_AT_ranges is more likely to be reliable or complete
                // if it is present.
                //
                // .debug_aranges must be used before DW_AT_low_pc/DW_AT_high_pc because
                // it has been observed on macOS that DW_AT_ranges was not emitted even for
                // discontiguous CUs.
                let i = match ranges.ranges_offset {
                    Some(_) => None,
                    None => aranges.binary_search_by_key(&offset, |x| x.0).ok(),
                };
                if let Some(mut i) = i {
                    // There should be only one set per CU, but in practice multiple
                    // sets have been observed. This is probably a compiler bug, but
                    // either way we need to handle it.
                    while i > 0 && aranges[i - 1].0 == offset {
                        i -= 1;
                    }
                    for (_, aranges_offset) in aranges[i..].iter().take_while(|x| x.0 == offset) {
                        let aranges_header = sections.debug_aranges.header(*aranges_offset)?;
                        let mut aranges = aranges_header.entries();
                        while let Some(arange) = aranges.next()? {
                            if arange.length() != 0 {
                                unit_ranges.push(UnitRange {
                                    range: arange.range(),
                                    unit_id,
                                    max_end: 0,
                                });
                                have_unit_range = true;
                            }
                        }
                    }
                } else {
                    have_unit_range |= ranges.for_each_range(&sections, &dw_unit, |range| {
                        unit_ranges.push(UnitRange {
                            range,
                            unit_id,
                            max_end: 0,
                        });
                    })?;
                }
            }

            let lines = LazyCell::new();
            if !have_unit_range {
                // The unit did not declare any ranges.
                // Try to get some ranges from the line program sequences.
                if let Some(ref ilnp) = dw_unit.line_program {
                    if let Ok(lines) = lines
                        .borrow_with(|| Lines::parse(&dw_unit, ilnp.clone(), &sections))
                        .as_ref()
                    {
                        for sequence in lines.sequences.iter() {
                            unit_ranges.push(UnitRange {
                                range: gimli::Range {
                                    begin: sequence.start,
                                    end: sequence.end,
                                },
                                unit_id,
                                max_end: 0,
                            })
                        }
                    }
                }
            }

            res_units.push(Unit {
                offset,
                dw_unit,
                lang,
                lines,
                funcs: LazyCell::new(),
            });
        }

        // Sort this for faster lookup in `find_unit_and_address` below.
        unit_ranges.sort_by_key(|i| i.range.begin);

        // Calculate the `max_end` field now that we've determined the order of
        // CUs.
        let mut max = 0;
        for i in unit_ranges.iter_mut() {
            max = max.max(i.range.end);
            i.max_end = max;
        }

        let slf = Self {
            dwarf: sections,
            unit_ranges,
            units: res_units.into_boxed_slice(),
        };
        Ok(slf)
    }

    /// Finds the CUs for the function address given.
    ///
    /// There might be multiple CUs whose range contains this address.
    /// Weak symbols have shown up in the wild which cause this to happen
    /// but otherwise this can happen if the CU has non-contiguous functions
    /// but only reports a single range.
    ///
    /// Consequently we return an iterator for all CUs which may contain the
    /// address, and the caller must check if there is actually a function or
    /// location in the CU for that address.
    fn find_units(&self, probe: u64) -> impl Iterator<Item = &Unit<R>> {
        self.find_units_range(probe, probe + 1)
            .map(|(unit, _range)| unit)
    }

    /// Finds the CUs covering the range of addresses given.
    ///
    /// The range is [low, high) (ie, the upper bound is exclusive). This can return multiple
    /// ranges for the same unit.
    #[inline]
    fn find_units_range(
        &self,
        probe_low: u64,
        probe_high: u64,
    ) -> impl Iterator<Item = (&Unit<R>, &gimli::Range)> {
        // First up find the position in the array which could have our function
        // address.
        let pos = match self
            .unit_ranges
            .binary_search_by_key(&probe_high, |i| i.range.begin)
        {
            // Although unlikely, we could find an exact match.
            Ok(i) => i + 1,
            // No exact match was found, but this probe would fit at slot `i`.
            // This means that slot `i` is bigger than `probe`, along with all
            // indices greater than `i`, so we need to search all previous
            // entries.
            Err(i) => i,
        };

        // Once we have our index we iterate backwards from that position
        // looking for a matching CU.
        self.unit_ranges[..pos]
            .iter()
            .rev()
            .take_while(move |i| {
                // We know that this CU's start is beneath the probe already because
                // of our sorted array.
                debug_assert!(i.range.begin <= probe_high);

                // Each entry keeps track of the maximum end address seen so far,
                // starting from the beginning of the array of unit ranges. We're
                // iterating in reverse so if our probe is beyond the maximum range
                // of this entry, then it's guaranteed to not fit in any prior
                // entries, so we break out.
                probe_low < i.max_end
            })
            .filter_map(move |i| {
                // If this CU doesn't actually contain this address, move to the
                // next CU.
                if probe_low >= i.range.end || probe_high <= i.range.begin {
                    return None;
                }
                Some((&self.units[i.unit_id], &i.range))
            })
    }

    pub fn find_function(&self, probe: u64) -> Result<Option<&Function<R>>, gimli::Error> {
        let mut units_iter = self.find_units(probe);
        for unit in units_iter {
            let result = unit.find_function_or_location(probe, &self.dwarf)?;
            match result {
                (Some(function), _) => {
                    return Ok(Some(function))
                },
                (None, Some(_location)) => {
                    // We found the address in the unit, we just couldn't get
                    // any symbol information.
                    return Ok(None)
                },
                (None, None) => {
                    // No luck. Let's try another unit.
                },
            }
        }
        Ok(None)
    }

    /// Find the source file and line corresponding to the given virtual memory address.
    pub fn find_location(&self, probe: u64) -> Result<Option<Location<'_>>, gimli::Error> {
        for unit in self.find_units(probe) {
            if let Some(location) = unit.find_location(probe, &self.dwarf)? {
                return Ok(Some(location));
            }
        }
        Ok(None)
    }

    pub fn find_name<'dwarf>(
        &'dwarf self,
        name: &'dwarf str,
    ) -> impl Iterator<Item = Result<&'dwarf Function<R>, gimli::Error>> + 'dwarf {
        self.units
            .iter()
            .filter_map(|unit| unit.find_name(name, &self.dwarf).transpose())
    }
}
