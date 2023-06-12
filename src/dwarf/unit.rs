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

use super::function::Functions;
use super::lazy::LazyCell;
use super::line::Lines;
use super::range::RangeAttributes;


struct UnitRange {
    unit_id: usize,
    max_end: u64,
    range: gimli::Range,
}


struct Unit<R: gimli::Reader> {
    offset: gimli::DebugInfoOffset<R::Offset>,
    dw_unit: gimli::Unit<R>,
    lines: LazyCell<Result<Lines, gimli::Error>>,
    funcs: LazyCell<Result<Functions<R>, gimli::Error>>,
}

struct Units<R: gimli::Reader> {
    /// The ranges of the units encountered.
    unit_ranges: Vec<UnitRange>,
    /// All units along with meta-data.
    units: Vec<Unit<R>>,
}

impl<R: gimli::Reader> Units<R> {
    fn parse(sections: &gimli::Dwarf<R>) -> Result<Self, gimli::Error> {
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
                    have_unit_range |= ranges.for_each_range(sections, &dw_unit, |range| {
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
                        .borrow_with(|| Lines::parse(&dw_unit, ilnp.clone(), sections))
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
            unit_ranges,
            units: res_units,
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
}
