use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RelocationMapEntry {
    implicit_addend: bool,
    addend: u64,
}

/// A map from section offsets to relocation information.
///
/// This can be used to apply relocations to a value at a given section offset.
/// This is intended for use with DWARF in relocatable object files, and only
/// supports relocations that are used in DWARF.
#[derive(Debug, Default)]
pub(crate) struct RelocationMap(HashMap<u64, RelocationMapEntry>);

impl RelocationMap {
    /// Construct a new relocation map for a section.
    ///
    /// Fails if any relocation cannot be added to the map.
    /// You can manually use `add` if you need different error handling,
    /// such as to list all errors or to ignore them.
    pub fn new<'data, 'file, T>(file: &'file T, section: &T::Section<'file>) -> Result<Self>
    where
        T: Object<'data>,
    {
        let mut map = RelocationMap(HashMap::new());
        for (offset, relocation) in section.relocations() {
            map.add(file, offset, relocation)?;
        }
        Ok(map)
    }

    /// Add a single relocation to the map.
    pub fn add<'data: 'file, 'file, T>(
        &mut self,
        file: &'file T,
        offset: u64,
        relocation: Relocation,
    ) -> Result<()>
    where
        T: Object<'data>,
    {
        let mut entry = RelocationMapEntry {
            implicit_addend: relocation.has_implicit_addend(),
            addend: relocation.addend() as u64,
        };
        match relocation.kind() {
            RelocationKind::Absolute => match relocation.target() {
                RelocationTarget::Symbol(symbol_idx) => {
                    let symbol = file
                        .symbol_by_index(symbol_idx)
                        .read_error("Relocation with invalid symbol")?;
                    entry.addend = symbol.address().wrapping_add(entry.addend);
                }
                RelocationTarget::Section(section_idx) => {
                    let section = file
                        .section_by_index(section_idx)
                        .read_error("Relocation with invalid section")?;
                    // DWARF parsers expect references to DWARF sections to be section offsets,
                    // not addresses. Addresses are useful for everything else.
                    if section.kind() != SectionKind::Debug {
                        entry.addend = section.address().wrapping_add(entry.addend);
                    }
                }
                _ => {
                    return Err(Error("Unsupported relocation target"));
                }
            },
            _ => {
                return Err(Error("Unsupported relocation type"));
            }
        }
        if self.0.insert(offset, entry).is_some() {
            return Err(Error("Multiple relocations for offset"));
        }
        Ok(())
    }

    /// Relocate a value that was read from the section at the given offset.
    pub fn relocate(&self, offset: u64, value: u64) -> u64 {
        if let Some(relocation) = self.0.get(&offset) {
            if relocation.implicit_addend {
                // Use the explicit addend too, because it may have the symbol value.
                value.wrapping_add(relocation.addend)
            } else {
                relocation.addend
            }
        } else {
            value
        }
    }
}
