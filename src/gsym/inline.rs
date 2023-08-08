use crate::util::upper_bound;
use crate::util::upper_bound_by;
use crate::util::ReadRaw as _;
use crate::IntoError as _;
use crate::Result;


#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Range {
    start: u64,
    end: u64,
}

impl Range {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }

    pub fn adjoins_or_intersects(&self, rhs: &Range) -> bool {
        self.start <= rhs.end && self.end >= rhs.start
    }

    pub fn intersects(&self, rhs: &Range) -> bool {
        self.start < rhs.end && self.end > rhs.start
    }
}


#[derive(Debug, Default)]
struct Ranges {
    ranges: Vec<Range>,
}

impl Ranges {
    pub fn insert(&mut self, range: Range) {
        let pos = upper_bound(&self.ranges, range);
        self.ranges.insert(pos, range);
    }

    pub fn contains(&self, addr: u64) -> bool {
        if self.ranges.is_empty() {
            return false
        }

        if let Some(first) = self.ranges.first() {
            if addr < first.start {
                return false
            }
        }

        if let Some(last) = self.ranges.last() {
            if addr >= last.end {
                return false
            }
        }

        let mut pos = upper_bound_by(&self.ranges, |range| range.start.cmp(&addr));
        if pos == self.ranges.len() {
            self.ranges.last().unwrap().contains(addr)
        } else if pos != 0 {
            pos -= 1;
            self.ranges[pos].contains(addr)
        } else {
            false
        }
    }
}


#[derive(Clone)]
pub(super) struct InlineInfo {
    pub name: u32,
    pub call_file: Option<u32>,
    pub call_line: Option<u32>,

    ranges: Vec<Range>,
    children: Vec<Self>,
}

impl InlineInfo {
    /// Decode InlineInfo from data file. In the second variant, only ranges and
    /// children containing lookup_addr will be stored. For lookup_addr < 0 we will
    /// just skip the data in the data file. Returns true if successful, false if
    /// InlineInfo is empty (meaning end of list).
    pub fn parse(
        data: &mut &[u8],
        base_addr: u64,
        lookup_addr: Option<u64>,
    ) -> Result<Option<InlineInfo>> {
        let range_cnt = data
            .read_u128_leb128()
            .ok_or_invalid_data(|| "failed to read range count from inline information")?
            .0;
        let range_cnt = usize::try_from(range_cnt)
            .ok()
            .ok_or_invalid_data(|| "range count ({}) is too big")?;
        if range_cnt == 0 {
            return Ok(None)
        }

        let mut ranges = Vec::with_capacity(range_cnt);

        let mut child_base_addr = 0u64;
        if let Some(lookup_addr) = lookup_addr {
            for i in 0..range_cnt {
                let offset = data
                    .read_u128_leb128()
                    .ok_or_invalid_data(|| "failed to read offset from inline information")?
                    .0;
                let offset = u64::try_from(offset)
                    .ok()
                    .ok_or_invalid_data(|| "offset ({}) is too big")?;
                let size = data
                    .read_u128_leb128()
                    .ok_or_invalid_data(|| "failed to read size from inline information")?
                    .0;
                let size = u64::try_from(size)
                    .ok()
                    .ok_or_invalid_data(|| "size ({}) is too big")?;

                let start = base_addr + offset;
                let end = start + size;
                if i == 0 {
                    child_base_addr = start;
                }
                if start <= lookup_addr && end > lookup_addr {
                    let () = ranges.push(Range { start, end });
                }
            }
        } else {
            for _ in 0..range_cnt {
                let _offset = data
                    .read_u128_leb128()
                    .ok_or_invalid_data(|| "failed to read offset from inline information")?;
                let _size = data
                    .read_u128_leb128()
                    .ok_or_invalid_data(|| "failed to read size from inline information")?;
            }
        }

        let child_cnt = data
            .read_u8()
            .ok_or_invalid_data(|| "failed to read child count from inline information")?;
        let has_children = child_cnt != 0;
        let name = data
            .read_u32()
            .ok_or_invalid_data(|| "failed to read name from inline information")?;

        let (call_file, call_line) = if lookup_addr.is_some() {
            let call_file = data
                .read_u128_leb128()
                .ok_or_invalid_data(|| "failed to read call file from inline information")?
                .0;
            let call_file = u32::try_from(call_file)
                .ok()
                .ok_or_invalid_data(|| "call file index ({}) is too big")?;
            let call_line = data
                .read_u128_leb128()
                .ok_or_invalid_data(|| "failed to read call line from inline information")?
                .0;
            let call_line = u32::try_from(call_line).unwrap_or(u32::MAX);
            (Some(call_file), Some(call_line))
        } else {
            let _call_file = data
                .read_u128_leb128()
                .ok_or_invalid_data(|| "failed to read call file from inline information")?;
            let _call_line = data
                .read_u128_leb128()
                .ok_or_invalid_data(|| "failed to read call line from inline information")?;
            (None, None)
        };

        let mut children = Vec::new();
        if has_children {
            if ranges.is_empty() {
                // This inlined function does not contain `lookup_addr`, no need
                // to decode ranges, just skip.
                while let Some(_child) = Self::parse(data, child_base_addr, None)? {
                    // Do nothing; we just skip the data.
                }
            } else {
                while let Some(child) = Self::parse(data, child_base_addr, lookup_addr)? {
                    let () = children.push(child);
                }
            }
        }

        let slf = Self {
            name,
            call_file,
            call_line,
            ranges,
            children,
        };
        Ok(Some(slf))
    }

    fn inline_stack_impl(&self, addr: u64, inlined: &mut Vec<Self>) -> bool {
        for range in &self.ranges {
          if range.contains(addr) {
            if self.name > 0 {
              inlined.insert(0, self.clone());
            }

            for child in &self.children {
              if child.inline_stack_impl(addr, inlined) {
                break
              }
            }
            return true;
          }
        }
        return false;
    }

    pub fn inline_stack(&self, addr: u64) -> Vec<Self> {
        let mut inlined = Vec::new();
        let _done = self.inline_stack_impl(addr, &mut inlined);
        inlined
    }
}
