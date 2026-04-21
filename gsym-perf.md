# Gsym Symbolization Performance Report

## Benchmark setup
- Binary: `vmlinux-5.17.12-100.fc34.x86_64.gsym` (~18 MB, Linux kernel)
- Benchmarks:
  - `symbolize_gsym`: single address (0xffffffff8110ecb0 → "abort_creds"), end-to-end including setup
  - `symbolize_gsym_multi_no_setup`: 6 addresses with >=12 inline frames each, setup amortized outside loop
- Profiling: `perf record -F 997 --call-graph dwarf,64000`

## Baseline profiling

Hotspots in `symbolize_gsym_multi_no_setup` (self time):

| Function | Self % | Issue |
|---|---|---|
| `InlineInfo::parse` | 24.7% | Builds full tree with Vec allocs at every node |
| `InlineInfo` drop | 1.7% | Recursive drop of tree with Vec<Range> + Vec<Self> fields |
| `find_sym` | 14.2% | Includes 8.9% from LineTableRow::clone |
| `run_op` | 10.2% | Line table VM execution — inherent cost |
| `query_frame_code_info` | 2.6% | String table lookups — inherent cost |

The `InlineInfo::parse` function was the clear bottleneck at ~26%
combined with drop. It built a recursive tree structure with heap
allocations at every node, even for subtrees that didn't contain the
lookup address. The tree was then walked to extract matching frames.

## Changes

### 1. Make `LineTableRow` Copy and use copy assignment (linetab.rs, resolver.rs)

Added `Copy` derive to `LineTableRow` (16-byte struct: u64 + u32 + u32)
and replaced `.clone()` calls with plain assignment in
`parse_line_tab_info`. With `Copy`, assignment is a direct bitwise copy
that avoids the `Clone::clone` method call overhead.

The `parse_line_tab_info` loop saves `last_lntab_row` on every new row
emission, so this is called frequently.

### 2. Flatten InlineInfo parsing (inline.rs, resolver.rs)

Replaced the two-phase tree approach with a single-pass flat parser:

**Before**:
1. `InlineInfo::parse()` builds recursive tree (Vec<Range<u64>> +
   Vec<Self> at every node, even non-matching)
2. `inline_stack()` walks tree to find matching frames

**After**:
1. `InlineInfo::parse_inline_stack()` produces `Vec<InlineFrame>`
   directly in a single pass
2. `InlineInfo::skip()` advances the data cursor past non-matching
   subtrees without any allocation
3. `InlineFrame` is a simple 12-byte value type (u32 name + Option<u32>
   call_file + Option<u32> call_line) — no heap fields

Key differences:
- Range containment checked with a bool flag during parsing, not stored
  in a Vec
- Matching frames pushed directly to a shared output Vec
- Non-matching subtrees use `skip()` — zero allocation
- No tree construction, no recursive Drop

**Profile after**:

| Function | Before | After |
|---|---|---|
| `InlineInfo::parse` | 24.7% | — (eliminated) |
| `InlineInfo::parse_into_stack` | — | 7.5% |
| `InlineInfo::skip` | — | 9.5% |
| `InlineInfo` drop | 1.7% | 0% (eliminated) |

## Results

| Benchmark | Before | After | Improvement |
|---|---|---|---|
| `symbolize_gsym` | ~77 µs | ~77 µs | no change (expected: no inlines) |
| `symbolize_gsym_multi_no_setup` | ~242 µs | ~160 µs | **~34% faster** |

All existing tests pass, including the inline resolution test
(`find_line_info`) which verifies correct name, file, and line number
for 2 layers of inlined functions.
