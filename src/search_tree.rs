//! A cache-efficient static search tree (S+ tree) over sorted `u64` keys.
//!
//! Symbolization repeatedly maps an address to the covering symbol via a
//! lower-bound search over a large, sorted, immutable set of keys (symbol
//! addresses). A textbook binary search over a plain sorted array touches
//! `log2(n)` scattered cache lines per lookup and, when the keys are reached
//! through an index array, additionally dereferences a random element per
//! probe. Both waste memory bandwidth: only a single key from each fetched
//! cache line is ever used.
//!
//! This module lays the keys out as an *S+ tree*, following the implementation
//! from <https://curiouscoding.nl/posts/static-search-tree/> and
//! <https://github.com/RagnarGrootKoerkamp/static-search-tree> (in turn based
//! on <https://en.algorithmica.org/hpc/data-structures/s-tree/>). Each node
//! packs `B` keys into a single, cache-line-aligned 64-byte block and has
//! `B + 1` children, so one fetched cache line advances the search by a full
//! `log2(B + 1)` levels and a lookup fetches only `~log(B+1)(n)` cache lines
//! instead of `log2(n)`. The topmost levels — probed by every query — stay
//! resident in cache. It is a "plus" tree in that the leaf layer holds every
//! key in sorted order and the internal layers hold routing keys (the minimum
//! of each right subtree). Because the leaves are the sorted sequence, the
//! leaf position a query lands on is directly its rank, so no auxiliary rank
//! table is needed.
//!
//! The upstream code targets 32-bit keys with hand-written AVX2 (and nightly
//! portable) SIMD, query batching, and hugepage-backed storage. This port
//! keeps the layout, construction, and descent verbatim but adapts them to
//! blazesym's constraints: 64-bit keys (so `B` is 8, one cache line), a
//! portable, branchless scalar in-node search (upstream's `find_linear_count`,
//! which auto-vectorizes), and ordinary allocation. The SIMD search and
//! batching trade portability for throughput on huge query streams and are
//! not adopted.

/// The number of keys per node. Eight 8-byte keys fill one 64-byte cache line;
/// each node therefore has nine children. (Upstream calls this both `B` and
/// `N`; the two coincide here because nodes are full.)
const B: usize = 8;

/// The sentinel filling unused key slots. A scalar `key < q` comparison never
/// counts it (no real address reaches `u64::MAX`), so it acts as `+inf`.
const MAX: u64 = u64::MAX;


/// The number of `B`-key nodes required to hold `n` keys.
const fn blocks(n: usize) -> usize {
    n.div_ceil(B)
}

/// The number of keys in the layer above one holding `n` keys: one routing key
/// per child node, rounded up to whole nodes.
const fn prev_keys(n: usize) -> usize {
    blocks(n).div_ceil(B + 1) * B
}

/// The height (number of layers) of a balanced S+ tree over `n` keys.
const fn height(n: usize) -> usize {
    if n <= B {
        1
    } else {
        height(prev_keys(n)) + 1
    }
}

/// The number of keys in layer `h` of a tree of the given `height` over `n`
/// keys (layer `0` is the root, `height - 1` the leaves).
fn layer_keys(mut n: usize, h: usize, height: usize) -> usize {
    for _ in h..height - 1 {
        n = prev_keys(n);
    }
    n
}


/// A tree node: `B` keys packed into a single cache-line-aligned block.
#[repr(align(64))]
#[derive(Clone, Copy, Debug)]
struct Node {
    data: [u64; B],
}

impl Node {
    /// Count the keys strictly less than `q`.
    ///
    /// The keys are sorted ascending, so this is equivalently the index of the
    /// first key `>= q` within the node (in `0..=B`). Written as a branchless
    /// accumulation (upstream's `find_linear_count`) so it compiles to a
    /// handful of vector comparisons.
    #[inline]
    fn rank(&self, q: u64) -> usize {
        let mut count = 0;
        for &key in &self.data {
            count += usize::from(key < q);
        }
        count
    }
}


/// A static search tree (S+ tree) over a set of sorted `u64` keys.
#[derive(Debug)]
pub(crate) struct SearchTree {
    /// The nodes of all layers, packed back to back. The root layer comes
    /// first and the leaf layer (all keys, in sorted order) last.
    tree: Box<[Node]>,
    /// The start node index of each layer in `tree`; `offsets[0] == 0` (root)
    /// and the last entry is the leaf layer. Has one entry per layer.
    offsets: Box<[usize]>,
    /// The number of real keys (excluding padding).
    len: usize,
}

impl SearchTree {
    /// Build a tree from `n` keys accessible in ascending sorted order via
    /// `key(i)` for `i` in `0..n`.
    ///
    /// Returns `None` when there is nothing to gain (no keys) or when `n`
    /// exceeds what the layout can address; callers should then fall back to a
    /// plain search over the sorted data.
    pub(crate) fn build<F>(n: usize, key: F) -> Option<Self>
    where
        F: Fn(usize) -> u64,
    {
        // The padded tree is a small constant factor larger than `n`; guard
        // against sizes where the child arithmetic could overflow.
        if n == 0 || n > usize::MAX / (B + 1) {
            return None
        }

        let height = height(n);
        let layer_sizes = (0..height)
            .map(|h| blocks(layer_keys(n, h, height)))
            .collect::<Vec<_>>();
        let n_blocks = layer_sizes.iter().sum::<usize>();

        // Layers are stored root-first; `offsets[h]` is the prefix sum of the
        // preceding layer sizes.
        let mut offsets = Vec::with_capacity(height);
        let mut sum = 0;
        for &size in &layer_sizes {
            let () = offsets.push(sum);
            sum += size;
        }

        let mut tree = vec![Node { data: [MAX; B] }; n_blocks].into_boxed_slice();

        // Copy the input keys into the leaf layer, in order.
        let leaves = offsets[height - 1];
        for i in 0..n {
            tree[leaves + i / B].data[i % B] = key(i);
        }

        // Fill the internal layers bottom-up. Each routing key is the minimum
        // of its right subtree: step to the right of the key, then descend to
        // the leftmost leaf and take its first (smallest) key. (Faithful to
        // upstream's `new_params` / Algorithmica's construction.)
        for h in (0..height - 1).rev() {
            let layer = offsets[h];
            for i in 0..B * layer_sizes[h] {
                let mut leaf = i / B * (B + 1) + i % B + 1;
                for _ in h..height - 2 {
                    leaf *= B + 1;
                }
                tree[layer + i / B].data[i % B] = if leaf * B < n {
                    tree[leaves + leaf].data[0]
                } else {
                    MAX
                };
            }
        }

        Some(Self {
            tree,
            offsets: offsets.into_boxed_slice(),
            len: n,
        })
    }

    /// The number of keys in the tree.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Return the number of keys strictly less than `q`, i.e. the rank in the
    /// original sorted sequence of the first key `>= q` (in `0..=len()`).
    ///
    /// This mirrors `<[_]>::partition_point(|k| k < q)` over the sorted keys.
    #[inline]
    pub(crate) fn partition_point(&self, q: u64) -> usize {
        // Descend from the root: in each node the count of keys `< q` picks the
        // child to visit, mapping node index `k` to child `k * (B + 1) + rank`.
        let mut k = 0;
        let (&leaves, internal) = self.offsets.split_last().unwrap();
        for &layer in internal {
            // SANITY: The descent only ever addresses valid node starts.
            let rank = self.tree[layer + k].rank(q);
            k = k * (B + 1) + rank;
        }
        // In the leaf layer the node position `k` times the node width plus the
        // in-node rank is the global sorted rank. `rank == B` (all keys `< q`)
        // rolls over into the next node; padding keeps it from exceeding `len`.
        let rank = self.tree[leaves + k].rank(q);
        (k * B + rank).min(self.len)
    }

    /// Perform a lower-bound search matching the semantics of
    /// [`crate::util::find_match_or_lower_bound_by_key`], but using the search
    /// tree for the descent.
    ///
    /// `key(i)` must return the sort key of the `i`th element of the original
    /// sorted sequence (the same sequence the tree was built from). The
    /// returned index refers into that sorted sequence.
    #[inline]
    pub(crate) fn find_match_or_lower_bound_by_key<F>(&self, item: u64, key: F) -> Option<usize>
    where
        F: Fn(usize) -> u64,
    {
        let n = self.len();
        let idx = self.partition_point(item);

        // `idx` is the first element greater than or equal to `item`.
        if idx < n && key(idx) == item {
            // An exact match; `partition_point` already yields the first of
            // any equal run.
            return Some(idx)
        }

        // Otherwise `idx` points just past the last element less than `item`
        // (or `item` is smaller than everything, in which case there is no
        // match). Pick the previous element and rewind over its equal run,
        // reproducing `find_match_or_lower_bound_by_key` exactly (including
        // its handling of a run that reaches the start of the slice).
        let idx = idx.checked_sub(1)?;
        let cmp = key(idx);
        for i in (0..idx).rev() {
            if key(i) != cmp {
                return Some(i + 1)
            }
        }
        Some(idx)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::find_match_or_lower_bound_by_key;


    /// Build a tree from a sorted slice.
    fn tree_of(sorted: &[u64]) -> Option<SearchTree> {
        SearchTree::build(sorted.len(), |i| sorted[i])
    }

    /// Check that `partition_point` matches the std slice implementation across
    /// a range of sizes, in particular ones that span multiple tree layers.
    #[test]
    fn partition_point_matches_std() {
        // Cover single-node trees as well as sizes straddling the node size
        // (`B`) and branching factor (`B + 1`) at several layers.
        let sizes = [
            0, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 72, 73, 80, 81, 100, 511, 512, 728, 729, 1000,
            5000,
        ];
        for &size in &sizes {
            let sorted = (0..size).map(|i| (i as u64) * 2 + 3).collect::<Vec<u64>>();
            let tree = tree_of(&sorted);
            for probe in 0..=sorted.len() {
                // Query values that fall exactly on, just below, and just above
                // a key, plus below/above the whole range.
                for x in [
                    probe as u64 * 2 + 2,
                    probe as u64 * 2 + 3,
                    probe as u64 * 2 + 4,
                ] {
                    let expected = sorted.partition_point(|&k| k < x);
                    let actual = match &tree {
                        Some(tree) => tree.partition_point(x),
                        None => 0,
                    };
                    assert_eq!(actual, expected, "size={size} x={x}");
                }
            }
        }
    }

    /// Check that the tree-backed lower-bound search reproduces the plain
    /// [`find_match_or_lower_bound_by_key`] result across exhaustive small
    /// inputs, including duplicates.
    #[test]
    fn find_match_or_lower_bound_matches_plain() {
        // A small deterministic PRNG; the std library provides none and we do
        // not want to pull in a dependency for a test.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..3000 {
            let len = (next() % 200) as usize;
            let modulus = 1 + next() % 32;
            let mut sorted = (0..len).map(|_| next() % modulus).collect::<Vec<u64>>();
            let () = sorted.sort_unstable();

            let tree = tree_of(&sorted);
            for x in 0..=modulus + 1 {
                let expected = find_match_or_lower_bound_by_key(&sorted, x, |&k| k);
                let actual = match &tree {
                    Some(tree) => tree.find_match_or_lower_bound_by_key(x, |i| sorted[i]),
                    None => None,
                };
                assert_eq!(actual, expected, "sorted={sorted:?} x={x}");
            }
        }
    }

    /// Check that ranks recovered from the tree address the sorted elements.
    #[test]
    fn ranks_are_consistent() {
        let sorted = (0..1000).map(|i| i * 3).collect::<Vec<u64>>();
        let tree = tree_of(&sorted).unwrap();
        assert_eq!(tree.len(), sorted.len());

        for (i, &key) in sorted.iter().enumerate() {
            // Every key is found at its own rank.
            assert_eq!(tree.partition_point(key), i);
            // ... and the element just after it starts at `i + 1`.
            assert_eq!(tree.partition_point(key + 1), i + 1);
        }
    }
}
