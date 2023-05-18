//! Functionality for address normalization.
//!
//! Address normalization is one step of address symbolization: before an
//! address as captured in a process can be looked up in a file, it needs to be
//! converted into an address as it will be used inside the file. E.g.,
//! addresses in a shared object (or any position independent binary) may be
//! relative to that file. When such a shared object is loaded into a process,
//! it is relocated. Normalization removes this relocation information and
//! similar adjustments made by the system (e.g., by address space layout
//! randomization).
//!
//! ```no_run
//! use blazesym::normalize::Normalizer;
//! use blazesym::Addr;
//! use blazesym::Pid;
//!
//! let normalizer = Normalizer::new();
//! let fopen_addr = libc::fopen as Addr;
//! let addrs = [fopen_addr];
//! let pid = Pid::Slf;
//! let norm_addrs = normalizer.normalize_user_addrs(&addrs, pid).unwrap();
//! assert_eq!(norm_addrs.addrs.len(), 1);
//!
//! let (addr, meta_idx) = norm_addrs.addrs[0];
//! // fopen (0x7f5f8e23a790) corresponds to address 0x77790 within Binary(Binary { path: "/usr/lib64/libc.so.6", build_id: Some([...]), ... })
//! println!("fopen (0x{fopen_addr:x}) corresponds to address 0x{addr:x} within {:?}", norm_addrs.meta[meta_idx]);
//! ```

mod meta;
mod normalizer;

pub use meta::Archive;
pub use meta::Binary;
pub use meta::Unknown;
pub use meta::UserAddrMeta;
pub use normalizer::NormalizedUserAddrs;
pub use normalizer::Normalizer;

pub(crate) use normalizer::normalize_elf_addr;
pub(crate) use normalizer::normalize_sorted_user_addrs_with_entries;
pub(crate) use normalizer::Handler;
