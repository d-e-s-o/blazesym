use std::borrow::Cow;
use std::fmt::Debug;

use crate::inspect::SymInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::Addr;
use crate::Error;
use crate::Result;
use crate::SymType;

/// BPF kernel programs show up with this prefix followed by a tag and
/// some other meta-data.
const BPF_PROG_PREFIX: &str = "bpf_prog_";
/// The size of a BPF tag, as defined in `include/uapi/linux/bpf.h`.
const BPF_TAG_SIZE: usize = 8;

pub type BpfTag = u64;

const _: () = assert!(size_of::<BpfTag>() == BPF_TAG_SIZE);


/// Information about a BPF program.
#[derive(Debug)]
pub struct BpfProg {
    addr: Addr,
    name: Box<str>,
    tag: BpfTag,
}

impl BpfProg {
    /// Parse information about a BPF program from part of a `kallsyms`
    /// line.
    pub fn parse(s: &str, addr: Addr) -> Option<Self> {
        let s = s.strip_prefix(BPF_PROG_PREFIX)?;
        let (tag, name) = s.split_once('_')?;
        // Each byte of the tag is encoded as two hexadecimal characters.
        if tag.len() != 2 * BPF_TAG_SIZE {
            return None
        }

        let tag = BpfTag::from_str_radix(tag, 16).ok()?;
        let prog = BpfProg {
            addr,
            name: Box::from(name),
            tag,
        };
        Some(prog)
    }

    pub fn resolve(&self, _addr: Addr, _opts: &FindSymOpts) -> Result<ResolvedSym<'_>> {
        // TODO: Need to look up BPF specific information.
        let BpfProg { name, addr, .. } = self;
        let sym = ResolvedSym {
            name,
            addr: *addr,
            size: None,
            lang: SrcLang::Unknown,
            code_info: None,
            inlined: Box::new([]),
        };
        Ok(sym)
    }

    /// Retrieve the program's start address.
    pub fn addr(&self) -> Addr {
        self.addr
    }

    /// Retrieve the program's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieve the program's tag.
    pub fn tag(&self) -> BpfTag {
        self.tag
    }
}

impl<'prog> TryFrom<&'prog BpfProg> for SymInfo<'prog> {
    type Error = Error;

    fn try_from(other: &'prog BpfProg) -> Result<Self, Self::Error> {
        let BpfProg { addr, name, .. } = other;
        let sym = SymInfo {
            name: Cow::Borrowed(name),
            addr: *addr,
            size: 0,
            sym_type: SymType::Function,
            file_offset: None,
            obj_file_name: None,
        };
        Ok(sym)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;
    use test_tag::tag;


    /// Test that we can parse a BPF program string as it may appear in
    /// `kallsyms` successfully.
    #[tag(miri)]
    #[test]
    fn bpf_prog_str_parsing() {
        let addr = 0x1337;
        let name = "bpf_prog_30304e82b4033ea3_kprobe__cap_capable";
        let bpf_prog = BpfProg::parse(name, addr).unwrap();
        assert_eq!(bpf_prog.addr, addr);
        assert_eq!(&*bpf_prog.name, "kprobe__cap_capable");
        assert_eq!(bpf_prog.tag, 0x30304e82b4033ea3);

        let name = "bpf_prog_run";
        assert!(BpfProg::parse(name, addr).is_none());

        let name = "bpf_prog_get_curr_or_next";
        assert!(BpfProg::parse(name, addr).is_none());
    }
}
