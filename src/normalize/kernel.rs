use std::error::Error as StdError;
use std::fs::File;
use std::io;
use std::io::Read as _;
use std::path::Path;
use std::str;
use std::str::FromStr;

use crate::elf;
use crate::elf::types::Elf64_Nhdr;
use crate::elf::ElfParser;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::IntoError as _;
use crate::Result;

use super::meta::KernelAddrMeta;
use super::normalizer::Output;


/// A type representing normalized kernel addresses.
pub type KernelOutput<'src> = Output<KernelAddrMeta<'src>>;


#[derive(Debug)]
enum KaslrState {
    /// KASLR is known to be disabled.
    Disabled,
    /// KASLR is known to be enabled.
    Enabled,
    /// The state of KASLR on the system could not be determined.
    Unknown,
}

impl FromStr for KaslrState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let value = usize::from_str(s.trim()).map_err(|err| Error::with_invalid_data(err))?;
        match value {
            0 => Ok(KaslrState::Disabled),
            1 | 2 => Ok(KaslrState::Enabled),
            // It's unclear whether we should error out here or map anything
            // "unknown" to `Unknown`.
            x => Err(Error::with_invalid_data(format!(
                "/proc/sys/kernel/randomize_va_space node value {x} is not understood"
            ))),
        }
    }
}


fn read_proc_node_value<T>(path: &Path) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: StdError + Send + Sync + 'static,
{
    let result = File::open(path);
    let mut file = match result {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    // We don't want to blindly use Read::read_to_end or something like
    // that if we can avoid it. We don't anticipate this function to be
    // used for nodes with large content, so just stack allocate a 64KiB
    // buffer.
    let mut buffer = [0; u16::MAX as usize];
    let count = file.read(&mut buffer)?;
    if count >= u16::MAX.into() {
        // Error our if more data is present.
        return Err(Error::with_invalid_data(
            "file content is larger than 64 KiB",
        ))
    }

    let s = str::from_utf8(&buffer[0..count]).map_err(|err| Error::with_invalid_data(err))?;
    let value = T::from_str(s).map_err(|err| Error::with_invalid_data(err))?;
    Ok(Some(value))
}


/// Try to determine the KASLR state of the system.
fn determine_kaslr_state() -> Result<KaslrState> {
    // https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space
    let kaslr =
        read_proc_node_value::<KaslrState>(Path::new("/proc/sys/kernel/randomize_va_space"))?
            .unwrap_or(KaslrState::Unknown);
    Ok(kaslr)
}

//OSRELEASE=6.2.15-100.fc36.x86_64
//BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
//PAGESIZE=4096
//SYMBOL(init_uts_ns)=ffffffffb72b8160
//OFFSET(uts_namespace.name)=0
//SYMBOL(node_online_map)=ffffffffb731a760
//SYMBOL(swapper_pg_dir)=ffffffffb7010000
//SYMBOL(_stext)=ffffffffb5000000
//SYMBOL(vmap_area_list)=ffffffffb71cab10
//SYMBOL(mem_section)=ffff8dab5f7cd000
//LENGTH(mem_section)=4096
//SIZE(mem_section)=32
//OFFSET(mem_section.section_mem_map)=0
//NUMBER(SECTION_SIZE_BITS)=27
//NUMBER(MAX_PHYSMEM_BITS)=46
//SIZE(page)=64
//SIZE(pglist_data)=175168
//SIZE(zone)=1728
//SIZE(free_area)=104
//SIZE(list_head)=16
//SIZE(nodemask_t)=128
//OFFSET(page.flags)=0
//OFFSET(page._refcount)=52
//OFFSET(page.mapping)=24
//OFFSET(page.lru)=8
//OFFSET(page._mapcount)=48
//OFFSET(page.private)=40
//OFFSET(page.compound_dtor)=16
//OFFSET(page.compound_order)=17
//OFFSET(page.compound_head)=8
//OFFSET(pglist_data.node_zones)=0
//OFFSET(pglist_data.nr_zones)=172512
//OFFSET(pglist_data.node_start_pfn)=172520
//OFFSET(pglist_data.node_spanned_pages)=172536
//OFFSET(pglist_data.node_id)=172544
//OFFSET(zone.free_area)=256
//OFFSET(zone.vm_stat)=1536
//OFFSET(zone.spanned_pages)=144
//OFFSET(free_area.free_list)=0
//OFFSET(list_head.next)=0
//OFFSET(list_head.prev)=8
//OFFSET(vmap_area.va_start)=0
//OFFSET(vmap_area.list)=40
//LENGTH(zone.free_area)=11
//SYMBOL(prb)=ffffffffb7064760
//SYMBOL(printk_rb_static)=ffffffffb7064780
//SYMBOL(clear_seq)=ffffffffb8990300
//SIZE(printk_ringbuffer)=88
//OFFSET(printk_ringbuffer.desc_ring)=0
//OFFSET(printk_ringbuffer.text_data_ring)=48
//OFFSET(printk_ringbuffer.fail)=80
//SIZE(prb_desc_ring)=48
//OFFSET(prb_desc_ring.count_bits)=0
//OFFSET(prb_desc_ring.descs)=8
//OFFSET(prb_desc_ring.infos)=16
//OFFSET(prb_desc_ring.head_id)=24
//OFFSET(prb_desc_ring.tail_id)=32
//SIZE(prb_desc)=24
//OFFSET(prb_desc.state_var)=0
//OFFSET(prb_desc.text_blk_lpos)=8
//SIZE(prb_data_blk_lpos)=16
//OFFSET(prb_data_blk_lpos.begin)=0
//OFFSET(prb_data_blk_lpos.next)=8
//SIZE(printk_info)=88
//OFFSET(printk_info.seq)=0
//OFFSET(printk_info.ts_nsec)=8
//OFFSET(printk_info.text_len)=16
//OFFSET(printk_info.caller_id)=20
//OFFSET(printk_info.dev_info)=24
//SIZE(dev_printk_info)=64
//OFFSET(dev_printk_info.subsystem)=0
//LENGTH(printk_info_subsystem)=16
//OFFSET(dev_printk_info.device)=16
//LENGTH(printk_info_device)=48
//SIZE(prb_data_ring)=32
//OFFSET(prb_data_ring.size_bits)=0
//OFFSET(prb_data_ring.data)=8
//OFFSET(prb_data_ring.head_lpos)=16
//OFFSET(prb_data_ring.tail_lpos)=24
//SIZE(atomic_long_t)=8
//OFFSET(atomic_long_t.counter)=0
//SIZE(latched_seq)=24
//OFFSET(latched_seq.val)=8
//LENGTH(free_area.free_list)=6
//NUMBER(NR_FREE_PAGES)=0
//NUMBER(PG_lru)=4
//NUMBER(PG_private)=13
//NUMBER(PG_swapcache)=10
//NUMBER(PG_swapbacked)=19
//NUMBER(PG_slab)=9
//NUMBER(PG_hwpoison)=23
//NUMBER(PG_head_mask)=65536
//NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE)=-129
//NUMBER(HUGETLB_PAGE_DTOR)=2
//NUMBER(PAGE_OFFLINE_MAPCOUNT_VALUE)=-257
//SYMBOL(kallsyms_names)=ffffffffb654a988
//SYMBOL(kallsyms_num_syms)=ffffffffb654a980
//SYMBOL(kallsyms_token_table)=ffffffffb6839ed0
//SYMBOL(kallsyms_token_index)=ffffffffb683a298
//SYMBOL(kallsyms_offsets)=ffffffffb64847b8
//SYMBOL(kallsyms_relative_base)=ffffffffb654a978
//NUMBER(phys_base)=31541166080
//SYMBOL(init_top_pgt)=ffffffffb7010000
//NUMBER(pgtable_l5_enabled)=0
//SYMBOL(node_data)=ffffffffb7315820
//LENGTH(node_data)=1024
//KERNELOFFSET=34000000
//NUMBER(KERNEL_IMAGE_SIZE)=1073741824
//NUMBER(sme_mask)=0

/// Find and read the `KERNELOFFSET` note in a "kcore" file represented by
/// `parser` (i.e., already opened as an ELF).
fn find_kcore_kernel_offset_note(parser: &ElfParser) -> Result<Option<&[u8]>> {
    let shdrs = parser.section_headers()?;
    for (idx, shdr) in shdrs.iter().enumerate() {
        if shdr.sh_type != elf::types::SHT_NOTE {
            continue
        }

        // SANITY: We just found the index so the section data should always
        //         be found.
        let mut bytes = parser.section_data(idx).unwrap();
        let header = bytes
            .read_pod_ref::<Elf64_Nhdr>()
            .ok_or_invalid_data(|| "failed to read notes section header")?;
        let name = bytes
            .read_slice(header.n_namesz as _)
            .and_then(|mut name| name.read_cstr())
            .ok_or_invalid_data(|| "failed to read build ID section name")?;
        // No point in checking `header.n_type`, as we have seen it be
        // simply 0 on valid kcore instances.
        if name.to_bytes() == b"VMCOREINFO\0" {
            let info = bytes
                .read_slice(header.n_descsz as _)
                .ok_or_invalid_data(|| "failed to read VMCOREINFO note section contents")?;
            return Ok(Some(info))
        }
    }
    Ok(None)
}

pub(super) fn normalize_kernel_addrs(_addrs: &[Addr]) -> Result<KernelOutput<'static>> {
    // No PID means that we can only resolve kernel addresses.

    // TODO: We'd need to take into account KASLR offsets here, for
    //       example.

    // The canonical source for getting its value is /proc/kcore.
    // But that file may not be present. Reference:
    // https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html#kerneloffset
    //
    // https://github.com/osandov/drgn/blob/c76f25b8525c9a80ee4b4f5ce3292c14125c9e1b/libdrgn/drgn_program_parse_vmcoreinfo.inc.strswitch#L51
    // has example logic

    // May have to check 'kernel.randomize_va_space' sysctl
    // Check System.map-<kernel version>
    // - discrepancy to /proc/kallsysms contents would be KASLR offset
    // - _head or _text symbol from /proc/kallsysms could point to kernel base
    //   address
    //
    // /sys/kernel/debug/kernel_page_tables could potentially be of
    // interest, too
    //
    // CONFIG_RANDOMIZE_BASE seems to be a necessity
    //
    // nokaslr would disable KASLR, kaslr would enable it
    // /proc/cmdline contains command line
    //
    // try lsmod or /proc/modules to access module address
    //
    // Could potentially parse dmesg:
    // > 505.654475:   <6> Kernel Offset: 0x2c28000000 from 0xffffff8008000000
    //
    // May be worth looking at
    // https://github.com/libvmi/libvmi/blob/0f832ebfc41bde5977be0547d9bfa9722891e631/libvmi/os/linux/core.c#L404
    // as well

    Err(Error::with_unsupported("not yet implemented"))
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Check that we can determine the system's KASLR state.
    #[test]
    fn kaslr_detection() {
        let _state = determine_kaslr_state().unwrap();
        println!("system KASLR state: {_state:?}");

        let parser = ElfParser::open(Path::new("/proc/kcore")).unwrap();
        let notes = find_kcore_kernel_offset_note(&parser).unwrap().unwrap();
        println!("{notes:?}");
    }
}
