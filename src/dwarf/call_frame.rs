use super::{
    decode_leb128, decode_leb128_s, decode_sdword, decode_shalf, decode_sword, decode_udword,
    decode_uhalf, decode_uword,
};
use crate::elf::Elf64Parser;
use crate::tools::extract_string;

use std::cell::RefCell;
use std::clone::Clone;
use std::collections::HashMap;

use std::io::{Error, ErrorKind};
use std::mem;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub enum CFARule {
    #[allow(non_camel_case_types)]
    reg_offset(u64, i64),
    #[allow(non_camel_case_types)]
    expression(Vec<u8>),
}

#[derive(Clone, Debug)]
enum RegRule {
    #[allow(non_camel_case_types)]
    undefined,
    #[allow(non_camel_case_types)]
    same_value,
    #[allow(non_camel_case_types)]
    offset(i64),
    #[allow(non_camel_case_types)]
    val_offset(i64),
    #[allow(non_camel_case_types)]
    register(u64),
    #[allow(non_camel_case_types)]
    expression(Vec<u8>),
    #[allow(non_camel_case_types)]
    val_expression(Vec<u8>),
    #[allow(non_camel_case_types)]
    architectural,
}

struct CFCIEAux {
    raw: Vec<u8>,
    init_cfa: CFARule,
    init_regs: Vec<RegRule>,
}

/// CIE record of Call Frame.
pub struct CFCIE<'a> {
    offset: usize,
    /// from a .debug_frame or .eh_frame section.
    version: u32,
    augmentation: &'a str,
    pointer_encoding: u8,
    eh_data: u64,
    address_size: u8,
    segment_selector_size: u8,
    code_align_factor: u64,
    data_align_factor: i64,
    return_address_register: u8,
    augmentation_data: &'a [u8],
    init_instructions: &'a [u8],

    aux: CFCIEAux,
}

/// FDE record of Call Frame.
pub struct CFFDE<'a> {
    offset: usize,
    cie_pointer: u32,
    initial_location: u64,
    address_range: u64,
    augmentation_data: &'a [u8],
    instructions: &'a [u8],
    raw: Vec<u8>,
}

/// Exception Header pointer relocation worker.
///
/// The implementations apply base addresses to pointers.  The pointer
/// may relate to pc, text section, data section, or function
/// beginning.
///
/// This is a helper trait of [`EHPointerDecoder`].  It is trait
/// because parts of implementation vary according to application.
///
/// An instance of the class that implements this trait is shared by
/// decoders.  [`EHPDBuilder`] holds an instance to create all
/// flyweights.
trait DHPointerReloc {
    fn apply_pcrel(&self, ptr: u64, off: u64) -> u64;
    fn apply_textrel(&self, ptr: u64) -> u64;
    fn apply_datarel(&self, ptr: u64) -> u64;
    fn apply_funcrel(&self, ptr: u64) -> u64;
    fn apply_aligned(&self, ptr: u64) -> u64;
}

/// Decode pointers for Exception Header.
///
/// The format of `.eh_frame` is an extendsion of `.debug_frame`.  It
/// encodes addresses in various ways with various sizes and bases.
/// The encoding type of a pointer is encoded as a 1-byte value.
/// `EHPointerDecoder` decode pointers in the way of the gien encoding
/// type.
///
/// See https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/dwarfext.html
/// https://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
/// and https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
struct EHPointerDecoder {
    enc_type: u8, // The value of 'L', 'P', and 'R' letters in Augmentation String
    pointer_sz: usize,
    applier: Rc<Box<dyn DHPointerReloc>>,
}

impl EHPointerDecoder {
    fn apply(&self, v: u64, off: u64) -> u64 {
        let applier = &self.applier;

        match self.enc_type >> 4 {
            0x0 => v,
            0x1 => applier.apply_pcrel(v, off),
            0x2 => applier.apply_textrel(v),
            0x3 => applier.apply_datarel(v),
            0x4 => applier.apply_funcrel(v),
            0x5 => applier.apply_aligned(v),
            _ => {
                panic!("unknown pointer type ({})", self.enc_type);
            }
        }
    }

    fn apply_s(&self, v: i64, off: u64) -> u64 {
        self.apply(v as u64, off)
    }

    fn decode(&self, data: &[u8], off: u64) -> Option<(u64, usize)> {
        // see https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/dwarfext.html
        match self.enc_type & 0xf {
            0x00 => {
                let v = decode_uN(self.pointer_sz, data);
                let v = self.apply(v, off);
                Some((v, self.pointer_sz))
            }
            0x01 => {
                let (v, bytes) = decode_leb128(data).unwrap();
                let v = self.apply(v, off);
                Some((v, bytes as usize))
            }
            0x02 => {
                let v = decode_uN(2, data);
                let v = self.apply(v, off);
                Some((v, 2))
            }
            0x03 => {
                let v = decode_uN(4, data);
                let v = self.apply(v, off);
                Some((v, 4))
            }
            0x04 => {
                let v = decode_uN(4, data);
                let v = self.apply(v, off);
                Some((v, 4))
            }
            0x09 => {
                let (v, bytes) = decode_leb128_s(data).unwrap();
                let v = self.apply_s(v, off);
                Some((v, bytes as usize))
            }
            0x0a => {
                let v = decode_iN(2, data);
                let v = self.apply_s(v, off);
                Some((v, 2))
            }
            0x0b => {
                let v = decode_iN(4, data);
                let v = self.apply_s(v, off);
                Some((v, 4))
            }
            0x0c => {
                let v = decode_iN(8, data);
                let v = self.apply_s(v, off);
                Some((v, 8))
            }
            _ => None,
        }
    }
}

/// Build pointer decoders and maintain a cache.
///
/// It implements the Flyweight Pattern for [`EHPointerDecoder`].  It
/// always returns the same instance for requests with the same
/// encoding type.
struct EHPDBuilder {
    decoders: RefCell<HashMap<u8, Rc<EHPointerDecoder>>>,
    applier: Rc<Box<dyn DHPointerReloc>>,
    pointer_sz: usize,
}

impl EHPDBuilder {
    fn new(applier: Rc<Box<dyn DHPointerReloc>>) -> EHPDBuilder {
        EHPDBuilder {
            decoders: RefCell::new(HashMap::new()),
            applier: applier,
            pointer_sz: mem::size_of::<*const u8>(),
        }
    }

    fn build(&self, enc_type: u8) -> Rc<EHPointerDecoder> {
        let mut decoders = self.decoders.borrow_mut();
        if let Some(decoder) = decoders.get(&enc_type) {
            (*decoder).clone()
        } else {
            let decoder = Rc::new(EHPointerDecoder {
                enc_type,
                pointer_sz: self.pointer_sz,
                applier: self.applier.clone(),
            });
            decoders.insert(enc_type, decoder.clone());
            decoder
        }
    }
}

enum CieOrCieID {
    #[allow(non_camel_case_types)]
    CIE,
    #[allow(non_camel_case_types)]
    CIE_PTR(u32),
}

/// Parser of records in .debug_frame or .eh_frame sections.
pub struct CallFrameParser {
    pd_builder: EHPDBuilder,
    is_debug_frame: bool,
    pointer_sz: usize,
}

impl CallFrameParser {
    fn new(pd_builder: EHPDBuilder, is_debug_frame: bool) -> CallFrameParser {
        CallFrameParser {
            pd_builder,
            is_debug_frame,
            pointer_sz: mem::size_of::<*const u8>(),
        }
    }

    pub fn from_parser(parser: &Elf64Parser, is_debug_frame: bool) -> CallFrameParser {
        let applier = DHPointerRelocElf::new(parser, is_debug_frame);
        let applier_box = Box::new(applier) as Box<dyn DHPointerReloc>;
        let pd_builder = EHPDBuilder::new(Rc::<Box<dyn DHPointerReloc>>::new(applier_box));
        CallFrameParser::new(pd_builder, is_debug_frame)
    }

    /// Find pointer encoding of a CIE.
    fn get_ptr_enc_type(&self, cie: &CFCIE) -> u8 {
        let mut aug = cie.augmentation.chars();
        if aug.next() != Some('z') {
            return 0;
        }
        let mut aug_data_off = 0;
        for c in aug {
            match c {
                'e' | 'h' => {
                    // skip eh
                }
                'L' => {
                    aug_data_off += 1;
                }
                'P' => match cie.augmentation_data[aug_data_off] & 0xf {
                    0 => {
                        aug_data_off += 1 + self.pointer_sz;
                    }
                    0x1 | 0x9 => {
                        let opt_v = decode_leb128(&cie.augmentation_data[(aug_data_off + 1)..]);
                        if opt_v.is_none() {
                            return 0;
                        }
                        let (_, bytes) = opt_v.unwrap();
                        aug_data_off += 1 + bytes as usize;
                    }
                    0x2 | 0xa => {
                        aug_data_off += 3;
                    }
                    0x3 | 0xb => {
                        aug_data_off += 5;
                    }
                    0x4 | 0xc => {
                        aug_data_off += 9;
                    }
                    _ => {
                        panic!("invalid encoding in augmentation");
                    }
                },
                'R' => {
                    return cie.augmentation_data[aug_data_off];
                }
                _ => todo!(),
            }
        }

        0
    }

    fn parse_call_frame_cie(&self, raw: &[u8], cie: &mut CFCIE) -> Result<(), Error> {
        let mut offset: usize = 4; // skip CIE_id

        let ensure = |offset, x| {
            if x + offset <= raw.len() {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the call frame data is broken",
                ))
            }
        };

        ensure(offset, 1)?;
        cie.version = raw[offset] as u32;
        offset += 1;

        cie.augmentation = unsafe {
            let aug = &*(extract_string(&raw, offset).ok_or_else(|| Error::new(
                ErrorKind::InvalidData,
                "can not extract augmentation",
            ))? as *const str);
            offset += aug.len() + 1;
            aug
        };

        if !self.is_debug_frame && cie.augmentation == "eh" {
            // see https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
            ensure(offset, 8)?;
            cie.eh_data = decode_udword(&raw[offset..]);
            offset += 8; // for 64 bit arch
        } else {
            cie.eh_data = 0;
        }

        if self.is_debug_frame {
            ensure(offset, 2)?;
            cie.address_size = raw[offset];
            cie.segment_selector_size = raw[offset + 1];
            offset += 2;
        } else {
            cie.address_size = 8;
            cie.segment_selector_size = 0;
        }

        cie.code_align_factor = {
            let (code_align_factor, bytes) = decode_leb128(&raw[offset..]).ok_or(Error::new(
                ErrorKind::InvalidData,
                "failed to decode code alignment factor",
            ))?;
            offset += bytes as usize;
            code_align_factor
        };

        cie.data_align_factor = {
            let (data_align_factor, bytes) = decode_leb128_s(&raw[offset..]).ok_or(Error::new(
                ErrorKind::InvalidData,
                "failed to decode data alignment factor",
            ))?;
            offset += bytes as usize;
            data_align_factor
        };

        ensure(offset, 1)?;
        cie.return_address_register = raw[offset];
        offset += 1;

        cie.augmentation_data = if cie.augmentation.len() >= 1 && &cie.augmentation[0..1] == "z" {
            let (aug_data_len, bytes) = decode_leb128(&raw[offset..]).ok_or(Error::new(
                ErrorKind::InvalidData,
                "failed to decode augmentation data length factor",
            ))?;
            offset += bytes as usize;

            ensure(offset, aug_data_len as usize)?;
            let aug_data = unsafe { &*(&raw[offset..] as *const [u8]) };
            offset += aug_data_len as usize;

            aug_data
        } else {
            &[]
        };

        cie.init_instructions = unsafe { &*(&raw[offset..] as *const [u8]) };

        if !self.is_debug_frame {
            cie.pointer_encoding = self.get_ptr_enc_type(cie);
        } else {
            cie.pointer_encoding = 0;
        }

        Ok(())
    }

    fn parse_call_frame_fde(&self, raw: &[u8], fde: &mut CFFDE, cie: &CFCIE) -> Result<(), Error> {
        let mut offset: usize = 0;

        let ensure = |offset, x| {
            if x + offset <= raw.len() {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the call frame data is broken",
                ))
            }
        };

        fde.cie_pointer = cie.offset as u32;
        offset += 4;

        if self.is_debug_frame {
            ensure(offset, 8)?;
            fde.initial_location = decode_udword(&raw);
            offset += 8;

            ensure(offset, 8)?;
            fde.address_range = decode_udword(&raw);
            offset += 8;
        } else {
            let decoder = self.pd_builder.build(cie.pointer_encoding);
            let (v, bytes) =
                decoder
                    .decode(&raw[offset..], fde.offset as u64)
                    .ok_or(Error::new(
                        ErrorKind::InvalidData,
                        "fail to decode initial_location",
                    ))?;
            fde.initial_location = v;
            offset += bytes;
            let (v, bytes) =
                decoder
                    .decode(&raw[offset..], fde.offset as u64)
                    .ok_or(Error::new(
                        ErrorKind::InvalidData,
                        "fail to decode address)rabge",
                    ))?;
            fde.address_range = v;
            offset += bytes;

            fde.augmentation_data = if cie.augmentation.starts_with("z") {
                let (sz, bytes) = decode_leb128(&raw[offset..]).ok_or(Error::new(
                    ErrorKind::InvalidData,
                    "fail to decode augmentation length",
                ))?;
                offset += bytes as usize + sz as usize;
                unsafe { &*(&raw[(offset - sz as usize)..offset] as *const [u8]) }
            } else {
                unsafe { &*(&raw[offset..offset] as *const [u8]) }
            };
        }

        fde.instructions = unsafe { &*(&raw[offset..] as *const [u8]) };

        Ok(())
    }

    fn get_cie_id(&self, raw: &Vec<u8>) -> CieOrCieID {
        let cie_id_or_cie_ptr = decode_uword(&raw);
        let cie_id: u32 = if self.is_debug_frame { 0xffffffff } else { 0x0 };
        if cie_id_or_cie_ptr == cie_id {
            CieOrCieID::CIE
        } else {
            CieOrCieID::CIE_PTR(cie_id_or_cie_ptr)
        }
    }

    /// parse a single Call Frame record.
    ///
    /// A record is either a CIE or a DFE.  This function would parse
    /// one record if there is.  It would append CIE to `cies` while
    /// append FDE to `fdes`.
    fn parse_call_frame(
        &self,
        mut raw: Vec<u8>,
        offset: usize,
        cies: &mut Vec<CFCIE>,
        fdes: &mut Vec<CFFDE>,
    ) -> Result<(), Error> {
        match self.get_cie_id(&raw) {
            CieOrCieID::CIE => {
                let i = cies.len();
                unsafe {
                    if cies.capacity() <= i {
                        if cies.capacity() != 0 {
                            cies.reserve(cies.capacity());
                        } else {
                            cies.reserve(16);
                        }
                    }
                    // Append an element without initialization.  Should be
                    // very careful to make sure that parse_call_frame_cie()
                    // has initialized the element fully.
                    cies.set_len(i + 1);

                    let cie = &mut cies[i];
                    cie.offset = offset;

                    let result = self.parse_call_frame_cie(&raw, cie);

                    if result.is_ok() {
                        // Initialize aux parts by swapping and dropping.
                        let mut aux = vec![CFCIEAux {
                            raw,
                            init_cfa: CFARule::reg_offset(0, 0),
                            init_regs: Vec::with_capacity(0),
                        }];
                        mem::swap(&mut cie.aux, &mut aux[0]);
                        // Drop all content! We don't to call destructors for them since they are garbage data.
                        aux.set_len(0);
                    }
                    result
                }
            }
            CieOrCieID::CIE_PTR(cie_ptr) => {
                let cie_offset = if self.is_debug_frame {
                    cie_ptr as usize
                } else {
                    (offset + 4) - cie_ptr as usize
                };
                let cie = {
                    'outer: loop {
                        for i in (0..cies.len()).rev() {
                            // It is ususally the last one in cies.
                            if cies[i].offset == cie_offset {
                                break 'outer &cies[i];
                            }
                        }
                        return Err(Error::new(ErrorKind::InvalidData, "invalid CIE pointer"));
                    }
                };

                let idx = fdes.len();
                unsafe {
                    if fdes.capacity() <= idx {
                        if fdes.capacity() != 0 {
                            fdes.reserve(fdes.capacity());
                        } else {
                            fdes.reserve(16);
                        }
                    }
                    // Append an element without initialization.  Should be
                    // very carful to make sure that parse_call_frame_fde()
                    // has initialized the element fully.
                    fdes.set_len(idx + 1);
                    let fde = &mut fdes[idx];
                    fde.offset = offset;
                    let result = self.parse_call_frame_fde(&raw, fde, cie);

                    // Keep a reference to raw to make sure it's life-time is
                    // logner than or equal to the fields refering it.
                    mem::swap(&mut fde.raw, &mut raw);
                    raw.leak(); // garbage data

                    result
                }
            }
        }
    }

    pub fn parse_call_frames(
        &self,
        parser: &Elf64Parser,
    ) -> Result<(Vec<CFCIE>, Vec<CFFDE>), Error> {
        let debug_frame_idx = if self.is_debug_frame {
            parser.find_section(".debug_frame").unwrap()
        } else {
            parser.find_section(".eh_frame").unwrap()
        };
        let sect_sz = parser.get_section_size(debug_frame_idx)?;
        parser.section_seek(debug_frame_idx)?;

        let mut offset: usize = 0;

        let mut cies = Vec::<CFCIE>::new();
        let mut fdes = Vec::<CFFDE>::new();

        while offset < sect_sz {
            // Parse the length of the entry. (4 bytes or 12 bytes)
            let mut len_bytes = 4;
            let mut buf: [u8; 4] = [0; 4];
            unsafe { parser.read_raw(&mut buf)? };
            let mut ent_size = decode_uword(&buf) as u64;
            if ent_size == 0xffffffff {
                // 64-bit DWARF format. We don't support it yet.
                let mut buf: [u8; 8] = [0; 8];
                unsafe { parser.read_raw(&mut buf)? };
                ent_size = decode_udword(&buf);
                len_bytes = 12;
            }

            if ent_size != 0 {
                let mut raw = Vec::<u8>::with_capacity(ent_size as usize);
                unsafe { raw.set_len(ent_size as usize) };
                unsafe { parser.read_raw(&mut raw)? };

                self.parse_call_frame(raw, offset, &mut cies, &mut fdes)?;
            }

            offset += len_bytes + ent_size as usize;
        }

        Ok((cies, fdes))
    }
}

/// Implementation of DHPointerReloc for ELF.
///
/// It is a partial implementation without function relative and
/// aligned since both feature are OS/device dependent.
struct DHPointerRelocElf {
    section_addr: u64,
    text_addr: u64,
    data_addr: u64,
}

impl DHPointerRelocElf {
    fn new(parser: &Elf64Parser, is_debug_frame: bool) -> DHPointerRelocElf {
        let sect = if is_debug_frame {
            parser.find_section(".debug_frame").unwrap()
        } else {
            parser.find_section(".eh_frame").unwrap()
        };
        let section_addr = parser.get_section_addr(sect).unwrap();

        let text_sect = parser.find_section(".text").unwrap();
        let text_addr = parser.get_section_addr(text_sect).unwrap();
        let data_sect = parser.find_section(".data").unwrap();
        let data_addr = parser.get_section_addr(data_sect).unwrap();

        DHPointerRelocElf {
            section_addr,
            text_addr,
            data_addr,
        }
    }
}

impl DHPointerReloc for DHPointerRelocElf {
    fn apply_pcrel(&self, ptr: u64, off: u64) -> u64 {
        unsafe {
            mem::transmute::<i64, u64>(
                mem::transmute::<u64, i64>(self.section_addr)
                    + mem::transmute::<u64, i64>(off)
                    + mem::transmute::<u64, i64>(ptr),
            )
        }
    }

    fn apply_textrel(&self, ptr: u64) -> u64 {
        self.text_addr + ptr
    }

    fn apply_datarel(&self, ptr: u64) -> u64 {
        self.data_addr + ptr
    }

    fn apply_funcrel(&self, _ptr: u64) -> u64 {
        // Not implemented
        0
    }

    fn apply_aligned(&self, _ptr: u64) -> u64 {
        // Not implemented
        0
    }
}

#[derive(Debug)]
pub enum CFInsn {
    #[allow(non_camel_case_types)]
    DW_CFA_advance_loc(u8),
    #[allow(non_camel_case_types)]
    DW_CFA_offset(u8, u64),
    #[allow(non_camel_case_types)]
    DW_CFA_restore(u8),
    #[allow(non_camel_case_types)]
    DW_CFA_nop,
    #[allow(non_camel_case_types)]
    DW_CFA_set_loc(u64),
    #[allow(non_camel_case_types)]
    DW_CFA_advance_loc1(u8),
    #[allow(non_camel_case_types)]
    DW_CFA_advance_loc2(u16),
    #[allow(non_camel_case_types)]
    DW_CFA_advance_loc4(u32),
    #[allow(non_camel_case_types)]
    DW_CFA_offset_extended(u64, u64),
    #[allow(non_camel_case_types)]
    DW_CFA_restore_extended(u64),
    #[allow(non_camel_case_types)]
    DW_CFA_undefined(u64),
    #[allow(non_camel_case_types)]
    DW_CFA_same_value(u64),
    #[allow(non_camel_case_types)]
    DW_CFA_register(u64, u64),
    #[allow(non_camel_case_types)]
    DW_CFA_remember_state,
    #[allow(non_camel_case_types)]
    DW_CFA_restore_state,
    #[allow(non_camel_case_types)]
    DW_CFA_def_cfa(u64, u64),
    #[allow(non_camel_case_types)]
    DW_CFA_def_cfa_register(u64),
    #[allow(non_camel_case_types)]
    DW_CFA_def_cfa_offset(u64),
    #[allow(non_camel_case_types)]
    DW_CFA_def_cfa_expression(Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_CFA_expression(u64, Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_CFA_offset_extended_sf(u64, i64),
    #[allow(non_camel_case_types)]
    DW_CFA_def_cfa_sf(u64, i64),
    #[allow(non_camel_case_types)]
    DW_CFA_def_cfa_offset_sf(i64),
    #[allow(non_camel_case_types)]
    DW_CFA_val_offset(u64, u64),
    #[allow(non_camel_case_types)]
    DW_CFA_val_offset_sf(u64, i64),
    #[allow(non_camel_case_types)]
    DW_CFA_val_expression(u64, Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_CFA_lo_user,
    #[allow(non_camel_case_types)]
    DW_CFA_hi_user,
}

/// Parse Call Frame Instructors found in CIE & FDE records.
///
/// Parse instructions from [`CFCIE::initial_instructions`] and
/// [`CFFDE::instrauctions`].
pub struct CFInsnParser<'a> {
    offset: usize,
    address_size: usize,
    raw: &'a [u8],
}

impl<'a> CFInsnParser<'a> {
    pub fn new(raw: &'a [u8], address_size: usize) -> CFInsnParser {
        CFInsnParser {
            offset: 0,
            address_size,
            raw,
        }
    }
}

#[allow(non_snake_case)]
fn decode_uN(sz: usize, raw: &[u8]) -> u64 {
    match sz {
        1 => raw[0] as u64,
        2 => decode_uhalf(raw) as u64,
        4 => decode_uword(raw) as u64,
        8 => decode_udword(raw) as u64,
        _ => panic!("invalid unsigned integer size: {}", sz),
    }
}

#[allow(non_snake_case)]
fn decode_iN(sz: usize, raw: &[u8]) -> i64 {
    match sz {
        1 => {
            if raw[0] & 0x80 == 0x80 {
                -((!raw[0]) as i64 + 1)
            } else {
                raw[0] as i64
            }
        }
        2 => decode_shalf(raw) as i64,
        4 => decode_sword(raw) as i64,
        8 => decode_sdword(raw) as i64,
        _ => panic!("invalid unsigned integer size: {}", sz),
    }
}

impl<'a> Iterator for CFInsnParser<'a> {
    type Item = CFInsn;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() <= self.offset {
            return None;
        }

        let op = self.raw[self.offset];
        match op >> 6 {
            0 => match op & 0x3f {
                0x0 => {
                    self.offset += 1;
                    Some(CFInsn::DW_CFA_nop)
                }
                0x1 => {
                    let off = self.offset + 1;
                    self.offset += 1 + self.address_size;
                    Some(CFInsn::DW_CFA_set_loc(decode_uN(
                        self.address_size,
                        &self.raw[off..],
                    )))
                }
                0x2 => {
                    self.offset += 2;
                    Some(CFInsn::DW_CFA_advance_loc1(self.raw[self.offset - 1]))
                }
                0x3 => {
                    self.offset += 3;
                    Some(CFInsn::DW_CFA_advance_loc2(decode_uhalf(
                        &self.raw[(self.offset - 2)..],
                    )))
                }
                0x4 => {
                    self.offset += 5;
                    Some(CFInsn::DW_CFA_advance_loc4(decode_uword(
                        &self.raw[(self.offset - 4)..],
                    )))
                }
                0x5 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_offset_extended(reg, off))
                }
                0x6 => {
                    let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    self.offset += 1 + bytes as usize;
                    Some(CFInsn::DW_CFA_restore_extended(reg))
                }
                0x7 => {
                    let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    self.offset += 1 + bytes as usize;
                    Some(CFInsn::DW_CFA_undefined(reg))
                }
                0x8 => {
                    let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    self.offset += 1 + bytes as usize;
                    Some(CFInsn::DW_CFA_same_value(reg))
                }
                0x9 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_register(reg, off))
                }
                0xa => {
                    self.offset += 1;
                    Some(CFInsn::DW_CFA_remember_state)
                }
                0xb => {
                    self.offset += 1;
                    Some(CFInsn::DW_CFA_restore_state)
                }
                0xc => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_def_cfa(reg, off))
                }
                0xd => {
                    let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    self.offset += 1 + bytes as usize;
                    Some(CFInsn::DW_CFA_def_cfa_register(reg))
                }
                0xe => {
                    let (off, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    self.offset += 1 + bytes as usize;
                    Some(CFInsn::DW_CFA_def_cfa_offset(off))
                }
                0xf => {
                    let (sz, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let expr = Vec::from(
                        &self.raw[(self.offset + 1 + bytes as usize)
                            ..(self.offset + 1 + bytes as usize + sz as usize)],
                    );
                    self.offset += 1 + bytes as usize + sz as usize;
                    Some(CFInsn::DW_CFA_def_cfa_expression(expr))
                }
                0x10 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (sz, sbytes) =
                        decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    let bytes = rbytes + sbytes;
                    let expr = Vec::from(
                        &self.raw[(self.offset + 1 + bytes as usize)
                            ..(self.offset + 1 + bytes as usize + sz as usize)],
                    );
                    self.offset += 1 + bytes as usize + sz as usize;
                    Some(CFInsn::DW_CFA_expression(reg, expr))
                }
                0x11 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128_s(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_offset_extended_sf(reg, off))
                }
                0x12 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128_s(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_def_cfa_sf(reg, off))
                }
                0x13 => {
                    let (off, bytes) = decode_leb128_s(&self.raw[(self.offset + 1)..]).unwrap();
                    self.offset += 1 + bytes as usize;
                    Some(CFInsn::DW_CFA_def_cfa_offset_sf(off))
                }
                0x14 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_val_offset(reg, off))
                }
                0x15 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (off, obytes) =
                        decode_leb128_s(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    self.offset += 1 + rbytes as usize + obytes as usize;
                    Some(CFInsn::DW_CFA_val_offset_sf(reg, off))
                }
                0x16 => {
                    let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                    let (sz, sbytes) =
                        decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                    let bytes = rbytes + sbytes;
                    let expr = Vec::from(
                        &self.raw[(self.offset + 1 + bytes as usize)
                            ..(self.offset + 1 + bytes as usize + sz as usize)],
                    );
                    self.offset += 1 + bytes as usize + sz as usize;
                    Some(CFInsn::DW_CFA_val_expression(reg, expr))
                }
                0x1c => {
                    self.offset += 1;
                    Some(CFInsn::DW_CFA_lo_user)
                }
                0x3f => {
                    self.offset += 1;
                    Some(CFInsn::DW_CFA_hi_user)
                }
                _ => None,
            },
            1 => {
                self.offset += 1;
                Some(CFInsn::DW_CFA_advance_loc(op & 0x3f))
            }
            2 => {
                let (off, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
                self.offset += bytes as usize + 1;
                Some(CFInsn::DW_CFA_offset(op & 0x3f, off))
            }
            3 => {
                self.offset += 1;
                Some(CFInsn::DW_CFA_restore(op & 0x3f))
            }
            _ => None,
        }
    }
}

/// Keep states for Call Frame Instructions.
///
/// Maintain the states of the machine running Call Frame
/// Instructions, e.q. [`CFInsn`], to make data/side-effects flow from
/// an instruction to another.
#[derive(Clone, Debug)]
struct CallFrameMachine {
    code_align_factor: u64,
    data_align_factor: i64,
    loc: u64,
    ra_reg: u64,  // return address register
    cfa: CFARule, // Canonical Frame Address
    regs: Vec<RegRule>,
    pushed: Vec<Vec<RegRule>>, // the stack of pushed states (save/restore)
    init_regs: Vec<RegRule>,   // the register values when the machine is just initialized.
}

impl CallFrameMachine {
    fn new(cie: &CFCIE, reg_num: usize) -> CallFrameMachine {
        let mut state = CallFrameMachine {
            code_align_factor: cie.code_align_factor,
            data_align_factor: cie.data_align_factor,
            loc: 0,
            ra_reg: cie.return_address_register as u64,
            cfa: cie.aux.init_cfa.clone(),
            regs: cie.aux.init_regs.clone(),
            pushed: vec![],
            init_regs: cie.aux.init_regs.clone(),
        };
        state.regs.resize(reg_num, RegRule::undefined);
        state
    }

    /// Run a Call Frame Instruction on a call frame machine.
    ///
    /// [`CallFrameMachine`] models a call frame machine
    fn run_insn(&mut self, insn: CFInsn) -> Option<u64> {
        match insn {
            CFInsn::DW_CFA_advance_loc(adj) => {
                let loc = self.loc;
                self.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
                Some(loc)
            }
            CFInsn::DW_CFA_offset(reg, offset) => {
                self.regs[reg as usize] =
                    RegRule::offset(offset as i64 * self.data_align_factor as i64);
                None
            }
            CFInsn::DW_CFA_restore(reg) => {
                self.regs[reg as usize] = self.init_regs[reg as usize].clone();
                None
            }
            CFInsn::DW_CFA_nop => None,
            CFInsn::DW_CFA_set_loc(loc) => {
                let old_loc = self.loc;
                self.loc = loc;
                Some(old_loc)
            }
            CFInsn::DW_CFA_advance_loc1(adj) => {
                let loc = self.loc;
                self.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
                Some(loc)
            }
            CFInsn::DW_CFA_advance_loc2(adj) => {
                let loc = self.loc;
                self.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
                Some(loc)
            }
            CFInsn::DW_CFA_advance_loc4(adj) => {
                let loc = self.loc;
                self.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
                Some(loc)
            }
            CFInsn::DW_CFA_offset_extended(reg, offset) => {
                self.regs[reg as usize] =
                    RegRule::offset(offset as i64 * self.data_align_factor as i64);
                None
            }
            CFInsn::DW_CFA_restore_extended(reg) => {
                self.regs[reg as usize] = self.init_regs[reg as usize].clone();
                None
            }
            CFInsn::DW_CFA_undefined(reg) => {
                self.regs[reg as usize] = RegRule::undefined;
                None
            }
            CFInsn::DW_CFA_same_value(reg) => {
                self.regs[reg as usize] = RegRule::same_value;
                None
            }
            CFInsn::DW_CFA_register(reg, reg_from) => {
                self.regs[reg as usize] = RegRule::register(reg_from);
                None
            }
            CFInsn::DW_CFA_remember_state => {
                let regs = self.regs.clone();
                self.pushed.push(regs);
                None
            }
            CFInsn::DW_CFA_restore_state => {
                let pushed = if let Some(pushed) = self.pushed.pop() {
                    pushed
                } else {
                    #[cfg(debug_assertions)]
                    eprintln!("Fail to restore state; inconsistent!");
                    return None;
                };
                self.regs = pushed;
                None
            }
            CFInsn::DW_CFA_def_cfa(reg, offset) => {
                self.cfa = CFARule::reg_offset(reg, offset as i64);
                None
            }
            CFInsn::DW_CFA_def_cfa_register(reg) => {
                if let CFARule::reg_offset(cfa_reg, _offset) = &mut self.cfa {
                    *cfa_reg = reg;
                }
                None
            }
            CFInsn::DW_CFA_def_cfa_offset(offset) => {
                if let CFARule::reg_offset(_reg, cfa_offset) = &mut self.cfa {
                    *cfa_offset = offset as i64;
                }
                None
            }
            CFInsn::DW_CFA_def_cfa_expression(expr) => {
                self.cfa = CFARule::expression(expr);
                None
            }
            CFInsn::DW_CFA_expression(reg, expr) => {
                self.regs[reg as usize] = RegRule::expression(expr);
                None
            }
            CFInsn::DW_CFA_offset_extended_sf(reg, offset) => {
                self.regs[reg as usize] =
                    RegRule::offset(offset as i64 * self.data_align_factor as i64);
                None
            }
            CFInsn::DW_CFA_def_cfa_sf(reg, offset) => {
                self.cfa = CFARule::reg_offset(reg, offset * self.data_align_factor as i64);
                None
            }
            CFInsn::DW_CFA_def_cfa_offset_sf(offset) => {
                if let CFARule::reg_offset(_reg, cfa_offset) = &mut self.cfa {
                    *cfa_offset = offset as i64 * self.data_align_factor as i64;
                }
                None
            }
            CFInsn::DW_CFA_val_offset(reg, offset) => {
                self.regs[reg as usize] =
                    RegRule::val_offset(offset as i64 * self.data_align_factor as i64);
                None
            }
            CFInsn::DW_CFA_val_offset_sf(reg, offset) => {
                self.regs[reg as usize] =
                    RegRule::val_offset(offset * self.data_align_factor as i64);
                None
            }
            CFInsn::DW_CFA_val_expression(reg, expr) => {
                self.regs[reg as usize] = RegRule::val_expression(expr);
                None
            }
            CFInsn::DW_CFA_lo_user => None,
            CFInsn::DW_CFA_hi_user => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DwarfExprOp {
    #[allow(non_camel_case_types)]
    DW_OP_addr(u64),
    #[allow(non_camel_case_types)]
    DW_OP_deref,
    #[allow(non_camel_case_types)]
    DW_OP_const1u(u8),
    #[allow(non_camel_case_types)]
    DW_OP_const1s(i8),
    #[allow(non_camel_case_types)]
    DW_OP_const2u(u16),
    #[allow(non_camel_case_types)]
    DW_OP_const2s(i16),
    #[allow(non_camel_case_types)]
    DW_OP_const4u(u32),
    #[allow(non_camel_case_types)]
    DW_OP_const4s(i32),
    #[allow(non_camel_case_types)]
    DW_OP_const8u(u64),
    #[allow(non_camel_case_types)]
    DW_OP_const8s(i64),
    #[allow(non_camel_case_types)]
    DW_OP_constu(u64),
    #[allow(non_camel_case_types)]
    DW_OP_consts(i64),
    #[allow(non_camel_case_types)]
    DW_OP_dup,
    #[allow(non_camel_case_types)]
    DW_OP_drop,
    #[allow(non_camel_case_types)]
    DW_OP_over,
    #[allow(non_camel_case_types)]
    DW_OP_pick(u8),
    #[allow(non_camel_case_types)]
    DW_OP_swap,
    #[allow(non_camel_case_types)]
    DW_OP_rot,
    #[allow(non_camel_case_types)]
    DW_OP_xderef,
    #[allow(non_camel_case_types)]
    DW_OP_abs,
    #[allow(non_camel_case_types)]
    DW_OP_and,
    #[allow(non_camel_case_types)]
    DW_OP_div,
    #[allow(non_camel_case_types)]
    DW_OP_minus,
    #[allow(non_camel_case_types)]
    DW_OP_mod,
    #[allow(non_camel_case_types)]
    DW_OP_mul,
    #[allow(non_camel_case_types)]
    DW_OP_neg,
    #[allow(non_camel_case_types)]
    DW_OP_not,
    #[allow(non_camel_case_types)]
    DW_OP_or,
    #[allow(non_camel_case_types)]
    DW_OP_plus,
    #[allow(non_camel_case_types)]
    DW_OP_plus_uconst(u64),
    #[allow(non_camel_case_types)]
    DW_OP_shl,
    #[allow(non_camel_case_types)]
    DW_OP_shr,
    #[allow(non_camel_case_types)]
    DW_OP_shra,
    #[allow(non_camel_case_types)]
    DW_OP_xor,
    #[allow(non_camel_case_types)]
    DW_OP_bra(i16),
    #[allow(non_camel_case_types)]
    DW_OP_eq,
    #[allow(non_camel_case_types)]
    DW_OP_ge,
    #[allow(non_camel_case_types)]
    DW_OP_gt,
    #[allow(non_camel_case_types)]
    DW_OP_le,
    #[allow(non_camel_case_types)]
    DW_OP_lt,
    #[allow(non_camel_case_types)]
    DW_OP_ne,
    #[allow(non_camel_case_types)]
    DW_OP_skip(i16),
    #[allow(non_camel_case_types)]
    DW_OP_lit(u8),
    #[allow(non_camel_case_types)]
    DW_OP_reg(u8),
    #[allow(non_camel_case_types)]
    DW_OP_breg(u8, i64),
    #[allow(non_camel_case_types)]
    DW_OP_regx(u64),
    #[allow(non_camel_case_types)]
    DW_OP_fbreg(i64),
    #[allow(non_camel_case_types)]
    DW_OP_bregx(u64, i64),
    #[allow(non_camel_case_types)]
    DW_OP_piece(u64),
    #[allow(non_camel_case_types)]
    DW_OP_deref_size(u8),
    #[allow(non_camel_case_types)]
    DW_OP_xderef_size(u8),
    #[allow(non_camel_case_types)]
    DW_OP_nop,
    #[allow(non_camel_case_types)]
    DW_OP_push_object_address,
    #[allow(non_camel_case_types)]
    DW_OP_call2(u16),
    #[allow(non_camel_case_types)]
    DW_OP_call4(u32),
    #[allow(non_camel_case_types)]
    DW_OP_call_ref(u64),
    #[allow(non_camel_case_types)]
    DW_OP_form_tls_address,
    #[allow(non_camel_case_types)]
    DW_OP_call_frame_cfa,
    #[allow(non_camel_case_types)]
    DW_OP_bit_piece(u64, u64),
    #[allow(non_camel_case_types)]
    DW_OP_implicit_value(Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_OP_stack_value,
    #[allow(non_camel_case_types)]
    DW_OP_implicit_pointer(u64, i64),
    #[allow(non_camel_case_types)]
    DW_OP_addrx(u64),
    #[allow(non_camel_case_types)]
    DW_OP_constx(u64),
    #[allow(non_camel_case_types)]
    DW_OP_entry_value(Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_OP_const_type(u64, Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_OP_regval_type(u64, u64),
    #[allow(non_camel_case_types)]
    DW_OP_deref_type(u8, u64),
    #[allow(non_camel_case_types)]
    DW_OP_xderef_type(u8, u64),
    #[allow(non_camel_case_types)]
    DW_OP_convert(u64),
    #[allow(non_camel_case_types)]
    DW_OP_reinterpret(u64),
    #[allow(non_camel_case_types)]
    DW_OP_lo_user,
    #[allow(non_camel_case_types)]
    DW_OP_hi_user,
}

pub struct DwarfExprParser<'a> {
    address_size: usize,
    offset: usize,
    raw: &'a [u8],
}

impl<'a> DwarfExprParser<'a> {
    pub fn from(raw: &'a [u8], address_size: usize) -> Self {
        DwarfExprParser {
            address_size,
            offset: 0,
            raw,
        }
    }
}

impl<'a> Iterator for DwarfExprParser<'a> {
    type Item = (u64, DwarfExprOp);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.raw.len() {
            return None;
        }

        let raw = self.raw;
        let op = raw[self.offset];
        let saved_offset = self.offset as u64;
        match op {
            0x3 => {
                let addr = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
                self.offset += 1 + self.address_size;
                Some((saved_offset, DwarfExprOp::DW_OP_addr(addr)))
            }
            0x6 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_deref))
            }
            0x8 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const1u(raw[self.offset - 1]),
                ))
            }
            0x9 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const1s(raw[self.offset - 1] as i8),
                ))
            }
            0xa => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const2u(decode_uhalf(&raw[(self.offset - 2)..])),
                ))
            }
            0xb => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const2s(decode_shalf(&raw[(self.offset - 2)..])),
                ))
            }
            0xc => {
                self.offset += 5;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const4u(decode_uword(&raw[(self.offset - 4)..])),
                ))
            }
            0xd => {
                self.offset += 5;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const4s(decode_sword(&raw[(self.offset - 4)..])),
                ))
            }
            0xe => {
                self.offset += 9;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const8u(decode_udword(&raw[(self.offset - 8)..])),
                ))
            }
            0xf => {
                self.offset += 9;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const8s(decode_sdword(&raw[(self.offset - 8)..])),
                ))
            }
            0x10 => {
                let (v, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_constu(v)))
            }
            0x11 => {
                let (v, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_consts(v)))
            }
            0x12 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_dup))
            }
            0x13 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_drop))
            }
            0x14 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_over))
            }
            0x15 => {
                self.offset += 2;
                Some((saved_offset, DwarfExprOp::DW_OP_pick(raw[self.offset - 1])))
            }
            0x16 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_swap))
            }
            0x17 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_rot))
            }
            0x18 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_xderef))
            }
            0x19 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_abs))
            }
            0x1a => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_and))
            }
            0x1b => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_div))
            }
            0x1c => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_minus))
            }
            0x1d => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_mod))
            }
            0x1e => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_mul))
            }
            0x1f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_neg))
            }
            0x20 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_not))
            }
            0x21 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_or))
            }
            0x22 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_plus))
            }
            0x23 => {
                let (addend, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_plus_uconst(addend)))
            }
            0x24 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_shl))
            }
            0x25 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_shr))
            }
            0x26 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_shra))
            }
            0x27 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_xor))
            }
            0x28 => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_bra(decode_shalf(&raw[(self.offset - 2)..])),
                ))
            }
            0x29 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_eq))
            }
            0x2a => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_ge))
            }
            0x2b => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_gt))
            }
            0x2c => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_le))
            }
            0x2d => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_lt))
            }
            0x2e => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_ne))
            }
            0x2f => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_skip(decode_shalf(&raw[(self.offset - 2)..])),
                ))
            }
            0x30..=0x4f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_lit(op - 0x30)))
            }
            0x50..=0x6f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_reg(op - 0x50)))
            }
            0x70..=0x8f => {
                let (offset, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_breg(op - 0x70, offset)))
            }
            0x90 => {
                let (offset, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_regx(offset)))
            }
            0x91 => {
                let (offset, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_fbreg(offset)))
            }
            0x92 => {
                let (reg, rbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let (offset, obytes) =
                    decode_leb128_s(&raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                self.offset += 1 + rbytes as usize + obytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_bregx(reg, offset)))
            }
            0x93 => {
                let (piece_sz, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_piece(piece_sz)))
            }
            0x94 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_deref_size(raw[self.offset - 1]),
                ))
            }
            0x95 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_xderef_size(raw[self.offset - 1]),
                ))
            }
            0x96 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_nop))
            }
            0x97 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_push_object_address))
            }
            0x98 => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_call2(decode_uhalf(&raw[(self.offset - 2)..])),
                ))
            }
            0x99 => {
                self.offset += 5;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_call4(decode_uword(&raw[(self.offset - 4)..])),
                ))
            }
            0x9a => {
                let off = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
                self.offset += 1 + self.address_size;
                Some((saved_offset, DwarfExprOp::DW_OP_call_ref(off)))
            }
            0x9b => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_form_tls_address))
            }
            0x9c => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_call_frame_cfa))
            }
            0x9d => {
                let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let (off, obytes) =
                    decode_leb128(&raw[(self.offset + 1 + sbytes as usize)..]).unwrap();
                self.offset += 1 + sbytes as usize + obytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_bit_piece(sz, off)))
            }
            0x9e => {
                let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let blk = Vec::from(
                    &raw[(self.offset + 1 + sbytes as usize)
                        ..(self.offset + 1 + sbytes as usize + sz as usize)],
                );
                Some((saved_offset, DwarfExprOp::DW_OP_implicit_value(blk)))
            }
            0x9f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_stack_value))
            }
            0xa0 => {
                let die_off = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
                let (const_off, bytes) =
                    decode_leb128_s(&raw[(self.offset + 1 + self.address_size)..]).unwrap();
                self.offset += 1 + self.address_size + bytes as usize;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_implicit_pointer(die_off, const_off),
                ))
            }
            0xa1 => {
                let (addr, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_addrx(addr)))
            }
            0xa2 => {
                let (v, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_constx(v)))
            }
            0xa3 => {
                let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let blk = Vec::from(
                    &raw[(self.offset + 1 + sbytes as usize)
                        ..(self.offset + 1 + sbytes as usize + sz as usize)],
                );
                self.offset += 1 + sbytes as usize + sz as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_entry_value(blk)))
            }
            0xa4 => {
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let pos = self.offset + 1 + bytes as usize;
                let sz = raw[pos];
                let pos = pos + 1;
                let v = Vec::from(&raw[pos..(pos + sz as usize)]);
                self.offset += pos + sz as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_const_type(ent_off, v)))
            }
            0xa5 => {
                let (reg, rbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let pos = self.offset + 1 + rbytes as usize;
                let (off, obytes) = decode_leb128(&raw[pos..]).unwrap();
                self.offset += pos + obytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_regval_type(reg, off)))
            }
            0xa6 => {
                let sz = raw[self.offset + 1];
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 2)..]).unwrap();
                self.offset = self.offset + 2 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_deref_type(sz, ent_off)))
            }
            0xa7 => {
                let sz = raw[self.offset + 1];
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 2)..]).unwrap();
                self.offset = self.offset + 2 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_xderef_type(sz, ent_off)))
            }
            0xa8 => {
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset = self.offset + 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_convert(ent_off)))
            }
            0xa9 => {
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset = self.offset + 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_reinterpret(ent_off)))
            }
            0xe0 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_lo_user))
            }
            0xff => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_hi_user))
            }
            _ => None,
        }
    }
}

#[derive(Clone)]
enum DwarfExprPCOp {
    #[allow(non_camel_case_types)]
    go_next,
    #[allow(non_camel_case_types)]
    skip(i64),
    #[allow(non_camel_case_types)]
    stack_value,
    #[allow(non_camel_case_types)]
    in_reg(u8),
    #[allow(non_camel_case_types)]
    implicit(u128),
}

fn run_dwarf_expr_insn(
    insn: DwarfExprOp,
    fb_expr: &[u8],
    stack: &mut Vec<u64>,
    regs: &[u64],
    address_size: usize,
    get_mem: &dyn Fn(u64, usize) -> u64,
    cfa: &CFARule,
) -> Result<DwarfExprPCOp, Error> {
    match insn {
        DwarfExprOp::DW_OP_addr(v_u64) => {
            stack.push(v_u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_deref => {
            if let Some(addr) = stack.pop() {
                let val = get_mem(addr, 8);
                stack.push(val);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_const1u(v_u8) => {
            stack.push(v_u8 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const1s(v_i8) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i8 as i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const2u(v_u16) => {
            stack.push(v_u16 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const2s(v_i16) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i16 as i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const4u(v_u32) => {
            stack.push(v_u32 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const4s(v_i32) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i32 as i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const8u(v_u64) => {
            stack.push(v_u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const8s(v_i64) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_constu(v_u64) => {
            stack.push(v_u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_consts(v_i64) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_dup => {
            if !stack.is_empty() {
                stack.push(stack[stack.len() - 1]);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_drop => {
            if !stack.is_empty() {
                stack.pop();
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_over => {
            if stack.len() >= 2 {
                stack.push(stack[stack.len() - 2]);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_pick(v_u8) => {
            if stack.len() >= (v_u8 as usize + 1) {
                stack.push(stack[stack.len() - 1 - v_u8 as usize]);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_swap => {
            let len = stack.len();
            let tmp = stack[len - 1];
            stack[len - 1] = stack[len - 2];
            stack[len - 2] = tmp;
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_rot => {
            let len = stack.len();
            let tmp = stack[len - 1];
            stack[len - 1] = stack[len - 2];
            stack[len - 2] = stack[len - 3];
            stack[len - 3] = tmp;
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_xderef => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_xderef is not implemented",
        )),
        DwarfExprOp::DW_OP_abs => {
            let len = stack.len();
            stack[len - 1] = unsafe {
                mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(stack[len - 1]).abs())
            };
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_and => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(first & second);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_div => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                if first != 0 {
                    stack.push(second / first);
                    return Ok(DwarfExprPCOp::go_next);
                }
            }
            Err(Error::new(ErrorKind::Other, "divide by zerror"))
        }
        DwarfExprOp::DW_OP_minus => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second - first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_mod => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second % first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_mul => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second * first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_neg => {
            let len = stack.len();
            if len >= 1 {
                stack[len - 1] = unsafe {
                    mem::transmute::<i64, u64>(-mem::transmute::<u64, i64>(stack[len - 1]))
                };
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_not => {
            let len = stack.len();
            if len >= 1 {
                stack[len - 1] = !stack[len - 1];
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_or => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second | first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_plus => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second + first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_plus_uconst(v_u64) => {
            let len = stack.len();
            if len >= 1 {
                stack[len - 1] += v_u64;
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_shl => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second << first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_shr => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second >> first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_shra => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();

                let mut val = second >> first;
                val |= 0 - ((second & 0x8000000000000000) >> first);
                stack.push(val);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_xor => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second ^ first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_bra(v_i16) => {
            if let Some(top) = stack.pop() {
                if top == 0 {
                    Ok(DwarfExprPCOp::go_next)
                } else {
                    Ok(DwarfExprPCOp::skip(v_i16 as i64))
                }
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_eq => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second == first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_ge => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second >= first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_gt => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second > first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_le => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second <= first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_lt => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second < first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_ne => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second != first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_skip(v_i16) => Ok(DwarfExprPCOp::skip(v_i16 as i64)),
        DwarfExprOp::DW_OP_lit(v_u8) => {
            stack.push(v_u8 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_reg(v_u8) => {
            stack.push(regs[v_u8 as usize]);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_breg(v_u8, v_i64) => {
            stack.push(unsafe {
                mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(regs[v_u8 as usize]) + v_i64)
            });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_regx(v_u64) => {
            stack.push(regs[v_u64 as usize]);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_fbreg(v_i64) => {
            let value = run_dwarf_expr(fb_expr, &[], 32, regs, address_size, get_mem, cfa)?;
            stack.push((value as i128 + v_i64 as i128) as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_bregx(v_u64, v_i64) => {
            stack.push(unsafe {
                mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(regs[v_u64 as usize]) + v_i64)
            });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_piece(_v_u64) => Ok(DwarfExprPCOp::go_next),
        DwarfExprOp::DW_OP_deref_size(v_u8) => {
            if let Some(addr) = stack.pop() {
                let v = get_mem(addr, v_u8 as usize);
                stack.push(v);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_xderef_size(_v_u8) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_xderef_size is not implemented",
        )),
        DwarfExprOp::DW_OP_nop => Ok(DwarfExprPCOp::go_next),
        DwarfExprOp::DW_OP_push_object_address => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_push_object_address is not implemented",
        )),
        DwarfExprOp::DW_OP_call2(_v_u16) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_call2 is not implemented",
        )),
        DwarfExprOp::DW_OP_call4(_v_u32) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_call4 is not implemented",
        )),
        DwarfExprOp::DW_OP_call_ref(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_call_ref is not implemented",
        )),
        DwarfExprOp::DW_OP_form_tls_address => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_form_tls_address is not implemented",
        )),
        DwarfExprOp::DW_OP_call_frame_cfa => {
            match cfa {
                CFARule::reg_offset(reg, off) => {
                    stack.push((*reg as i128 + *off as i128) as u64);
                }
                CFARule::expression(cfa_expr) => {
                    let value =
                        run_dwarf_expr(&cfa_expr, &[], 32, regs, address_size, get_mem, cfa)?;
                    stack.push(value);
                }
            }
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_bit_piece(_v_u64, _v_u64_1) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_bit_piece is not implemented",
        )),
        DwarfExprOp::DW_OP_implicit_value(v_vu8) => {
            let mut v: u64 = 0;
            for (i, v8) in v_vu8.iter().enumerate() {
                v |= (*v8 as u64) << (i * 8);
            }
            stack.push(v);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_stack_value => Ok(DwarfExprPCOp::stack_value),
        DwarfExprOp::DW_OP_implicit_pointer(_v_u64, _v_i64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_implicit_pointer is not implemented",
        )),
        DwarfExprOp::DW_OP_addrx(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_addrx is not implemented",
        )),
        DwarfExprOp::DW_OP_constx(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_constx is not implemented",
        )),
        DwarfExprOp::DW_OP_entry_value(_v_vu8) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_constx is not implemented",
        )),
        DwarfExprOp::DW_OP_const_type(_v_u64, _v_vu8) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_constx is not implemented",
        )),
        DwarfExprOp::DW_OP_regval_type(v_u64, _v_u64_1) => {
            stack.push(regs[v_u64 as usize]);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_deref_type(v_u8, _v_u64) => {
            if let Some(addr) = stack.pop() {
                let v = get_mem(addr, v_u8 as usize);
                stack.push(v);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_xderef_type(_v_u8, _v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_xderef_type is not implemented",
        )),
        DwarfExprOp::DW_OP_convert(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_convert is not implemented",
        )),
        DwarfExprOp::DW_OP_reinterpret(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_reinterpret is not implemented",
        )),
        DwarfExprOp::DW_OP_lo_user => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_lo_user is not implemented",
        )),
        DwarfExprOp::DW_OP_hi_user => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_hi_user is not implemented",
        )),
    }
}

/// Run DWARF Expression and return a result.
///
/// # Arguments
///
/// * `max_rounds` - how many rounds (instructions) up to this function can run to limit the runtime of the expression.
/// * `regs` - The values of registers that the expressiopn will read.
/// * `address_size` - The size of a pointer/address.
/// * `get_mem` - The call funciton to fetach the content of a given address.
pub fn run_dwarf_expr(
    expr: &[u8],
    fb_expr: &[u8],
    max_rounds: usize,
    regs: &[u64],
    address_size: usize,
    get_mem: &dyn Fn(u64, usize) -> u64,
    cfa: &CFARule,
) -> Result<u64, Error> {
    let insns: Vec<(u64, DwarfExprOp)> = DwarfExprParser::from(expr, address_size).collect();
    let mut idx = 0;
    let mut stack = Vec::<u64>::new();
    let mut rounds = 0;

    while idx < insns.len() {
        if rounds >= max_rounds {
            return Err(Error::new(ErrorKind::Other, "spend too much time"));
        }
        rounds += 1;

        let (_offset, insn) = &insns[idx];

        match run_dwarf_expr_insn(
            insn.clone(),
            fb_expr,
            &mut stack,
            regs,
            address_size,
            get_mem,
            cfa,
        ) {
            Err(err) => {
                return Err(err);
            }
            Ok(DwarfExprPCOp::go_next) => {
                idx += 1;
            }
            Ok(DwarfExprPCOp::skip(rel)) => {
                let tgt_offset = (if idx < (insns.len() - 1) {
                    insns[idx].0 as i64
                } else {
                    expr.len() as i64
                } + rel) as u64;

                if tgt_offset == expr.len() as u64 {
                    break;
                }

                while tgt_offset < insns[idx].0 && idx > 0 {
                    idx -= 1;
                }
                while tgt_offset > insns[idx].0 && idx < (insns.len() - 1) {
                    idx += 1;
                }
                if tgt_offset != insns[idx].0 {
                    return Err(Error::new(ErrorKind::Other, "invalid branch target"));
                }
            }
            Ok(DwarfExprPCOp::stack_value) => {
                break;
            }
	    Ok(DwarfExprPCOp::in_reg(no)) => {
		break;
	    }
	    Ok(DwarfExprPCOp::implicit(bytes)) => {
		break;
	    }
        }
    }

    if let Some(v) = stack.pop() {
        println!("stack size {}", stack.len());
        Ok(v)
    } else {
        Err(Error::new(ErrorKind::Other, "stack is empty"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use std::path::Path;

    fn test_parse_call_frames(
        is_debug_frame: bool,
        bin_name: &Path,
        expected_offsets: &[usize],
        expected_cfi_locs: &[u64],
    ) {
        let parser_r = Elf64Parser::open(bin_name.to_str().unwrap());
        assert!(parser_r.is_ok());
        let parser = parser_r.unwrap();

        let cfsession = CallFrameParser::from_parser(&parser, is_debug_frame);
        let cies_fdes = cfsession.parse_call_frames(&parser);
        //assert!(cies_fdes.is_ok());
        let (mut cies, fdes) = cies_fdes.unwrap();
        println!("cies len={}, fdes len={}", cies.len(), fdes.len());

        let mut eo_idx = 0;
        for cie in &mut cies {
            println!(
                "address size {} data alignment {} offset {}",
                cie.address_size, cie.data_align_factor, cie.offset
            );
            println!("{:?}", cie.init_instructions);
            let insniter = CFInsnParser::new(cie.init_instructions, cie.address_size as usize);
            let mut state = CallFrameMachine::new(&cie, 32);
            for insn in insniter {
                println!("INSN: {:?}", insn);
                state.run_insn(insn);
            }
            cie.aux.init_cfa = state.cfa;
            cie.aux.init_regs = state.regs;
            assert!(cie.offset == expected_offsets[eo_idx]);
            eo_idx += 1;
        }

        let mut el_idx = 0;
        let address_size = mem::size_of::<*const u8>();

        for fde in fdes {
            println!("CIE @ {}, pointer {}", fde.offset, fde.cie_pointer);
            let insniter = CFInsnParser::new(fde.instructions, address_size);

            for insn in insniter {
                println!("INSN: {:?}", insn);
                if let CFInsn::DW_CFA_def_cfa_expression(expression) = insn {
                    for (off, insn) in DwarfExprParser::from(&expression, address_size) {
                        println!("    {} {:?}", off, insn);
                    }
                }
            }

            let mut state = None;
            for cie in &cies {
                if cie.offset == fde.cie_pointer as usize {
                    state = Some(CallFrameMachine::new(cie, 32));
                }
            }

            if let Some(state) = state.as_mut() {
                let insniter = CFInsnParser::new(fde.instructions, address_size);
                for insn in insniter {
                    if let Some(loc) = state.run_insn(insn) {
                        println!("  loc={} cfa={:?}", loc, state.cfa,);
                        print!("    ");
                        for reg in &state.regs {
                            if let RegRule::undefined = reg {
                                print!("x ");
                            } else {
                                print!("{:?} ", reg);
                            }
                        }
                        println!("");

                        assert!(loc == expected_cfi_locs[el_idx]);
                        el_idx += 1;
                    }
                }
                println!("  loc={} cfa={:?}", state.loc, state.cfa);
                print!("    ");
                for reg in &state.regs {
                    if let RegRule::undefined = reg {
                        print!("x ");
                    } else {
                        print!("{:?} ", reg);
                    }
                }
                println!("");

                assert!(state.loc == expected_cfi_locs[el_idx]);
                el_idx += 1;
            }
            assert!(fde.offset == expected_offsets[eo_idx]);
            eo_idx += 1;
        }
        assert!(eo_idx == expected_offsets.len());
        assert!(el_idx == expected_cfi_locs.len());
    }

    #[test]
    fn test_parse_call_frames_debug_frame() {
        let bin_name = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests")
            .join("eh_frame-sample");
        let expected_offsets = [0, 48];
        let expected_cfi_locs: [u64; 0] = [];
        test_parse_call_frames(true, &bin_name, &expected_offsets, &expected_cfi_locs)
    }

    #[test]
    fn test_parse_call_frames_eh_frame() {
        let bin_name = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests")
            .join("eh_frame-sample");
        let expected_offsets = [0, 24, 48, 88, 112];
        let expected_cfi_locs = [0 as u64, 4, 0, 6, 16, 0, 4, 61, 0];
        test_parse_call_frames(false, &bin_name, &expected_offsets, &expected_cfi_locs)
    }

    #[test]
    fn test_run_dwarf_expr() {
        //  0 DW_OP_breg(7, 8)
        //  2 DW_OP_breg(16, 0)
        //  4 DW_OP_lit(15)
        //  5 DW_OP_and
        //  6 DW_OP_lit(11)
        //  7 DW_OP_ge
        //  8 DW_OP_lit(3)
        //  9 DW_OP_shl
        //  10 DW_OP_plus
        let expr = [119 as u8, 8, 128, 0, 63, 26, 59, 42, 51, 36, 34];
        let regs = [14 as u64; 32];
        let get_mem = |_addr: u64, _sz: usize| -> u64 { 0 };

        let address_size = mem::size_of::<*const u8>();
        let v = run_dwarf_expr(
            &expr,
            &[],
            9,
            &regs,
            address_size,
            &get_mem,
            &CFARule::expression(vec![]),
        );
        assert!(v.is_ok());
        assert!(v.unwrap() == 30);

        // max_rounds is too small.
        let v = run_dwarf_expr(
            &expr,
            &[],
            8,
            &regs,
            address_size,
            &get_mem,
            &CFARule::expression(vec![]),
        );
        assert!(v.is_err());
    }
}
