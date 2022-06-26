use super::elf::Elf64Parser;
use super::tools::{search_address_key, extract_string};

use std::cell::RefCell;
use std::clone::Clone;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::mem;
use std::rc::Rc;
use std::slice;

#[cfg(test)]
use std::env;

fn decode_leb128(data: &[u8]) -> Option<(u64, u8)> {
    let mut sz = 0;
    let mut v: u64 = 0;
    for c in data {
        v |= ((c & 0x7f) as u64) << sz;
        sz += 7;
        if (c & 0x80) == 0 {
            return Some((v, sz / 7));
        }
    }
    None
}

fn decode_leb128_s(data: &[u8]) -> Option<(i64, u8)> {
    if let Some((v, s)) = decode_leb128(data) {
        let s_mask: u64 = 1 << (s * 7 - 1);
        return if (v & s_mask) != 0 {
            // negative
            Some(((v as i64) - ((s_mask << 1) as i64), s))
        } else {
            Some((v as i64, s))
        };
    }
    None
}

#[inline(always)]
fn decode_uhalf(data: &[u8]) -> u16 {
    (data[0] as u16) | ((data[1] as u16) << 8)
}

#[allow(dead_code)]
#[inline(always)]
fn decode_shalf(data: &[u8]) -> i16 {
    let uh = decode_uhalf(data);
    if uh >= 0x8000 {
        ((uh as i32) - 0x10000) as i16
    } else {
        uh as i16
    }
}

#[inline(always)]
fn decode_uword(data: &[u8]) -> u32 {
    (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16) | ((data[3] as u32) << 24)
}

#[allow(dead_code)]
#[inline(always)]
fn decode_sword(data: &[u8]) -> i32 {
    let uw = decode_uword(data);
    if uw >= 0x80000000 {
        ((uw as i64) - 0x100000000) as i32
    } else {
        uw as i32
    }
}

#[inline(always)]
fn decode_udword(data: &[u8]) -> u64 {
    decode_uword(data) as u64 | ((decode_uword(&data[4..]) as u64) << 32)
}

#[allow(dead_code)]
#[inline(always)]
fn decode_sdword(data: &[u8]) -> i64 {
    let udw = decode_udword(data);
    if udw >= 0x8000000000000000 {
        ((udw as i128) - 0x10000000000000000) as i64
    } else {
        udw as i64
    }
}

pub struct ArangesCU {
    pub debug_line_off: usize,
    pub aranges: Vec<(u64, u64)>,
}

fn parse_aranges_cu(data: &[u8]) -> Result<(ArangesCU, usize), Error> {
    if data.len() < 12 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid arange header (too small)",
        ));
    }
    let len = decode_uword(data);
    let version = decode_uhalf(&data[4..]);
    let offset = decode_uword(&data[6..]);
    let addr_sz = data[10];
    let _seg_sz = data[11];

    if data.len() < (len + 4) as usize {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "data is broken (too small)",
        ));
    }

    // Size of the header
    let mut pos = 12;

    // Padding to align with the size of addresses on the target system.
    pos += addr_sz as usize - 1;
    pos -= pos % addr_sz as usize;

    let mut aranges = Vec::<(u64, u64)>::new();
    match addr_sz {
        4 => {
            while pos < (len + 4 - 8) as usize {
                let start = decode_uword(&data[pos..]);
                pos += 4;
                let size = decode_uword(&data[pos..]);
                pos += 4;

                if start == 0 && size == 0 {
                    break;
                }
                aranges.push((start as u64, size as u64));
            }
        }
        8 => {
            while pos < (len + 4 - 16) as usize {
                let start = decode_udword(&data[pos..]);
                pos += 8;
                let size = decode_udword(&data[pos..]);
                pos += 8;

                if start == 0 && size == 0 {
                    break;
                }
                aranges.push((start, size));
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "unsupported address size {} ver {} off 0x{:x}",
                    addr_sz, version, offset
                ),
            ));
        }
    }

    Ok((
        ArangesCU {
            debug_line_off: offset as usize,
            aranges,
        },
        len as usize + 4,
    ))
}

fn parse_aranges_elf_parser(parser: &Elf64Parser) -> Result<Vec<ArangesCU>, Error> {
    let debug_aranges_idx = parser.find_section(".debug_aranges")?;

    let raw_data = parser.read_section_raw(debug_aranges_idx)?;

    let mut pos = 0;
    let mut acus = Vec::<ArangesCU>::new();
    while pos < raw_data.len() {
        let (acu, bytes) = parse_aranges_cu(&raw_data[pos..])?;
        acus.push(acu);
        pos += bytes;
    }

    Ok(acus)
}

pub fn parse_aranges_elf(filename: &str) -> Result<Vec<ArangesCU>, Error> {
    let parser = Elf64Parser::open(filename)?;
    parse_aranges_elf_parser(&parser)
}

#[repr(packed)]
struct DebugLinePrologueV2 {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

/// DebugLinePrologue is actually a V4.
///
/// DebugLinePrologueV2 will be converted to this type.
#[allow(dead_code)]
#[repr(packed)]
struct DebugLinePrologue {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    maximum_ops_per_instruction: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

/// The file information of a file for a CU.
struct DebugLineFileInfo {
    name: String,
    dir_idx: u32, // Index to include_directories of DebugLineCU.
    #[allow(dead_code)]
    mod_tm: u64,
    #[allow(dead_code)]
    size: usize,
}

/// Represent a Compile Unit (CU) in a .debug_line section.
struct DebugLineCU {
    prologue: DebugLinePrologue,
    #[allow(dead_code)]
    standard_opcode_lengths: Vec<u8>,
    include_directories: Vec<String>,
    files: Vec<DebugLineFileInfo>,
    matrix: Vec<DebugLineStates>,
}

impl DebugLineCU {
    fn find_line(&self, address: u64) -> Option<(&str, &str, usize)> {
        let idx = search_address_key(&self.matrix, address, &|x: &DebugLineStates| -> u64 {
            x.address
        })?;

        let states = &self.matrix[idx];
        if states.end_sequence {
            // This is the first byte after the last instruction
            return None;
        }

        self.stringify_row(idx as usize)
    }

    fn stringify_row(&self, idx: usize) -> Option<(&str, &str, usize)> {
        let states = &self.matrix[idx];
        let (dir, file) = {
            if states.file > 0 {
                let file = &self.files[states.file - 1];
                let dir = {
                    if file.dir_idx == 0 {
                        ""
                    } else {
                        self.include_directories[file.dir_idx as usize - 1].as_str()
                    }
                };
                (dir, file.name.as_str())
            } else {
                ("", "")
            }
        };

        Some((dir, file, states.line as usize))
    }
}

/// Parse the list of directory paths for a CU.
fn parse_debug_line_dirs(data_buf: &[u8]) -> Result<(Vec<String>, usize), Error> {
    let mut strs = Vec::<String>::new();
    let mut pos = 0;

    while pos < data_buf.len() {
        if data_buf[pos] == 0 {
            return Ok((strs, pos + 1));
        }

        // Find NULL byte
        let mut end = pos;
        while end < data_buf.len() && data_buf[end] != 0 {
            end += 1;
        }
        if end < data_buf.len() {
            let mut str_vec = Vec::<u8>::with_capacity(end - pos);
            str_vec.extend_from_slice(&data_buf[pos..end]);

            let str_r = String::from_utf8(str_vec);
            if str_r.is_err() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"));
            }

            strs.push(str_r.unwrap());
            end += 1;
        }
        pos = end;
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "Do not found null string",
    ))
}

/// Parse the list of file information for a CU.
fn parse_debug_line_files(data_buf: &[u8]) -> Result<(Vec<DebugLineFileInfo>, usize), Error> {
    let mut strs = Vec::<DebugLineFileInfo>::new();
    let mut pos = 0;

    while pos < data_buf.len() {
        if data_buf[pos] == 0 {
            return Ok((strs, pos + 1));
        }

        // Find NULL byte
        let mut end = pos;
        while end < data_buf.len() && data_buf[end] != 0 {
            end += 1;
        }
        if end < data_buf.len() {
            // Null terminated file name string
            let mut str_vec = Vec::<u8>::with_capacity(end - pos);
            str_vec.extend_from_slice(&data_buf[pos..end]);

            let str_r = String::from_utf8(str_vec);
            if str_r.is_err() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"));
            }
            end += 1;

            // LEB128 directory index
            let dir_idx_r = decode_leb128(&data_buf[end..]);
            if dir_idx_r.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invliad directory index",
                ));
            }
            let (dir_idx, bytes) = dir_idx_r.unwrap();
            end += bytes as usize;

            // LEB128 last modified time
            let mod_tm_r = decode_leb128(&data_buf[end..]);
            if mod_tm_r.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid last modified time",
                ));
            }
            let (mod_tm, bytes) = mod_tm_r.unwrap();
            end += bytes as usize;

            // LEB128 file size
            let flen_r = decode_leb128(&data_buf[end..]);
            if flen_r.is_none() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid file size"));
            }
            let (flen, bytes) = flen_r.unwrap();
            end += bytes as usize;

            strs.push(DebugLineFileInfo {
                name: str_r.unwrap(),
                dir_idx: dir_idx as u32,
                mod_tm,
                size: flen as usize,
            });
        }
        pos = end;
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "Do not found null string",
    ))
}

fn parse_debug_line_cu(
    parser: &Elf64Parser,
    addresses: &[u64],
    reused_buf: &mut Vec<u8>,
) -> Result<DebugLineCU, Error> {
    let mut prologue_sz: usize = mem::size_of::<DebugLinePrologueV2>();
    let prologue_v4_sz: usize = mem::size_of::<DebugLinePrologue>();
    let buf = reused_buf;

    buf.resize(prologue_sz, 0);
    let prologue = unsafe {
        parser.read_raw(buf.as_mut_slice())?;
        let prologue_raw = buf.as_mut_ptr() as *mut DebugLinePrologueV2;
        let v2 = Box::<DebugLinePrologueV2>::from_raw(prologue_raw);

        if v2.version != 0x2 && v2.version != 0x4 {
            let version = v2.version;
            Box::leak(v2);
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Support DWARF version 2 & 4 (version: {})", version),
            ));
        }

        if v2.version == 0x4 {
            // Upgrade to V4.
            // V4 has more fields to read.
            Box::leak(v2);
            buf.resize(prologue_v4_sz, 0);
            parser.read_raw(&mut buf.as_mut_slice()[prologue_sz..])?;
            let prologue_raw = buf.as_mut_ptr() as *mut DebugLinePrologue;
            let v4 = Box::<DebugLinePrologue>::from_raw(prologue_raw);
            prologue_sz = prologue_v4_sz;
            let prologue_v4 = DebugLinePrologue { ..(*v4) };
            Box::leak(v4);
            prologue_v4
        } else {
            // Convert V2 to V4
            let prologue_v4 = DebugLinePrologue {
                total_length: v2.total_length,
                version: v2.version,
                prologue_length: v2.prologue_length,
                minimum_instruction_length: v2.minimum_instruction_length,
                maximum_ops_per_instruction: 0,
                default_is_stmt: v2.default_is_stmt,
                line_base: v2.line_base,
                line_range: v2.line_range,
                opcode_base: v2.opcode_base,
            };
            Box::leak(v2);
            prologue_v4
        }
    };

    let to_read = prologue.total_length as usize + 4 - prologue_sz;
    let data_buf = buf;
    if to_read <= data_buf.capacity() {
        // Gain better performance by skipping initialization.
        unsafe { data_buf.set_len(to_read) };
    } else {
        data_buf.resize(to_read, 0);
    }
    unsafe { parser.read_raw(data_buf.as_mut_slice())? };

    let mut pos = 0;

    let std_op_num = (prologue.opcode_base - 1) as usize;
    let mut std_op_lengths = Vec::<u8>::with_capacity(std_op_num);
    std_op_lengths.extend_from_slice(&data_buf[pos..pos + std_op_num]);
    pos += std_op_num;

    let (inc_dirs, bytes) = parse_debug_line_dirs(&data_buf[pos..])?;
    pos += bytes;

    let (files, bytes) = parse_debug_line_files(&data_buf[pos..])?;
    pos += bytes;

    let matrix = run_debug_line_stmts(&data_buf[pos..], &prologue, addresses)?;

    #[cfg(debug_assertions)]
    for i in 1..matrix.len() {
        if matrix[i].address < matrix[i - 1].address && !matrix[i - 1].end_sequence {
            panic!(
                "Not in ascent order @ [{}] {:?} [{}] {:?}",
                i - 1,
                matrix[i - 1],
                i,
                matrix[i]
            );
        }
    }

    Ok(DebugLineCU {
        prologue,
        standard_opcode_lengths: std_op_lengths,
        include_directories: inc_dirs,
        files,
        matrix,
    })
}

#[derive(Clone, Debug)]
struct DebugLineStates {
    address: u64,
    file: usize,
    line: usize,
    column: usize,
    discriminator: u64,
    is_stmt: bool,
    basic_block: bool,
    end_sequence: bool,
    prologue_end: bool,
    should_reset: bool,
}

impl DebugLineStates {
    fn new(prologue: &DebugLinePrologue) -> DebugLineStates {
        DebugLineStates {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            discriminator: 0,
            is_stmt: prologue.default_is_stmt != 0,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            should_reset: false,
        }
    }

    fn reset(&mut self, prologue: &DebugLinePrologue) {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.discriminator = 0;
        self.is_stmt = prologue.default_is_stmt != 0;
        self.basic_block = false;
        self.end_sequence = false;
        self.prologue_end = false;
        self.should_reset = false;
    }
}

/// Return `Ok((insn_bytes, emit))` if success.  `insn_bytes1 is the
/// size of the instruction at the position given by ip.  `emit` is
/// true if this instruction emit a new row to describe line
/// information of an address.  Not every instructions emit rows.
/// Some instructions create only intermediate states for the next row
/// going to emit.
fn run_debug_line_stmt(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    ip: usize,
    states: &mut DebugLineStates,
) -> Result<(usize, bool), Error> {
    // Standard opcodes
    const DW_LNS_EXT: u8 = 0;
    const DW_LNS_COPY: u8 = 1;
    const DW_LNS_ADVANCE_PC: u8 = 2;
    const DW_LNS_ADVANCE_LINE: u8 = 3;
    const DW_LNS_SET_FILE: u8 = 4;
    const DW_LNS_SET_COLUMN: u8 = 5;
    const DW_LNS_NEGATE_STMT: u8 = 6;
    const DW_LNS_SET_BASIC_BLOCK: u8 = 7;
    const DW_LNS_CONST_ADD_PC: u8 = 8;
    const DW_LNS_FIXED_ADVANCE_PC: u8 = 9;
    const DW_LNS_SET_PROLOGUE_END: u8 = 10;

    // Extended opcodes
    const DW_LINE_END_SEQUENCE: u8 = 1;
    const DW_LINE_SET_ADDRESS: u8 = 2;
    const DW_LINE_DEFINE_FILE: u8 = 3;
    const DW_LINE_SET_DISCRIMINATOR: u8 = 4;

    let opcode_base = prologue.opcode_base;
    let opcode = stmts[ip];

    match opcode {
        DW_LNS_EXT => {
            // Extended opcodes
            if let Some((insn_size, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                if insn_size < 1 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "invalid extended opcode (ip=0x{:x}, insn_size=0x{:x}",
                            ip, insn_size
                        ),
                    ));
                }
                let ext_opcode = stmts[ip + 1 + bytes as usize];
                match ext_opcode {
                    DW_LINE_END_SEQUENCE => {
                        states.end_sequence = true;
                        states.should_reset = true;
                        Ok((1 + bytes as usize + insn_size as usize, true))
                    }
                    DW_LINE_SET_ADDRESS => match insn_size - 1 {
                        4 => {
                            let address = decode_uword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address as u64;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        8 => {
                            let address = decode_udword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        _ => Err(Error::new(
                            ErrorKind::Unsupported,
                            format!("unsupported address size ({})", insn_size),
                        )),
                    },
                    DW_LINE_DEFINE_FILE => Err(Error::new(
                        ErrorKind::Unsupported,
                        "DW_LINE_define_file is not supported yet",
                    )),
                    DW_LINE_SET_DISCRIMINATOR => {
                        if let Some((discriminator, discr_bytes)) =
                            decode_leb128(&stmts[(ip + 1 + bytes as usize + 1)..])
                        {
                            if discr_bytes as u64 + 1 == insn_size {
                                states.discriminator = discriminator;
                                Ok((1 + bytes as usize + insn_size as usize, false))
                            } else {
                                Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "unmatched instruction size for DW_LINE_set_discriminator",
                                ))
                            }
                        } else {
                            Err(Error::new(
                                ErrorKind::InvalidData,
                                "discriminator is broken",
                            ))
                        }
                    }
                    _ => Err(Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "invalid extended opcode (ip=0x{:x}, ext_opcode=0x{:x})",
                            ip, ext_opcode
                        ),
                    )),
                }
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid extended opcode (ip=0x{:x})", ip),
                ))
            }
        }
        DW_LNS_COPY => Ok((1, true)),
        DW_LNS_ADVANCE_PC => {
            if let Some((adv, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.address += adv * prologue.minimum_instruction_length as u64;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_pc is broken",
                ))
            }
        }
        DW_LNS_ADVANCE_LINE => {
            if let Some((adv, bytes)) = decode_leb128_s(&stmts[(ip + 1)..]) {
                states.line = (states.line as i64 + adv) as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_line is broken",
                ))
            }
        }
        DW_LNS_SET_FILE => {
            if let Some((file_idx, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.file = file_idx as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_file is broken",
                ))
            }
        }
        DW_LNS_SET_COLUMN => {
            if let Some((column, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.column = column as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_column is broken",
                ))
            }
        }
        DW_LNS_NEGATE_STMT => {
            states.is_stmt = !states.is_stmt;
            Ok((1, false))
        }
        DW_LNS_SET_BASIC_BLOCK => {
            states.basic_block = true;
            Ok((1, false))
        }
        DW_LNS_CONST_ADD_PC => {
            let addr_adv = (255 - opcode_base) / prologue.line_range;
            states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
            Ok((1, false))
        }
        DW_LNS_FIXED_ADVANCE_PC => {
            if (ip + 3) < stmts.len() {
                let addr_adv = decode_uhalf(&stmts[(ip + 1)..]);
                states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
                Ok((1, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of fixed_advance_pc is broken",
                ))
            }
        }
        DW_LNS_SET_PROLOGUE_END => {
            states.prologue_end = true;
            Ok((1, false))
        }
        _ => {
            // Special opcodes
            let desired_line_incr = (opcode - opcode_base) % prologue.line_range;
            let addr_adv = (opcode - opcode_base) / prologue.line_range;
            states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
            states.line = (states.line as i64
                + (desired_line_incr as i16 + prologue.line_base as i16) as i64
                    * prologue.minimum_instruction_length as i64)
                as usize;
            Ok((1, true))
        }
    }
}

fn run_debug_line_stmts(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    addresses: &[u64],
) -> Result<Vec<DebugLineStates>, Error> {
    let mut ip = 0;
    let mut matrix = Vec::<DebugLineStates>::new();
    let mut should_sort = false;
    let mut states_cur = DebugLineStates::new(prologue);
    let mut states_last = states_cur.clone();
    let mut last_ip_pushed = false;
    let mut force_no_emit = false;

    while ip < stmts.len() {
        match run_debug_line_stmt(stmts, prologue, ip, &mut states_cur) {
            Ok((sz, emit)) => {
                ip += sz;
                if emit {
                    if states_cur.address == 0 {
                        // This is a speical case. Somehow, rust
                        // compiler generate debug_line for some
                        // builtin code starting from 0.  And, it
                        // causes incorrect behavior.
                        force_no_emit = true;
                    }
                    if !force_no_emit {
                        if !addresses.is_empty() {
                            let mut pushed = false;
                            for addr in addresses {
                                if *addr == states_cur.address
                                    || (states_last.address != 0
                                        && !states_last.end_sequence
                                        && *addr < states_cur.address
                                        && *addr > states_last.address as u64)
                                {
                                    if !last_ip_pushed && *addr != states_cur.address {
                                        // The address falls between current and last emitted row.
                                        matrix.push(states_last.clone());
                                    }
                                    matrix.push(states_cur.clone());
                                    pushed = true;
                                    break;
                                }
                            }
                            last_ip_pushed = pushed;
                            states_last = states_cur.clone();
                        } else {
                            matrix.push(states_cur.clone());
                        }
                        if states_last.address > states_cur.address {
                            should_sort = true;
                        }
                    }
                }
                if states_cur.should_reset {
                    states_cur.reset(prologue);
                    force_no_emit = false;
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    if should_sort {
        matrix.sort_by_key(|x| x.address);
    }

    Ok(matrix)
}

/// If addresses is empty, it return a full version of debug_line matrics.
/// If addresses is not empty, return only data needed to resolve given addresses .
fn parse_debug_line_elf_parser(
    parser: &Elf64Parser,
    addresses: &[u64],
) -> Result<Vec<DebugLineCU>, Error> {
    let debug_line_idx = parser.find_section(".debug_line")?;
    let debug_line_sz = parser.get_section_size(debug_line_idx)?;
    let mut remain_sz = debug_line_sz;
    let prologue_size: usize = mem::size_of::<DebugLinePrologueV2>();
    let mut not_found = Vec::from(addresses);

    parser.section_seek(debug_line_idx)?;

    let mut all_cus = Vec::<DebugLineCU>::new();
    let mut buf = Vec::<u8>::new();
    while remain_sz > prologue_size {
        let debug_line_cu = parse_debug_line_cu(parser, &not_found, &mut buf)?;
        let prologue = &debug_line_cu.prologue;
        remain_sz -= prologue.total_length as usize + 4;

        if debug_line_cu.matrix.is_empty() {
            continue;
        }

        if !addresses.is_empty() {
            let mut last_row = &debug_line_cu.matrix[0];
            for row in debug_line_cu.matrix.as_slice() {
                let mut i = 0;
                // Remove addresses found in this CU from not_found.
                while i < not_found.len() {
                    let addr = addresses[i];
                    if addr == row.address || (addr < row.address && addr > last_row.address) {
                        not_found.remove(i);
                    } else {
                        i += 1;
                    }
                }
                last_row = row;
            }

            all_cus.push(debug_line_cu);

            if not_found.is_empty() {
                return Ok(all_cus);
            }
        } else {
            all_cus.push(debug_line_cu);
        }
    }

    if remain_sz != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "remain garbage data at the end",
        ));
    }

    Ok(all_cus)
}

#[allow(dead_code)]
fn parse_debug_line_elf(filename: &str) -> Result<Vec<DebugLineCU>, Error> {
    let parser = Elf64Parser::open(filename)?;
    parse_debug_line_elf_parser(&parser, &[])
}

#[derive(Clone, Debug)]
enum CFARule {
    reg_offset (u64, i64),
    expression (Vec<u8>),
}

#[derive(Clone, Debug)]
enum RegRule {
    undefined,
    same_value,
    offset (i64),
    val_offset (i64),
    register (u64),
    expression (Vec<u8>),
    val_expression (Vec<u8>),
    architectural,
}

#[derive(Clone, Debug)]
struct CallFrameState {
    code_align_factor: u64,
    data_align_factor: i64,
    loc: u64,
    ra_reg: u64,
    cfa: CFARule,
    regs: Vec<RegRule>,
    pushed: Vec<Vec<RegRule>>,
    init_regs: Vec<RegRule>,
}

impl CallFrameState {
    fn new(cie: &CFCIE, reg_num: usize) -> CallFrameState {
	let mut state = CallFrameState {
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
}

fn run_call_frame_insn(insn: CFInsn, state: &mut CallFrameState) -> Option<u64> {
    match insn {
	CFInsn::DW_CFA_advance_loc (adj) => {
	    let loc = state.loc;
	    state.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
	    Some(loc)
	},
	CFInsn::DW_CFA_offset (reg, offset) => {
	    state.regs[reg as usize] = RegRule::offset (offset as i64 * state.data_align_factor as i64);
	    None
	},
	CFInsn::DW_CFA_restore (reg) => {
	    state.regs[reg as usize] = state.init_regs[reg as usize].clone();
	    None
	},
	CFInsn::DW_CFA_nop => None,
	CFInsn::DW_CFA_set_loc (loc) => {
	    let old_loc = state.loc;
	    state.loc = loc;
	    Some(old_loc)
	},
	CFInsn::DW_CFA_advance_loc1 (adj) => {
	    let loc = state.loc;
	    state.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
	    Some(loc)
	},
	CFInsn::DW_CFA_advance_loc2 (adj) => {
	    let loc = state.loc;
	    state.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
	    Some(loc)
	},
	CFInsn::DW_CFA_advance_loc4 (adj) => {
	    let loc = state.loc;
	    state.loc = unsafe { mem::transmute::<i64, u64>(loc as i64 + adj as i64) };
	    Some(loc)
	},
	CFInsn::DW_CFA_offset_extended (reg, offset) => {
	    state.regs[reg as usize] = RegRule::offset (offset as i64 * state.data_align_factor as i64);
	    None
	},
	CFInsn::DW_CFA_restore_extended (reg) => {
	    state.regs[reg as usize] = state.init_regs[reg as usize].clone();
	    None
	},
	CFInsn::DW_CFA_undefined (reg) => {
	    state.regs[reg as usize] = RegRule::undefined;
	    None
	},
	CFInsn::DW_CFA_same_value (reg) => {
	    state.regs[reg as usize] = RegRule::same_value;
	    None
	},
	CFInsn::DW_CFA_register (reg, reg_from) => {
	    state.regs[reg as usize] = RegRule::register (reg_from);
	    None
	},
	CFInsn::DW_CFA_remember_state => {
	    let regs = state.regs.clone();
	    state.pushed.push(regs);
	    None
	},
	CFInsn::DW_CFA_restore_state => {
	    let pushed = if let Some(pushed) = state.pushed.pop() {
		pushed
	    } else {
		#[cfg(debug_assertions)]
		eprintln!("Fail to restore state; inconsistent!");
		return None
	    };
	    state.regs = pushed;
	    None
	},
	CFInsn::DW_CFA_def_cfa (reg, offset) => {
	    state.cfa = CFARule::reg_offset (reg, offset as i64);
	    None
	},
	CFInsn::DW_CFA_def_cfa_register (reg) => {
	    if let CFARule::reg_offset(cfa_reg, _offset) = &mut state.cfa {
		*cfa_reg = reg;
	    }
	    None
	},
	CFInsn::DW_CFA_def_cfa_offset (offset) => {
	    if let CFARule::reg_offset(_reg, cfa_offset) = &mut state.cfa {
		*cfa_offset = offset as i64;
	    }
	    None
	},
	CFInsn::DW_CFA_def_cfa_expression (expr) => {
	    state.cfa = CFARule::expression (expr);
	    None
	},
	CFInsn::DW_CFA_expression (reg, expr) => {
	    state.regs[reg as usize] = RegRule::expression (expr);
	    None
	},
	CFInsn::DW_CFA_offset_extended_sf (reg, offset) => {
	    state.regs[reg as usize] = RegRule::offset (offset as i64 * state.data_align_factor as i64);
	    None
	},
	CFInsn::DW_CFA_def_cfa_sf (reg, offset) => {
	    state.cfa = CFARule::reg_offset (reg, offset * state.data_align_factor as i64);
	    None
	},
	CFInsn::DW_CFA_def_cfa_offset_sf (offset) => {
	    if let CFARule::reg_offset(_reg, cfa_offset) = &mut state.cfa {
		*cfa_offset = offset as i64 * state.data_align_factor as i64;
	    }
	    None
	},
	CFInsn::DW_CFA_val_offset (reg, offset) => {
	    state.regs[reg as usize] = RegRule::val_offset (offset as i64 * state.data_align_factor as i64);
	    None
	},
	CFInsn::DW_CFA_val_offset_sf (reg, offset) => {
	    state.regs[reg as usize] = RegRule::val_offset (offset * state.data_align_factor as i64);
	    None
	},
	CFInsn::DW_CFA_val_expression (reg, expr) => {
	    state.regs[reg as usize] = RegRule::val_expression (expr);
	    None
	},
	CFInsn::DW_CFA_lo_user => {None},
	CFInsn::DW_CFA_hi_user => {None},
    }
}

struct CFCIE_aux {
    raw: Vec<u8>,
    init_cfa: CFARule,
    init_regs: Vec<RegRule>,
}

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

    aux: CFCIE_aux,
}

pub struct CFFDE<'a> {
    offset: usize,
    cie_pointer: u32,
    initial_location: u64,
    address_range: u64,
    augmentation_data: &'a [u8],
    instructions: &'a [u8],
    raw: Vec<u8>,
}

/// Exception Header pointer encoding applier.
///
/// The implementations apply base addresses to pointers.  The pointer
/// may relate to pc, text section, data section, or function
/// beginning.
trait EHPointerApplier {
    fn apply_pcrel(&self, ptr: u64, off: u64) -> u64;
    fn apply_textrel(&self, ptr: u64) -> u64;
    fn apply_datarel(&self, ptr: u64) -> u64;
    fn apply_funcrel(&self, ptr: u64) -> u64;
    fn apply_aligned(&self, ptr: u64) -> u64;
}

/// Decode pointers for Exception Header.
///
/// See https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/dwarfext.html
/// https://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
/// and https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
struct EHPointerDecoder {
    type_value: u8,		// The value of 'L', 'P', and 'R' letters in Augmentation String
    pointer_sz: usize,
    applier: Rc<Box<dyn EHPointerApplier>>,
}

impl EHPointerDecoder {
    fn apply(&self, v: u64, off: u64) -> u64 {
	let applier = &self.applier;

	match self.type_value >> 4 {
	    0x0 => v,
	    0x1 => applier.apply_pcrel(v, off),
	    0x2 => applier.apply_textrel(v),
	    0x3 => applier.apply_datarel(v),
	    0x4 => applier.apply_funcrel(v),
	    0x5 => applier.apply_aligned(v),
	    _ => {
		panic!("unknown pointer type ({})", self.type_value);
	    },
	}
    }

    fn apply_s(&self, v: i64, off: u64) -> u64 {
	self.apply(v as u64, off)
    }

    fn decode(&self, data: &[u8], off: u64) -> Option<(u64, usize)> {
	// see https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/dwarfext.html
	match self.type_value & 0xf {
	    0x00 => {
		let v = decode_uN(self.pointer_sz, data);
		let v = self.apply(v, off);
		Some((v, self.pointer_sz))
	    },
	    0x01 => {
		let (v, bytes) = decode_leb128(data).unwrap();
		let v = self.apply(v, off);
		Some((v, bytes as usize))
	    },
	    0x02 => {
		let v = decode_uN(2, data);
		let v = self.apply(v, off);
		Some((v, 2))
	    },
	    0x03 => {
		let v = decode_uN(4, data);
		let v = self.apply(v, off);
		Some((v, 4))
	    },
	    0x04 => {
		let v = decode_uN(4, data);
		let v = self.apply(v, off);
		Some((v, 4))
	    },
	    0x09 => {
		let (v, bytes) = decode_leb128_s(data).unwrap();
		let v = self.apply_s(v, off);
		Some((v, bytes as usize))
	    },
	    0x0a => {
		let v = decode_iN(2, data);
		let v = self.apply_s(v, off);
		Some((v, 2))
	    },
	    0x0b => {
		let v = decode_iN(4, data);
		let v = self.apply_s(v, off);
		Some((v, 4))
	    },
	    0x0c => {
		let v = decode_iN(8, data);
		let v = self.apply_s(v, off);
		Some((v, 8))
	    },
	    _ => None,
	}
    }
}

struct EHPDBuilder {
    decoders: RefCell<HashMap<u8, Rc<EHPointerDecoder>>>,
    applier: Rc<Box<dyn EHPointerApplier>>,
    pointer_sz: usize,
}

impl EHPDBuilder {
    fn new(applier: Rc<Box<dyn EHPointerApplier>>) -> EHPDBuilder {
	EHPDBuilder {
	    decoders: RefCell::new(HashMap::new()),
	    applier: applier,
	    pointer_sz: mem::size_of::<*const u8>(),
	}
    }

    fn build(&self, type_value: u8) -> Rc<EHPointerDecoder> {
	let mut decoders = self.decoders.borrow_mut();
	if let Some(decoder) = decoders.get(&type_value) {
	    (*decoder).clone()
	} else {
	    let decoder = Rc::new(
		EHPointerDecoder {
		    type_value,
		    pointer_sz: self.pointer_sz,
		    applier: self.applier.clone(),
		});
	    decoders.insert(type_value, decoder.clone());
	    decoder
	}
    }
}

pub struct CallFrameSession {
    pd_builder: EHPDBuilder,
    is_debug_frame: bool,
    pointer_sz: usize,
}

impl CallFrameSession {
    fn new(pd_builder: EHPDBuilder, is_debug_frame: bool) -> CallFrameSession {
	CallFrameSession {
	    pd_builder,
	    is_debug_frame,
	    pointer_sz: mem::size_of::<*const u8>(),
	}
    }

    pub fn from_parser(parser: &Elf64Parser, is_debug_frame: bool) -> CallFrameSession {
	let applier = EHPointerApplierElf::new(parser, is_debug_frame);
	let applier_box = Box::new(applier) as Box<dyn EHPointerApplier>;
	let pd_builder = EHPDBuilder::new(Rc::<Box<dyn EHPointerApplier>>::new(applier_box));
	CallFrameSession::new(pd_builder, is_debug_frame)
    }

    /// Find pointer encoding of a CIE.
    fn get_pointer_encoding(&self, cie: &CFCIE) -> u8 {
	let mut aug = cie.augmentation.chars();
	if aug.next() != Some('z') {
	    return 0;
	}
	let mut aug_data_off = 0;
	for c in aug {
	    match c {
		'e' | 'h' => {
		    // skip eh
		},
		'L' => {
		    aug_data_off += 1;
		},
		'P' => {
		    match cie.augmentation_data[aug_data_off] & 0xf {
			0 => {
			    aug_data_off += 1 + self.pointer_sz;
			},
			0x1 | 0x9 => {
			    let opt_v = decode_leb128(&cie.augmentation_data[(aug_data_off + 1)..]);
			    if opt_v.is_none() {
				return 0;
			    }
			    let (_, bytes) = opt_v.unwrap();
			    aug_data_off += 1 + bytes as usize;
			},
			0x2 | 0xa => {
			    aug_data_off += 3;
			},
			0x3 | 0xb => {
			    aug_data_off += 5;
			},
			0x4 | 0xc => {
			    aug_data_off += 9;
			},
			_ => {
			    panic!("invalid encoding in augmentation");
			}
		    }
		},
		'R' => {
		    return cie.augmentation_data[aug_data_off];
		},
		_ => todo!(),
	    }
	}

	0
    }

    fn parse_call_frame_cie(&self, raw: &[u8], offset: usize, cie: &mut CFCIE) -> Result<(), Error> {
	let mut offset: usize = 4;	// skip CIE_id

	let ensure = |offset, x| {
	    if x + offset <= raw.len() {
		Ok(())
	    } else {
		Err(Error::new(ErrorKind::InvalidData, "the call frame data is broken"))
	    }
	};

	ensure(offset, 1)?;
	cie.version = raw[offset] as u32;
	offset += 1;

	cie.augmentation = unsafe {
	    let aug = &*(extract_string(&raw, offset).ok_or(
		Error::new(ErrorKind::InvalidData, "can not extract augmentation"))? as *const str);
	    offset += aug.len() + 1;
	    aug
	};

	if !self.is_debug_frame && cie.augmentation == "eh" {
	    // see https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
	    ensure(offset, 8)?;
	    cie.eh_data = decode_udword(&raw[offset..]);
	    offset += 8;		// for 64 bit arch
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
	    let (code_align_factor, bytes) =
		decode_leb128(&raw[offset..]).
		ok_or(Error::new(ErrorKind::InvalidData, "failed to decode code alignment factor"))?;
	    offset += bytes as usize;
	    code_align_factor
	};

	cie.data_align_factor = {
	    let (data_align_factor, bytes) =
		decode_leb128_s(&raw[offset..]).
		ok_or(Error::new(ErrorKind::InvalidData, "failed to decode data alignment factor"))?;
	    offset += bytes as usize;
	    data_align_factor
	};

	ensure(offset, 1)?;
	cie.return_address_register = raw[offset];
	offset += 1;

	cie.augmentation_data =
	    if cie.augmentation.len() >= 1 && &cie.augmentation[0..1] == "z" {
		let (aug_data_len, bytes) =
		    decode_leb128(&raw[offset..]).
		    ok_or(Error::new(ErrorKind::InvalidData, "failed to decode augmentation data length factor"))?;
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
	    cie.pointer_encoding = self.get_pointer_encoding(cie);
	} else {
	    cie.pointer_encoding = 0;
	}

	Ok(())
    }

    fn parse_call_frame_fde(&self, mut raw: &[u8], off: usize, fde: &mut CFFDE, cie: &CFCIE) -> Result<(), Error> {
	let mut offset: usize = 0;

	let ensure = |offset, x| {
	    if x + offset <= raw.len() {
		Ok(())
	    } else {
		Err(Error::new(ErrorKind::InvalidData, "the call frame data is broken"))
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
	    let (v, bytes) = decoder.decode(&raw[offset..], off as u64)
		.ok_or(Error::new(ErrorKind::InvalidData, "fail to decode initial_location"))?;
	    fde.initial_location = v;
	    offset += bytes;
	    let (v, bytes) = decoder.decode(&raw[offset..], off as u64)
		.ok_or(Error::new(ErrorKind::InvalidData, "fail to decode address)rabge"))?;
	    fde.address_range = v;
	    offset += bytes;

	    fde.augmentation_data = if cie.augmentation.starts_with("z") {
		let (sz, bytes) = decode_leb128(&raw[offset..])
		    .ok_or(Error::new(ErrorKind::InvalidData, "fail to decode augmentation length"))?;
		offset += bytes as usize + sz as usize;
		unsafe { &*(&raw[(offset - sz as usize)..offset] as *const [u8])}
	    } else {
		unsafe { &*(&raw[offset..offset] as *const [u8]) }
	    };
	}

	fde.instructions = unsafe { &*(&raw[offset..] as *const [u8]) };

	Ok(())
    }

    fn parse_call_frame(&self, mut raw: Vec<u8>, offset: usize,
			cies: &mut Vec<CFCIE>, fdes: &mut Vec<CFFDE>) -> Result<(), Error> {
	let cie_id_or_cie_ptr = decode_uword(&raw);
	let cie_id = if self.is_debug_frame { 0xffffffff } else { 0x0 };
	if cie_id_or_cie_ptr == cie_id {
	    let i = cies.len();
	    unsafe {
		if cies.capacity() <= i {
		    if cies.capacity() != 0{
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

		let result = self.parse_call_frame_cie(&raw, offset, cie);

		if result.is_ok() {
		    // Initialize aux parts by swapping and dropping.
		    let mut aux = vec![CFCIE_aux {
			raw,
			init_cfa: CFARule::reg_offset (0, 0),
			init_regs: Vec::with_capacity(0),
		    }];
		    mem::swap(&mut cie.aux, &mut aux[0]);
		    // Drop all content! We don't to call destructors for them since they are garbage data.
		    aux.set_len(0);
		}
		result
	    }
	} else {
	    let cie_offset =
		if self.is_debug_frame {
		    cie_id_or_cie_ptr as usize
		} else {
		    (offset + 4) - cie_id_or_cie_ptr as usize
		};
	    let cie = {
		'outer: loop {
		    for i in (0..cies.len()).rev() {
			// It is ususally the last one in cies.
			if cies[i].offset == cie_offset {
			    break 'outer  &cies[i];
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
		let result = self.parse_call_frame_fde(&raw, offset, fde, cie);

		// Keep a reference to raw to make sure it's life-time is
		// logner than or equal to the fields refering it.
		mem::swap(&mut fde.raw, &mut raw);
		raw.leak();	// garbage data

		result
	    }
	}
    }

    pub fn parse_call_frames(&self, parser: &Elf64Parser) -> Result<(Vec<CFCIE>, Vec<CFFDE>), Error> {
	let mut is_debug_frame = true;
	let debug_frame_idx =
	    if self.is_debug_frame {
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

struct EHPointerApplierElf {
    section_addr: u64,
    text_addr: u64,
    data_addr: u64,
}

impl EHPointerApplierElf {
    fn new(parser: &Elf64Parser, is_debug_frame: bool) -> EHPointerApplierElf {
	let sect =
	    if is_debug_frame {
		parser.find_section(".debug_frame").unwrap()
	    } else {
		parser.find_section(".eh_frame").unwrap()
	    };
	let section_addr = parser.get_section_addr(sect).unwrap();

	let text_sect = parser.find_section(".text").unwrap();
	let text_addr = parser.get_section_addr(text_sect).unwrap();
	let data_sect = parser.find_section(".data").unwrap();
	let data_addr = parser.get_section_addr(data_sect).unwrap();

	EHPointerApplierElf {
	    section_addr,
	    text_addr,
	    data_addr,
	}
    }
}

impl EHPointerApplier for EHPointerApplierElf {
    fn apply_pcrel(&self, ptr: u64, off: u64) -> u64 {
	unsafe {
	    mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(self.section_addr) +
				       mem::transmute::<u64, i64>(off) +
				       mem::transmute::<u64, i64>(ptr))
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
    DW_CFA_advance_loc (u8),
    DW_CFA_offset (u8, u64),
    DW_CFA_restore (u8),
    DW_CFA_nop,
    DW_CFA_set_loc (u64),
    DW_CFA_advance_loc1 (u8),
    DW_CFA_advance_loc2 (u16),
    DW_CFA_advance_loc4 (u32),
    DW_CFA_offset_extended (u64, u64),
    DW_CFA_restore_extended (u64),
    DW_CFA_undefined (u64),
    DW_CFA_same_value (u64),
    DW_CFA_register (u64, u64),
    DW_CFA_remember_state,
    DW_CFA_restore_state,
    DW_CFA_def_cfa (u64, u64),
    DW_CFA_def_cfa_register (u64),
    DW_CFA_def_cfa_offset (u64),
    DW_CFA_def_cfa_expression (Vec<u8>),
    DW_CFA_expression (u64, Vec<u8>),
    DW_CFA_offset_extended_sf (u64, i64),
    DW_CFA_def_cfa_sf (u64, i64),
    DW_CFA_def_cfa_offset_sf (i64),
    DW_CFA_val_offset (u64, u64),
    DW_CFA_val_offset_sf (u64, i64),
    DW_CFA_val_expression (u64, Vec<u8>),
    DW_CFA_lo_user,
    DW_CFA_hi_user,
}

pub struct CFInsnParser<'a> {
    offset: usize,
    address_size: usize,
    raw: &'a [u8],
}

impl<'a> CFInsnParser<'a> {
    pub fn new(raw: &'a [u8], address_size: usize) -> CFInsnParser {
	CFInsnParser { offset: 0, address_size, raw }
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
	1 => if raw[0] & 0x80 == 0x80 {
	    -((!raw[0]) as i64 + 1)
	} else {
	    raw[0] as i64
	},
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
	    return None
	}

	let op = self.raw[self.offset];
	match op >> 6 {
	    0 => {
		match op & 0x3f {
		    0x0 => {
			self.offset += 1;
			Some(CFInsn::DW_CFA_nop)
		    },
		    0x1 => {
			let off = self.offset + 1;
			self.offset += 1 + self.address_size;
			Some(CFInsn::DW_CFA_set_loc (decode_uN(self.address_size, &self.raw[off..])))
		    },
		    0x2 => {
			self.offset += 2;
			Some(CFInsn::DW_CFA_advance_loc1 (self.raw[self.offset - 1]))
		    },
		    0x3 => {
			self.offset += 3;
			Some(CFInsn::DW_CFA_advance_loc2 (decode_uhalf(&self.raw[(self.offset - 2)..])))
		    },
		    0x4 => {
			self.offset += 5;
			Some(CFInsn::DW_CFA_advance_loc4 (decode_uword(&self.raw[(self.offset - 4)..])))
		    },
		    0x5 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_offset_extended (reg, off))
		    },
		    0x6 => {
			let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			self.offset += 1 + bytes as usize;
			Some(CFInsn::DW_CFA_restore_extended (reg))
		    },
		    0x7 => {
			let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			self.offset += 1 + bytes as usize;
			Some(CFInsn::DW_CFA_undefined (reg))
		    },
		    0x8 => {
			let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			self.offset += 1 + bytes as usize;
			Some(CFInsn::DW_CFA_same_value (reg))
		    },
		    0x9 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_register (reg, off))
		    },
		    0xa => {
			self.offset += 1;
			Some(CFInsn::DW_CFA_remember_state)
		    },
		    0xb => {
			self.offset += 1;
			Some(CFInsn::DW_CFA_restore_state)
		    },
		    0xc => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_def_cfa (reg, off))
		    },
		    0xd => {
			let (reg, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			self.offset += 1 + bytes as usize;
			Some(CFInsn::DW_CFA_def_cfa_register (reg))
		    },
		    0xe => {
			let (off, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			self.offset += 1 + bytes as usize;
			Some(CFInsn::DW_CFA_def_cfa_offset (off))
		    },
		    0xf => {
			let (sz, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let expr = Vec::from(&self.raw[(self.offset + 1 + bytes as usize)..(self.offset + 1 + bytes as usize + sz as usize)]);
			self.offset += 1 + bytes as usize + sz as usize;
			Some(CFInsn::DW_CFA_def_cfa_expression (expr))
		    },
		    0x10 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (sz, sbytes) = decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			let bytes = rbytes + sbytes;
			let expr = Vec::from(&self.raw[(self.offset + 1 + bytes as usize)..(self.offset + 1 + bytes as usize + sz as usize)]);
			self.offset += 1 + bytes as usize + sz as usize;
			Some(CFInsn::DW_CFA_expression (reg, expr))
		    },
		    0x11 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128_s(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_offset_extended_sf (reg, off))
		    },
		    0x12 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128_s(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_def_cfa_sf (reg, off))
		    },
		    0x13 => {
			let (off, bytes) = decode_leb128_s(&self.raw[(self.offset + 1)..]).unwrap();
			self.offset += 1 + bytes as usize;
			Some(CFInsn::DW_CFA_def_cfa_offset_sf (off))
		    },
		    0x14 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_val_offset (reg, off))
		    },
		    0x15 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (off, obytes) = decode_leb128_s(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			self.offset += 1 + rbytes as usize + obytes as usize;
			Some(CFInsn::DW_CFA_val_offset_sf (reg, off))
		    },
		    0x16 => {
			let (reg, rbytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
			let (sz, sbytes) = decode_leb128(&self.raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
			let bytes = rbytes + sbytes;
			let expr = Vec::from(&self.raw[(self.offset + 1 + bytes as usize)..(self.offset + 1 + bytes as usize + sz as usize)]);
			self.offset += 1 + bytes as usize + sz as usize;
			Some(CFInsn::DW_CFA_val_expression (reg, expr))
		    },
		    0x1c => {
			self.offset += 1;
			Some(CFInsn::DW_CFA_lo_user)
		    },
		    0x3f => {
			self.offset += 1;
			Some(CFInsn::DW_CFA_hi_user)
		    },
		    _ => {
			None
		    },
		}
	    },
	    1 => {
		self.offset += 1;
		Some(CFInsn::DW_CFA_advance_loc (op & 0x3f))
	    },
	    2 => {
		let (off, bytes) = decode_leb128(&self.raw[(self.offset + 1)..]).unwrap();
		self.offset += bytes as usize + 1;
		Some(CFInsn::DW_CFA_offset (op & 0x3f, off))
	    },
	    3 => {
		self.offset += 1;
		Some(CFInsn::DW_CFA_restore (op & 0x3f))
	    },
	    _ => {
		None
	    }
	}
    }
}

#[derive(Debug, Clone)]
pub enum DwarfExprOp {
    DW_OP_addr (u64),
    DW_OP_deref,
    DW_OP_const1u (u8),
    DW_OP_const1s (i8),
    DW_OP_const2u (u16),
    DW_OP_const2s (i16),
    DW_OP_const4u (u32),
    DW_OP_const4s (i32),
    DW_OP_const8u (u64),
    DW_OP_const8s (i64),
    DW_OP_constu (u64),
    DW_OP_consts (i64),
    DW_OP_dup,
    DW_OP_drop,
    DW_OP_over,
    DW_OP_pick (u8),
    DW_OP_swap,
    DW_OP_rot,
    DW_OP_xderef,
    DW_OP_abs,
    DW_OP_and,
    DW_OP_div,
    DW_OP_minus,
    DW_OP_mod,
    DW_OP_mul,
    DW_OP_neg,
    DW_OP_not,
    DW_OP_or,
    DW_OP_plus,
    DW_OP_plus_uconst (u64),
    DW_OP_shl,
    DW_OP_shr,
    DW_OP_shra,
    DW_OP_xor,
    DW_OP_bra (i16),
    DW_OP_eq,
    DW_OP_ge,
    DW_OP_gt,
    DW_OP_le,
    DW_OP_lt,
    DW_OP_ne,
    DW_OP_skip (i16),
    DW_OP_lit (u8),
    DW_OP_reg (u8),
    DW_OP_breg (u8, i64),
    DW_OP_regx (u64),
    DW_OP_fbreg (i64),
    DW_OP_bregx (u64, i64),
    DW_OP_piece (u64),
    DW_OP_deref_size (u8),
    DW_OP_xderef_size (u8),
    DW_OP_nop,
    DW_OP_push_object_address,
    DW_OP_call2 (u16),
    DW_OP_call4 (u32),
    DW_OP_call_ref (u64),
    DW_OP_form_tls_address,
    DW_OP_call_frame_cfa,
    DW_OP_bit_piece (u64, u64),
    DW_OP_implicit_value (Vec<u8>),
    DW_OP_stack_value,
    DW_OP_implicit_pointer (u64, i64),
    DW_OP_addrx (u64),
    DW_OP_constx (u64),
    DW_OP_entry_value (Vec<u8>),
    DW_OP_const_type (u64, Vec<u8>),
    DW_OP_regval_type (u64, u64),
    DW_OP_deref_type (u8, u64),
    DW_OP_xderef_type (u8, u64),
    DW_OP_convert (u64),
    DW_OP_reinterpret (u64),
    DW_OP_lo_user,
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
		Some((saved_offset, DwarfExprOp::DW_OP_addr (addr)))
	    },
	    0x6 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_deref))
	    },
	    0x8 => {
		self.offset += 2;
		Some((saved_offset, DwarfExprOp::DW_OP_const1u (raw[self.offset - 1])))
	    },
	    0x9 => {
		self.offset += 2;
		Some((saved_offset, DwarfExprOp::DW_OP_const1s (raw[self.offset - 1] as i8)))
	    },
	    0xa => {
		self.offset += 3;
		Some((saved_offset, DwarfExprOp::DW_OP_const2u (decode_uhalf(&raw[(self.offset - 2)..]))))
	    },
	    0xb => {
		self.offset += 3;
		Some((saved_offset, DwarfExprOp::DW_OP_const2s (decode_shalf(&raw[(self.offset - 2)..]))))
	    },
	    0xc => {
		self.offset += 5;
		Some((saved_offset, DwarfExprOp::DW_OP_const4u (decode_uword(&raw[(self.offset - 4)..]))))
	    },
	    0xd => {
		self.offset += 5;
		Some((saved_offset, DwarfExprOp::DW_OP_const4s (decode_sword(&raw[(self.offset - 4)..]))))
	    },
	    0xe => {
		self.offset += 9;
		Some((saved_offset, DwarfExprOp::DW_OP_const8u (decode_udword(&raw[(self.offset - 8)..]))))
	    },
	    0xa => {
		self.offset += 9;
		Some((saved_offset, DwarfExprOp::DW_OP_const8s (decode_sdword(&raw[(self.offset - 8)..]))))
	    },
	    0x10 => {
		let (v, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_constu (v)))
	    },
	    0x11 => {
		let (v, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_consts (v)))
	    },
	    0x12 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_dup))
	    },
	    0x13 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_drop))
	    },
	    0x14 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_over))
	    },
	    0x15 => {
		self.offset += 2;
		Some((saved_offset, DwarfExprOp::DW_OP_pick (raw[self.offset - 1])))
	    },
	    0x16 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_swap))
	    },
	    0x17 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_rot))
	    },
	    0x18 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_xderef))
	    },
	    0x19 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_abs))
	    },
	    0x1a => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_and))
	    },
	    0x1b => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_div))
	    },
	    0x1c => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_minus))
	    },
	    0x1d => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_mod))
	    },
	    0x1e => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_mul))
	    },
	    0x1f => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_neg))
	    },
	    0x20 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_not))
	    },
	    0x21 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_or))
	    },
	    0x22 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_plus))
	    },
	    0x23 => {
		let (addend, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_plus_uconst (addend)))
	    },
	    0x24 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_shl))
	    },
	    0x25 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_shr))
	    },
	    0x26 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_shra))
	    },
	    0x27 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_xor))
	    },
	    0x28 => {
		self.offset += 3;
		Some((saved_offset, DwarfExprOp::DW_OP_bra (decode_shalf(&raw[(self.offset - 2)..]))))
	    },
	    0x29 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_eq))
	    },
	    0x2a => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_ge))
	    },
	    0x2b => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_gt))
	    },
	    0x2c => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_le))
	    },
	    0x2d => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_lt))
	    },
	    0x2e => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_ne))
	    },
	    0x2f => {
		self.offset += 3;
		Some((saved_offset, DwarfExprOp::DW_OP_skip(decode_shalf(&raw[(self.offset - 2)..]))))
	    },
	    0x30..=0x4f => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_lit (op - 0x30)))
	    },
	    0x50..=0x6f => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_reg (op - 0x50)))
	    },
	    0x70..=0x8f => {
		let (offset, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_breg (op - 0x70, offset)))
	    },
	    0x90 => {
		let (offset, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_regx (offset)))
	    },
	    0x91 => {
		let (offset, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_fbreg (offset)))
	    },
	    0x92 => {
		let (reg, rbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		let (offset, obytes) = decode_leb128_s(&raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
		self.offset += 1 + rbytes as usize + obytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_bregx (reg, offset)))
	    },
	    0x93 => {
		let (piece_sz, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_piece (piece_sz)))
	    },
	    0x94 => {
		self.offset += 2;
		Some((saved_offset, DwarfExprOp::DW_OP_deref_size (raw[self.offset - 1])))
	    },
	    0x95 => {
		self.offset += 2;
		Some((saved_offset, DwarfExprOp::DW_OP_xderef_size (raw[self.offset - 1])))
	    },
	    0x96 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_nop))
	    },
	    0x97 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_push_object_address))
	    },
	    0x98 => {
		self.offset += 3;
		Some((saved_offset, DwarfExprOp::DW_OP_call2 (decode_uhalf(&raw[(self.offset - 2)..]))))
	    },
	    0x99 => {
		self.offset += 5;
		Some((saved_offset, DwarfExprOp::DW_OP_call4 (decode_uword(&raw[(self.offset - 4)..]))))
	    },
	    0x9a => {
		let off = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
		self.offset += 1 + self.address_size;
		Some((saved_offset, DwarfExprOp::DW_OP_call_ref (off)))
	    },
	    0x9b => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_form_tls_address))
	    },
	    0x9c => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_call_frame_cfa))
	    },
	    0x9d => {
		let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		let (off, obytes) = decode_leb128(&raw[(self.offset + 1 + sbytes as usize)..]).unwrap();
		self.offset += 1 + sbytes as usize + obytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_bit_piece (sz, off)))
	    },
	    0x9e => {
		let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		let blk = Vec::from(&raw[(self.offset + 1 + sbytes as usize)..(self.offset + 1 + sbytes as usize + sz as usize)]);
		Some((saved_offset, DwarfExprOp::DW_OP_implicit_value (blk)))
	    },
	    0x9f => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_stack_value))
	    },
	    0xa0 => {
		let die_off = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
		let (const_off, bytes) = decode_leb128_s(&raw[(self.offset + 1 + self.address_size)..]).unwrap();
		self.offset += 1 + self.address_size + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_implicit_pointer (die_off, const_off)))
	    },
	    0xa1 => {
		let (addr, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_addrx (addr)))
	    },
	    0xa2 => {
		let (v, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset += 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_constx (v)))
	    },
	    0xa3 => {
		let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		let blk = Vec::from(&raw[(self.offset + 1 + sbytes as usize)..(self.offset + 1 + sbytes as usize + sz as usize)]);
		self.offset += 1 + sbytes as usize + sz as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_entry_value (blk)))
	    },
	    0xa4 => {
		let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		let pos = self.offset + 1 + bytes as usize ;
		let sz = raw[pos];
		let pos = pos + 1;
		let v = Vec::from(&raw[pos..(pos + sz as usize)]);
		self.offset += pos + sz as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_const_type (ent_off, v)))
	    },
	    0xa5 => {
		let (reg, rbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		let pos = self.offset + 1 + rbytes as usize;
		let (off, obytes) = decode_leb128(&raw[pos..]).unwrap();
		self.offset += pos + obytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_regval_type (reg, off)))
	    },
	    0xa6 => {
		let sz = raw[self.offset + 1];
		let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 2)..]).unwrap();
		self.offset = self.offset + 2 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_deref_type (sz, ent_off)))
	    },
	    0xa7 => {
		let sz = raw[self.offset + 1];
		let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 2)..]).unwrap();
		self.offset = self.offset + 2 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_xderef_type (sz, ent_off)))
	    },
	    0xa8 => {
		let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset = self.offset + 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_convert (ent_off)))
	    },
	    0xa9 => {
		let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
		self.offset = self.offset + 1 + bytes as usize;
		Some((saved_offset, DwarfExprOp::DW_OP_reinterpret (ent_off)))
	    },
	    0xe0 => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_lo_user))
	    },
	    0xff => {
		self.offset += 1;
		Some((saved_offset, DwarfExprOp::DW_OP_hi_user))
	    },
	    _ => {
		None
	    }
	}
    }
}

#[derive(Clone)]
enum DwarfExprPCOp {
    go_next,
    skip (i64),
    stack_value,
}

fn run_dwarf_expr_insn(insn: DwarfExprOp, stack: &mut Vec<u64>, regs: &[u64], get_mem: &dyn Fn(u64, usize) -> u64) -> Result<DwarfExprPCOp, Error> {
    match insn {
	DwarfExprOp::DW_OP_addr (v_u64) => {
	    stack.push(v_u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_deref => {
	    if let Some(addr) = stack.pop() {
		let val = get_mem(addr, 8);
		stack.push(val);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_const1u (v_u8) => {
	    stack.push(v_u8 as u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const1s (v_i8) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(v_i8 as i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const2u (v_u16) => {
	    stack.push(v_u16 as u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const2s (v_i16) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(v_i16 as i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const4u (v_u32) => {
	    stack.push(v_u32 as u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const4s (v_i32) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(v_i32 as i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const8u (v_u64) => {
	    stack.push(v_u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_const8s (v_i64) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(v_i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_constu (v_u64) => {
	    stack.push(v_u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_consts (v_i64) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(v_i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_dup => {
	    if !stack.is_empty() {
		stack.push(stack[stack.len() - 1]);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_drop => {
	    if !stack.is_empty() {
		stack.pop();
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_over => {
	    if stack.len() >= 2 {
		stack.push(stack[stack.len() - 2]);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_pick (v_u8) => {
	    if stack.len() >= (v_u8 as usize + 1) {
		stack.push(stack[stack.len() - 1 - v_u8 as usize]);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_swap => {
	    let len = stack.len();
	    let tmp = stack[len - 1];
	    stack[len - 1] = stack[len - 2];
	    stack[len - 2] = tmp;
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_rot => {
	    let len = stack.len();
	    let tmp = stack[len - 1];
	    stack[len - 1] = stack[len - 2];
	    stack[len - 2] = stack[len - 3];
	    stack[len - 3] = tmp;
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_xderef => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_xderef is not implemented"))
	},
	DwarfExprOp::DW_OP_abs => {
	    let len = stack.len();
	    stack[len - 1] = unsafe { mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(stack[len - 1]).abs()) };
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_and => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(first & second);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
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
	},
	DwarfExprOp::DW_OP_minus => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second - first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_mod => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second % first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_mul => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second * first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_neg => {
	    let len = stack.len();
	    if len >= 1 {
		stack[len - 1] = unsafe { mem::transmute::<i64, u64>(-mem::transmute::<u64, i64>(stack[len - 1])) };
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_not => {
	    let len = stack.len();
	    if len >= 1 {
		stack[len - 1] = !stack[len - 1];
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_or => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second | first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_plus => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second + first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_plus_uconst (v_u64) => {
	    let len = stack.len();
	    if len >= 1 {
		stack[len - 1] += v_u64;
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_shl => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second << first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_shr => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second >> first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
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
	},
	DwarfExprOp::DW_OP_xor => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(second ^ first);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_bra (v_i16) => {
	    if let Some(top) = stack.pop() {
		if top == 0 {
		    Ok(DwarfExprPCOp::go_next)
		} else {
		    Ok(DwarfExprPCOp::skip (v_i16 as i64))
		}
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_eq => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(if second == first { 1 } else { 0 });
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_ge => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(if second >= first { 1 } else { 0 });
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_gt => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(if second > first { 1 } else { 0 });
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_le => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(if second <= first { 1 } else { 0 });
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_lt => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(if second < first { 1 } else { 0 });
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_ne => {
	    if stack.len() >= 2 {
		let first = stack.pop().unwrap();
		let second = stack.pop().unwrap();
		stack.push(if second != first { 1 } else { 0 });
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_skip (v_i16) => {
	    Ok(DwarfExprPCOp::skip (v_i16 as i64))
	},
	DwarfExprOp::DW_OP_lit (v_u8) => {
	    stack.push(v_u8 as u64);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_reg (v_u8) => {
	    stack.push(regs[v_u8 as usize]);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_breg (v_u8, v_i64) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(regs[v_u8 as usize]) + v_i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_regx (v_u64) => {
	    stack.push(regs[v_u64 as usize]);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_fbreg (v_i64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_breg is not implemented"))
	},
	DwarfExprOp::DW_OP_bregx (v_u64, v_i64) => {
	    stack.push(unsafe { mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(regs[v_u64 as usize]) + v_i64) });
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_piece (v_u64) => {
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_deref_size (v_u8) => {
	    if let Some(addr) = stack.pop() {
		let v = get_mem(addr, v_u8 as usize);
		stack.push(v);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_xderef_size (v_u8) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_xderef_size is not implemented"))
	},
	DwarfExprOp::DW_OP_nop => {
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_push_object_address => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_push_object_address is not implemented"))
	},
	DwarfExprOp::DW_OP_call2 (v_u16) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_call2 is not implemented"))
	},
	DwarfExprOp::DW_OP_call4 (v_u32) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_call4 is not implemented"))
	},
	DwarfExprOp::DW_OP_call_ref (v_u64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_call_ref is not implemented"))
	},
	DwarfExprOp::DW_OP_form_tls_address => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_form_tls_address is not implemented"))
	},
	DwarfExprOp::DW_OP_call_frame_cfa => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_call_frame_cfa is not implemented"))
	},
	DwarfExprOp::DW_OP_bit_piece (v_u64, v_u64_1) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_bit_piece is not implemented"))
	},
	DwarfExprOp::DW_OP_implicit_value (v_vu8) => {
	    let mut v: u64 = 0;
	    for (i, v8) in v_vu8.iter().enumerate() {
		v |= (*v8 as u64) << (i * 8);
	    }
	    stack.push(v);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_stack_value => {
	    Ok(DwarfExprPCOp::stack_value)
	},
	DwarfExprOp::DW_OP_implicit_pointer (v_u64, v_i64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_implicit_pointer is not implemented"))
	},
	DwarfExprOp::DW_OP_addrx (v_u64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_addrx is not implemented"))
	},
	DwarfExprOp::DW_OP_constx (v_u64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_constx is not implemented"))
	},
	DwarfExprOp::DW_OP_entry_value (v_vu8) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_constx is not implemented"))
	},
	DwarfExprOp::DW_OP_const_type (v_u64, v_vu8) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_constx is not implemented"))
	},
	DwarfExprOp::DW_OP_regval_type (v_u64, v_u64_1) => {
	    stack.push(regs[v_u64 as usize]);
	    Ok(DwarfExprPCOp::go_next)
	},
	DwarfExprOp::DW_OP_deref_type (v_u8, v_u64) => {
	    if let Some(addr) = stack.pop() {
		let v = get_mem(addr, v_u8 as usize);
		stack.push(v);
		Ok(DwarfExprPCOp::go_next)
	    } else {
		Err(Error::new(ErrorKind::Other, "stack is empty"))
	    }
	},
	DwarfExprOp::DW_OP_xderef_type (v_u8, v_u64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_xderef_type is not implemented"))
	},
	DwarfExprOp::DW_OP_convert (v_u64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_convert is not implemented"))
	},
	DwarfExprOp::DW_OP_reinterpret (v_u64) => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_reinterpret is not implemented"))
	},
	DwarfExprOp::DW_OP_lo_user => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_lo_user is not implemented"))
	},
	DwarfExprOp::DW_OP_hi_user => {
	    Err(Error::new(ErrorKind::Unsupported, "DW_OP_hi_user is not implemented"))
	},
    }
}

pub fn run_dwarf_expr(expr: &[u8], max_rounds: usize, regs: &[u64], get_mem: &dyn Fn(u64, usize) -> u64) -> Result<u64, Error> {
    let insns: Vec<(u64, DwarfExprOp)> = DwarfExprParser::from(expr, 8).collect();
    let mut idx = 0;
    let mut stack = Vec::<u64>::new();
    let mut rounds = 0;

    while idx < insns.len() {
	if rounds >= max_rounds {
	    return Err(Error::new(ErrorKind::Other, "spend too much time"));
	}
	rounds += 1;

	let (offset, insn) = &insns[idx];

	match run_dwarf_expr_insn(insn.clone(), &mut stack, regs, get_mem) {
	    Err(err) => {
		return Err(err);
	    },
	    Ok(DwarfExprPCOp::go_next) => {
		idx += 1;
	    },
	    Ok(DwarfExprPCOp::skip (rel)) => {
		let tgt_offset =
		    (if idx < (insns.len() - 1) {
			insns[idx].0 as i64
		    } else {
			expr.len() as i64
		    } + rel) as u64;

		if tgt_offset == expr.len() as u64{
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
	    },
	    Ok(DwarfExprPCOp::stack_value) => {
		break;
	    },
	}
    }

    if let Some(v) = stack.pop() {
	println!("stack size {}", stack.len());
	Ok(v)
    } else {
	Err(Error::new(ErrorKind::Other, "stack is empty"))
    }
}

/// DwarfResolver provide abilities to query DWARF information of binaries.
pub struct DwarfResolver {
    parser: Rc<Elf64Parser>,
    debug_line_cus: Vec<DebugLineCU>,
    addr_to_dlcu: Vec<(u64, u32)>,
}

impl DwarfResolver {
    pub fn get_parser(&self) -> &Elf64Parser {
        &*self.parser
    }

    pub fn from_parser_for_addresses(
        parser: Rc<Elf64Parser>,
        addresses: &[u64],
        line_number_info: bool,
    ) -> Result<DwarfResolver, Error> {
        let debug_line_cus: Vec<DebugLineCU> = if line_number_info {
            parse_debug_line_elf_parser(&*parser, addresses)?
        } else {
            vec![]
        };

        let mut addr_to_dlcu = Vec::with_capacity(debug_line_cus.len());
        for (idx, dlcu) in debug_line_cus.iter().enumerate() {
            if dlcu.matrix.is_empty() {
                continue;
            }
            let first_addr = dlcu.matrix[0].address;
            addr_to_dlcu.push((first_addr, idx as u32));
        }
        addr_to_dlcu.sort_by_key(|v| v.0);

        Ok(DwarfResolver {
            parser,
            debug_line_cus,
            addr_to_dlcu,
        })
    }

    /// Open a binary to load .debug_line only enough for a given list of addresses.
    ///
    /// When `addresses` is not empty, the returned instance only has
    /// data that related to these addresses.  For this case, the
    /// isntance have the ability that can serve only these addresses.
    /// This would be much faster.
    ///
    /// If `addresses` is empty, the returned instance has all data
    /// from the given file.  If the instance will be used for long
    /// running, you would want to load all data into memory to have
    /// the ability of handling all possible addresses.
    pub fn open_for_addresses(
        filename: &str,
        addresses: &[u64],
        line_number_info: bool,
    ) -> Result<DwarfResolver, Error> {
        let parser = Elf64Parser::open(filename)?;
        Self::from_parser_for_addresses(Rc::new(parser), addresses, line_number_info)
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    pub fn open(filename: &str, debug_line_info: bool) -> Result<DwarfResolver, Error> {
        Self::open_for_addresses(filename, &[], debug_line_info)
    }

    fn find_dlcu_index(&self, address: u64) -> Option<usize> {
        let a2a = &self.addr_to_dlcu;
        let a2a_idx = search_address_key(a2a, address, &|x: &(u64, u32)| -> u64 { x.0 as u64 })?;
        let dlcu_idx = a2a[a2a_idx].1 as usize;

        Some(dlcu_idx)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    pub fn find_line_as_ref(&self, address: u64) -> Option<(&str, &str, usize)> {
        let idx = self.find_dlcu_index(address)?;
        let dlcu = &self.debug_line_cus[idx as usize];

        dlcu.find_line(address)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    ///
    /// This function is pretty much the same as `find_line_as_ref()`
    /// except returning a copies of `String` instead of `&str`.
    pub fn find_line(&self, address: u64) -> Option<(String, String, usize)> {
        let (dir, file, line_no) = self.find_line_as_ref(address)?;
        Some((String::from(dir), String::from(file), line_no))
    }

    #[cfg(test)]
    fn pick_address_for_test(&self) -> (u64, &str, &str, usize) {
        let (addr, idx) = self.addr_to_dlcu[self.addr_to_dlcu.len() / 3];
        let dlcu = &self.debug_line_cus[idx as usize];
        let (dir, file, line) = dlcu.stringify_row(0).unwrap();
        (addr, dir, file, line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_leb128() {
        let data = vec![0xf4, 0xf3, 0x75];
        let result = decode_leb128(&data);
        assert!(result.is_some());
        if let Some((v, s)) = result {
            assert_eq!(v, 0x1d79f4);
            assert_eq!(s, 3);
        }

        let result = decode_leb128_s(&data);
        assert!(result.is_some());
        if let Some((v, s)) = result {
            assert_eq!(v, -165388);
            assert_eq!(s, 3);
        }
    }

    #[test]
    fn test_decode_words() {
        let data = vec![0x7f, 0x85, 0x36, 0xf9];
        assert_eq!(decode_uhalf(&data), 0x857f);
        assert_eq!(decode_shalf(&data), -31361);
        assert_eq!(decode_uword(&data), 0xf936857f);
        assert_eq!(decode_sword(&data), -113867393);
    }

    #[test]
    fn test_parse_debug_line_elf() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];

        let r = parse_debug_line_elf(bin_name);
        if r.is_err() {
            println!("{:?}", r.as_ref().err().unwrap());
        }
        assert!(r.is_ok());
    }

    #[test]
    fn test_run_debug_line_stmts_1() {
        let stmts = [
            0x00, 0x09, 0x02, 0x30, 0x8b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xa0, 0x04,
            0x01, 0x05, 0x06, 0x0a, 0x08, 0x30, 0x02, 0x05, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {:?}", e);
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 3);
        assert_eq!(matrix[0].line, 545);
        assert_eq!(matrix[0].address, 0x18b30);
        assert_eq!(matrix[1].line, 547);
        assert_eq!(matrix[1].address, 0x18b43);
        assert_eq!(matrix[2].line, 547);
        assert_eq!(matrix[2].address, 0x18b48);
    }

    #[test]
    fn test_run_debug_line_stmts_2() {
        //	File name                            Line number    Starting address    View    Stmt
        //	    methods.rs                                   789             0x18c70               x
        //	    methods.rs                                   791             0x18c7c               x
        //	    methods.rs                                   791             0x18c81
        //	    methods.rs                                   790             0x18c86               x
        //	    methods.rs                                     0             0x18c88
        //	    methods.rs                                   791             0x18c8c               x
        //	    methods.rs                                     0             0x18c95
        //	    methods.rs                                   792             0x18c99               x
        //	    methods.rs                                   792             0x18c9d
        //	    methods.rs                                     0             0x18ca4
        //	    methods.rs                                   791             0x18ca8               x
        //	    methods.rs                                   792             0x18caf               x
        //	    methods.rs                                     0             0x18cb6
        //	    methods.rs                                   792             0x18cba
        //	    methods.rs                                     0             0x18cc4
        //	    methods.rs                                   792             0x18cc8
        //	    methods.rs                                   790             0x18cce               x
        //	    methods.rs                                   794             0x18cd0               x
        //	    methods.rs                                   794             0x18cde               x
        let stmts = [
            0x00, 0x09, 0x02, 0x70, 0x8c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x94, 0x06,
            0x01, 0x05, 0x0d, 0x0a, 0xbc, 0x05, 0x26, 0x06, 0x58, 0x05, 0x09, 0x06, 0x57, 0x06,
            0x03, 0xea, 0x79, 0x2e, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x06, 0x03, 0xe9,
            0x79, 0x90, 0x05, 0x0d, 0x06, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x12, 0x06, 0x4a, 0x03,
            0xe8, 0x79, 0x74, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x05, 0x12, 0x75, 0x06,
            0x03, 0xe8, 0x79, 0x74, 0x05, 0x20, 0x03, 0x98, 0x06, 0x4a, 0x03, 0xe8, 0x79, 0x9e,
            0x05, 0x12, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x09, 0x06, 0x64, 0x05, 0x06, 0x32, 0x02,
            0x0e, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {:?}", e);
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();

        assert_eq!(matrix.len(), 19);
        assert_eq!(matrix[0].line, 789);
        assert_eq!(matrix[0].address, 0x18c70);
        assert_eq!(matrix[0].is_stmt, true);

        assert_eq!(matrix[1].line, 791);
        assert_eq!(matrix[1].address, 0x18c7c);
        assert_eq!(matrix[1].is_stmt, true);

        assert_eq!(matrix[2].line, 791);
        assert_eq!(matrix[2].address, 0x18c81);
        assert_eq!(matrix[2].is_stmt, false);

        assert_eq!(matrix[13].line, 792);
        assert_eq!(matrix[13].address, 0x18cba);
        assert_eq!(matrix[13].is_stmt, false);

        assert_eq!(matrix[14].line, 0);
        assert_eq!(matrix[14].address, 0x18cc4);
        assert_eq!(matrix[14].is_stmt, false);

        assert_eq!(matrix[18].line, 794);
        assert_eq!(matrix[18].address, 0x18cde);
        assert_eq!(matrix[18].is_stmt, true);
    }

    #[test]
    fn test_parse_aranges_elf() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];

        let r = parse_aranges_elf(bin_name);
        if r.is_err() {
            println!("{:?}", r.as_ref().err().unwrap());
        }
        assert!(r.is_ok());
        let _acus = r.unwrap();
    }

    #[test]
    fn test_dwarf_resolver() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let resolver_r = DwarfResolver::open(bin_name, true);
        assert!(resolver_r.is_ok());
        let resolver = resolver_r.unwrap();
        let (addr, dir, file, line) = resolver.pick_address_for_test();

        let line_info = resolver.find_line(addr);
        assert!(line_info.is_some());
        let (dir_ret, file_ret, line_ret) = line_info.unwrap();
        println!("{}/{} {}", dir_ret, file_ret, line_ret);
        assert_eq!(dir, dir_ret);
        assert_eq!(file, file_ret);
        assert_eq!(line, line_ret);
    }

    fn test_parse_call_frames(is_debug_frame: bool) {
	let args: Vec<String> = env::args().collect();
	let bin_name = &args[0];
	let parser_r = Elf64Parser::open(bin_name);
	assert!(parser_r.is_ok());
	let parser = parser_r.unwrap();

	let cfsession = CallFrameSession::from_parser(&parser, is_debug_frame);
	let cies_fdes = cfsession.parse_call_frames(&parser);
	//assert!(cies_fdes.is_ok());
	let (mut cies, fdes) = cies_fdes.unwrap();
	println!("cies len={}, fdes len={}", cies.len(), fdes.len());

	for cie in &mut cies {
	    println!("address size {} data alignment {} offset {}", cie.address_size, cie.data_align_factor, cie.offset);
	    println!("{:?}", cie.init_instructions);
	    let insniter = CFInsnParser::new(cie.init_instructions, cie.address_size as usize);
	    let mut state = CallFrameState::new(&cie, 32);
	    for insn in insniter {
		println!("INSN: {:?}", insn);
		run_call_frame_insn(insn, &mut state);
	    }
	    cie.aux.init_cfa = state.cfa;
	    cie.aux.init_regs = state.regs;
	}
	for fde in fdes {
	    println!("CIE pointer {}", fde.cie_pointer);
	    let insniter = CFInsnParser::new(fde.instructions, 8);

	    for insn in insniter {
		println!("INSN: {:?}", insn);
		if let CFInsn::DW_CFA_def_cfa_expression(expression) = insn {
		    for (off, insn) in DwarfExprParser::from(&expression, 8) {
			println!("    {} {:?}", off, insn);
		    }
		}
	    }

	    let mut state = None;
	    for cie in &cies {
		if cie.offset == fde.cie_pointer as usize {
		    state = Some(CallFrameState::new(cie, 32));
		}
	    }

	    if let Some(state) = state.as_mut() {
		let insniter = CFInsnParser::new(fde.instructions, 8);
		for insn in insniter {
		    if let Some(loc) = run_call_frame_insn(insn, state) {
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
	    }
	}
	assert!(false);
    }

    #[test]
    fn test_parse_call_frames_debug_frame() {
	test_parse_call_frames(true)
    }

    #[test]
    fn test_parse_call_frames_eh_frame() {
	test_parse_call_frames(false)
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
	let regs = [14 as u64;32];
	let get_mem = |addr: u64, sz: usize| -> u64 {
	    0
	};

	let v = run_dwarf_expr(&expr, 9, &regs, &get_mem);
	assert!(v.is_ok());
	assert!(v.unwrap() == 30);

	// max_rounds is too small.
	let v = run_dwarf_expr(&expr, 8, &regs, &get_mem);
	assert!(v.is_err());
    }
}
