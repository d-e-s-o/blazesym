#[allow(dead_code, non_upper_case_globals)]
pub const DW_UT_compile: u8 = 0x1;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_UT_type: u8 = 0x2;

#[allow(dead_code, non_upper_case_globals)]
pub const DW_TAG_array_type: u8 = 0x1;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_TAG_enumeration_type: u8 = 0x4;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_TAG_compile_unit: u8 = 0x11;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_TAG_subprogram: u8 = 0x2e;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_TAG_variable: u8 = 0x34;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_TAG_namespace: u8 = 0x39;

#[allow(dead_code, non_upper_case_globals)]
pub const DW_CHILDREN_no: u8 = 0x00;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_CHILDREN_yes: u8 = 0x01;

#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_sibling: u8 = 0x01;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_location: u8 = 0x02;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_name: u8 = 0x03;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_lo_pc: u8 = 0x11;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_hi_pc: u8 = 0x12;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_entry_pc: u8 = 0x52;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_AT_linkage_name: u8 = 0x6e;

#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_addr: u8 = 0x01;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_block2: u8 = 0x03;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_block4: u8 = 0x04;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_data2: u8 = 0x05;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_data4: u8 = 0x06;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_data8: u8 = 0x07;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_string: u8 = 0x08;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_block: u8 = 0x09;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_block1: u8 = 0x0a;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_data1: u8 = 0x0b;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_flag: u8 = 0x0c;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_sdata: u8 = 0x0d;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_strp: u8 = 0x0e;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_udata: u8 = 0x0f;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref_addr: u8 = 0x10;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref1: u8 = 0x11;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref2: u8 = 0x12;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref4: u8 = 0x13;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref8: u8 = 0x14;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref_udata: u8 = 0x15;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_indirect: u8 = 0x16;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_sec_offset: u8 = 0x17;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_exprloc: u8 = 0x18;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_flag_present: u8 = 0x19;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_strx: u8 = 0x1a;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_addrx: u8 = 0x1b;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref_sup4: u8 = 0x1c;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_strp_sup: u8 = 0x1d;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_data16: u8 = 0x1e;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_line_strp: u8 = 0x1f;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref_sig8: u8 = 0x20;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_implicit_const: u8 = 0x21;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_loclistx: u8 = 0x22;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_rnglistx: u8 = 0x23;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_ref_sup8: u8 = 0x24;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_str1: u8 = 0x25;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_str2: u8 = 0x26;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_str3: u8 = 0x27;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_str4: u8 = 0x28;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_addrx1: u8 = 0x29;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_addrx2: u8 = 0x2a;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_addrx3: u8 = 0x2b;
#[allow(dead_code, non_upper_case_globals)]
pub const DW_FORM_addrx4: u8 = 0x2c;
