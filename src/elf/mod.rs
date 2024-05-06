mod debug_link;
mod parser;
#[cfg_attr(not(feature = "dwarf"), allow(unused_variables))]
mod resolver;
#[allow(dead_code, non_camel_case_types)]
pub(crate) mod types;

pub(crate) use parser::ElfParser;
pub(crate) use resolver::ElfResolverData;

pub use resolver::ElfResolver;
