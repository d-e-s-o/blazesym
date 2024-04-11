use std::fmt::Debug;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::SrcLang;
use crate::symbolize::Sym;
use crate::Addr;
use crate::Result;


/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e.g., a symbol file.
pub(crate) trait SymResolver
where
    Self: Debug,
{
    /// Find the symbol corresponding to the given address.
    fn find_sym(
        &self,
        addr: Addr,
        opts: &FindSymOpts,
    ) -> Result<Result<(Sym<'_>, SrcLang), Reason>>;

    /// Find information about a symbol given its name.
    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'_>>>;
}
