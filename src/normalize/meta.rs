use std::path::PathBuf;


/// A GNU build ID.
type BuildId = String;


/// Meta information about a user space binary (executable, shared object, APK,
/// ...).
#[derive(Clone, Debug, PartialEq)]
pub struct Binary {
    /// The canonical absolute path to the binary, including its name.
    pub path: PathBuf,
    /// The binary's build ID, if available.
    pub build_id: Option<BuildId>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}


/// Meta information about an address that could not be determined to be
/// belonging to a specific component. Such an address will be reported
/// in non-normalized form (as provided by the user).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Unknown {
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}

impl From<Unknown> for UserAddrMeta {
    fn from(unknown: Unknown) -> Self {
        Self::Unknown(unknown)
    }
}


/// Meta information for an address.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum UserAddrMeta {
    Binary(Binary),
    Unknown(Unknown),
}
