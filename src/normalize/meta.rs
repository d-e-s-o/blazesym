use std::path::PathBuf;


/// A GNU build ID, as raw bytes.
type BuildId = Vec<u8>;


/// Meta information about an archive (e.g., an APK).
#[derive(Clone, Debug, PartialEq)]
pub struct Archive {
    /// The canonical absolute path to the archive, including its name.
    pub path: PathBuf,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub(crate) _non_exhaustive: (),
}


/// Meta information about a user space binary (executable, shared object,
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
    Archive(Archive),
    Binary(Binary),
    Unknown(Unknown),
}

impl UserAddrMeta {
    /// Retrieve the [`Archive`] of this enum, if this variant is active.
    pub fn archive(&self) -> Option<&Archive> {
        match self {
            Self::Archive(archive) => Some(archive),
            _ => None,
        }
    }

    /// Retrieve the [`Binary`] of this enum, if this variant is active.
    pub fn binary(&self) -> Option<&Binary> {
        match self {
            Self::Binary(binary) => Some(binary),
            _ => None,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Check that we can access individual variants of a
    /// [`UserAddrMeta`] via the accessor functions.
    #[test]
    fn user_addr_meta_accessors() {
        let meta = UserAddrMeta::Archive(Archive {
            path: PathBuf::from("/tmp/archive.apk"),
            _non_exhaustive: (),
        });
        assert!(meta.archive().is_some());
        assert!(meta.binary().is_none());

        let meta = UserAddrMeta::Binary(Binary {
            path: PathBuf::from("/tmp/executable.bin"),
            build_id: None,
            _non_exhaustive: (),
        });
        assert!(meta.archive().is_none());
        assert!(meta.binary().is_some());
    }
}
