cfg_apk! {
/// A single APK file.
///
/// This type is used in the [`Source::Apk`] variant.
#[derive(Clone)]
pub struct Apk {
    /// The path to an APK file.
    pub path: PathBuf,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    ///
    /// On top of this runtime configuration, the crate needs to be
    /// built with the `dwarf` feature to actually consult debug
    /// symbols. If neither is satisfied, ELF symbols will be used.
    pub debug_syms: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Apk {
    /// Create a new [`Apk`] object, referencing the provided path.
    ///
    /// `debug_syms` defaults to `true` when using this constructor.
    #[inline]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            debug_syms: true,
            _non_exhaustive: (),
        }
    }
}

impl From<Apk> for Source<'static> {
    #[inline]
    fn from(apk: Apk) -> Self {
        Source::Apk(apk)
    }
}

impl Debug for Apk {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            path,
            debug_syms: _,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Apk)).field(path).finish()
    }
}
}


/// Configuration for process based address symbolization.
///
/// This type is used in the [`Source::Process`] variant.
///
/// The corresponding addresses supplied to [`Symbolizer::symbolize`] are
/// expected to be absolute addresses
/// ([`Input::AbsAddr`][crate::symbolize::Input::AbsAddr]) as valid within the
/// process identified by the [`pid`][Process::pid] member.
#[derive(Clone)]
pub struct Process {
    /// The referenced process' ID.
    pub pid: Pid,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    ///
    /// On top of this runtime configuration, the crate needs to be
    /// built with the `dwarf` feature to actually consult debug
    /// symbols. If neither is satisfied, ELF symbols will be used.
    pub debug_syms: bool,
    /// Whether to incorporate a process' [perf map][] file into the
    /// symbolization procedure.
    ///
    /// Perf map files mostly have relevance in just-in-time compiled languages,
    /// where they provide an interface for the runtime to expose addresses of
    /// dynamic symbols to profiling tools.
    ///
    /// [perf map]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jit-interface.txt
    pub perf_map: bool,
    /// Whether to work with `/proc/<pid>/map_files/` entries or with
    /// symbolic paths mentioned in `/proc/<pid>/maps` instead.
    /// `map_files` usage is generally strongly encouraged, as symbolic
    /// path usage is unlikely to work reliably in mount namespace
    /// contexts or when files have been deleted from the file system.
    /// However, by using symbolic paths the need for requiring the
    /// `SYS_ADMIN` capability is eliminated.
    pub map_files: bool,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl Process {
    /// Create a new [`Process`] object using the provided `pid`.
    ///
    /// `debug_syms` and `perf_map` default to `true` when using this
    /// constructor.
    #[inline]
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            debug_syms: true,
            perf_map: true,
            map_files: true,
            _non_exhaustive: (),
        }
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            pid,
            debug_syms: _,
            perf_map: _,
            map_files: _,
            _non_exhaustive: (),
        } = self;

        f.debug_tuple(stringify!(Process))
            // We use the `Display` representation here.
            .field(&format_args!("{pid}"))
            .finish()
    }
}

impl From<Process> for Source<'static> {
    #[inline]
    fn from(process: Process) -> Self {
        Source::Process(process)
    }
}


/// XXX
///
/// Objects of this type are used first and foremost with the
/// [`Resolver::resolve`] method.
#[derive(Clone)]
#[non_exhaustive]
pub enum Source {
    /// A single APK file.
    #[cfg(feature = "apk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "apk")))]
    Apk(Apk),
    /// Information about the Linux kernel.
    Kernel(Kernel),
    /// Information about a process.
    Process(Process),
}

impl Debug for Source<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            #[cfg(feature = "apk")]
            Self::Apk(apk) => Debug::fmt(apk, f),
            Self::Kernel(kernel) => Debug::fmt(kernel, f),
            Self::Process(process) => Debug::fmt(process, f),
        }
    }
}
