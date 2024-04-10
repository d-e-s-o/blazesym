/// XXX
#[derive(Debug)]
pub struct Resolver {
    #[allow(clippy::type_complexity)]
    #[cfg(feature = "apk")]
    apk_cache: FileCache<(zip::Archive, InsertMap<Range<u64>, Rc<ElfResolver>>)>,
    perf_map_cache: FileCache<PerfMap>,
}

impl Resolver {
    /// XXX
    pub fn resolve(&self, input: Input<u64>) -> Result<Rc<Resolver>> {}
}
