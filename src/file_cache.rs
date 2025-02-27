use std::fs::File;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;

use crate::insert_map::InsertMap;
use crate::once::OnceCell;
use crate::util::stat;
use crate::ErrorExt as _;
use crate::Result;


#[derive(Debug, Eq, Hash, PartialEq)]
// `libc` has deprecated `time_t` usage on `musl`. See
// https://github.com/rust-lang/libc/issues/1848
#[cfg_attr(target_env = "musl", allow(deprecated))]
struct FileMeta {
    dev: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    mtime_sec: libc::time_t,
    #[cfg(linux)]
    mtime_nsec: i64,
}

impl From<&libc::stat> for FileMeta {
    fn from(other: &libc::stat) -> Self {
        // Casts are necessary because on Android some libc types do not
        // use proper typedefs. https://github.com/rust-lang/libc/issues/3285
        Self {
            dev: other.st_dev as _,
            inode: other.st_ino as _,
            size: other.st_size as _,
            mtime_sec: other.st_mtime,
            #[cfg(linux)]
            mtime_nsec: other.st_mtime_nsec as _,
        }
    }
}


pub(crate) trait PathLike
where
    Self: Eq + Hash + PartialEq,
{
    fn path(&self) -> &Path;
}


impl PathLike for PathBuf {
    fn path(&self) -> &Path {
        self.deref()
    }
}


#[derive(Debug, Eq, Hash, PartialEq)]
struct EntryMeta<P> {
    path: P,
    meta: Option<FileMeta>,
}

impl<P> EntryMeta<P> {
    /// Create a new [`EntryMeta`] object. If `stat` is [`None`] file
    /// modification times and other meta data are effectively ignored.
    fn new(path: P, stat: Option<&libc::stat>) -> Self {
        Self {
            path,
            meta: stat.map(FileMeta::from),
        }
    }
}


#[derive(Debug)]
struct Entry<T> {
    file: File,
    value: OnceCell<T>,
}

impl<T> Entry<T> {
    fn new(file: File) -> Self {
        Self {
            file,
            value: OnceCell::new(),
        }
    }
}


/// A builder for configurable construction of [`FileCache`] objects.
///
/// By default all features are enabled.
#[derive(Clone, Debug)]
pub(crate) struct Builder<T, P> {
    /// Whether to attempt to gather source code location information.
    ///
    /// This setting implies usage of debug symbols and forces the corresponding
    /// flag to `true`.
    auto_reload: bool,
    /// Phantom data for our otherwise "unused" generic argument.
    _phantom: PhantomData<(T, P)>,
}

impl<T, P> Builder<T, P> {
    /// Enable/disable auto reloading of files when stale.
    pub(crate) fn enable_auto_reload(mut self, enable: bool) -> Self {
        self.auto_reload = enable;
        self
    }

    /// Create the [`FileCache`] object.
    pub(crate) fn build(self) -> FileCache<T, P> {
        let Builder {
            auto_reload,
            _phantom: _,
        } = self;

        FileCache {
            cache: InsertMap::new(),
            auto_reload,
        }
    }
}

impl<T, P> Default for Builder<T, P> {
    fn default() -> Self {
        Self {
            auto_reload: true,
            _phantom: PhantomData,
        }
    }
}


/// A lookup cache for data associated with a file, looked up by path.
///
/// The cache transparently checks whether the file contents have
/// changed based on file system meta data and creates and hands out a
/// new entry if so.
/// Note that stale/old entries are never evicted.
#[derive(Debug)]
pub(crate) struct FileCache<T, P = PathBuf> {
    /// The map we use for associating file meta data with user-defined
    /// data.
    cache: InsertMap<EntryMeta<P>, Entry<T>>,
    /// Whether or not to automatically reload files that were updated
    /// since the last open.
    auto_reload: bool,
}

impl<T, P> FileCache<T, P> {
    /// Retrieve a [`Builder`] object for configurable construction of a
    /// [`FileCache`].
    pub(crate) fn builder() -> Builder<T, P> {
        Builder::default()
    }

    /// Retrieve an entry for the file at the given `path`.
    pub(crate) fn entry(&self, path: P) -> Result<(&File, &OnceCell<T>)>
    where
        P: PathLike,
    {
        let fs_path = path.path().to_path_buf();
        let stat = if self.auto_reload {
            let stat = stat(&fs_path)
                .with_context(|| format!("failed to stat `{}`", fs_path.display()))?;
            Some(stat)
        } else {
            None
        };

        let meta = EntryMeta::new(path, stat.as_ref());
        let entry = self.cache.get_or_try_insert(meta, || {
            // We may end up associating this file with a potentially
            // outdated `stat` (which could have changed), but the only
            // consequence is that we'd create a new entry again in the
            // future. On the bright side, we save one `stat` call.
            let file = File::open(&fs_path)
                .with_context(|| format!("failed to open file `{}`", fs_path.display()))?;
            let entry = Entry::new(file);
            Ok(entry)
        })?;

        Ok((&entry.file, &entry.value))
    }
}

impl<T, P> Default for FileCache<T, P> {
    fn default() -> Self {
        Self::builder().build()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read as _;
    use std::io::Write as _;
    use std::thread::sleep;
    use std::time::Duration;

    use tempfile::tempdir;
    use tempfile::tempfile;
    use tempfile::NamedTempFile;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let cache = FileCache::<()>::default();
        assert_ne!(format!("{cache:?}"), "");

        let tmpfile = tempfile().unwrap();
        let entry = Entry::<usize>::new(tmpfile);
        assert_ne!(format!("{entry:?}"), "");
    }

    /// Check that we can associate data with a file.
    #[test]
    fn lookup() {
        let cache = FileCache::<usize>::default();
        let tmpfile = NamedTempFile::new().unwrap();

        {
            let (_file, cell) = cache.entry(tmpfile.path().to_path_buf()).unwrap();
            assert_eq!(cell.get(), None);

            let () = cell.set(42).unwrap();
        }

        {
            let (_file, cell) = cache.entry(tmpfile.path().to_path_buf()).unwrap();
            assert_eq!(cell.get(), Some(&42));
        }
    }

    /// Check that our `FileCache` does not represent symbolic links
    /// pointing to the same file as equal entries.
    #[cfg(linux)]
    #[test]
    fn file_symlinks() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::symlink;

        let tmpfile = NamedTempFile::new().unwrap();
        let tmpdir = tempdir().unwrap();
        let link = tmpdir.path().join("symlink");
        let () = symlink(tmpfile.path(), &link).unwrap();

        let cache = FileCache::<usize>::default();
        let (file1, cell) = cache.entry(tmpfile.path().to_path_buf()).unwrap();
        let () = cell.set(42).unwrap();

        let (file2, cell) = cache.entry(link).unwrap();
        assert_eq!(cell.get(), None);

        assert_ne!(file1.as_raw_fd(), file2.as_raw_fd());
    }

    /// Make sure that a changed file purges the cache entry .
    #[test]
    fn outdated() {
        fn test(auto_reload: bool) {
            let cache = FileCache::<usize>::builder()
                .enable_auto_reload(auto_reload)
                .build();
            let tmpfile = NamedTempFile::new().unwrap();
            let modified = {
                let (file, cell) = cache.entry(tmpfile.path().to_path_buf()).unwrap();
                assert_eq!(cell.get(), None);

                let () = cell.set(42).unwrap();
                file.metadata().unwrap().modified().unwrap()
            };

            // Sleep briefly to make sure that file times will end up being
            // different.
            let () = sleep(Duration::from_millis(10));

            let path = tmpfile.path().to_path_buf();
            let () = drop(tmpfile);

            {
                let mut _file = File::create(&path).unwrap();
                let () = _file.write_all(b"foobar").unwrap();
            }

            {
                let (mut file, entry) = cache.entry(path).unwrap();

                if auto_reload {
                    assert_eq!(entry.get(), None);
                    assert_ne!(file.metadata().unwrap().modified().unwrap(), modified);

                    let mut content = Vec::new();
                    let _count = file.read_to_end(&mut content);
                    assert_eq!(content, b"foobar");
                } else {
                    assert_eq!(entry.get(), Some(&42));
                    assert_eq!(file.metadata().unwrap().modified().unwrap(), modified);
                }
            }
        }

        for auto_reload in [false, true] {
            let () = test(auto_reload);
        }
    }
}
