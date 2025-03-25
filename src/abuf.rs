use std::alloc::alloc_zeroed;
use std::alloc::dealloc;
use std::alloc::handle_alloc_error;
use std::alloc::Layout;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr;
use std::slice;


#[derive(Debug)]
pub(crate) struct AlignedBuf {
    data: *mut u8,
    layout: Layout,
}

impl AlignedBuf {
    /// Allocate a new buffer with the provided size and alignment.
    pub fn new(size: usize, align: usize) -> Self {
        assert_ne!(size, 0);

        let layout = Layout::from_size_align(size, align).unwrap();
        let data = unsafe { alloc_zeroed(layout) };
        if data.is_null() {
            handle_alloc_error(layout);
        }

        Self { data, layout }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.data, self.layout.size()) }
    }

    #[inline]
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data, self.layout.size()) }
    }
}

impl Deref for AlignedBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_slice_mut()
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let () = unsafe { dealloc(self.data, self.layout) };
        if cfg!(debug_assertions) {
            self.data = ptr::null_mut();
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_tag::tag;


    /// That that we can create an `AlignedBuf`.
    #[tag(miri)]
    #[test]
    fn aligned_box_creation() {
        let size = 512;
        let align = 4096;
        let mut buf = AlignedBuf::new(size, align);
        let ptr = buf.as_slice().as_ptr();
        assert_eq!(ptr as usize % align, 0);

        let () = buf
            .as_slice_mut()
            .copy_from_slice((0..size).map(|_| 42u8).collect::<Vec<u8>>().as_slice());

        assert_eq!(buf[0], 42);
        assert_eq!(buf[size - 1], 42);
    }
}
