//! C API bindings for the library.
//!
//! # Compatibility
//! The library aims to provide forward compatibility with newer versions and
//! backward compatibility with older ones. To make that happen, users should
//! make sure to use the `BLAZE_INPUT` to initialize structured types that are
//! being passed to the library:
//! ```c
#![doc = include_str!("../examples/input-struct-init.c")]
//! ```

#![allow(
    clippy::collapsible_if,
    clippy::field_reassign_with_default,
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::manual_non_exhaustive
)]
#![deny(unsafe_op_in_unsafe_fn)]


macro_rules! input_zeroed {
    ($container_ptr:ident, $container_ty:ty) => {{
        if $container_ptr.is_null() {
            true
        } else {
            let user_size = unsafe { $container_ptr.cast::<usize>().read() };
            if user_size < std::mem::size_of_val(&user_size) {
                false
            } else {
                let type_size = memoffset::offset_of!($container_ty, _last_field);
                unsafe {
                    crate::is_mem_zero(
                        $container_ptr.cast::<u8>().add(type_size),
                        user_size.saturating_sub(type_size),
                    )
                }
            }
        }
    }};
}


#[allow(non_camel_case_types)]
mod inspect;
#[allow(non_camel_case_types)]
mod normalize;
#[allow(non_camel_case_types)]
mod symbolize;

use std::ptr::NonNull;
use std::slice;

pub use inspect::*;
pub use normalize::*;
pub use symbolize::*;


/// Check whether the given piece of memory is zeroed out.
///
/// # Safety
/// The caller needs to make sure that `mem` points to `len` (or more) bytes of
/// valid memory.
pub(crate) unsafe fn is_mem_zero(mut mem: *const u8, mut len: usize) -> bool {
    while len > 0 {
        if unsafe { mem.read() } != 0 {
            return false
        }
        mem = unsafe { mem.add(1) };
        len -= 1;
    }
    true
}


/// "Safely" create a slice from a user provided array.
pub(crate) unsafe fn slice_from_user_array<'t, T>(items: *const T, num_items: usize) -> &'t [T] {
    let items = if items.is_null() {
        // `slice::from_raw_parts` requires a properly aligned non-NULL pointer.
        // Craft one.
        NonNull::dangling().as_ptr()
    } else {
        items
    };
    unsafe { slice::from_raw_parts(items, num_items) }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;


    /// Check that `is_mem_zero` works as it should.
    #[test]
    fn mem_zeroed_checking() {
        let mut bytes = [0u8; 64];
        assert!(
            unsafe { is_mem_zero(bytes.as_slice().as_ptr(), bytes.len()) },
            "{bytes:#x?}"
        );

        bytes[bytes.len() / 2] = 42;
        assert!(
            !unsafe { is_mem_zero(bytes.as_slice().as_ptr(), bytes.len()) },
            "{bytes:#x?}"
        );
    }

    /// Test the `slice_from_user_array` helper in the presence of various
    /// inputs.
    #[test]
    fn slice_creation() {
        let slice = unsafe { slice_from_user_array::<u64>(ptr::null(), 0) };
        assert_eq!(slice, &[]);

        let array = [];
        let slice = unsafe { slice_from_user_array::<u64>(&array as *const _, array.len()) };
        assert_eq!(slice, &[]);

        let array = [42u64, 1337];
        let slice = unsafe { slice_from_user_array::<u64>(&array as *const _, array.len()) };
        assert_eq!(slice, &[42, 1337]);
    }
}
