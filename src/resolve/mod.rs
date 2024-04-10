//! Functionality for XXX
//!
//! This module contains functionality for ... XXX

mod resolver;
mod source;

cfg_apk! {
  pub use source::Apk;
}
pub use source::Kernel;
pub use source::Process;
pub use source::Source;
