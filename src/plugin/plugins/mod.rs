//! Code for all the plugins supported

#[cfg(feature = "syscalls")]
pub mod dlopen;

#[cfg(feature = "syscalls")]
pub mod files;

#[cfg(feature = "syscalls")]
pub mod mmap;

#[cfg(feature = "syscalls")]
pub mod prctl;

#[cfg(feature = "syscalls")]
pub mod reads;

#[cfg(feature = "syscalls")]
pub(crate) use dlopen::DlopenDetect;

#[cfg(feature = "syscalls")]
pub(crate) use files::Files;

#[cfg(feature = "syscalls")]
pub(crate) use mmap::Mmap;

#[cfg(feature = "syscalls")]
pub(crate) use prctl::Prctl;
