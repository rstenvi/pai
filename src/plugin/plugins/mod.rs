//! Code for all the plugins supported

pub mod dlopen;
pub mod files;
pub mod mmap;
pub mod prctl;
pub mod reads;

pub(crate) use dlopen::DlopenDetect;
pub(crate) use files::Files;
pub(crate) use mmap::Mmap;
pub(crate) use prctl::Prctl;
