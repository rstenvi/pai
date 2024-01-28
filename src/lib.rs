//! # Process Analyzer and Instrumenter
//!
//! ## Examples
//! 
//! **minimal.rs**
//! 
//! Below is a minimal example spawning a program and tracing it. Since no
//! handlers are registered, it doesn't do anything useful. 
//! This is the example [minimal.rs](https://github.com/rstenvi/pai/examples/minimal.rs)
//! 
//! ```rust
#![doc = include_str!("../examples/minimal.rs")]
//! ```
//! 
//! **strace.rs**
//! 
//! A slightly more complicated example is the strace-like program below.
//! This is the example [strace.rs](https://github.com/rstenvi/pai/examples/strace.rs)
//! 
//! ```rust
#![doc = include_str!("../examples/strace.rs")]
//! ```
//! 
//! **state.r**
//! 
//! The second argument passed in [ctx::Main::spawn] is a state which
//! the caller can access on each callback. The following example is very
//! similar to the previous one, but it counts the number of system calls
//! instead.
//! 
//! This is the example [state.rs](https://github.com/rstenvi/pai/examples/state.rs)
//! 
//! ```rust
#![doc = include_str!("../examples/state.rs")]
//! ```
//! 
//! **breakpoint.rs**
//! 
//! This shows an example of inserting a breakpoint.
//! 
//! This is the example [state.rs](https://github.com/rstenvi/pai/examples/breakpoint.rs)
//! 
//! ```rust
#![doc = include_str!("../examples/breakpoint.rs")]
//! ```


#![feature(extract_if)]
#![feature(hash_extract_if)]
#![allow(clippy::result_large_err)]
#![allow(clippy::redundant_closure)]
// TODO: Remove before prod
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(clippy::useless_conversion)]
// Necessary for benchmarking
#![feature(test)]

extern crate test;

pub mod api;
pub mod arch;
pub mod buildinfo;
pub mod ctx;
pub mod plugin;
pub mod syscalls;
pub mod utils;

pub(crate) mod ctrl;
pub mod exe;
pub(crate) mod trace;

#[cfg(target_pointer_width = "64")]
pub type TargetPtr = u64;

#[cfg(target_pointer_width = "32")]
pub type TargetPtr = u32;

/// The main Result-type used is most functions
pub type Result<T> = std::result::Result<T, crate::Error>;

/// Result returned externally
pub type RemoteResult<T> = std::result::Result<T, crate::RemoteError>;

/// Used where we expect errors to occur and the caller to handle them in a
/// reasonable manner.
///
/// It should also be fairly easy to deduce where the error originated from
/// because it happened in a specific call.
pub(crate) type UntrackedResult<T> = std::result::Result<T, crate::Error>;

#[cfg(target_arch = "x86_64")]
pub type Registers = crate::arch::x86_64::user_regs_struct;

#[cfg(target_arch = "x86")]
pub type Registers = crate::arch::x86::user_regs_struct;

#[cfg(target_arch = "aarch64")]
pub type Registers = crate::arch::aarch64::user_regs_struct;

/// Non-fatal error occured during operation.
///
/// [enum@Error] is not safe to send across threads, so [enum@Error] is serialized into
/// [RemoteError] and sent across threads. This is used when the client sent a
/// command which resulted in an error. When this is returned, the bug is likely
/// not in this crate, but rather in the crate-importer.
#[derive(thiserror::Error, Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteError {
	msg: String,
}
impl RemoteError {
	pub fn new<S: Into<String>>(msg: S) -> Self {
		Self { msg: msg.into() }
	}
}
impl std::fmt::Display for RemoteError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.msg.as_str())
	}
}

impl From<Error> for RemoteError {
	fn from(value: Error) -> Self {
		let msg = format!("{value:?}");
		Self::new(msg)
	}
}
impl From<RemoteError> for Error {
	fn from(value: RemoteError) -> Self {
		let msg = format!("{value:?}");
		Self::Msg { msg }
	}
}
impl From<serde_json::Error> for RemoteError {
	fn from(value: serde_json::Error) -> Self {
		let msg = format!("{value:?}");
		Self::new(msg)
	}
}

/// All the different error-values the crate can generate
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub enum Error {
	#[error("Msg: {msg}")]
	Msg { msg: String },

	#[error("failed to recv data")]
	CrossbeamRecv(#[from] crossbeam_channel::RecvError),

	#[error("target stopped")]
	TargetStopped,

	#[error("TryFromIntError")]
	FromInt(#[from] std::num::TryFromIntError),

	#[error("ParseIntError")]
	ParseInt(#[from] std::num::ParseIntError),

	#[error("procfs error")]
	Procfs(#[from] procfs::ProcError),

	#[error("pete error")]
	Pete(#[from] pete::Error),

	#[error("crossbeam error Response")]
	SendResponse(#[from] crossbeam_channel::SendError<crate::api::messages::Response>),

	#[error("crossbeam error RemoteCmd")]
	SendRemoteCmd(#[from] crossbeam_channel::SendError<crate::api::messages::RemoteCmd>),

	#[error("crossbeam error Command")]
	SendCommand(#[from] crossbeam_channel::SendError<crate::api::messages::Command>),

	#[error("crossbeam error MasterComm")]
	SendMasterComm(#[from] crossbeam_channel::SendError<crate::api::messages::MasterComm>),

	#[error("crossbeam error NewClientReq")]
	SendNewClientReq(#[from] crossbeam_channel::SendError<crate::api::messages::NewClientReq>),

	#[error("serde json")]
	SerdeJson(#[from] serde_json::Error),

	#[error("parse error")]
	ParseError(#[from] elf::ParseError),

	#[error("IO")]
	Io(#[from] std::io::Error),

	#[error("Utf8Error")]
	Utf8Error(#[from] std::str::Utf8Error),

	#[error("Syzlang")]
	Syzlang(#[from] syzlang_parser::Error),

	#[error("unknown error")]
	Unknown,

	#[error("Infallible")]
	Infallible(#[from] std::convert::Infallible),

	#[error("errno")]
	Errno(#[from] nix::errno::Errno),

	#[error("not found")]
	NotFound,

	#[error("Tid '{tid}' not found")]
	TidNotFound { tid: crate::utils::process::Tid },
}
impl Error {
	pub fn msg<S: Into<String>>(s: S) -> Self {
		let msg: String = s.into();
		log::error!("generated error: '{msg}'");
		Self::Msg { msg }
	}
}

macro_rules! gbugreport {
	() => {
		bugreport::bugreport!()
			.info(bugreport::collector::SoftwareVersion::default())
			.info(bugreport::collector::CommandLine::default())
			.info(bugreport::collector::CompileTimeInformation::default())
			.print::<bugreport::format::Markdown>();
	};
}
use std::io::Read;

pub(crate) use gbugreport;

macro_rules! bug {
	($fmt:literal, $($fmta: tt)*) => {
		{
			log::error!("encountered a bug, please file a bug report with the following information");
			crate::gbugreport!();
			panic!($fmt, $($fmta)*);
		}
	};
	($fmt:literal) => {
		{
			log::error!("encountered a bug, please file a bug report with the following information");
			crate::gbugreport!();
			panic!($fmt);
		}
	};
}
pub(crate) use bug;

macro_rules! bug_assert {
	($expr:expr) => {{
		if (!($expr)) {
			crate::bug!("")
		}
	}};
}
pub(crate) use bug_assert;

pub(crate) fn syzarch() -> syzlang_parser::parser::Arch {
	#[cfg(target_arch = "x86_64")]
	{
		syzlang_parser::parser::Arch::X86_64
	}
	#[cfg(target_arch = "x86")]
	{
		syzlang_parser::parser::Arch::X86
	}

	#[cfg(target_arch = "aarch64")]
	{
		syzlang_parser::parser::Arch::Aarch64
	}
}

lazy_static::lazy_static! {
	#[derive(Default)]
	static ref BUILD_INFO: std::sync::RwLock<buildinfo::BuildInfo> = {
		// This is slower than unencoded, but saves ~6MB in final ELF file
		let raw = include_bytes!(concat!(env!("OUT_DIR"), "/build_info.json"));
		let str = std::str::from_utf8(raw).expect("build_info.json not valid utf-8");
		let info: buildinfo::BuildInfo = serde_json::from_str(str)
			.expect("unable to parse json from build.rs as variable");
		std::sync::RwLock::new(info)
	};
}

lazy_static::lazy_static! {
	#[derive(Default)]
	static ref PARSED: std::sync::RwLock<syzlang_parser::parser::Parsed> = {
		// This is slower than unencoded, but saves ~6MB in final ELF file
		let raw = include_bytes!(concat!(env!("OUT_DIR"), "/syscalls.json.gz"));
		let mut gz = flate2::bufread::GzDecoder::new(&raw[..]);
		let mut s = String::new();
		gz.read_to_string(&mut s).expect("unable to decompress gz from build.rs");
		let parsed: syzlang_parser::parser::Parsed = serde_json::from_str(&s)
			.expect("unable to parse compressed json from build.rs as variable");
		std::sync::RwLock::new(parsed)
	};
}

lazy_static::lazy_static! {
	pub(crate) static ref SYSCALLS: std::sync::RwLock<syscalls::Syscalls> = {
		if let Ok(parsed) = PARSED.read() {
			let syscalls: syscalls::Syscalls = parsed.clone().try_into()
				.expect("unable to convert from parsed syscalls to our Syscalls");
			std::sync::RwLock::new(syscalls)
		} else {
			crate::bug!("unable to get lock for PARSED???");
		}
	};
}

#[cfg(test)]
lazy_static::lazy_static! {
	#[derive(Default)]
	static ref TESTDATA: std::sync::RwLock<Vec<u8>> = {
		let raw = include_bytes!(concat!(env!("OUT_DIR"), "/testdata.tar.gz"));
		std::sync::RwLock::new(raw.to_vec())
	};
}

#[cfg(test)]
#[ctor::dtor]
fn global_test_destructor() {
	log::debug!("destructor");
	if let Some(p) = tests::testdata_unpack() {
		log::info!("removing {p:?}");
		assert!(!p.ends_with("testdata"));
		std::fs::remove_dir_all(p).unwrap();
	}
}

#[cfg(test)]
#[ctor::ctor]
fn global_test_setup() {
	env_logger::builder().format_timestamp_millis().init();
	log::debug!("constructor");

	if let Some(to) = tests::testdata_unpack() {
		log::debug!("unpacking to {to:?}");
		let testdata = TESTDATA.read().expect("").clone();
		let dec = flate2::bufread::GzDecoder::new(testdata.as_slice());
		let mut tar = tar::Archive::new(dec);
		tar.unpack(to).unwrap();
	} else {
		log::info!("develop = test machine, so not unpacking testdata/");
	}
}

#[cfg(test)]
pub mod tests {
	use std::path::PathBuf;

	use super::*;

	pub fn develop_equal_test() -> bool {
		testdata_unpack().is_none()
	}
	pub fn testdata_unpack() -> Option<PathBuf> {
		#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
		{
			None
		}
		#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
		{
			#[cfg(target_os = "android")]
			{
				Some(PathBuf::from("/data/local/tmp/gratisida/"))
			}
			#[cfg(target_os = "linux")]
			{
				Some(PathBuf::from("/tmp/gratisida/"))
			}
		}
	}
	pub fn testdata_dir() -> PathBuf {
		if let Some(mut p) = testdata_unpack() {
			p.push("testdata");
			p
		} else {
			let testdata = env!("CARGO_MANIFEST_DIR");
			let mut testdata = PathBuf::from(testdata);
			testdata.push("testdata");
			testdata
		}
	}
}
