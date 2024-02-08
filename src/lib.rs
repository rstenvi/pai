//! # Process Analyzer and Instrumenter
//! 
//! ## Benchmarking and speed
//! 
//! Speed is not the main goal in the development of this crate, it is however
//! still recognized as an important attribute of tracing. There are some key
//! benchmark tests to evaluate speed over time:
//!
//! - `bench_baseline_true`
//!   - Execute the `true` to get a baseline for how long it takes to execute 
//! - `bench_trace_inner` / `bench_trace_outer`
//!   - Execute program under tracing, but don't do anything
//!   - Tracing directly at the ptrace-level and at the Context level
//!   - This is used to measure the overhead of tracing and Context-level code
//! - `bench_baseline_strace`
//!   - Execute command under `strace`
//!   - Gives us something to compare against
//! - `bench_trace_strace_raw` / `bench_trace_strace_basic` /
//!   `bench_trace_strace_full`
//!   - Trace syscalls with various levels of details read about each call
//!   - If you run these tests, you will likely see a spike in time for
//!     `bench_trace_strace_full`
//!     - If you're tracing something time-critical, this is something to be
//!       aware of. 
//!
//! ## Architecture
//!
//! The crate is logically separated into 4 different components:
//!
//! 1. `trace` - currently only `ptrace` in supported
//! 2. `ctrl` - controls the tracer
//! 3. Script - program which decides on tracing actions is called client
//! 4. [ctx] - each client holds a context object to manage the tracee
//!
//! ### Tracer
//!
//! This is fairly simple and has various low-level operations to read/write
//! memory, get registers, etc.
//!
//! ### Control
//!
//! - One control `tracer` which must run on the same thread as the tracer (this
//!   is a requirement in `ptrace`).
//! - One control `thread` which is started for each script connected. Since we
//!   can only have one `main` thread, we offload some work to control `thread`.
//!
//! ### Script
//!
//! There is generally one main script which is written by the analyst. This is
//! typically written specifically for a single target to accomplish a specific
//! purpose. When there are other scripts attached, they are generally referred
//! to as plugins.
//!
//! There are for instance a plugin to detect when `dlopen()` is called. This is
//! a generic script which could be used in several analysis scenarios.
//!
//! ### Context
//!
//! This is the interface a script has to control the tracee. It has three
//! layers:
//!
//! 1. **main** - the first context created, there will only be one of these
//!    created during the session.
//! 2. **secondary** - each connected script get their own `secondary` context.
//! 3. **client** - access to send messages to threads controlling the tracee.
//!
//! ## Design of scripts
//!
//! The scripts are generally designed to be event-driven. So you register the
//! different events you are interested and provide callbacks for those events.
//! The callback can then also register new events to monitor. This can be a bit
//! cumbersome in the beginning, so there is also a mechanism to run until some
//! event has happened and continue with the script as usual from there on. See
//! the example scripts for more details.
//!
//! ## Features
//!
//! - Syscall tracing
//!   - Get details about each syscall argument, include `syscalls` feature
//! - Manage breakpoints
//! - Single stepping
//! - Call function / system call
//! - Resolve symbols in ELF-files
//! - Read/write memory to process
//! - Allocate memory in process
//! - Multiple clients can trace a process, unaware of eachother
//!
//! ## Examples
//!
//! **minimal.rs**
//!
//! Below is a minimal example spawning a program and tracing it. Since no
//! handlers are registered, it doesn't do anything useful.
//!
//! This is the example
//! [minimal.rs](https://github.com/rstenvi/pai/tree/main/examples/minimal.rs)
//!
//! ```rust
#![doc = include_str!("../examples/minimal.rs")]
//! ```
//!
//! **strace.rs**
//!
//! A slightly more complicated example is the strace-like program below.
//!
//! This is the example [strace.rs](https://github.com/rstenvi/pai/tree/main/examples/strace.rs)
//!
//! ```rust
#![doc = include_str!("../examples/strace.rs")]
//! ```
//!
//! **state.rs**
//!
//! The second argument passed in [ctx::Main::new_spawn] is a state which
//! the caller can access on each callback. The following example is very
//! similar to the previous one, but it counts the number of system calls
//! instead.
//!
//! This is the example [state.rs](https://github.com/rstenvi/pai/tree/main/examples/state.rs)
//!
//! ```rust
#![doc = include_str!("../examples/state.rs")]
//! ```
//!
//! **breakpoint.rs**
//!
//! This shows an example of inserting a breakpoint.
//!
//! This is the example [breakpoint.rs](https://github.com/rstenvi/pai/tree/main/examples/breakpoint.rs)
//!
//! ```rust
#![doc = include_str!("../examples/breakpoint.rs")]
//! ```
//! **breakpoint-noevent.rs**
//!
//! This shows an example of inserting breakpoint without using the event-driven method.
//!
//! This is the example [breakpoint-noevent.rs](https://github.com/rstenvi/pai/tree/main/examples/breakpoint-noevent.rs)
//!
//! ```rust
#![doc = include_str!("../examples/breakpoint-noevent.rs")]
//! ```

#![feature(extract_if)]
#![feature(hash_extract_if)]
// #![allow(clippy::result_large_err)]
// #![allow(clippy::redundant_closure)]
#![allow(clippy::unnecessary_cast)]
// TODO: Remove before prod
#![allow(dead_code)]
#![allow(unused_imports)]
// #![allow(unused_macros)]

// Necessary for benchmarking
#![feature(test)]

extern crate test;

pub mod api;
pub mod arch;
pub mod ctx;
pub mod utils;

pub(crate) mod buildinfo;
pub(crate) mod ctrl;
pub(crate) mod exe;
pub(crate) mod trace;

#[cfg(feature = "plugins")]
pub mod plugin;

#[cfg(feature = "syscalls")]
pub mod syscalls;

#[cfg(feature = "syscalls")]
use std::io::Read;

// #[cfg(target_pointer_width = "64")]
// pub type TargetPtr = u64;

// #[cfg(target_pointer_width = "32")]
// pub type TargetPtr = u32;

#[derive(Copy, Clone, Default, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetPtr {
	raw: usize,
}
impl TargetPtr {
	fn twos_complement(&self, bits: usize) -> isize {
		let mask = ((1_usize<<bits)-1) as usize;
		let num = self.raw & mask;
		let and = 1 << (bits - 1);
		// #[cfg(target_pointer_width = "32")]
		// let and = 1 << 31;
		// #[cfg(target_pointer_width = "64")]
		// let and = 1 << 63;
	
		// let num: usize = self.raw.into();
		if num & and != 0 {
			if num == isize::MIN as usize {
				isize::MIN
			} else {
				let twos = -(num as isize) as usize;
				let twos = twos as isize;
				-twos
			}
		} else {
			num as isize
		}
	}
}

macro_rules! conv_target_int {
	($int:ty) => {
		impl From<$int> for TargetPtr {
			fn from(value: $int) -> Self {
				Self { raw: value as usize }
			}
		}
		impl From<TargetPtr> for $int {
			fn from(value: TargetPtr) -> Self {
				value.raw as $int
			}
		}
		
	};
}
// impl From<*mut libc::c_void> for TargetPtr {
//     fn from(value: *mut libc::c_void) -> Self {
//         Self { raw: value as usize }
//     }
// }

conv_target_int! { usize }
conv_target_int! { isize }
conv_target_int! { i32 }
conv_target_int! { u64 }
conv_target_int! { i64 }
conv_target_int! { u32 }
conv_target_int! { u8 }
conv_target_int! { u16 }
conv_target_int! { i16 }
conv_target_int! { *const libc::c_void }


// conv_target_int! { libc::c_long }
// conv_target_int! { libc::c_int }

impl From<TargetPtr> for serde_json::value::Number {
    fn from(value: TargetPtr) -> Self {
        serde_json::value::Number::from(value.raw)
    }
}
impl std::ops::BitAnd for TargetPtr {
    type Output = TargetPtr;

    fn bitand(self, rhs: Self) -> Self::Output {
        let raw = self.raw & rhs.raw;
		Self { raw }
    }
}
impl std::ops::Sub for TargetPtr {
    type Output = TargetPtr;

    fn sub(self, rhs: Self) -> Self::Output {
        let raw = self.raw - rhs.raw;
		Self { raw }
    }
}
impl std::ops::Add for TargetPtr {
    type Output = TargetPtr;

    fn add(self, rhs: Self) -> Self::Output {
        let raw = self.raw + rhs.raw;
		Self { raw }
    }
}
impl std::ops::AddAssign for TargetPtr {
    fn add_assign(&mut self, rhs: Self) {
        self.raw += rhs.raw;
    }
}
impl std::ops::MulAssign for TargetPtr {
    fn mul_assign(&mut self, rhs: Self) {
        self.raw *= rhs.raw;
    }
}

impl std::fmt::LowerHex for TargetPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:x}", self.raw))
    }
}
impl std::fmt::Display for TargetPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.raw))
    }
}

/// The main Result-type used is most functions
pub type Result<T> = std::result::Result<T, crate::Error>;

#[cfg(target_arch = "x86_64")]
/// x86_64 registers the same way they are defined in C
pub type Registers = crate::arch::x86_64::user_regs_struct;

#[cfg(target_arch = "x86")]
/// x86 registers the same way they are defined in C
pub type Registers = crate::arch::x86::user_regs_struct;

#[cfg(target_arch = "aarch64")]
/// Aarch64 registers the same way they are defined in C
pub type Registers = crate::arch::aarch64::user_regs_struct;

#[cfg(target_arch = "arm")]
/// Aarch32 registers the same way they are defined in C
pub type Registers = crate::arch::aarch32::user_regs_struct;

/// [api::Client] interface for all non-internal clients.
pub type Client = crate::api::Client<api::Command, api::Response>;

macro_rules! error_from_crate {
	($err:ty) => {
		impl From<$err> for Error {
			fn from(value: $err) -> Self {
				let name = stringify!($err);
				let msg = format!("{value:?}");
				log::debug!("generated error {msg}");
				Self::OtherCrate {
					name: name.into(),
					msg,
				}
			}
		}
	};
}

error_from_crate! { crossbeam_channel::RecvError }
error_from_crate! { std::num::TryFromIntError }
error_from_crate! { std::num::ParseIntError }
error_from_crate! { procfs::ProcError }
error_from_crate! { pete::Error }
error_from_crate! { crossbeam_channel::SendError<crate::api::messages::Response> }
error_from_crate! { crossbeam_channel::SendError<crate::api::messages::RemoteCmd> }
error_from_crate! { crossbeam_channel::SendError<crate::api::messages::Command> }
error_from_crate! { crossbeam_channel::SendError<crate::api::messages::MasterComm> }
error_from_crate! { crossbeam_channel::SendError<crate::api::messages::NewClientReq> }
error_from_crate! { serde_json::Error }
error_from_crate! { elf::ParseError }
error_from_crate! { std::io::Error }
error_from_crate! { std::str::Utf8Error }
error_from_crate! { syzlang_parser::Error }
error_from_crate! { std::convert::Infallible }
error_from_crate! { nix::errno::Errno }
error_from_crate! { anyhow::Error }

/// All the different error-values the crate can generate
#[derive(thiserror::Error, Debug, serde::Serialize, serde::Deserialize)]
#[error(transparent)]
pub enum Error {
	#[error("Msg: {msg}")]
	Msg { msg: String },

	#[error("OtherCrate: {name} | {msg}")]
	OtherCrate { name: String, msg: String },

	#[error("target stopped")]
	TargetStopped,

	#[error("unknown error")]
	Unknown,

	#[error("Unsupported")]
	Unsupported,

	#[error("not found")]
	NotFound,

	#[error("Too many attempts")]
	TooManyAttempts,

	#[error("Tid '{tid}' not found")]
	TidNotFound { tid: crate::utils::process::Tid },

	#[error("Client '{id}' not found")]
	ClientNotFound { id: usize },

	#[error("Scratch addr not found {addr:x}")]
	ScratchAddrNotFound { addr: TargetPtr },
}
impl Error {
	pub fn msg<S: Into<String>>(s: S) -> Self {
		let msg: String = s.into();
		Self::Msg { msg }
	}
	pub fn scratch_addr_not_found(addr: TargetPtr) -> Self {
		Self::ScratchAddrNotFound { addr }
	}
	pub fn client_not_found(id: usize) -> Self {
		Self::ClientNotFound { id }
	}
	pub fn tid_not_found(tid: crate::utils::process::Tid) -> Self {
		Self::TidNotFound { tid }
	}
	pub fn unsupported() -> Self {
		Self::Unsupported
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

#[cfg(feature = "syscalls")]
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

	#[cfg(target_arch = "arm")]
	{
		syzlang_parser::parser::Arch::Aarch32
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

#[cfg(feature = "syscalls")]
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

#[cfg(feature = "syscalls")]
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

// #[cfg(test)]
// #[ctor::dtor]
// fn global_test_destructor_rust_dtor_dtor() {
// 	log::debug!("destructor");
// }

#[cfg(test)]
#[ctor::ctor]
fn global_test_setup() {
	env_logger::builder().format_timestamp_millis().init();
	log::debug!("constructor");
}

#[cfg(test)]
pub(crate) mod tests {
	use std::collections::HashMap;
	use std::io::Read;

	use super::*;

	pub fn get_all_tar_files() -> Result<HashMap<String, Vec<u8>>> {
		let testdata = TESTDATA.read().expect("").clone();
		let dec = flate2::bufread::GzDecoder::new(testdata.as_slice());
		let mut tar = tar::Archive::new(dec);
		let ret = tar
			.entries()?
			.filter_map(|x| x.ok())
			.map(|mut x| -> Result<(String, Vec<u8>)> {
				let path = x.path()?.to_path_buf();
				let fname = path
					.file_name()
					.expect("uanble to get file_name")
					.to_str()
					.expect("unable to convert OsStr to str");
				let mut buf = Vec::new();
				x.read_to_end(&mut buf)?;
				Ok((fname.to_string(), buf))
			})
			.filter_map(|x| x.ok())
			.collect::<HashMap<_, _>>();
		Ok(ret)
	}

	#[test]
	fn extract_tar_files() {
		let maps = get_all_tar_files().unwrap();
		assert!(maps.get("waitpid").is_some());
	}
}
