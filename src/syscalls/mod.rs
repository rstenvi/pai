//! Code relevant to parsing syscall arguments.

use crate::api::messages::{Direction, LenType, SysArg, SysValue, SyscallItem, Value, ValueLen};
use crate::api::{Client, Command, Response};
use crate::arch::RegisterAccess;
use crate::buildinfo::BuildArch;
use crate::target::Target;
use crate::Error;
use crate::{
	ctx,
	utils::{self, process::Tid},
	Result, TargetPtr,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use syzlang_parser::parser::{self, ArgOpt, ArgType, Argument, Identifier};

pub(crate) mod parsed;
pub(crate) use parsed::{Syscall, Syscalls};

macro_rules! get_parsed {
	() => {{
		log::trace!("getting read lock");
		&crate::SYSCALLS
			.read()
			.expect("unable to read lock SYSCALLS")
			.parsed
	}};
}
pub(crate) use get_parsed;
macro_rules! get_syscalls {
	() => {{
		log::trace!("getting read lock");
		&crate::SYSCALLS
			.read()
			.expect("unable to read lock SYSCALLS")
	}};
}

macro_rules! write_syscalls {
	() => {{
		log::trace!("getting write lock");
		&mut crate::SYSCALLS
			.write()
			.expect("unable to write lock SYSCALLS")
	}};
}

impl std::fmt::Display for LenType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LenType::Len => f.write_str("len"),
			LenType::Bytesize => f.write_str("bytesize"),
			LenType::Bitsize => f.write_str("bitsize"),
		}
	}
}

// #[allow(non_camel_case_types)]
// #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
// #[repr(C)]
// pub struct libc_stat {
// 	pub st_dev: libc::dev_t,
// 	pub st_ino: libc::ino_t,
// 	pub st_nlink: libc::nlink_t,
// 	pub st_mode: libc::mode_t,
// 	pub st_uid: libc::uid_t,
// 	pub st_gid: libc::gid_t,
// 	__pad0: libc::c_int,
// 	pub st_rdev: libc::dev_t,
// 	pub st_size: libc::off_t,
// 	pub st_blksize: libc::blksize_t,
// 	pub st_blocks: libc::blkcnt_t,
// 	pub st_atime: libc::time_t,
// 	pub st_atime_nsec: i64,
// 	pub st_mtime: libc::time_t,
// 	pub st_mtime_nsec: i64,
// 	pub st_ctime: libc::time_t,
// 	pub st_ctime_nsec: i64,
// 	__unused: [i64; 3],
// }

impl std::fmt::Display for Value {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ByteArray { buffer } => f.write_fmt(format_args!("buffer(len={})", buffer.len())),
			Self::FileOffset { offset } => f.write_fmt(format_args!("fileOffset({offset})")),
			Self::Buffer { ptr } => f.write_fmt(format_args!("buffer({ptr})")),
			Self::Bool { value } => f.write_fmt(format_args!("bool({value})")),
			Self::Error { code, msg } => f.write_fmt(format_args!("{code} {msg}")),
			// Self::Stat { stat: _ } => f.write_fmt(format_args!("struct stat {{}}")),
			Self::String { string } => f.write_fmt(format_args!("\"{string}\"")),
			Self::Filename { path } => f.write_fmt(format_args!("\"{path}\"")),
			Self::Fd { fd } => f.write_fmt(format_args!("fd({fd})")),
			Self::FdConst { value: _, name } => f.write_fmt(format_args!("fd({name})")),
			Self::ShallowPtr {
				value,
				arg: _,
				opts: _,
				optional: _,
			} => f.write_fmt(format_args!("ptr({value:x})")),
			Self::Vma { value, bits: _ } => f.write_fmt(format_args!("vma(0x{value:x})")),
			Self::Len { of, len } => f.write_fmt(format_args!("lenof({of}, {len})")),
			Self::Void { value } => f.write_fmt(format_args!("void(0x{value:x})")),
			Self::Flag { set } => {
				let s = set.join("|");
				f.write_fmt(format_args!("flags({s})"))
			}
			Self::Int { value, bits } => f.write_fmt(format_args!("int{bits}({value})")),
			Self::Resource { name, sub } => {
				if let Some(sub) = sub {
					f.write_fmt(format_args!("resource({name}={sub})"))
				} else {
					f.write_fmt(format_args!("resource({name}=None)"))
				}
			}
			Self::Const { matches, symbol } => {
				f.write_fmt(format_args!("const({symbol}, {matches})"))
			}
			Self::Struct { name, value } => {
				f.write_fmt(format_args!("struct({name} = {{ {value:?} }} )"))
			}
			Self::ParsedPtr { old: _, value } => f.write_fmt(format_args!("ptr({value})")),
		}
	}
}

impl Value {
	fn new_void(value: TargetPtr) -> Self {
		Self::Void { value }
	}
	fn new_byte_array(buffer: Vec<u8>) -> Self {
		Self::ByteArray { buffer }
	}
	fn is_error(&self) -> bool {
		matches!(self, Self::Error { code: _, msg: _ })
	}
	fn new_string<S: Into<String>>(string: S) -> Self {
		Self::String {
			string: string.into(),
		}
	}
	fn new_parsed_ptr(old: Value, value: Value) -> Self {
		Self::ParsedPtr {
			old: Box::new(old),
			value: Box::new(value),
		}
	}
	fn new_struct<S: Into<String>>(name: S, value: serde_json::Value) -> Self {
		log::trace!("creating new struct with {value:?}");
		Self::Struct {
			name: name.into(),
			value,
		}
	}
	fn new_bool(value: bool) -> Self {
		Self::Bool { value }
	}
	fn new_buffer(ptr: TargetPtr) -> Self {
		Self::Buffer { ptr }
	}
	fn new_file_offset(offset: usize) -> Self {
		Self::FileOffset { offset }
	}
	fn new_filename<S: Into<String>>(path: S) -> Self {
		Self::Filename { path: path.into() }
	}
	fn new_error<S: Into<String>>(code: i32, msg: S) -> Self {
		Self::Error {
			code,
			msg: msg.into(),
		}
	}
	fn new_fd_const<S: Into<String>>(value: i32, name: S) -> Self {
		let name = name.into();
		Self::FdConst { value, name }
	}
	fn new_error_or_default(err: i32, def: Self) -> Self {
		log::trace!("err {err:?} | {err:x}");
		let err = std::num::Wrapping(err);
		let err = (-err).0;
		match err {
			libc::ENOENT => Value::new_error(err, "ENOENT"),
			libc::ESRCH => Value::new_error(err, "ESRCH"),
			libc::EINTR => Value::new_error(err, "EINTR"),
			libc::EIO => Value::new_error(err, "EIO"),
			libc::ENXIO => Value::new_error(err, "ENXIO"),
			libc::E2BIG => Value::new_error(err, "E2BIG"),
			libc::ENOEXEC => Value::new_error(err, "ENOEXEC"),
			libc::EBADF => Value::new_error(err, "EBADF"),
			libc::ECHILD => Value::new_error(err, "ECHILD"),
			libc::EAGAIN => Value::new_error(err, "EAGAIN"),
			libc::ENOMEM => Value::new_error(err, "ENOMEM"),
			libc::EACCES => Value::new_error(err, "EACCES"),
			libc::EFAULT => Value::new_error(err, "EFAULT"),
			libc::ENOTBLK => Value::new_error(err, "ENOTBLK"),
			libc::EBUSY => Value::new_error(err, "EBUSY"),
			libc::EEXIST => Value::new_error(err, "EEXIST"),
			libc::EXDEV => Value::new_error(err, "EXDEV"),
			libc::ENODEV => Value::new_error(err, "ENODEV"),
			libc::ENOTDIR => Value::new_error(err, "ENOTDIR"),
			libc::EISDIR => Value::new_error(err, "EISDIR"),
			libc::EINVAL => Value::new_error(err, "EINVAL"),
			libc::ENFILE => Value::new_error(err, "ENFILE"),
			libc::EMFILE => Value::new_error(err, "EMFILE"),
			libc::ENOTTY => Value::new_error(err, "ENOTTY"),
			libc::ETXTBSY => Value::new_error(err, "ETXTBSY"),
			libc::EFBIG => Value::new_error(err, "EFBIG"),
			libc::ENOSPC => Value::new_error(err, "ENOSPC"),
			libc::ESPIPE => Value::new_error(err, "ESPIPE"),
			libc::EROFS => Value::new_error(err, "EROFS"),
			libc::EMLINK => Value::new_error(err, "EMLINK"),
			libc::EPIPE => Value::new_error(err, "EPIPE"),
			libc::EDOM => Value::new_error(err, "EDOM"),
			libc::ERANGE => Value::new_error(err, "ERANGE"),
			libc::EPERM => Value::new_error(err, "EPERM"),
			_ => def,
		}
	}
	fn new_fd(fd: i32, dir: Direction) -> Self {
		let isin = matches!(dir, Direction::In | Direction::InOut);
		match fd {
			libc::STDIN_FILENO => Self::new_fd_const(fd, "stdin"),
			libc::STDOUT_FILENO => Self::new_fd_const(fd, "stdout"),
			libc::STDERR_FILENO => Self::new_fd_const(fd, "stderr"),
			libc::AT_FDCWD => Self::new_fd_const(fd, "AT_FDCWD"),
			libc::AT_SYMLINK_NOFOLLOW => Self::new_fd_const(fd, "AT_SYMLINK_NOFOLLOW"),
			libc::AT_REMOVEDIR => Self::new_fd_const(fd, "AT_REMOVEDIR"),
			libc::AT_SYMLINK_FOLLOW => Self::new_fd_const(fd, "AT_SYMLINK_FOLLOW"),
			libc::AT_NO_AUTOMOUNT => Self::new_fd_const(fd, "AT_NO_AUTOMOUNT"),
			libc::AT_EMPTY_PATH => Self::new_fd_const(fd, "AT_EMPTY_PATH"),
			libc::AT_RECURSIVE => Self::new_fd_const(fd, "AT_RECURSIVE"),
			_ => {
				let ret = Self::Fd { fd };
				if !isin {
					Self::new_error_or_default(fd, ret)
				} else {
					ret
				}
			}
		}
	}
	fn new_resource<S: Into<String>>(name: S, sub: Option<Self>) -> Self {
		let name = name.into();
		let sub = sub.map(Box::new);
		Self::Resource { name, sub }
	}
	fn new_shallow_ptr(value: TargetPtr, arg: ArgType, opts: Vec<ArgOpt>, optional: bool) -> Self {
		Self::ShallowPtr {
			value,
			arg,
			opts,
			optional,
		}
	}
	fn new_int(raw: TargetPtr, bits: usize) -> Self {
		let v: usize = raw.into();
		let value: serde_json::value::Number = v.into();
		Self::Int { value, bits }
	}
	fn new_number(value: serde_json::value::Number, bits: usize) -> Self {
		Self::Int { value, bits }
	}
	fn new_len(of: String, ltype: LenType, value: TargetPtr) -> Self {
		let len = ValueLen::new(ltype, value);
		Self::Len { of, len }
	}
	fn new_flags(set: Vec<String>) -> Self {
		Self::Flag { set }
	}
	fn new_int_ptrsize(raw: TargetPtr) -> Self {
		let bits = std::mem::size_of::<TargetPtr>();
		Self::new_int(raw, bits)
	}
	fn new_vma(value: TargetPtr, bits: usize) -> Self {
		// let value: serde_json::value::Number = raw.into();
		Self::Vma { value, bits }
	}
	fn new_const(matches: bool, symbol: String) -> Self {
		Self::Const { matches, symbol }
	}
}

impl std::fmt::Display for SysValue {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Some(parsed) = self.parsed.as_ref() {
			f.write_fmt(format_args!("{parsed}"))
		} else {
			f.write_fmt(format_args!("0x{:x}", self.raw_value))
		}
	}
}

impl SysValue {
	fn new(raw_value: TargetPtr, parsed: Option<Value>) -> Self {
		Self { raw_value, parsed }
	}
	pub fn is_error(&self) -> Option<bool> {
		self.parsed.as_ref().map(|parsed| parsed.is_error())
	}
	pub fn raw_value(&self) -> TargetPtr {
		self.raw_value
	}
}

impl std::fmt::Display for SysArg {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{}={}", self.name, self.value))
	}
}

impl SysArg {
	fn new(name: String, raw_value: TargetPtr, parsed: Option<Value>, dir: Direction) -> Self {
		let value = SysValue::new(raw_value, parsed);
		Self { name, value, dir }
	}
	fn new_basic(name: String, raw_value: TargetPtr, dir: Direction) -> Self {
		Self::new(name, raw_value, None, dir)
	}
	pub fn raw_value(&self) -> TargetPtr {
		self.value.raw_value()
	}
	pub fn as_i32(&self) -> i32 {
		self.raw_value().as_i32()
	}
	pub fn as_u32(&self) -> u32 {
		self.raw_value().as_u32()
	}
	pub fn parsed(&self) -> &Option<Value> {
		&self.value.parsed
	}
	fn set_parsed(&mut self, parsed: Value) {
		self.value.parsed = Some(parsed);
	}
	pub fn is_output(&self) -> bool {
		matches!(self.dir, Direction::Out | Direction::InOut)
	}
	pub fn clear_parsed(&mut self) {
		log::debug!("clearing {:?}", self.value.parsed);
		if let Some(Value::ParsedPtr { old, value: _ }) = std::mem::take(&mut self.value.parsed) {
			self.value.parsed = Some(*old);
		}
	}
}

impl Direction {
	pub fn matches(&self, other: &Self) -> bool {
		*self == *other || *self == Self::InOut || *other == Self::InOut
	}
	pub fn is_in(&self) -> bool {
		matches!(self, Self::In | Self::InOut)
	}
	pub fn is_out(&self) -> bool {
		matches!(self, Self::Out | Self::InOut)
	}
}

impl From<syzlang_parser::parser::Direction> for Direction {
	fn from(value: syzlang_parser::parser::Direction) -> Self {
		match value {
			parser::Direction::In => Self::In,
			parser::Direction::Out => Self::Out,
			parser::Direction::InOut => Self::InOut,
		}
	}
}

impl std::fmt::Display for SyscallItem {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut n = format!("[{}]: ", self.tid);
		if !self.name.is_empty() {
			n.push_str(&self.name);
		} else {
			n.push_str(&format!("{}", self.sysno));
		}
		n.push('(');

		let mut parts = Vec::new();
		for arg in self.args.iter() {
			let ins = format!("{arg}");
			parts.push(ins);
		}

		n.push_str(&parts.join(", "));

		n.push(')');

		if let Some(v) = &self.output {
			n.push_str(" = ");
			n.push_str(&format!("{v}"));
		}
		f.write_fmt(format_args!("{n}"))
	}
}

#[derive(Debug)]
enum TmpParseValue {
	Number(serde_json::Number),
	Ptr(TargetPtr, Vec<ArgOpt>),
	Value(Value),
	Serde(serde_json::Value),
}

impl TmpParseValue {
	fn into_value(self) -> Result<serde_json::Value> {
		match self {
			TmpParseValue::Number(v) => Ok(serde_json::to_value(v)?),
			TmpParseValue::Ptr(v, _) => Ok(serde_json::to_value(v.as_u64())?),
			TmpParseValue::Value(v) => Ok(serde_json::to_value(&v)?),
			TmpParseValue::Serde(v) => Ok(v),
		}
	}
}

#[derive(Default)]
pub struct BuildValue {
	pointers: Vec<(Vec<String>, Vec<ArgOpt>)>,
	data: Vec<u8>,
	obj: serde_json::Value,
}
impl BuildValue {
	fn evaluate_size_struct(
		&mut self,
		names: &mut Vec<String>,
		s: &parser::Struct,
	) -> Result<usize> {
		let mut ret = 0;
		names.push(s.identifier().name.clone());
		for field in s.args() {
			names.push(field.identifier().name.clone());
			ret += self.evaluate_size_field(names, field.arg_type(), &field.opts)?;
			names.pop();
		}
		names.pop();
		Ok(ret)
	}
	fn take(&mut self, len: usize) -> Result<Vec<u8>> {
		if self.data.len() >= len {
			let mut take = Vec::with_capacity(len);
			for _i in 0..len {
				take.push(self.data.remove(0));
			}
			Ok(take)
		} else {
			Err(Error::Unknown)
		}
	}
	fn set_value(&mut self, names: &[String], value: serde_json::Value) {
		let mut obj = &mut self.obj;
		for (i, name) in names.iter().enumerate() {
			if i + 1 < names.len() {
				obj = &mut obj[name];
			} else {
				obj[name] = value;
				break;
			}
		}
	}
	fn evaluate_size_field(
		&mut self,
		names: &mut Vec<String>,
		arg: &ArgType,
		opts: &[ArgOpt],
	) -> Result<usize> {
		if arg.is_int() {
			let sz = arg.evaluate_size(&Target::syzarch())?;
			if let Ok(take) = self.take(sz) {
				let v = TargetPtr::from_bytes_unsigned(&take)?;
				let v: serde_json::Number = v.into();
				self.set_value(names, serde_json::to_value(v)?);
			}
			Ok(sz)
		} else if arg.is_ptr() {
			let sz = Target::ptr_size();
			log::debug!("PTR TO {opts:?}");
			if let Ok(take) = self.take(sz) {
				self.pointers.push((names.clone(), opts.to_vec()));
				let v = TargetPtr::from_bytes_unsigned(&take)?;
				self.set_value(names, serde_json::to_value(v)?);
			}
			Ok(sz)
		} else if let ArgType::Ident(ident) = arg {
			if let Some(at) = get_syscalls!().resolve_resource(ident) {
				// Avoid holding read-lock
				let at = at.clone();
				self.evaluate_size_field(names, &at, &[])
			} else if let Some(st) = get_syscalls!().resolve_struct(ident) {
				let st = st.clone();
				self.evaluate_size_struct(names, &st)
			} else {
				log::warn!("unknown ident {ident:?}");
				Err(Error::Unsupported)
			}
		} else if matches!(
			arg,
			ArgType::Const | ArgType::Flags | ArgType::Bytesize | ArgType::Bitsize | ArgType::Len
		) {
			for opt in opts.iter() {
				if let ArgOpt::FullArg(arg) = opt {
					return self.evaluate_size_field(names, arg.arg_type(), &arg.opts);
				}
			}
			log::warn!("found no subtype specifying size");
			Err(Error::Unsupported)
		} else {
			log::warn!("how to handle {arg:?}");
			Err(Error::Unsupported)
		}
	}
}

impl SyscallItem {
	/// Return true if syscall has failed or if we don't know if it has failed
	/// or not
	pub fn has_failed(&self) -> bool {
		self.syscall_errored().unwrap_or(true)
	}
	/// Return true if syscall has succeeded or if we don't know if it succeeded
	/// or not.
	pub fn has_succeeded(&self) -> bool {
		!self.syscall_errored().unwrap_or(false)
	}
	pub fn syscall_errored(&self) -> Option<bool> {
		if let Some(output) = &self.output {
			output.is_error()
		} else {
			None
		}
	}
	pub fn is_entry(&self) -> bool {
		self.output.is_none()
	}
	pub fn is_exit(&self) -> bool {
		!self.is_entry()
	}
	pub fn output_as_raw(&self) -> TargetPtr {
		assert!(self.output.is_some());
		if let Some(o) = &self.output {
			o.raw_value()
		} else {
			panic!("Tried to get output on syscall which is entry");
		}
	}

	fn next_fullarg(opts: &[ArgOpt]) -> Option<Argument> {
		for opt in opts.iter() {
			if let ArgOpt::FullArg(arg) = opt {
				return Some(*arg.clone());
			}
		}
		None
	}
	fn parse_ptr_ident<T: Send + 'static>(
		raw: TargetPtr,
		id: &parser::Identifier,
		tid: isize,
		client: &mut Client<T, Response>,
		maxdepth: isize,
	) -> Result<Option<serde_json::Value>>
	where
		crate::Error: From<crossbeam_channel::SendError<T>>,
	{
		// return Ok(None);
		// std::thread::sleep(std::time::Duration::from_millis(1000));
		// Example if we have the struct as Rust code
		// "stat" => {
		//		let bytes = std::mem::size_of::<libc_stat>();
		//		let bytes = client.read_bytes(tid, raw, bytes)?;

		//		let (head, body, _tail) = unsafe { bytes.align_to::<libc_stat>() };
		//		assert!(head.is_empty(), "Data was not aligned");
		//		let stat = body[0].clone();
		//		Some(Value::Stat { stat })
		//	}

		log::debug!("attempting to parse {raw:x} ident {id:?}");
		if raw != 0.into() {
			let mut build = BuildValue::default();
			let size = build.evaluate_size_field(
				&mut Vec::new(),
				&parser::ArgType::Ident(id.clone()),
				&[],
			)?;
			log::debug!("size @{id:?}:{raw:x} = {size}");
			let data = client.read_bytes(tid, raw, size)?;

			build.data = data;
			let _size = build.evaluate_size_field(
				&mut Vec::new(),
				&parser::ArgType::Ident(id.clone()),
				&[],
			)?;
			let mut obj = build.obj;
			let pointers = std::mem::take(&mut build.pointers);
			for (ptr, opts) in pointers.into_iter() {
				let mut n = &mut obj;
				for p in ptr.iter() {
					n = &mut n[p];
				}

				if let Ok(nptr) = serde_json::from_value::<TargetPtr>(n.clone()) {
					if nptr != raw && nptr != 0.into() {
						if let Some(narg) = Self::next_fullarg(&opts) {
							if let Some(value) = Self::parse_ptr(
								nptr,
								tid,
								client,
								&narg.argtype,
								&narg.opts,
								None,
								maxdepth - 1,
							)? {
								*n = serde_json::to_value(value)?;
							}
						}
					}
				} else {
					log::warn!("unable to parse {n:?} as ptr");
				}
			}
			log::debug!("obj {obj:?}");
			Ok(Some(obj))
		} else {
			log::debug!("pointer was NULL");
			Ok(None)
		}
	}
	fn parse_ptr<T: Send + 'static>(
		raw: TargetPtr,
		tid: Tid,
		client: &mut Client<T, Response>,
		arg: &ArgType,
		opts: &[ArgOpt],
		len: Option<&ValueLen>,
		maxdepth: isize,
	) -> Result<Option<Value>>
	where
		crate::Error: From<crossbeam_channel::SendError<T>>,
	{
		if maxdepth <= 0 {
			Err(Error::TooManyAttempts)
		} else if arg.refers_c_string() {
			let string = client.read_c_string(tid, raw)?;
			let value = if arg.is_filename() {
				Value::new_filename(string)
			} else {
				Value::new_string(string)
			};
			Ok(Some(value))
		} else if let ArgType::Ident(id) = arg {
			match Self::parse_ptr_ident(raw, id, tid, client, maxdepth - 1) {
				Ok(n) => match n {
					Some(n) => Ok(Some(Value::new_struct(id.unique_name(), n))),
					None => {
						log::warn!("got None when parsing struct {id:?}");
						Ok(None)
					}
				},
				Err(e) => {
					log::warn!("got error when trying to parse struct {id:?} {e:?}");
					Ok(None)
				}
			}
		} else if arg.is_int() {
			if raw != 0.into() {
				let sz = arg.arg_size(std::mem::size_of::<TargetPtr>())?;
				let bytes = client.read_bytes(tid, raw, sz)?;
				let value = TargetPtr::from_bytes_unsigned(&bytes)?;
				let value: serde_json::Number = value.into();
				let value = Value::new_number(value, sz * 8);
				Ok(Some(value))
			} else {
				log::debug!("not parsing ptr because it's NULL");
				Ok(None)
			}
		} else if arg.is_array() {
			if let Some(len) = len {
				if let Some(ArgOpt::FullArg(farg)) = opts.first() {
					let sub = farg.arg_type();
					if let Ok(itemsz) = sub.arg_size(std::mem::size_of::<TargetPtr>()) {
						let bytes = len.bytes(itemsz);
						let data = client.read_bytes(tid, raw, bytes)?;
						if let ArgType::Int8 = sub {
							let value = Value::new_byte_array(data);
							Ok(Some(value))
						} else {
							log::warn!("not sure how to parse {sub:?}");
							Ok(None)
						}
					} else {
						log::warn!("unable to determine array entry size");
						Ok(None)
					}
				} else {
					log::warn!("expected FullArg(...) as first ArgOpt for Array");
					Ok(None)
				}
			} else {
				log::warn!("got array, but no length specifier");
				Ok(None)
			}
		} else {
			log::warn!("not yet parsing ptr to {arg:?}");
			Ok(None)
		}
	}
	pub fn parse_deep<T: Send + 'static>(
		&mut self,
		tid: Tid,
		client: &mut Client<T, Response>,
		parsedir: Direction,
	) -> Result<()>
	where
		crate::Error: From<crossbeam_channel::SendError<T>>,
	{
		log::debug!("parsing deep values");
		let errored = self.syscall_errored().unwrap_or(true);

		let mut lens = HashMap::new();
		for inarg in self.args.iter() {
			if let Some(Value::Len { of, len }) = inarg.parsed() {
				lens.insert(of.clone(), len.clone());
			}
		}

		// Special handling of ioctl since the second argument usually specifies
		// the size of the third argument.
		if self.args.len() >= 2 && self.name.starts_with("ioctl") {
			let cmd = self.args[1].raw_value().as_ioctl_cmd()?;
			if cmd.size < 0x1000 {
				let of = "arg".to_string();
				let len = ValueLen::new(LenType::Bytesize, cmd.size.into());
				lens.insert(of, len);
				if let Some(dir) = &cmd.dir {
					if parsedir == Direction::Out && dir.is_out() && !self.args[2].dir.is_out() {
						log::debug!("setting dir {dir:?}");
						self.args[2].dir = dir.clone();
						self.args[2].clear_parsed();
					}
				}
			} else {
				log::warn!("got long size from parsing ioctl cmd, ignoring");
			}
		}

		for inarg in self.args.iter_mut() {
			let shouldparse =
				// Argument is in and parsing is on input
				(inarg.dir.is_in() && parsedir.is_in())
				||
				// Argument is out, parsing is out and syscall has not returned error
				(parsedir.is_out() && inarg.dir.is_out() && !errored)
			;

			if shouldparse {
				if let Some(n) = inarg.parsed() {
					if let Value::ShallowPtr {
						value,
						arg,
						opts,
						optional,
					} = n
					{
						let len = lens.get(&inarg.name);
						let v = Self::parse_ptr(inarg.raw_value(), tid, client, arg, opts, len, 8);
						match v {
							Ok(v) => match v {
								Some(v) => {
									let v = Value::new_parsed_ptr(
										Value::new_shallow_ptr(
											*value,
											arg.clone(),
											opts.clone(),
											*optional,
										),
										v,
									);
									inarg.set_parsed(v)
								}
								None => log::warn!(
									"reading of ptr {:x} with len {len:?} returned None",
									inarg.raw_value()
								),
							},
							Err(e) => log::warn!(
								"reading of ptr {:x} with len {len:?} returned error: {e:?}",
								inarg.raw_value()
							),
						}
						log::debug!("arg {inarg}");
					}
				} else {
					log::debug!("parsed arg was None, previous step of parsing has seemingly not been done: {inarg:?}");
				}
			}
		}
		Ok(())
	}
	fn error_or_def(raw: TargetPtr, def: Value) -> Value {
		let err = raw.as_i32();
		if err < 0 {
			Value::new_error_or_default(err, def)
		} else {
			def
		}
	}
	fn get_direction(opts: &[ArgOpt]) -> Direction {
		for opt in opts.iter() {
			if let ArgOpt::Dir(dir) = opt {
				return (*dir).into();
			}
		}
		Direction::In
	}
	fn parse_arg_type(raw: TargetPtr, atype: &ArgType, opts: &[ArgOpt]) -> Result<Option<Value>> {
		log::trace!("{raw:x} {atype:?}");
		let dir = Self::get_direction(opts);
		let isout = matches!(dir, Direction::Out);
		match atype {
			ArgType::Intptr
			| ArgType::Int64
			| ArgType::Int32
			| ArgType::Int16
			| ArgType::Int8
			| ArgType::Int64be
			| ArgType::Int32be
			| ArgType::Int16be => {
				let bytes = atype
					.arg_size(std::mem::size_of::<usize>())
					.unwrap_or_else(|_| panic!("unable to get size of int {atype:?})"));

				// We parse everything as unsigned here because Syzkaller does
				// not separate between signed and unsigned so we don't know
				// what it is.
				let value: serde_json::value::Number = match atype {
					ArgType::Intptr => raw.into(),
					ArgType::Int64 => raw.as_u64().into(),
					ArgType::Int32 => raw.as_u32().into(),
					ArgType::Int16 => raw.as_u16().into(),
					ArgType::Int8 => raw.as_u8().into(),
					ArgType::Int64be => {
						let v: u64 = raw.into();
						let v = u64::from_be(v);
						v.into()
					}
					ArgType::Int32be => {
						let v: u32 = raw.into();
						let v = u32::from_be(v);
						v.into()
					}
					ArgType::Int16be => {
						let v: u16 = raw.into();
						let v = u16::from_be(v);
						v.into()
					}
					_ => panic!(""),
				};
				let err = raw.as_i32();
				let ret = Value::new_number(value, bytes * 8);
				Ok(Some(if isout {
					Value::new_error_or_default(err, ret)
				} else {
					ret
				}))
			}
			ArgType::Csum => {
				log::warn!("need to parse csum {opts:?}");
				Ok(None)
			}
			ArgType::Proc => {
				log::warn!("need to parse proc {opts:?}");
				Ok(None)
			}
			ArgType::OffsetOf => {
				log::warn!("need to parse offsetof {opts:?}");
				Ok(None)
			}
			ArgType::Fmt => {
				log::warn!("need to parse fmt {opts:?}");
				Ok(None)
			}
			ArgType::CompressedImage => {
				log::warn!("need to parse CompressedImage {opts:?}");
				Ok(None)
			}
			ArgType::Bool => Ok(Some(Value::new_bool(raw != 0.into()))),
			ArgType::Void => Ok(Some(Self::error_or_def(raw, Value::new_void(raw)))),
			ArgType::Vma | ArgType::Vma64 => {
				let bits = if matches!(atype, ArgType::Vma64) {
					64
				} else {
					std::mem::size_of::<TargetPtr>() * 8
				};
				Ok(Some(Value::new_vma(raw, bits)))
			}
			ArgType::Const => Ok(if let Some(first) = opts.first() {
				let value = Self::resolve_const_opt(raw, first)?;
				Some(value)
			} else {
				None
			}),
			ArgType::Flags => Ok(if let Some(opt) = opts.first() {
				let set = Self::resolve_flag_opt(raw, opt)?;
				Some(Value::new_flags(set))
			} else {
				log::warn!("no argopt to parse flags {atype:?}");
				None
			}),
			ArgType::Len | ArgType::Bitsize | ArgType::Bytesize => {
				Ok(if let Some(lenof) = opts.first() {
					let lentype = match atype {
						ArgType::Len => LenType::Len,
						ArgType::Bitsize => LenType::Bitsize,
						ArgType::Bytesize => LenType::Bytesize,
						_ => panic!(""),
					};
					let lenof = Self::opt_to_name(lenof);
					Some(Value::new_len(lenof, lentype, raw))
				} else {
					None
				})
			}
			ArgType::Ident(ident) => match ident.name.as_str() {
				"boolptr" => Ok(Some(Value::new_bool(raw != 0.into()))),
				"buffer" => Ok(Some(Value::new_buffer(raw))),
				"fileoff" => Ok(Some(Value::new_file_offset(raw.into()))),
				_ => Self::resolve_resource_ident(raw, ident, dir),
			},
			ArgType::Ptr | ArgType::Ptr64 => {
				log::trace!("PTR {:?}", opts);
				if let Some(ArgOpt::Dir(_dir)) = opts.first() {
					let opt = matches!(opts.last(), Some(ArgOpt::Opt));
					if let Some(ArgOpt::FullArg(narg)) = opts.get(1) {
						let ret = Value::new_shallow_ptr(
							raw,
							narg.argtype.clone(),
							narg.opts.clone(),
							opt,
						);
						Ok(Some(ret))
					} else {
						log::warn!("unable to parse second arg as FullArgument");
						Ok(None)
					}
				} else {
					log::warn!("unable to get first opt as Direction {opts:?}");
					Ok(None)
				}
			}

			// These are all invalid without a pointer first
			ArgType::String | ArgType::StringNoz | ArgType::StringConst => {
				crate::bug!("got string type w/o pointer first???")
			}
			ArgType::Template(_) => crate::bug!("template should already be parsed"),
			ArgType::Text => crate::bug!("got text type w/o pointer first???"),
			ArgType::Array => crate::bug!("got array type w/o pointer first???"),
			ArgType::Glob => crate::bug!("got glob type w/o pointer first???"),
		}
	}
	fn parse_arg(raw: TargetPtr, arg: &Argument) -> Result<Option<Value>> {
		Self::parse_arg_type(raw, arg.arg_type(), &arg.opts)
	}

	pub fn patch_ioctl_call(&mut self, dir: &Direction) -> Result<()> {
		// Avoid re-parsing this on entry and exit
		if *dir == Direction::In || self.args[2].parsed().is_none() {
			log::debug!("sysno {} is ioctl", self.sysno);
			let cmd = self.args[1].as_u32();
			log::debug!("ioctl cmd {cmd:?}");
			if let Ok(Some(ioctl)) = write_syscalls!().find_matching_ioctl(cmd as u64) {
				log::trace!("found ioctl {ioctl:?}");
				self.name = format!("ioctl${}", ioctl.ident.subname.join("_"));
				if self.args.len() >= 2 && ioctl.args.len() >= 2 {
					log::debug!("parsing custom ioctl");
					let raw = self.args[2].raw_value();
					log::debug!("raw {raw:x}");
					let ins = Self::parse_arg(raw, &ioctl.args[2])?;
					self.args[2].value.parsed = ins;

					// Syzkaller does not necessarily mark input/output
					// correctly, if Syzkaller doesn't care about the output
					// date, they will likely mark it as just Input. To get
					// around this, we should have a way to patch entries and
					// override behaviour. Below is one test, to verify it
					// worked, but it will be global for all ioctl arguments.

					// self.args[2].dir = Direction::InOut;
				}
			}
		}
		Ok(())
	}
	pub fn enrich_values(&mut self) -> Result<()> {
		log::debug!("enriching values sysno: {}", self.sysno);

		if let Some(sys) = get_syscalls!().resolve(self.sysno) {
			for (i, arg) in sys.args.iter().enumerate() {
				if self.args[i].value.parsed.is_none() {
					let raw = self.args[i].raw_value();
					let ins = Self::parse_arg(raw, arg)?;
					self.args[i].value.parsed = ins;
				}
			}
			if let Some(out) = &mut self.output {
				if out.parsed.is_none() {
					let opts = vec![ArgOpt::Dir(syzlang_parser::parser::Direction::Out)];
					let ins = Self::parse_arg_type(out.raw_value(), &sys.output, &opts)?;
					out.parsed = ins;
				}
			}
		}
		Ok(())
	}
	fn argtypes_are_fd(ident: &Identifier, args: &[ArgType]) -> bool {
		if let Some(ArgType::Int32) = args.last() {
			let len = args.len();
			if len >= 2 {
				if let Some(ArgType::Ident(n)) = args.get(len - 2) {
					n.name == "fd"
				} else {
					false
				}
			} else {
				ident.name == "fd"
			}
		} else {
			false
		}
	}
	fn resolve_resource_ident(
		raw: TargetPtr,
		ident: &Identifier,
		dir: Direction,
	) -> Result<Option<Value>> {
		let basics = get_parsed!().resource_to_basics(ident);
		log::trace!("basics {ident:?} ->  {basics:?}");
		if Self::argtypes_are_fd(ident, &basics) {
			let fd = raw.as_i32();
			let r = Value::new_fd(fd, dir);
			Ok(Some(r))
		} else if let Some(at) = basics.last().cloned() {
			let sub = Self::parse_arg_type(raw, &at, &[])?;
			Ok(Some(Value::new_resource(ident.name.clone(), sub)))
		} else {
			Ok(None)
		}
	}
	fn opt_to_name(opt: &ArgOpt) -> String {
		match opt {
			ArgOpt::Ident(ident) => ident.name.clone(),
			_ => {
				crate::bug!("tried to parse {opt:?} as name");
			}
		}
	}
	fn resolve_const_opt(raw: TargetPtr, opt: &ArgOpt) -> Result<Value> {
		if let ArgOpt::Value(value) = opt {
			match value {
				parser::Value::Ident(ident) => {
					let n = Self::resolve_const_ident(&ident.name)?;
					let vi32 = raw.as_i32();
					let matches = n == raw || n == vi32.into();
					if matches {
						if ident.name == "AT_FDCWD" {
							Ok(Value::new_fd_const(vi32, "AT_FDCWD"))
						} else {
							Ok(Value::new_const(matches, ident.name.clone()))
						}
					} else if ident.name == "AT_FDCWD" {
						let value: serde_json::value::Number = vi32.into();
						let sub = Value::new_number(value, 32);
						Ok(Value::new_resource("fd", Some(sub)))
					} else {
						Err(Error::msg(format!(
							"unable to find matching const {:?}",
							ident.name
						)))
					}
				}
				parser::Value::Int(_n) => Ok(Value::new_int_ptrsize(raw)),
				_ => Err(Error::msg(format!(
					"encountered {value:?} when trying to resolve const"
				))),
			}
		} else {
			Err(Error::msg(format!(
				"encountered {opt:?} when trying to resolve const"
			)))
		}
	}
	fn resolve_flag_ident(raw: TargetPtr, ident: &Identifier) -> Result<Vec<String>> {
		let mut ret = Vec::new();
		let flag = get_parsed!().get_flag(ident).cloned();
		if let Some(flag) = flag {
			for val in flag.args() {
				match val {
					parser::Value::Ident(n) => {
						let v = Self::resolve_const_ident(&n.name)?;
						let ones = usize::count_ones(v.into());
						if ones > 1 {
							if v == raw {
								ret.push(n.name.clone());
							}
						} else if v == raw || i32::from(v) == raw.as_i32() || (raw & v) == v {
							ret.push(n.name.clone());
						}
					}
					_ => {
						return Err(Error::msg(format!(
							"encountered {val:?} when trying to resolve flag ident"
						)))
					}
				}
			}
		}
		Ok(ret)
	}
	fn resolve_flag_opt(raw: TargetPtr, opt: &ArgOpt) -> Result<Vec<String>> {
		match opt {
			ArgOpt::Ident(ident) => Self::resolve_flag_ident(raw, ident),
			_ => Err(Error::msg(format!(
				"encountered {opt:?} when trying to resolve flag opt"
			))),
		}
	}
	fn resolve_const_ident(name: &str) -> Result<TargetPtr> {
		if let Some(r) = get_parsed!()
			.consts()
			.find_name_arch(name, &Target::syzarch())
		{
			match r.value() {
				parser::Value::Int(n) => Ok((*n).into()),
				_ => Err(Error::msg(format!(
					"encountered {:?} when trying to resolve const ident",
					r.value()
				))),
			}
		} else {
			Err(Error::msg(format!(
				"const search for {name:?} returned None"
			)))
		}
	}

	pub fn from_regs(tid: Tid, sysno: usize, args: &[u64]) -> Self {
		log::debug!("parsing from_regs {sysno} {args:?}");
		let (name, args) = if let Some(sys) = get_syscalls!().resolve(sysno) {
			log::trace!("sysno {sysno} = {sys:?}");
			let mut shallows = Vec::new();
			for (i, arg) in sys.args.iter().enumerate() {
				let dir = arg.direction().into();
				let (_atype, _resource) = Self::get_shallow_value(arg.arg_type());
				let value = args[i].into();
				let ins = SysArg::new_basic(arg.identifier().safe_name(), value, dir);
				log::trace!("shallow[{i}]: {ins:?}");
				shallows.push(ins);
			}
			(sys.ident.name.clone(), shallows)
		} else {
			(format!("unknown_{sysno}"), Vec::new())
		};
		Self {
			tid,
			sysno,
			name,
			args,
			output: None,
		}
	}
	pub fn fill_in_output(&mut self, retval: TargetPtr) {
		let ins = SysValue::new(retval, None);
		self.output = Some(ins);
	}
	fn get_shallow_value(arg: &ArgType) -> (ArgType, Option<Identifier>) {
		log::debug!("getting shallow for {arg:?}");
		let (atype, resource) = if let ArgType::Ident(ident) = arg {
			if let Some(r) = get_parsed!().resource_to_basic_type(ident) {
				log::debug!("refers to {r:?}");
				(r, Some(ident.clone()))
			} else {
				log::trace!("unknown refer");
				(arg.clone(), None)
			}
		} else {
			log::trace!("returning same value");
			(arg.clone(), None)
		};
		(atype, resource)
	}
}

impl From<parser::Arch> for BuildArch {
	fn from(value: parser::Arch) -> Self {
		match value {
			parser::Arch::X86 => Self::X86,
			parser::Arch::X86_64 => Self::X86_64,
			parser::Arch::Aarch64 => Self::Aarch64,
			parser::Arch::Aarch32 => Self::Aarch32,
			parser::Arch::Mips64le => panic!("Mips64le not supported, should not get here"),
			parser::Arch::Ppc64le => panic!("Ppc64le not supported, should not get here"),
			parser::Arch::Riscv64 => Self::RiscV64,
			parser::Arch::S390x => panic!("S390x not supported, should not get here"),
			parser::Arch::Mips32 => Self::Mips32,
			parser::Arch::Native => panic!("From Native not supported"),
		}
	}
}
impl From<BuildArch> for parser::Arch {
	fn from(value: BuildArch) -> Self {
		match value {
			BuildArch::Aarch64 => Self::Aarch64,
			BuildArch::Aarch32 => Self::Aarch32,
			BuildArch::X86_64 => Self::X86_64,
			BuildArch::X86 => Self::X86,
			BuildArch::Mips32 => Self::Mips32,
			BuildArch::RiscV64 => Self::Riscv64,
		}
	}
}

impl Syscall {
	fn for_arch(&self, arch: &BuildArch) -> bool {
		let arch: parser::Arch = (*arch).clone().into();
		self.arches.contains(&arch)
	}
}

impl Syscalls {
	pub fn postprocess(&mut self) {
		// self.resources = HashMap::with_capacity(self.parsed.resources.len());
		// for res in std::mem::take(&mut self.parsed.resources).into_iter() {
		// 	self.resources.insert(res.name, res.atype);
		// }

		// self.structs = HashMap::with_capacity(self.parsed.structs.len());
		// for s in std::mem::take(&mut self.parsed.structs).into_iter() {
		// 	self.structs.insert(s.identifier().clone(), s);
		// }
	}

	pub fn resolve_resource(&self, ident: &Identifier) -> Option<&parser::ArgType> {
		self.resources.get(&ident.name)
	}
	pub fn resolve_struct(&self, ident: &Identifier) -> Option<&parser::Struct> {
		self.structs.get(&ident.name)
	}
	pub fn resolve(&self, sysno: usize) -> Option<&Syscall> {
		let arch = Target::arch();
		log::trace!("resolving arch {arch:?}");
		if let Some(calls) = self.syscalls.get(&sysno) {
			log::trace!("found calls {calls:?}");
			let rem = calls
				.iter()
				.filter(|x| x.for_arch(&arch))
				.collect::<Vec<_>>();
			rem.first().copied()
		} else {
			None
		}
	}
	pub fn find_matching_ioctl(&mut self, cmd: u64) -> Result<Option<&Syscall>> {
		if let Some(v) = self.ioctlcache.get(&cmd) {
			Ok(self.virts.ioctls.get(v))
		} else {
			let arch = Target::syzarch();
			let mut found = self.parsed.consts.all_consts_matching(cmd, &arch);
			log::trace!("found {found:?}");
			match found.len() {
				0 => Err(Error::NotFound),
				1 => {
					let c = found.remove(0);
					self.ioctlcache.insert(cmd, c.name.clone());
					Ok(self.virts.ioctls.get(&c.name))
				}
				_ => Err(Error::TooManyMatches),
			}
		}
	}
	pub fn name_to_sysno(&self, arch: BuildArch, name: &str) -> Option<usize> {
		let arch: parser::Arch = arch.into();
		let v = self
			.syscalls
			.iter()
			.filter(|(_sysno, sys)| {
				for item in sys.iter() {
					if item.ident.name == name && item.arches.contains(&arch) {
						return true;
					}
				}
				false
			})
			.map(|(sysno, _)| *sysno)
			.collect::<Vec<_>>();
		v.first().cloned()
	}
}
