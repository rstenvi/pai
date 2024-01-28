use crate::{
	arch::ReadRegisters,
	ctx,
	utils::{self, process::Tid},
	Error, Result, TargetPtr,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use syzlang_parser::parser::{self, ArgOpt, ArgType, Argument, Identifier};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum LenType {
	Len,
	Bytesize,
	Bitsize,
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

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[repr(C)]
pub struct libc_stat {
	pub st_dev: libc::dev_t,
	pub st_ino: libc::ino_t,
	pub st_nlink: libc::nlink_t,
	pub st_mode: libc::mode_t,
	pub st_uid: libc::uid_t,
	pub st_gid: libc::gid_t,
	__pad0: libc::c_int,
	pub st_rdev: libc::dev_t,
	pub st_size: libc::off_t,
	pub st_blksize: libc::blksize_t,
	pub st_blocks: libc::blkcnt_t,
	pub st_atime: libc::time_t,
	pub st_atime_nsec: i64,
	pub st_mtime: libc::time_t,
	pub st_mtime_nsec: i64,
	pub st_ctime: libc::time_t,
	pub st_ctime_nsec: i64,
	__unused: [i64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValueLen {
	ltype: LenType,
	value: TargetPtr,
}
impl std::fmt::Display for ValueLen {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("len({}, 0x{:x})", self.ltype, self.value))
	}
}

impl ValueLen {
	fn new(ltype: LenType, value: TargetPtr) -> Self {
		Self { ltype, value }
	}
	fn bytes(&self, itemsz: usize) -> usize {
		match self.ltype {
			LenType::Len => itemsz * self.value as usize,
			LenType::Bytesize => self.value as usize,
			LenType::Bitsize => self.value as usize / 8,
		}
	}
}

/// Similar to [serde_json::Value], but some added entries for easier
/// interpretation.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Value {
	Void {
		value: TargetPtr,
	},
	ByteArray {
		buffer: Vec<u8>,
	},
	Flag {
		set: Vec<String>,
	},
	Const {
		matches: bool,
		symbol: String,
	},
	Len {
		of: String,
		len: ValueLen,
	},
	Int {
		value: serde_json::value::Number,
		bits: usize,
	},
	Vma {
		value: TargetPtr,
		bits: usize,
	},
	Resource {
		name: String,
		sub: Option<Box<Self>>,
	},
	ShallowPtr {
		value: TargetPtr,
		arg: ArgType,
		opts: Vec<ArgOpt>,
		optional: bool,
	},
	Fd {
		fd: i32,
	},
	FdConst {
		value: i32,
		name: String,
	},
	Filename {
		path: String,
	},
	String {
		string: String,
	},
	Error {
		code: i32,
		msg: String,
	},
	Stat {
		stat: libc_stat,
	},
	Bool {
		value: bool,
	},
	Buffer {
		ptr: TargetPtr,
	},

	FileOffset {
		offset: usize,
	},
}

impl std::fmt::Display for Value {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ByteArray { buffer } => f.write_fmt(format_args!("buffer(len={})", buffer.len())),
			Self::FileOffset { offset } => f.write_fmt(format_args!("fileOffset({offset})")),
			Self::Buffer { ptr } => f.write_fmt(format_args!("buffer({ptr})")),
			Self::Bool { value } => f.write_fmt(format_args!("bool({value})")),
			Self::Error { code, msg } => f.write_fmt(format_args!("{code} {msg}")),
			Self::Stat { stat: _ } => f.write_fmt(format_args!("struct stat {{}}")),
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
			Self::Len { of, len } => f.write_fmt(format_args!("lenof(({of}), {len})")),
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
		match -err {
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
		let sub = sub.map(|x| Box::new(x));
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
		let value: serde_json::value::Number = raw.into();
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SysValue {
	pub raw_value: TargetPtr,
	pub parsed: Option<Value>,
}

impl SysValue {
	pub fn new(raw_value: TargetPtr, parsed: Option<Value>) -> Self {
		Self { raw_value, parsed }
	}
	pub fn is_error(&self) -> Option<bool> {
		self.parsed.as_ref().map(|parsed| parsed.is_error())
	}
	pub fn as_nice_str(&self) -> String {
		if let Some(parsed) = self.parsed.as_ref() {
			format!("{parsed}")
		} else {
			format!("0x{:x}", self.raw_value)
		}
	}
	pub fn raw_value(&self) -> TargetPtr {
		self.raw_value
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SysArg {
	pub name: String,
	value: SysValue,
	dir: Direction,
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
		let raw = self.raw_value();
		let signed = utils::twos_complement(raw);
		signed as i32
	}
	pub fn as_nice_str(&self) -> String {
		format!("{}={}", self.name, self.value.as_nice_str())
	}
	pub fn parsed(&self) -> &Option<Value> {
		&self.value.parsed
	}
	fn set_parsed(&mut self, parsed: Value) {
		self.value.parsed = Some(parsed);
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Direction {
	In,
	Out,
	InOut,
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SyscallItem {
	pub tid: Tid,
	pub sysno: TargetPtr,
	pub name: String,
	pub args: Vec<SysArg>,
	pub output: Option<SysValue>,
}

impl std::fmt::Display for SyscallItem {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{}", self.as_nice_str()))
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
	fn parse_ptr<T>(
		raw: TargetPtr,
		tid: Tid,
		ctx: &mut ctx::Secondary<T>,
		arg: &ArgType,
		opts: &[ArgOpt],
		len: Option<&ValueLen>,
	) -> Result<Option<Value>> {
		if arg.refers_c_string() {
			let string = ctx.client_mut().read_c_string(tid, raw)?;
			let value = if arg.is_filename() {
				Value::new_filename(string)
			} else {
				Value::new_string(string)
			};
			Ok(Some(value))
		} else if let ArgType::Ident(n) = arg {
			Ok(match n.name.as_str() {
				"stat" => {
					let bytes = std::mem::size_of::<libc_stat>();
					let bytes = ctx.client_mut().read_bytes(tid, raw, bytes)?;

					let (head, body, _tail) = unsafe { bytes.align_to::<libc_stat>() };
					assert!(head.is_empty(), "Data was not aligned");
					let stat = body[0].clone();
					// log::error!("stat {stat:?}");
					Some(Value::Stat { stat })
				}
				_ => None,
			})
		} else if arg.is_int() {
			if raw != 0 {
				let sz = arg.arg_size(std::mem::size_of::<TargetPtr>())?;
				let bytes = ctx.client_mut().read_bytes(tid, raw, sz)?;
				let value = arg.bytes_as_int(&bytes)?;
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
						let data = ctx.client_mut().read_bytes(tid, raw, bytes)?;
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
	pub fn parse_deep<T>(
		&mut self,
		tid: Tid,
		ctx: &mut ctx::Secondary<T>,
		parsedir: Direction,
	) -> Result<()> {
		self.enrich_values()?;
		let errored = self.syscall_errored().unwrap_or(true);

		let mut lens = HashMap::new();
		for inarg in self.args.iter() {
			if let Some(Value::Len { of, len }) = inarg.parsed() {
				lens.insert(of.clone(), len.clone());
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
						value: _,
						arg,
						opts,
						optional: _,
					} = n
					{
						let len = lens.get(&inarg.name);
						if let Some(v) =
							Self::parse_ptr(inarg.raw_value(), tid, ctx, arg, opts, len)?
						{
							inarg.set_parsed(v);
						}
					}
				} else {
					log::warn!("parsed arg was None, previous step of parsing has seemingly not been done: {inarg:?}");
				}
			}
		}
		Ok(())
	}
	fn error_or_def(raw: TargetPtr, def: Value) -> Value {
		let err = utils::twos_complement(raw) as i32;
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
	fn parse_arg_type(raw: TargetPtr, atype: &ArgType, opts: &[ArgOpt]) -> Option<Value> {
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
					.arg_size(std::mem::size_of::<TargetPtr>())
					.unwrap_or_else(|_| panic!("unable to get size of int {atype:?})"));
				let value = match atype {
					ArgType::Intptr => raw.into(),
					ArgType::Int64 => utils::twos_complement(raw as i64 as u64).into(),
					ArgType::Int32 => utils::twos_complement(raw as i32 as u64).into(),
					ArgType::Int16 => utils::twos_complement(raw as i16 as u64).into(),
					ArgType::Int8 => utils::twos_complement(raw as i8 as u64).into(),
					ArgType::Int64be => utils::twos_complement(u64::from_be(raw)).into(),
					ArgType::Int32be => {
						utils::twos_complement(u64::from_be(raw) as i32 as u64).into()
					}
					ArgType::Int16be => {
						utils::twos_complement(u64::from_be(raw) as i16 as u64).into()
					}
					_ => panic!(""),
				};
				let err = utils::twos_complement(raw) as i32;
				let ret = Value::new_number(value, bytes * 8);
				Some(if isout {
					Value::new_error_or_default(err, ret)
				} else {
					ret
				})
			}
			ArgType::Csum => {
				log::warn!("need to parse csum {opts:?}");
				None
			}
			ArgType::Proc => {
				log::warn!("need to parse proc {opts:?}");
				None
			}
			ArgType::OffsetOf => {
				log::warn!("need to parse offsetof {opts:?}");
				None
			}
			ArgType::Fmt => {
				log::warn!("need to parse fmt {opts:?}");
				None
			}
			ArgType::CompressedImage => {
				log::warn!("need to parse CompressedImage {opts:?}");
				None
			}
			ArgType::Bool => Some(Value::new_bool(raw != 0)),
			ArgType::Void => Some(Self::error_or_def(raw, Value::new_void(raw))),
			ArgType::Vma | ArgType::Vma64 => {
				let bits = if matches!(atype, ArgType::Vma64) {
					64
				} else {
					std::mem::size_of::<TargetPtr>() * 8
				};
				Some(Value::new_vma(raw, bits))
			}
			ArgType::Const => {
				if let Some(first) = opts.first() {
					let value = Self::resolve_const_opt(raw, first);
					Some(value)
				} else {
					None
				}
			}
			ArgType::Flags => {
				if let Some(opt) = opts.first() {
					let set = Self::resolve_flag_opt(raw, opt);
					Some(Value::new_flags(set))
				} else {
					log::warn!("no argopt to parse flags {atype:?}");
					None
				}
			}
			ArgType::Len | ArgType::Bitsize | ArgType::Bytesize => {
				if let Some(lenof) = opts.first() {
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
				}
			}
			ArgType::Ident(ident) => match ident.name.as_str() {
				"boolptr" => Some(Value::new_bool(raw != 0)),
				"buffer" => Some(Value::new_buffer(raw)),
				"fileoff" => Some(Value::new_file_offset(raw as usize)),
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
						Some(ret)
					} else {
						log::warn!("unable to parse second arg as FullArgument");
						None
					}
				} else {
					log::warn!("unable to get first opt as Direction {opts:?}");
					None
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
	fn parse_arg(raw: TargetPtr, arg: &Argument) -> Option<Value> {
		Self::parse_arg_type(raw, arg.arg_type(), &arg.opts)
	}
	pub fn enrich_values(&mut self) -> crate::Result<()> {
		if let Some(sys) = crate::SYSCALLS
			.read()
			.expect("unable to lock syscalls")
			.resolve(self.sysno)
		{
			for (i, arg) in sys.args.iter().enumerate() {
				let raw = self.args[i].raw_value();
				let ins = Self::parse_arg(raw, arg);
				self.args[i].value.parsed = ins;
			}

			if let Some(out) = &mut self.output {
				let opts = vec![ArgOpt::Dir(syzlang_parser::parser::Direction::Out)];
				let ins = Self::parse_arg_type(out.raw_value(), &sys.output, &opts);
				out.parsed = ins;
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
	fn resolve_resource_ident(raw: TargetPtr, ident: &Identifier, dir: Direction) -> Option<Value> {
		let basics = crate::PARSED
			.read()
			.expect("unable to lock parsed")
			.resource_to_basics(ident);
		log::trace!("basics {ident:?} ->  {basics:?}");
		if Self::argtypes_are_fd(ident, &basics) {
			let fd = utils::twos_complement(raw) as i32;
			let r = Value::new_fd(fd, dir);
			Some(r)
		} else if let Some(at) = basics.last().cloned() {
			let sub = Self::parse_arg_type(raw, &at, &[]);
			Some(Value::new_resource(ident.name.clone(), sub))
		} else {
			None
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
	fn resolve_const_opt(raw: TargetPtr, opt: &ArgOpt) -> Value {
		if let ArgOpt::Value(value) = opt {
			match value {
				parser::Value::Ident(ident) => {
					let n = Self::resolve_const_ident(&ident.name);
					let vi32 = utils::twos_complement(raw) as i32;
					let matches = n == raw || n as i32 == vi32;
					if matches {
						if ident.name == "AT_FDCWD" {
							Value::new_fd_const(vi32, "AT_FDCWD")
						} else {
							Value::new_const(matches, ident.name.clone())
						}
					} else if ident.name == "AT_FDCWD" {
						let value: serde_json::value::Number = vi32.into();
						let sub = Value::new_number(value, 32);
						Value::new_resource("fd", Some(sub))
					} else {
						crate::bug!("unable to find matching const {:?}", ident.name);
					}
				}
				parser::Value::Int(_n) => Value::new_int_ptrsize(raw),
				_ => crate::bug!("encountered {value:?} when trying to resolve const"),
			}
		} else {
			crate::bug!("encountered {opt:?} when trying to resolve const")
		}
	}
	fn resolve_flag_ident(raw: TargetPtr, ident: &Identifier) -> Vec<String> {
		let mut ret = Vec::new();
		let flag = crate::PARSED
			.read()
			.expect("unable to lock parsed")
			.get_flag(ident)
			.cloned();
		if let Some(flag) = flag {
			for val in flag.args() {
				match val {
					parser::Value::Int(_v) => todo!(),
					parser::Value::Ident(n) => {
						let v = Self::resolve_const_ident(&n.name);
						let ones = u64::count_ones(v);
						if ones > 1 {
							if v == raw {
								ret.push(n.name.clone());
							}
						} else if v == raw
							|| v as i32 == utils::twos_complement(raw) as i32
							|| (raw & v) == v
						{
							ret.push(n.name.clone());
						}
					}
					_ => crate::bug!("encountered {val:?} when trying to resolve flag ident"),
				}
			}
		}
		ret
	}
	fn resolve_flag_opt(raw: TargetPtr, opt: &ArgOpt) -> Vec<String> {
		match opt {
			ArgOpt::Ident(ident) => Self::resolve_flag_ident(raw, ident),
			_ => crate::bug!("encountered {opt:?} when trying to resolve flag opt"),
		}
	}
	fn resolve_const_ident(name: &str) -> TargetPtr {
		if let Some(r) = crate::PARSED
			.read()
			.expect("unable to lock parsed")
			.consts()
			.find_name_arch(name, &crate::syzarch())
		{
			match r.value() {
				parser::Value::Int(n) => *n as TargetPtr,
				_ => crate::bug!(
					"encountered {:?} when trying to resolve const ident",
					r.value()
				),
			}
		} else {
			crate::bug!("cosnt search for {name:?} returned None");
		}
	}

	pub fn from_regs(tid: Tid, regs: &dyn ReadRegisters) -> Self {
		let sysno = regs.sysno();
		let (name, args) = if let Some(sys) = crate::SYSCALLS
			.read()
			.expect("unable to lock syscalls")
			.resolve(sysno)
		{
			let mut shallows = Vec::new();
			for (i, arg) in sys.args.iter().enumerate() {
				let dir = arg.direction().into();
				let (_atype, _resource) = Self::get_shallow_value(arg.arg_type());
				let value = regs.arg_syscall(i);
				let ins = SysArg::new_basic(arg.identifier().safe_name(), value, dir);
				shallows.push(ins);
			}
			(sys.name.clone(), shallows)
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
	pub fn fill_in_output(&mut self, regs: &dyn ReadRegisters) {
		let retval = regs.ret_syscall();
		let ins = SysValue::new(retval, None);
		self.output = Some(ins);
	}
	fn get_shallow_value(arg: &ArgType) -> (ArgType, Option<Identifier>) {
		let (atype, resource) = if let ArgType::Ident(ident) = arg {
			if let Some(r) = crate::PARSED
				.read()
				.expect("unable to lock parsed")
				.resource_to_basic_type(ident)
			{
				log::debug!("refers to {r:?}");
				(r, Some(ident.clone()))
			} else {
				log::trace!("unknown refer");
				(arg.clone(), None)
			}
		} else {
			(arg.clone(), None)
		};
		(atype, resource)
	}
	pub fn as_nice_str(&self) -> String {
		let mut n = format!("[{}]: ", self.tid);
		if !self.name.is_empty() {
			n.push_str(&self.name);
		} else {
			n.push_str(&format!("{}", self.sysno));
		}
		n.push('(');

		let mut parts = Vec::new();
		for arg in self.args.iter() {
			let ins = arg.as_nice_str();
			parts.push(ins);
		}

		n.push_str(&parts.join(", "));

		n.push(')');

		if let Some(v) = &self.output {
			n.push_str(" = ");
			n.push_str(&v.as_nice_str());
		}
		n
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
}

#[derive(Debug)]
pub struct Syscall {
	pub name: String,
	pub sysno: TargetPtr,
	pub args: Vec<Argument>,
	pub output: ArgType,
}

impl Syscall {
	pub fn new(name: String, sysno: TargetPtr, args: Vec<Argument>, output: ArgType) -> Self {
		Self {
			name,
			sysno,
			args,
			output,
		}
	}
}

#[derive(Debug, Default)]
pub struct Syscalls {
	pub syscalls: HashMap<TargetPtr, Syscall>,
}

impl Syscalls {
	pub fn resolve(&self, sysno: TargetPtr) -> Option<&Syscall> {
		self.syscalls.get(&sysno)
	}
	pub fn resolve_sysno(&self, sysno: TargetPtr) -> Option<&String> {
		self.syscalls.get(&sysno).map(|x| &x.name)
	}
}

impl TryFrom<&syzlang_parser::parser::Parsed> for Syscalls {
	type Error = crate::Error;

	fn try_from(value: &syzlang_parser::parser::Parsed) -> std::result::Result<Self, Self::Error> {
		Self::try_from(value.clone())
	}
}

impl TryFrom<syzlang_parser::parser::Parsed> for Syscalls {
	type Error = crate::Error;

	fn try_from(
		mut value: syzlang_parser::parser::Parsed,
	) -> std::result::Result<Self, Self::Error> {
		#[cfg(debug_assertions)]
		{
			assert!(value
				.functions
				.extract_if(|x| { x.is_virtual() })
				.collect::<Vec<_>>()
				.is_empty());
			assert!(value
				.functions
				.extract_if(|x| { !x.name.subname.is_empty() })
				.collect::<Vec<_>>()
				.is_empty());
		}

		// We only care about the basic ones, not sub-specification of syscalls
		let syscalls = value
			.functions
			.into_iter()
			// .filter(|x| {x.name.subname.is_empty() /*&& value.consts.find_sysno(&x.name.name, &syzarch).is_some() */ })
			.map(|func| {
				if let Some(sysno) = value.consts.find_sysno(&func.name.name, &crate::syzarch()) {
					let ins = Syscall::new(func.name.name, sysno as u64, func.args, func.output);
					Some((sysno, ins))
				} else {
					None
				}
			})
			.filter(|x| x.is_some())
			.map(|x| {
				let r = x.expect("impossible");
				(r.0 as u64, r.1)
			})
			.collect::<HashMap<_, _>>();
		Ok(Self { syscalls })
	}
}

#[cfg(test)]
mod test {

	#[test]
	fn test_syscalls() {
		let _ret = crate::PARSED
			.read()
			.expect("unable to lock parsed")
			.consts
			.find_sysno("prctl", &crate::syzarch());

		let r = crate::SYSCALLS.read().expect("unable to lock syscalls");
		let _r = r.resolve(157);
	}
}
