//! A collection of `struct`'s and `enum`'s which can be serialized/deserialized
//! and sent over a channel.
use std::path::PathBuf;

use crate::{
	target::Target,
	utils::{process::Tid, Perms},
	Error, Result, TargetPtr,
};
use serde::{Deserialize, Serialize};

use super::Args;

/// To perform certain tasks in the tracee, we rely on some trampoline code
/// snippets.
///
/// The script can query the location of these and also modify the assembly
/// snippets used.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum TrampType {
	/// Trigger syscall
	Syscall,

	/// Call a function in a pre-determined register.
	Call,

	/// Return from function
	Ret,
}

/// On callback functions for hooks and system calls, [CbAction] determines the
/// next steps to take.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum CbAction {
	/// Continue as usual
	None,

	/// Remove the hook
	Remove,

	/// Return without executing the function/syscall and set return value to
	/// `ret`
	EarlyRet { ret: TargetPtr },
}

/// On breakpoints, [BpRet] determines next action.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum BpRet {
	/// Keep the breakpoint
	Keep,

	/// Remove the breakpoint
	Remove,
}

/// Type of symbol, read ELF-specification for more details
#[repr(u8)]
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum SymbolType {
	NoType = 0,
	Object = 1,
	Func = 2,
	Section = 3,
	File = 4,
	Common = 5,
	Tls = 6,
	Unknown = 255,
}
impl From<u8> for SymbolType {
	fn from(value: u8) -> Self {
		match value {
			0 => Self::NoType,
			1 => Self::Object,
			2 => Self::Func,
			3 => Self::Section,
			4 => Self::File,
			5 => Self::Common,
			6 => Self::Tls,
			_ => Self::Unknown,
		}
	}
}
impl From<SymbolType> for u8 {
	fn from(value: SymbolType) -> Self {
		value as u8
	}
}

/// Details about one resolved symbol
#[derive(Clone, Serialize, Deserialize)]
pub struct ElfSymbol {
	pub name: String,
	pub value: TargetPtr,
	pub stype: SymbolType,
	pub bind: SymbolBind,
}

impl std::fmt::Debug for ElfSymbol {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ElfSymbol")
			.field("name", &self.name)
			.field("value", &format_args!("{:x}", self.value))
			.field("stype", &self.stype)
			.field("bind", &self.bind)
			.finish()
	}
}

impl ElfSymbol {
	pub fn add_value(&mut self, val: TargetPtr) {
		self.value += val;
	}
}

/// Symbol binding, read ELF-specification for more details
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum SymbolBind {
	Local = 0,
	Global = 1,
	Weak = 2,
	Unknown = 255,
}
impl From<u8> for SymbolBind {
	fn from(value: u8) -> Self {
		match value {
			0 => Self::Local,
			1 => Self::Global,
			2 => Self::Weak,
			_ => Self::Unknown,
		}
	}
}

#[derive(Debug)]
pub(crate) struct MasterComm {
	pub client: usize,
	pub cmd: Command,
}

impl MasterComm {
	pub fn new(client: usize, cmd: Command) -> Self {
		Self { client, cmd }
	}
}

/// Different types of events one can register to receive.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum RegEvent {
	Clone,
	Fork,
	Attached,
	Signal(i32),
	SyscallEnter,
	SyscallExit,
	Syscall(Option<TargetPtr>),
	Files,
	PluinLoad,
	Dlopen,
	Prctl,
	// Read,
	Mmap,
	// MsgLog,
}
impl RegEvent {
	#[allow(non_snake_case)]
	pub(crate) fn SIGKILL() -> Self {
		Self::Signal(libc::SIGKILL)
	}

	pub(crate) fn from_event(event: &EventInner) -> Self {
		match event {
			EventInner::FileOpened { fname: _, fd: _ } => Self::Files,
			EventInner::FileClosed { fname: _, fd: _ } => Self::Files,
			#[cfg(feature = "plugins")]
			EventInner::PluginLoad { ptype: _, id: _ } => Self::PluinLoad,
			EventInner::Dlopen { fname: _ } => Self::Dlopen,
			EventInner::Prctl { event: _ } => Self::Prctl,
			// EventInner::Read {
			// 	fname: _,
			// 	addr: _,
			// 	bytes: _,
			// 	offset: _,
			// } => Self::Read,
			EventInner::Mmap {
				addr: _,
				size: _,
				prot: _,
				flags: _,
				fd: _,
				offset: _,
			} => Self::Mmap,
			// EventInner::MsgLog { source: _, msg: _ } => Self::MsgLog,
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum EventPrctl {
	SetName {
		name: String,
	},
	SetVmaAnonName {
		name: String,
		addr: TargetPtr,
		size: usize,
	},
	Unknown {
		option: i32,
	},
	GetDumpable,
}

impl std::fmt::Display for EventPrctl {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			EventPrctl::SetName { name } => f.write_fmt(format_args!("SetName({name})")),
			EventPrctl::SetVmaAnonName { name, addr, size } => {
				f.write_fmt(format_args!("SetVmaAnonName({name}, {addr:x}, {size:x})"))
			}
			EventPrctl::Unknown { option } => f.write_fmt(format_args!("Unknown({option})")),
			EventPrctl::GetDumpable => f.write_fmt(format_args!("GetDumpable)")),
		}
	}
}

#[cfg(feature = "syscalls")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum LenType {
	Len,
	Bytesize,
	Bitsize,
}

#[cfg(feature = "syscalls")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValueLen {
	ltype: LenType,
	value: TargetPtr,
}
#[cfg(feature = "syscalls")]
impl std::fmt::Display for ValueLen {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("len({}, 0x{:x})", self.ltype, self.value))
	}
}
#[cfg(feature = "syscalls")]
impl ValueLen {
	pub(crate) fn new(ltype: LenType, value: TargetPtr) -> Self {
		Self { ltype, value }
	}
	pub fn bytes(&self, itemsz: usize) -> usize {
		let v: usize = self.value.into();
		match self.ltype {
			LenType::Len => itemsz * v,
			LenType::Bytesize => v,
			LenType::Bitsize => v / 8,
		}
	}
}

#[cfg(feature = "syscalls")]
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
		arg: syzlang_parser::parser::ArgType,
		opts: Vec<syzlang_parser::parser::ArgOpt>,
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
	// Stat {
	// 	stat: libc_stat,
	// },
	Bool {
		value: bool,
	},
	Buffer {
		ptr: TargetPtr,
	},

	FileOffset {
		offset: usize,
	},

	Struct {
		name: String,
		value: serde_json::Value,
	},

	ParsedPtr {
		old: Box<Self>,
		value: Box<Self>,
	},
}

#[cfg(feature = "syscalls")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Direction {
	In,
	Out,
	InOut,
}

#[cfg(feature = "syscalls")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SysValue {
	pub raw_value: TargetPtr,
	pub parsed: Option<Value>,
}

#[cfg(feature = "syscalls")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SysArg {
	pub name: String,
	pub(crate) value: SysValue,
	pub(crate) dir: Direction,
}

#[cfg(feature = "syscalls")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SyscallItem {
	pub tid: Tid,
	pub sysno: usize,
	pub name: String,
	pub args: Vec<SysArg>,
	pub output: Option<SysValue>,
}

/// All the different reasons the target may have stopped.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum Stop {
	SyscallEnter,
	SyscallExit,
	Exit { code: i32 },
	Signal { signal: i32, group: bool },
	Clone { pid: Tid },
	Attach,
	Breakpoint { pc: TargetPtr },
	Fork { newpid: Tid },
	Step { pc: TargetPtr },
	Exec { old: Tid },
	Signalling { signal: i32, core_dumped: bool },
	VforkStart { new: Tid },
	VforkDone { new: Tid },
	Seccomp { data: u16 },
}

/// Whenever the target stops, this struct describes the current state.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Stopped {
	pub pc: TargetPtr,
	pub stop: Stop,
	pub tid: Tid,
}
impl std::fmt::Debug for Stopped {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Stopped")
			.field("pc", &format_args!("0x{:x}", self.pc))
			.field("stop", &self.stop)
			.field("tid", &self.tid)
			.finish()
	}
}
impl TryFrom<Response> for Stopped {
	type Error = crate::Error;

	fn try_from(value: Response) -> std::result::Result<Self, Self::Error> {
		if let Response::Stopped(s) = value {
			Ok(s)
		} else {
			Err(Self::Error::msg("cannot find Stopped in Response"))
		}
	}
}
impl std::fmt::Display for Stopped {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!(
			"[{}]: {:?} @ 0x{:x}",
			self.tid, self.stop, self.pc
		))
	}
}

impl Stopped {
	pub(crate) fn new(pc: TargetPtr, stop: Stop, tid: Tid) -> Self {
		Self { pc, stop, tid }
	}
}

/// An event which has happened on the target.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Event {
	pub tid: Option<Tid>,
	pub event: EventInner,
}
impl std::fmt::Display for Event {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("[{}]: {}", self.tid.unwrap_or(0), self.event))
	}
}
impl Event {
	pub(crate) fn new(event: EventInner) -> Self {
		Self { tid: None, event }
	}
	pub(crate) fn new_attached(tid: Tid, event: EventInner) -> Self {
		Self {
			tid: Some(tid),
			event,
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum EventInner {
	FileOpened {
		fname: String,
		fd: isize,
	},
	FileClosed {
		fname: String,
		fd: isize,
	},
	#[cfg(feature = "plugins")]
	PluginLoad {
		ptype: crate::plugin::Plugin,
		id: usize,
	},
	Dlopen {
		fname: String,
	},
	Prctl {
		event: EventPrctl,
	},
	// Read {
	// 	fname: String,
	// 	addr: TargetPtr,
	// 	bytes: usize,
	// 	offset: usize,
	// },
	Mmap {
		addr: TargetPtr,
		size: TargetPtr,
		prot: TargetPtr,
		flags: TargetPtr,
		fd: TargetPtr,
		offset: TargetPtr,
	},
	// MsgLog {
	// 	source: String,
	// 	msg: serde_json::Value,
	// },
}

impl std::fmt::Display for EventInner {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			EventInner::FileOpened { fname, fd } => {
				f.write_fmt(format_args!("FileOpened({fname}) -> {fd}"))
			}
			EventInner::FileClosed { fname, fd } => {
				f.write_fmt(format_args!("FileClosed({fname}) -> {fd}"))
			}
			#[cfg(feature = "plugins")]
			EventInner::PluginLoad { ptype, id } => f.write_fmt(format_args!("PluginLoad({ptype}) -> {id}")),
			EventInner::Dlopen { fname } => f.write_fmt(format_args!("Dlopen({fname})")),
			EventInner::Prctl { event } => f.write_fmt(format_args!("Prctl({event})")),
			// EventInner::Read {
			// 	fname: _,
			// 	addr: _,
			// 	bytes: _,
			// 	offset: _,
			// } => todo!(),
			EventInner::Mmap {
				addr,
				size,
				prot,
				flags,
				fd,
				offset,
			} => f.write_fmt(format_args!(
				"Mmap(0x{addr:x}, 0x{size:x}, {prot:?}, {flags}, 0x{fd:x} 0x{offset:x})"
			)),
			// EventInner::MsgLog { source: _, msg: _ } => todo!(),
		}
	}
}

/// The different states threads can be in.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ThreadStatus {
	Running,
	Stopped(Stop),
}
impl ThreadStatus {
	pub fn is_running(&self) -> bool {
		matches!(self, Self::Running)
	}
	pub fn is_stopped(&self) -> bool {
		matches!(self, Self::Stopped(_))
	}
}

/// Information about a thread on the target.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Thread {
	pub id: Tid,
	pub status: ThreadStatus,
}
impl Thread {
	pub fn new(id: Tid, status: ThreadStatus) -> Self {
		Self { id, status }
	}
}

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub(crate) enum Wait {
	#[default]
	Cont,
	Syscall,

	// Step is not supported on arm, see link below for more details.
	// https://stackoverflow.com/a/25268484
	Step,
}

impl From<Wait> for pete::Restart {
	fn from(value: Wait) -> Self {
		match value {
			Wait::Cont => pete::Restart::Continue,
			Wait::Syscall => pete::Restart::Syscall,
			Wait::Step => pete::Restart::Step,
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
enum StrMatch {
	Equal,
	EndsWith,
	StartsWith,
	Contains,
}

impl StrMatch {
	pub fn matches(&self, _base: &str, _test: &str) -> bool {
		todo!();
	}
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
struct Search {
	s: String,
	m: StrMatch,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ProcessCmd {
	GetTids,
	GetThreadsStatus,
	GetPid,
	SetTrampolineCode { tramp: TrampType, code: Vec<u8> },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ExecSyscall {
	Getpid,
	MmapAnon { size: usize, prot: Perms },
}
impl ExecSyscall {
	#[cfg(feature = "syscalls")]
	pub fn as_sysno(&self) -> Result<usize> {
		let arch = Target::arch();
		let name = match self {
			ExecSyscall::Getpid => "getpid",
			ExecSyscall::MmapAnon { size: _, prot: _ } => "mmap",
		};

		let num = crate::SYSCALLS
			.read()
			.unwrap()
			.name_to_sysno(arch, name)
			.ok_or(Error::NotFound)?;

		Ok(num)
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum BpType {
	SingleUse,
	Recurring,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ThreadCmd {
	/// Get all registers
	GetRegisters,

	/// Set all registers
	SetRegisters {
		regs: Box<crate::Registers>,
	},

	GetTrampolineAddr {
		tramp: TrampType,
	},

	RunUntilTrap,

	/// Step one single instruction
	StepIns {
		count: usize,
	},

	/// Read memory address as a NULL-terminated C-string
	ReadCString {
		addr: TargetPtr,
	},

	ReadBytes {
		addr: TargetPtr,
		count: usize,
	},

	WriteBytes {
		addr: TargetPtr,
		bytes: Vec<u8>,
	},

	/// Insert breakpoint at addr, when hit id is returned as well as the
	/// address.
	///
	/// This command is associated with a thread because we need a stopped
	/// thread to insert the breakpoint. The actual breakpoint will trigger on
	/// all running and future threads.
	InsertBp {
		addr: TargetPtr,
		bptype: BpType,
	},

	/// Allocate some executable region and write a breakpoint to it, returning
	/// the address back to the caller.
	AllocAndWriteBp,

	// Remove the breakpoint inserted at addr.
	// RemoveBp {
	// 	addr: TargetPtr,
	// },

	// Get a single register, the argument is architecture agnostic
	// GetAgnosticReg { reg: AgnoReg },
	// CallFunc {
	// 	func: TargetPtr,
	// 	args: Vec<TargetPtr>,
	// },
	ExecRawSyscall {
		sysno: usize,
		args: Vec<TargetPtr>,
	},
	ExecRet,

	#[cfg(feature = "syscalls")]
	ExecSyscall {
		syscall: ExecSyscall,
	},

	WriteScratchBytes {
		bytes: Vec<u8>,
	},
	WriteScratchString {
		string: String,
	},
	FreeScratchAddr {
		addr: TargetPtr,
	},
}

impl ThreadCmd {
	pub fn read_c_string(addr: TargetPtr) -> Self {
		Self::ReadCString { addr }
	}
	pub fn exec_ret() -> Self {
		Self::ExecRet
	}
	pub fn write_scratch_string<S: Into<String>>(string: S) -> Self {
		Self::WriteScratchString {
			string: string.into(),
		}
	}
	pub fn write_scratch_bytes<S: Into<Vec<u8>>>(bytes: S) -> Self {
		Self::WriteScratchBytes {
			bytes: bytes.into(),
		}
	}
	pub fn free_scratch_addr(addr: TargetPtr) -> Self {
		Self::FreeScratchAddr { addr }
	}
	pub fn syscall(sysno: usize, args: Vec<TargetPtr>) -> Self {
		Self::ExecRawSyscall { sysno, args }
	}
	pub fn read_bytes(addr: TargetPtr, count: usize) -> Self {
		Self::ReadBytes { addr, count }
	}
	pub fn write_bytes(addr: TargetPtr, bytes: Vec<u8>) -> Self {
		Self::WriteBytes { addr, bytes }
	}
	pub fn insert_single_use_bp(addr: TargetPtr) -> Self {
		Self::InsertBp {
			addr,
			bptype: BpType::SingleUse,
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum RemoteCmd {
	Process { cmd: ProcessCmd },
	Thread { tid: Tid, cmd: ThreadCmd },
}

impl RemoteCmd {
	pub fn get_tids() -> Self {
		let cmd = ProcessCmd::GetTids;
		Self::Process { cmd }
	}
	pub fn write_scratch_string<S: Into<String>>(tid: Tid, string: S) -> Self {
		let cmd = ThreadCmd::write_scratch_string(string);
		Self::Thread { tid, cmd }
	}
	pub fn write_scratch_bytes<S: Into<Vec<u8>>>(tid: Tid, bytes: S) -> Self {
		let cmd = ThreadCmd::write_scratch_bytes(bytes);
		Self::Thread { tid, cmd }
	}
	pub fn free_scratch_addr(tid: Tid, addr: TargetPtr) -> Self {
		let cmd = ThreadCmd::free_scratch_addr(addr);
		Self::Thread { tid, cmd }
	}
	// pub fn call_func(tid: Tid, func: TargetPtr, args: Vec<TargetPtr>) -> Self {
	// 	let cmd = ThreadCmd::call_func(func, args);
	// 	Self::Thread { tid, cmd }
	// }
	pub fn syscall(tid: Tid, sysno: usize, args: Vec<TargetPtr>) -> Self {
		let cmd = ThreadCmd::syscall(sysno, args);
		Self::Thread { tid, cmd }
	}
	pub fn get_pid() -> Self {
		let cmd = ProcessCmd::GetPid;
		Self::Process { cmd }
	}
	pub fn insert_bp(tid: Tid, addr: TargetPtr) -> Self {
		let cmd = ThreadCmd::insert_single_use_bp(addr);
		Self::Thread { tid, cmd }
	}
	pub fn alloc_and_write_bp(tid: Tid) -> Self {
		let cmd = ThreadCmd::AllocAndWriteBp;
		Self::Thread { tid, cmd }
	}
	// pub fn remove_bp(tid: Tid, addr: TargetPtr) -> Self {
	// 	let cmd = ThreadCmd::remove_bp(addr);
	// 	Self::Thread { tid, cmd }
	// }
	pub fn read_bytes(tid: Tid, addr: TargetPtr, bytes: usize) -> Self {
		let cmd = ThreadCmd::read_bytes(addr, bytes);
		Self::Thread { tid, cmd }
	}
	pub fn write_bytes<B: Into<Vec<u8>>>(tid: Tid, addr: TargetPtr, bytes: B) -> Self {
		let cmd = ThreadCmd::write_bytes(addr, bytes.into());
		Self::Thread { tid, cmd }
	}
	pub fn read_c_string(tid: Tid, addr: TargetPtr) -> Self {
		let cmd = ThreadCmd::read_c_string(addr);
		Self::Thread { tid, cmd }
	}
	pub fn exec_ret(tid: Tid) -> Self {
		let cmd = ThreadCmd::exec_ret();
		Self::Thread { tid, cmd }
	}
	pub fn get_threads_status() -> Self {
		let cmd = ProcessCmd::GetThreadsStatus;
		Self::Process { cmd }
	}
	pub fn get_registers(tid: Tid) -> Self {
		Self::Thread {
			tid,
			cmd: ThreadCmd::GetRegisters,
		}
	}
	pub fn get_trampoline_addr(tid: Tid, tramp: TrampType) -> Self {
		Self::Thread {
			tid,
			cmd: ThreadCmd::GetTrampolineAddr { tramp },
		}
	}
	pub fn run_until_trap(tid: Tid) -> Self {
		Self::Thread {
			tid,
			cmd: ThreadCmd::RunUntilTrap,
		}
	}
	pub fn set_trampoline_code(tramp: TrampType, code: Vec<u8>) -> Self {
		Self::Process {
			cmd: ProcessCmd::SetTrampolineCode { tramp, code },
		}
	}
	pub fn set_registers(tid: Tid, regs: crate::Registers) -> Self {
		Self::Thread {
			tid,
			cmd: ThreadCmd::SetRegisters {
				regs: Box::new(regs),
			},
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ClientCmd {
	ResolveEntry,
	FirstStoppedTid,
	GetModule { path: PathBuf },
	ResolveSymbol { path: PathBuf, symbol: String },
	SymbolsOfType { path: PathBuf, symtype: SymbolType },
}

#[derive(Debug, Clone)]
pub(crate) enum NewClientReq {
	Regular,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ClientProxy {
	SetConfig {
		config: Args,
	},
	SetConfigThread {
		tid: Tid,
		config: Args,
	},
	GetConfig,
	GetConfigThread {
		tid: Tid,
	},
	#[cfg(feature = "syscalls")]
	ResolveSyscall(String),
	Detach,

	AddLogger {
		format: LogFormat,
		output: LogOutput,
	},
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum LogFormat {
	Display,
	Json,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum LogOutput {
	File { path: PathBuf },
	Tcp { addr: std::net::SocketAddr },
}
impl LogOutput {
	pub fn file<P: Into<PathBuf>>(path: P) -> Self {
		let path = path.into();
		Self::File { path }
	}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ManagerCmd {
	Wait,
	Detach,
	DetachThread {
		tid: Tid,
	},
	InitDone,
	PrepareLoadClient,
	SendEvent {
		event: Event,
	},
	RemoveClient {
		cid: usize,
	},
	SetConfig {
		config: Args,
	},
	SetConfigThread {
		tid: Tid,
		config: Args,
	},
	AddLogger {
		format: LogFormat,
		output: LogOutput,
	},
}

/// All the allowable commands to control the tracee.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Command {
	/// Commands targeting the traced process
	Tracer {
		cmd: RemoteCmd,
	},
	Client {
		tid: Tid,
		cmd: ClientCmd,
	},
	Manager {
		cmd: ManagerCmd,
	},
	ClientProxy {
		cmd: ClientProxy,
	},
}

impl Command {
	pub fn detach_thread(tid: Tid) -> Self {
		let cmd = ManagerCmd::DetachThread { tid };
		Self::Manager { cmd }
	}
	pub fn add_logger(format: LogFormat, output: LogOutput) -> Self {
		let cmd = ClientProxy::AddLogger { format, output };
		Self::ClientProxy { cmd }
	}
	pub fn prepare_load_client() -> Self {
		let cmd = ManagerCmd::PrepareLoadClient;
		Self::Manager { cmd }
	}
	pub fn send_event(event: Event) -> Self {
		let cmd = ManagerCmd::SendEvent { event };
		Self::Manager { cmd }
	}
	pub fn wait() -> Self {
		let cmd = ManagerCmd::Wait;
		Self::Manager { cmd }
	}
	pub fn detach() -> Self {
		let cmd = ClientProxy::Detach;
		Self::ClientProxy { cmd }
	}
	pub fn init_done() -> Self {
		let cmd = ManagerCmd::InitDone;
		Self::Manager { cmd }
	}
	pub fn remove_client(cid: usize) -> Self {
		let cmd = ManagerCmd::RemoveClient { cid };
		Self::Manager { cmd }
	}
	pub fn set_config(config: Args) -> Self {
		let cmd = ClientProxy::SetConfig { config };
		Self::ClientProxy { cmd }
	}
	pub fn set_config_thread(tid: Tid, config: Args) -> Self {
		let cmd = ClientProxy::SetConfigThread { tid, config };
		Self::ClientProxy { cmd }
	}
	pub fn get_config() -> Self {
		let cmd = ClientProxy::GetConfig;
		Self::ClientProxy { cmd }
	}
	pub fn get_config_thread(tid: Tid) -> Self {
		let cmd = ClientProxy::GetConfigThread { tid };
		Self::ClientProxy { cmd }
	}
	#[cfg(feature = "syscalls")]
	pub fn resolve_syscall<S: Into<String>>(s: S) -> Self {
		let cmd = ClientProxy::ResolveSyscall(s.into());
		Self::ClientProxy { cmd }
	}
	pub fn manager(cmd: ManagerCmd) -> Self {
		Self::Manager { cmd }
	}
}

/// All the possible responses to a [Command].
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum Response {
	Ack,
	Value(serde_json::Value),
	Event(Event),
	Error(String),
	#[cfg(feature = "syscalls")]
	Syscall(SyscallItem),
	Stopped(Stopped),
	TargetExit,
	Removed,
}

impl TryFrom<Response> for serde_json::Value {
	type Error = crate::Error;

	fn try_from(value: Response) -> std::result::Result<Self, Self::Error> {
		match value {
			Response::Value(v) => Ok(v),
			_ => Err(Self::Error::Unknown),
		}
	}
}
