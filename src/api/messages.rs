//! A collection of `struct`'s and `enum`'s which can be serialized/deserialized
//! and sent over a channel.
use std::path::PathBuf;

use crate::{
	target::Target,
	utils::{process::Tid, Perms},
	Error, Result, TargetPtr,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "syscalls")]
use crate::syscalls::SyscallItem;

use super::Args;

#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum TrampType {
	Syscall,
	Call,
	Ret,
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum CbAction {
	None,
	Remove,
	EarlyRet { ret: TargetPtr },
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum BpRet {
	Keep,
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
pub struct MasterComm {
	pub client: usize,
	pub cmd: Command,
}

impl MasterComm {
	pub fn new(client: usize, cmd: Command) -> Self {
		Self { client, cmd }
	}
}

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
	Read,
	Mmap,
	MsgLog,
}
impl RegEvent {
	#[allow(non_snake_case)]
	pub fn SIGKILL() -> Self {
		Self::Signal(libc::SIGKILL)
	}

	pub fn from_event(event: &EventInner) -> Self {
		match event {
			EventInner::FileOpened { fname: _, fd: _ } => Self::Files,
			EventInner::FileClosed { fname: _, fd: _ } => Self::Files,
			#[cfg(feature = "plugins")]
			EventInner::PluginLoad { ptype: _, id: _ } => Self::PluinLoad,
			EventInner::Dlopen { fname: _ } => Self::Dlopen,
			EventInner::Prctl { event: _ } => Self::Prctl,
			EventInner::Read {
				fname: _,
				addr: _,
				bytes: _,
				offset: _,
			} => Self::Read,
			EventInner::Mmap {
				addr: _,
				size: _,
				prot: _,
				flags: _,
				fd: _,
				offset: _,
			} => Self::Mmap,
			EventInner::MsgLog { source: _, msg: _ } => Self::MsgLog,
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

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum Stop {
	SyscallEnter,
	SyscallExit,

	// SyscallDone { sysno: usize, ret: TargetPtr },
	Exit {
		code: i32,
	},
	Signal {
		signal: i32,
		group: bool,
	},
	Clone {
		pid: Tid,
	},
	Attach,
	Breakpoint {
		pc: TargetPtr,
	},
	Fork {
		newpid: Tid,
	},
	Step {
		pc: TargetPtr,
	},
	Exec {
		old: Tid,
	},
}

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
	pub fn new(pc: TargetPtr, stop: Stop, tid: Tid) -> Self {
		Self { pc, stop, tid }
	}
}

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
	pub fn new(event: EventInner) -> Self {
		Self { tid: None, event }
	}
	pub fn new_attached(tid: Tid, event: EventInner) -> Self {
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
	Read {
		fname: String,
		addr: TargetPtr,
		bytes: usize,
		offset: usize,
	},
	Mmap {
		addr: TargetPtr,
		size: TargetPtr,
		prot: TargetPtr,
		flags: TargetPtr,
		fd: TargetPtr,
		offset: TargetPtr,
	},
	MsgLog {
		source: String,
		msg: serde_json::Value,
	},
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
			EventInner::Read {
				fname: _,
				addr: _,
				bytes: _,
				offset: _,
			} => todo!(),
			EventInner::Mmap {
				addr: _,
				size: _,
				prot: _,
				flags: _,
				fd: _,
				offset: _,
			} => todo!(),
			EventInner::MsgLog { source: _, msg: _ } => todo!(),
		}
	}
}

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
pub enum Cont {
	#[default]
	Cont,
	Syscall,

	// Step is not supported on arm, see link below for more details.
	// https://stackoverflow.com/a/25268484
	Step,
}

impl From<Cont> for pete::Restart {
	fn from(value: Cont) -> Self {
		match value {
			Cont::Cont => pete::Restart::Continue,
			Cont::Syscall => pete::Restart::Syscall,
			Cont::Step => pete::Restart::Step,
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum StrMatch {
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
pub struct Search {
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
			ExecSyscall::MmapAnon { size, prot } => "mmap",
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
	GetLibcRegs,

	/// Set all registers
	SetLibcRegs {
		regs: crate::Registers,
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
	pub fn get_libc_regs(tid: Tid) -> Self {
		Self::Thread {
			tid,
			cmd: ThreadCmd::GetLibcRegs,
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
	pub fn set_libc_regs(tid: Tid, regs: crate::Registers) -> Self {
		Self::Thread {
			tid,
			cmd: ThreadCmd::SetLibcRegs { regs },
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
pub enum NewClientReq {
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
