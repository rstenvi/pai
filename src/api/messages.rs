use std::path::PathBuf;

use crate::{
	exe::elf::SymbolType,
	plugin::Plugin,
	syscalls::SyscallItem,
	trace::{Stop, Stopped},
	utils::{process::Tid, Perms},
	TargetPtr,
};
use serde::{Deserialize, Serialize};

use super::Args;

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
		fd: i64,
	},
	FileClosed {
		fname: String,
		fd: i64,
	},
	PluginLoad {
		ptype: Plugin,
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
			EventInner::PluginLoad { ptype, id } => {
				f.write_fmt(format_args!("PluginLoad({ptype}) -> {id}"))
			}
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
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ExecSyscall {
	Getpid,
	MmapAnon { size: usize, prot: Perms },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ThreadCmd {
	/// Get all registers
	GetLibcRegs,

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
	},

	/// Remove the breakpoint inserted at addr.
	RemoveBp {
		addr: TargetPtr,
	},

	// Get a single register, the argument is architecture agnostic
	// GetAgnosticReg { reg: AgnoReg },
	CallFunc {
		func: TargetPtr,
		args: Vec<TargetPtr>,
	},
	ExecRawSyscall {
		sysno: TargetPtr,
		args: Vec<TargetPtr>,
	},

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
	pub fn call_func(func: TargetPtr, args: Vec<TargetPtr>) -> Self {
		Self::CallFunc { func, args }
	}
	pub fn syscall(sysno: TargetPtr, args: Vec<TargetPtr>) -> Self {
		Self::ExecRawSyscall { sysno, args }
	}
	pub fn read_bytes(addr: TargetPtr, count: usize) -> Self {
		Self::ReadBytes { addr, count }
	}
	pub fn write_bytes(addr: TargetPtr, bytes: Vec<u8>) -> Self {
		Self::WriteBytes { addr, bytes }
	}
	pub fn insert_bp(addr: TargetPtr) -> Self {
		Self::InsertBp { addr }
	}
	pub fn remove_bp(addr: TargetPtr) -> Self {
		Self::RemoveBp { addr }
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
	pub fn call_func(tid: Tid, func: TargetPtr, args: Vec<TargetPtr>) -> Self {
		let cmd = ThreadCmd::call_func(func, args);
		Self::Thread { tid, cmd }
	}
	pub fn syscall(tid: Tid, sysno: TargetPtr, args: Vec<TargetPtr>) -> Self {
		let cmd = ThreadCmd::syscall(sysno, args);
		Self::Thread { tid, cmd }
	}
	pub fn get_pid() -> Self {
		let cmd = ProcessCmd::GetPid;
		Self::Process { cmd }
	}
	pub fn insert_bp(tid: Tid, addr: TargetPtr) -> Self {
		let cmd = ThreadCmd::insert_bp(addr);
		Self::Thread { tid, cmd }
	}
	pub fn remove_bp(tid: Tid, addr: TargetPtr) -> Self {
		let cmd = ThreadCmd::remove_bp(addr);
		Self::Thread { tid, cmd }
	}
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
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ClientCmd {
	ResolveEntry,
	StoppedTids,
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
	SetConfig { config: Args },
	SetConfigThread { tid: Tid, config: Args },
	GetConfig,
	GetConfigThread { tid: Tid },
	ResolveSyscall(String),
	Detach,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ManagerCmd {
	Wait,
	Detach,
	DetachThread { tid: Tid },
	InitDone,
	PrepareLoadClient,
	SendEvent { event: Event },
	RemoveClient { cid: usize },
	SetConfig { config: Args },
	SetConfigThread { tid: Tid, config: Args },
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
	Syscall(SyscallItem),
	Stopped(Stopped),
	TargetExit,
	Removed,
}

impl TryFrom<Response> for serde_json::Value {
	type Error = crate::Error;

	fn try_from(value: Response) -> Result<Self, Self::Error> {
		match value {
			Response::Value(v) => Ok(v),
			_ => Err(Self::Error::Unknown),
		}
	}
}
