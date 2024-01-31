use serde::{Deserialize, Serialize};

use crate::{utils::process::Tid, TargetPtr};

pub mod ptrace;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum Stop {
	SyscallEnter,
	SyscallExit,

	// SyscallDone { sysno: usize, ret: TargetPtr },
	Exit { code: i32 },
	Signal { signal: i32, group: bool },
	Clone { pid: Tid },
	Attach,
	Breakpoint { pc: u64, clients: Vec<usize> },
	Fork { newpid: Tid },
	Step { pc: TargetPtr },
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

pub struct SwBp {
	addr: TargetPtr,
	oldcode: Vec<u8>,
	numhits: Option<usize>,
	clients: Vec<usize>,
}
impl std::fmt::Debug for SwBp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SwBp")
			.field("addr", &format_args!("{:x}", self.addr))
			.field("oldcode", &self.oldcode)
			.finish()
	}
}
impl SwBp {
	pub fn new_recurr(addr: TargetPtr, oldcode: Vec<u8>) -> Self {
		Self {
			addr,
			oldcode,
			numhits: None,
			clients: Vec::new(),
		}
	}
	pub fn new_limit(addr: TargetPtr, oldcode: Vec<u8>, numhits: usize) -> Self {
		Self {
			addr,
			oldcode,
			numhits: Some(numhits),
			clients: Vec::new(),
		}
	}
	pub fn add_client(&mut self, cid: usize) {
		self.clients.push(cid);
	}
	pub fn hit(&mut self) {
		if let Some(n) = &mut self.numhits {
			if *n == 0 {
				log::error!("hit BP after set to 0");
			} else {
				*n -= 1;
			}
		}
	}
	pub fn should_remove(&self) -> bool {
		self.numhits == Some(0)
	}
}
