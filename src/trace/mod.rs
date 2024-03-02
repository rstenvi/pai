use crate::api::messages::BpType;
use crate::api::messages::Thread;
use crate::api::messages::TrampType;
use crate::buildinfo::BuildArch;
use crate::utils::Location;
use crate::utils::Perms;
use crate::TargetPtr;

pub mod ptrace;

pub struct SwBp {
	addr: TargetPtr,
	oldcode: Vec<u8>,
	numhits: Option<usize>,
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
	pub fn new_singleuse(addr: TargetPtr, oldcode: Vec<u8>) -> Self {
		Self {
			addr,
			oldcode,
			numhits: Some(1),
		}
	}
	pub fn new_recurr(addr: TargetPtr, oldcode: Vec<u8>) -> Self {
		Self {
			addr,
			oldcode,
			numhits: None,
		}
	}
	pub fn new_limit(addr: TargetPtr, oldcode: Vec<u8>, numhits: usize) -> Self {
		Self {
			addr,
			oldcode,
			numhits: Some(numhits),
		}
	}
	pub fn hit(&mut self) {
		if let Some(n) = &mut self.numhits {
			if *n == 0 {
				log::trace!("hit BP after set to 0");
			} else {
				*n -= 1;
			}
		}
	}
	pub fn should_remove(&self) -> bool {
		self.numhits == Some(0)
	}
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Tracer {
	Ptrace,
}
impl Tracer {}

use crate::utils::process::{Pid, Tid};
use crate::Result;

pub trait TracerApiMeta {
	fn replace_tramp_code(&mut self, t: TrampType, code: Vec<u8>) -> Result<()>;
	fn target_arch(&mut self) -> BuildArch;
}
pub trait TracerApiProc {
	fn get_threads(&mut self) -> Result<Vec<Thread>>;
	fn get_pid(&mut self) -> Result<Pid>;
}
pub trait TracerApiStopped {
	fn alloc_scratch(&mut self, tid: Tid, size: usize, perms: Perms) -> Result<Location>;
	fn free_scratch(&mut self, tid: Tid, loc: Location) -> Result<()>;

	fn write_memory(&mut self, tid: Tid, addr: TargetPtr, data: &[u8]) -> Result<usize>;
	fn read_memory(&mut self, tid: Tid, addr: TargetPtr, data: &mut Vec<u8>) -> Result<usize>;
	fn read_c_str(&mut self, tid: Tid, addr: TargetPtr) -> Result<String>;

	fn exec_tramp(&mut self, tid: Tid, t: TrampType) -> Result<()>;

	fn get_regs(&mut self, tid: Tid) -> Result<crate::Registers>;
	fn set_regs(&mut self, tid: Tid, regs: crate::Registers) -> Result<()>;

	fn insert_bp(&mut self, tid: Tid, addr: TargetPtr, t: BpType) -> Result<()>;
	fn remove_bp(&mut self, tid: Tid, addr: TargetPtr) -> Result<()>;
}

trait TracerApi: TracerApiMeta + TracerApiProc + TracerApiStopped {}
