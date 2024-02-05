use serde::{Deserialize, Serialize};

use crate::{utils::process::Tid, Client, Result, TargetPtr};
use super::{Command, Response};



#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallLocation {
	Entry,
	Exit,
	Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrameArg {
	raw: TargetPtr,
}

impl CallFrameArg {
	pub fn new(raw: TargetPtr) -> Self {
		Self { raw }
	}
	pub fn raw(&self) -> TargetPtr {
		self.raw
	}
	pub fn read_ptr_as_str(&self, client: &mut Client) -> Result<String> {
		todo!();
	}
	pub fn as_i8(&self) -> i8 {
		crate::utils::twos_complement(self.raw as u8 as TargetPtr) as i8
	}
	pub fn read_ptr_as_u64(&mut self, client: &mut Client) -> Result<u64> {
		todo!();
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
	pub tid: Tid,
	pub regs: crate::Registers,
	pub func: TargetPtr,
	// loc: CallLocation,
	output: Option<CallFrameArg>,
}

impl CallFrame {
	pub fn new(tid: Tid, func: TargetPtr, regs: crate::Registers) -> Self {
		Self { tid, regs, func, output: None }
	}
	
	pub fn arg(&self, idx: usize) -> Result<CallFrameArg> {
		todo!();
	}
	pub fn retval(&self) -> Result<CallFrameArg> {
		todo!();
	}
	pub fn set_output(&mut self, output: TargetPtr) {
		self.output = Some(CallFrameArg::new(output));
	}
}