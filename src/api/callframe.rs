use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{Command, Response};
use crate::{target::GenericCc, utils::process::Tid, Client, Error, Result, TargetPtr};

macro_rules! arg_as_signed {
	($t:ty) => {
		paste::paste! {
			pub fn [<as_$t>](&self) -> $t {
				self.raw.[<as_$t>]()
			}
		}
	};
}

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
		log::debug!("reading {:x} as c_str", self.raw);
		let tids = client.get_stopped_tids()?;
		let tid = tids.first().ok_or(Error::msg("No stopped thread"))?;
		let s = client.read_c_string(*tid, self.raw.into())?;
		Ok(s)
	}
	arg_as_signed! { i8 }
	arg_as_signed! { i16 }
	arg_as_signed! { i32 }
	arg_as_signed! { i64 }
	arg_as_signed! { isize }
	arg_as_signed! { u8 }
	arg_as_signed! { u16 }
	arg_as_signed! { u32 }
	arg_as_signed! { u64 }
	arg_as_signed! { usize }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
	pub tid: Tid,
	pub regs: crate::Registers,
	pub func: u64,
	output: Option<CallFrameArg>,
	cc: GenericCc,
}

impl CallFrame {
	pub fn new(tid: Tid, func: u64, regs: crate::Registers) -> Self {
		let cc = GenericCc::new_host_systemv().unwrap();
		Self {
			tid,
			regs,
			func,
			output: None,
			cc,
		}
	}

	pub fn arg(&self, idx: usize, client: &mut crate::Client) -> Result<CallFrameArg> {
		let val = self.cc.get_arg(idx, &self.regs, client)?;
		let ins = CallFrameArg::new(val.into());
		Ok(ins)
	}
	pub fn retval(&self) -> Result<CallFrameArg> {
		self.output.as_ref().cloned().ok_or(crate::Error::NotFound)
	}
	pub fn set_output(&mut self, output: TargetPtr) {
		self.output = Some(CallFrameArg::new(output.into()));
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn frame_args() {
		let arg = CallFrameArg::new(0.into());
		assert_eq!(arg.raw(), 0.into());
		assert_eq!(arg.as_i8(), 0);
		assert_eq!(arg.as_i32(), 0);

		let arg = CallFrameArg::new(u64::MAX.into());
		assert_eq!(arg.raw(), u64::MAX.into());
		assert_eq!(arg.as_i16(), -1);
		assert_eq!(arg.as_i64(), -1);

		let arg = CallFrameArg::new(0xff.into());
		assert_eq!(arg.raw(), 0xff.into());
		assert_eq!(arg.as_i16(), 0xff);
		assert_eq!(arg.as_i8(), -1);
	}
}
