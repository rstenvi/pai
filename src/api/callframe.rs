use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{arch::{RegsAbiAccess, SystemV}, utils::process::Tid, Client, Result, TargetPtr};
use super::{Command, Response};

macro_rules! arg_as_signed {
	($t:ty, $tt:ty) => {
		paste::paste! {
			pub fn [<as_$t>](&self) -> $t {
				crate::utils::twos_complement((Into::<$tt>::into(self.raw)).into()) as $t
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
		todo!();
	}
	arg_as_signed! { i8, u8 }
	arg_as_signed! { i16, u16 }
	arg_as_signed! { i32, u32 }
	arg_as_signed! { i64, u64 }
	// pub fn as_i8(&self) -> i8 {
	// 	crate::utils::twos_complement(self.raw as u8 as TargetPtr) as i8
	// }
	// pub fn read_ptr_as_u64(&mut self, client: &mut Client) -> Result<u64> {
	// 	todo!();
	// }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
	// #[serde(skip)]
	// cc: Box<dyn RegsAbiAccess + Send + 'static>,
	pub tid: Tid,
	pub regs: crate::Registers,
	pub func: TargetPtr,
	// loc: CallLocation,
	output: Option<CallFrameArg>,

	// TODO: Should make it possible to change this
	cc: SystemV,
}

impl CallFrame {
	pub fn new(tid: Tid, func: TargetPtr, regs: crate::Registers) -> Self {
		let cc = SystemV::default();
		Self {
			tid,
			regs,
			func,
			output: None,
			cc,
		}
	}
	
	pub fn arg(&self, idx: usize) -> Result<CallFrameArg> {
		let val = self.cc.get_arg(&self.regs, idx)?;
		let ins = CallFrameArg::new(val);
		Ok(ins)
	}
	pub fn retval(&self) -> Result<CallFrameArg> {
		todo!();
	}
	pub fn set_output(&mut self, output: TargetPtr) {
		self.output = Some(CallFrameArg::new(output));
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