//! Code specific to Aarch64
//!
//! ABI is here: <https://github.com/ARM-software/abi-aa>
use crate::{api::CallFrame, Result, TargetPtr};
use serde::{Deserialize, Serialize};

// rasm2 -a arm -b 64 "brk #0"
pub(crate) const SW_BP: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];

// rasm2 -a arm -b 64 "ret"
pub(crate) const RET: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];

// rasm2 -a arm -b 64 "blr x9"
pub(crate) const CALL_TRAMP: [u8; 4] = [0x20, 0x01, 0x3f, 0xd6];

// rasm2 -a arm -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

// rasm2 -a arm -b 64 "svc #0"
pub(crate) const SYSCALL: [u8; 4] = [0x01, 0x00, 0x00, 0xd4];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub regs: [u64; 31],
	#[sp]
	pub sp: u64,
	#[pc]
	pub pc: u64,
	pub pstate: u64,
}
impl user_regs_struct {
	fn _get_sysno(&self) -> usize {
		self.regs[8] as usize
	}
	fn _set_sysno(&mut self, sysno: usize) {
		self.regs[8] = sysno as u64;
	}
}
#[cfg(target_arch = "aarch64")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "aarch64")]
super::impl_conv_pete_generic! { user_regs_struct, Aarch64 }

super::impl_from_generic! { user_regs_struct, Aarch64 }

super::impl_named_regs! { user_regs_struct }

pub(crate) fn syscall_shellcode(code: &mut Vec<u8>) {
	code.extend_from_slice(&NOP);
	code.extend_from_slice(&SYSCALL);
	code.extend_from_slice(&SW_BP);
}
pub(crate) fn call_shellcode(code: &mut Vec<u8>) {
	code.extend_from_slice(&NOP);
	code.extend_from_slice(&CALL_TRAMP);
	code.extend_from_slice(&SW_BP);
}
pub(crate) fn ret_shellcode(code: &mut Vec<u8>) {
	code.extend_from_slice(&NOP);
	code.extend_from_slice(&RET);
}
