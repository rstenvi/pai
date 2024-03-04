//! Code specific to x86_64
//!
//! ABI is here: <https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf>

use super::RegisterAccess;
use crate::{api::CallFrame, Client, Result, TargetPtr};
use serde::{Deserialize, Serialize};

// rasm2 -a x86 -b 64 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

// rasm2 -a x86 -b 64 "ret"
pub(crate) const RET: [u8; 1] = [0xc3];

// rasm2 -a x86 -b 64 "call r10"
pub(crate) const CALL_TRAMP: [u8; 3] = [0x41, 0xff, 0xd2];

// rasm2 -a x86 -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x90, 0x90, 0x90, 0x90];

// rasm2 -a x86 -b 64 "syscall"
pub(crate) const SYSCALL: [u8; 2] = [0x0f, 0x05];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub r15: u64,
	pub r14: u64,
	pub r13: u64,
	pub r12: u64,
	pub rbp: u64,
	pub rbx: u64,
	pub r11: u64,
	pub r10: u64,
	pub r9: u64,
	pub r8: u64,

	#[setsysno]
	pub rax: u64,
	pub rcx: u64,
	pub rdx: u64,
	pub rsi: u64,
	pub rdi: u64,

	#[getsysno]
	pub orig_rax: u64,

	#[pc]
	pub rip: u64,
	pub cs: u64,
	pub eflags: u64,

	#[sp]
	pub rsp: u64,
	pub ss: u64,
	pub fs_base: u64,
	pub gs_base: u64,
	pub ds: u64,
	pub es: u64,
	pub fs: u64,
	pub gs: u64,
}

#[cfg(target_arch = "x86_64")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "x86_64")]
super::impl_conv_pete_generic! { user_regs_struct, X86_64 }

super::impl_from_generic! { user_regs_struct, X86_64 }

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
