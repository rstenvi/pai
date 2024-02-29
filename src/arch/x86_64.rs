//! Code specific to x86_64
//!
//! ABI is here: <https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf>

use serde::{Deserialize, Serialize};
use crate::{api::CallFrame, Client, Result, TargetPtr};
use super::NamedRegs;

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
	pub r15: libc::c_ulonglong,
	pub r14: libc::c_ulonglong,
	pub r13: libc::c_ulonglong,
	pub r12: libc::c_ulonglong,
	pub rbp: libc::c_ulonglong,
	pub rbx: libc::c_ulonglong,
	pub r11: libc::c_ulonglong,
	pub r10: libc::c_ulonglong,
	pub r9: libc::c_ulonglong,
	pub r8: libc::c_ulonglong,

	#[setsysno]
	pub rax: libc::c_ulonglong,
	pub rcx: libc::c_ulonglong,
	pub rdx: libc::c_ulonglong,
	pub rsi: libc::c_ulonglong,
	pub rdi: libc::c_ulonglong,

	#[getsysno]
	pub orig_rax: libc::c_ulonglong,

	#[pc]
	pub rip: libc::c_ulonglong,
	pub cs: libc::c_ulonglong,
	pub eflags: libc::c_ulonglong,

	#[sp]
	pub rsp: libc::c_ulonglong,
	pub ss: libc::c_ulonglong,
	pub fs_base: libc::c_ulonglong,
	pub gs_base: libc::c_ulonglong,
	pub ds: libc::c_ulonglong,
	pub es: libc::c_ulonglong,
	pub fs: libc::c_ulonglong,
	pub gs: libc::c_ulonglong,
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
