//! Code specific to x86
//!
//! ABI is here: <https://github.com/hjl-tools/x86-psABI/wiki/intel386-psABI-1.1.pdf>
use crate::{api::CallFrame, Client, Result, TargetPtr};
use serde::{Deserialize, Serialize};

// rasm2 -a x86 -b 32 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

// rasm2 -a x86 -b 32 "ret"
pub(crate) const RET: [u8; 1] = [0xc3];

// rasm2 -a x86 -b 32 "call eax"
pub(crate) const CALL_TRAMP: [u8; 2] = [0xff, 0xd0];

// rasm2 -a x86 -b 32 "nop"
pub(crate) const NOP: [u8; 4] = [0x90, 0x90, 0x90, 0x90];

// rasm2 -a x86 -b 32 "int 0x80"
pub(crate) const SYSCALL: [u8; 2] = [0xcd, 0x80];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub ebx: u32,
	pub ecx: u32,
	pub edx: u32,
	pub esi: u32,
	pub edi: u32,
	pub ebp: u32,

	#[setsysno]
	pub eax: u32,
	pub xds: u32,
	pub xes: u32,
	pub xfs: u32,
	pub xgs: u32,

	#[getsysno]
	pub orig_eax: u32,

	#[pc]
	pub eip: u32,
	pub xcs: u32,
	pub eflags: u32,

	#[sp]
	pub esp: u32,
	pub xss: u32,
}

#[cfg(target_arch = "x86")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "x86")]
super::impl_conv_pete_generic! { user_regs_struct, X86 }

super::impl_from_generic! { user_regs_struct, X86 }

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
pub(crate) fn bp_shellcode(code: &mut Vec<u8>) {
	code.extend_from_slice(&SW_BP);
}