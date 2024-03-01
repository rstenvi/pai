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
	pub ebx: libc::c_long,
	pub ecx: libc::c_long,
	pub edx: libc::c_long,
	pub esi: libc::c_long,
	pub edi: libc::c_long,
	pub ebp: libc::c_long,

	#[setsysno]
	pub eax: libc::c_long,
	pub xds: libc::c_long,
	pub xes: libc::c_long,
	pub xfs: libc::c_long,
	pub xgs: libc::c_long,

	#[getsysno]
	pub orig_eax: libc::c_long,

	#[pc]
	pub eip: libc::c_long,
	pub xcs: libc::c_long,
	pub eflags: libc::c_long,

	#[sp]
	pub esp: libc::c_long,
	pub xss: libc::c_long,
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
