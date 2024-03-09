use crate::{api::CallFrame, target::Target, Client, Result, TargetPtr};
use serde::{Deserialize, Serialize};

use super::get_def_little;

// rasm2 -a x86 -b 64 "ebreak"
pub(crate) const SW_BP: [u8; 4] = [0x73, 0x00, 0x10, 0x00];

// rasm2 -a x86 -b 64 "ret"
pub(crate) const RET: [u8; 4] = [0x67, 0x80, 0x00, 0x00];

// rasm2 -a x86 -b 64 "jalr t0"
pub(crate) const CALL_TRAMP: [u8; 4] = [0xe7, 0x80, 0x02, 0x00];

// rasm2 -a x86 -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x13, 0x00, 0x00, 0x00];

// rasm2 -a x86 -b 64 "ecall"
pub(crate) const SYSCALL: [u8; 4] = [0x73, 0x00, 0x00, 0x00];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	#[pc]
	pub pc: u64,
	pub ra: u64,
	#[sp]
	pub sp: u64,
	pub gp: u64,
	pub tp: u64,
	pub t0: u64,
	pub t1: u64,
	pub t2: u64,
	pub s0: u64,
	pub s1: u64,
	pub a0: u64,
	pub a1: u64,
	pub a2: u64,
	pub a3: u64,
	pub a4: u64,
	pub a5: u64,
	pub a6: u64,
	#[sysno]
	pub a7: u64,
	pub s2: u64,
	pub s3: u64,
	pub s4: u64,
	pub s5: u64,
	pub s6: u64,
	pub s7: u64,
	pub s8: u64,
	pub s9: u64,
	pub s10: u64,
	pub s11: u64,
	pub t3: u64,
	pub t4: u64,
	pub t5: u64,
	pub t6: u64,
}

#[cfg(target_arch = "riscv64")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "riscv64")]
super::impl_conv_pete_generic! { user_regs_struct, Riscv64 }

super::impl_from_generic! { user_regs_struct, Riscv64 }

super::impl_named_regs! { user_regs_struct }

super::gen_syscall_shellcode! {}
super::gen_call_shellcode! {}
super::gen_ret_shellcode! {}
super::gen_bp_shellcode! {}
