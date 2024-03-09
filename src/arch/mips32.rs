//! Code Specific to MIPS32

use serde::{Deserialize, Serialize};

use crate::{api::CallFrame, Result, TargetPtr};

// rasm2 -a mips -b 32 break
pub(crate) const SW_BP: [u8; 4] = [0x0d, 0x00, 0x00, 0x00];

// rasm2 -a mips -b 32 "jr ra"
pub(crate) const RET: [u8; 4] = [0x08, 0x00, 0xe0, 0x03];

// Shows up wrong in rasm2 for some reason
// rasm2 -a mips -b 32 "jalr t9"
pub(crate) const CALL_TRAMP: [u8; 4] = [0x09, 0xf8, 0x20, 0x03];

// rasm2 -a mips -b 32 "nop"
pub(crate) const NOP: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

// rasm2 -a mips -b 32 "syscall"
pub(crate) const SYSCALL: [u8; 4] = [0x0c, 0x00, 0x00, 0x00];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	r0: u64,
	at: u64,

	// From linux kernel:
	// "v0 is the system call number, except for O32 ABI syscall(), where it
	// ends up in a0."
	#[sysno]
	v0: u64,
	v1: u64,

	a0: u64,
	a1: u64,
	a2: u64,

	// This is also used to mark syscall failure, 1 = failure, 0 = success
	a3: u64,
	a4: u64,
	a5: u64,
	a6: u64,
	a7: u64,

	t4: u64,
	t5: u64,
	t6: u64,
	t7: u64,

	s: [u64; 8],
	t8: u64,
	t9: u64,
	k0: u64,
	k1: u64,

	gp: u64,
	#[sp]
	sp: u64,
	fp: u64,
	ra: u64,
	lo: u64,
	hi: u64,

	#[pc]
	cp0_epc: u64,
	cp0_badvaddr: u64,
	cp0_status: u64,
	cp0_cause: u64,
}

#[cfg(target_arch = "mips")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "mips")]
super::impl_conv_pete_generic! { user_regs_struct, Mips32 }

super::impl_from_generic! { user_regs_struct, Mips32 }

super::impl_named_regs! { user_regs_struct }

super::gen_syscall_shellcode! {}
super::gen_call_shellcode! {}
super::gen_ret_shellcode! {}
super::gen_bp_shellcode! {}
