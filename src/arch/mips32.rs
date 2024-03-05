//! Code Specific to MIPS32

use serde::{Deserialize, Serialize};

use crate::{api::CallFrame, Result, TargetPtr};

pub(crate) const SW_BP: [u8; 0] = [];

// rasm2 -a arm -b 32 "bx lr"
pub(crate) const RET: [u8; 0] = [];

// rasm2 -a arm -b 32 "blx r9"
pub(crate) const CALL_TRAMP: [u8; 0] = [];

// rasm2 -a arm -b 32 "nop"
pub(crate) const NOP: [u8; 0] = [];

// rasm2 -a arm -b 32 "svc #0"
pub(crate) const SYSCALL: [u8; 0] = [];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	r0: u64,
	at: u64,
	v0: u64,
	v1: u64,
	#[sysno]
	a0: u64,
	a1: u64,
	a2: u64,
	a3: u64,
	t: [u64; 8],
	s: [u64; 8],
	t8: u64,
	t9: u64,
	k0: u64,
	k1: u64,

	gp: u64,
	#[sp]
	sp: u64,
	fp: u64,
	// Link reg
	ra: u64,

	
	lo: u64,
	hi: u64,

	// Unsure if it's this?
	#[pc]
	cp0_epc: u64,
	cp0_badvaddr: u64,
	cp0_status: u64,
	cp0_cause: u64,
}

impl user_regs_struct {

}

#[cfg(target_arch = "mips")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "mips")]
super::impl_conv_pete_generic! { user_regs_struct, Mips32 }

super::impl_from_generic! { user_regs_struct, Mips32 }

super::impl_named_regs! { user_regs_struct }

super::gen_syscall_shellcode! { }
super::gen_call_shellcode! { }
super::gen_ret_shellcode! { }
super::gen_bp_shellcode! {}
