//! Code specific to Aarch32
//!
//! ABI is here: <https://github.com/ARM-software/abi-aa>
use serde::{Deserialize, Serialize};

use crate::{api::CallFrame, Result, TargetPtr};

// TODO: These will not work if thumb mode

pub(crate) const SW_BP: [u8; 4] = [0xf0, 0x01, 0xf0, 0xe7];

// rasm2 -a arm -b 32 "pop {r11, lr}"
pub(crate) const EPILOGUE: [u8; 4] = [0x00, 0x48, 0xbd, 0xe8];

// rasm2 -a arm -b 32 "bx lr"
pub(crate) const RET: [u8; 4] = [0x1e, 0xff, 0x2f, 0xe1];

// rasm2 -a arm -b 32 "blx r9"
pub(crate) const CALL_TRAMP: [u8; 4] = [0x39, 0xff, 0x2f, 0xe1];

// rasm2 -a arm -b 32 "nop"
pub(crate) const NOP: [u8; 4] = [0x00, 0x00, 0xa0, 0xe1];

// rasm2 -a arm -b 32 "svc #0"
pub(crate) const SYSCALL: [u8; 4] = [0x00, 0x00, 0x00, 0xef];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub arm_r0: u32,
	pub arm_r1: u32,
	pub arm_r2: u32,
	pub arm_r3: u32,
	pub arm_r4: u32,
	pub arm_r5: u32,
	pub arm_r6: u32,

	#[sysno]
	pub arm_r7: u32,
	pub arm_r8: u32,
	pub arm_r9: u32,
	pub arm_r10: u32,
	pub arm_fp: u32,
	pub arm_ip: u32,

	#[sp]
	pub arm_sp: u32,
	pub arm_lr: u32,

	#[pc]
	pub arm_pc: u32,
	pub arm_cpsr: u32,
	pub arm_orig_r0: u32,
}

#[cfg(target_arch = "arm")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "arm")]
super::impl_conv_pete_generic! { user_regs_struct, Aarch32 }

super::impl_from_generic! { user_regs_struct, Aarch32 }

super::impl_named_regs! { user_regs_struct }

super::gen_syscall_shellcode! { }
super::gen_call_shellcode! { }
super::gen_ret_shellcode! { }
super::gen_bp_shellcode! {}
