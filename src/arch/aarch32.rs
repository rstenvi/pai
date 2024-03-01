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
	pub arm_r0: libc::c_ulong,
	pub arm_r1: libc::c_ulong,
	pub arm_r2: libc::c_ulong,
	pub arm_r3: libc::c_ulong,
	pub arm_r4: libc::c_ulong,
	pub arm_r5: libc::c_ulong,
	pub arm_r6: libc::c_ulong,

	#[sysno]
	pub arm_r7: libc::c_ulong,
	pub arm_r8: libc::c_ulong,
	pub arm_r9: libc::c_ulong,
	pub arm_r10: libc::c_ulong,
	pub arm_fp: libc::c_ulong,
	pub arm_ip: libc::c_ulong,

	#[sp]
	pub arm_sp: libc::c_ulong,
	pub arm_lr: libc::c_ulong,

	#[pc]
	pub arm_pc: libc::c_ulong,
	pub arm_cpsr: libc::c_ulong,
	pub arm_orig_r0: libc::c_ulong,
}

#[cfg(target_arch = "aarch32")]
super::impl_from_pete! { user_regs_struct }

#[cfg(target_arch = "aarch32")]
super::impl_conv_pete_generic! { user_regs_struct, Aarch32 }

super::impl_from_generic! { user_regs_struct, Aarch32 }

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
