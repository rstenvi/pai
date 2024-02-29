use crate::{api::CallFrame, Client, Result, TargetPtr};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(pai_macros::PaiRegs, Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	#[pc]
	pub pc: libc::c_ulong,
	pub ra: libc::c_ulong,
	#[sp]
	pub sp: libc::c_ulong,
	pub gp: libc::c_ulong,
	pub tp: libc::c_ulong,
	pub t0: libc::c_ulong,
	pub t1: libc::c_ulong,
	pub t2: libc::c_ulong,
	pub s0: libc::c_ulong,
	pub s1: libc::c_ulong,
	pub a0: libc::c_ulong,
	pub a1: libc::c_ulong,
	pub a2: libc::c_ulong,
	pub a3: libc::c_ulong,
	pub a4: libc::c_ulong,
	pub a5: libc::c_ulong,
	pub a6: libc::c_ulong,
	pub a7: libc::c_ulong,
	pub s2: libc::c_ulong,
	pub s3: libc::c_ulong,
	pub s4: libc::c_ulong,
	pub s5: libc::c_ulong,
	pub s6: libc::c_ulong,
	pub s7: libc::c_ulong,
	pub s8: libc::c_ulong,
	pub s9: libc::c_ulong,
	pub s10: libc::c_ulong,
	pub s11: libc::c_ulong,
	pub t3: libc::c_ulong,
	pub t4: libc::c_ulong,
	pub t5: libc::c_ulong,
	pub t6: libc::c_ulong,
}

pub(crate) fn syscall_shellcode(_code: &mut Vec<u8>) {
	todo!();
}
pub(crate) fn call_shellcode(_code: &mut Vec<u8>) {
	todo!();
}
pub(crate) fn ret_shellcode(_code: &mut Vec<u8>) {
	todo!();
}
