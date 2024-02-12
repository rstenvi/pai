use crate::{api::CallFrame, Client, Result, TargetPtr};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub pc: libc::c_ulong,
	pub ra: libc::c_ulong,
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

impl From<user_regs_struct> for pete::Registers {
	fn from(value: user_regs_struct) -> pete::Registers {
		unsafe { std::mem::transmute(value) }
	}
}
impl From<pete::Registers> for user_regs_struct {
	fn from(value: pete::Registers) -> user_regs_struct {
		unsafe { std::mem::transmute(value) }
	}
}

impl CallFrame {
	pub fn return_addr(&self, client: &mut Client) -> Result<TargetPtr> {
		todo!();
	}
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> crate::TargetPtr {
		todo!();
	}

	fn sp(&self) -> crate::TargetPtr {
		todo!();
	}

	fn sysno(&self) -> usize {
		todo!();
	}

	fn arg_syscall(&self, nr: usize) -> crate::TargetPtr {
		todo!();
	}
	fn ret_syscall(&self) -> crate::TargetPtr {
		todo!();
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: crate::TargetPtr) {
		todo!();
	}

	fn set_sp(&mut self, sp: crate::TargetPtr) {
		todo!();
	}

	fn set_sysno(&mut self, sysno: usize) {
		todo!();
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: crate::TargetPtr) {
		todo!();
	}

	fn set_ret_syscall(&mut self, ret: crate::TargetPtr) {
		todo!();
	}
}

impl super::RegsAbiAccess for super::SystemV {
	fn get_retval(&self, regs: &crate::Registers) -> TargetPtr {
		todo!();
	}

	fn set_retval(&self, regs: &mut crate::Registers, val: TargetPtr) {
		todo!();
	}

	fn get_arg(&self, regs: &crate::Registers, num: usize) -> Result<TargetPtr> {
		todo!();
	}

	fn get_arg_ext(
		&self,
		regs: &crate::Registers,
		num: usize,
		client: &mut crate::Client,
	) -> Result<TargetPtr> {
		crate::bug!("get_arg_ext on SystemV not supported")
	}

	fn set_arg(&self, regs: &mut crate::Registers, num: usize, val: TargetPtr) -> Result<()> {
		todo!();
	}

	fn set_arg_ext(
		&self,
		regs: &mut crate::Registers,
		num: usize,
		client: &mut crate::Client,
		val: TargetPtr,
	) -> Result<()> {
		crate::bug!("set_arg_ext on SystemV not supported")
	}

	fn set_reg_call_tramp(&self, regs: &mut crate::Registers, val: TargetPtr) {
		todo!();
	}

	fn call_trampoline(&self, code: &mut Vec<u8>) {
		todo!();
	}
}

pub(crate) fn syscall_shellcode(code: &mut Vec<u8>) {
	todo!();
}
pub(crate) fn call_shellcode(code: &mut Vec<u8>) {
	todo!();
}
pub(crate) fn ret_shellcode(code: &mut Vec<u8>) {
	todo!();
}
pub(crate) fn as_our_regs(regs: pete::Registers) -> user_regs_struct {
	regs.into()
}
