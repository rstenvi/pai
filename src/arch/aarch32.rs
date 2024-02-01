use serde::{Deserialize, Serialize};

use crate::TargetPtr;

// TODO: These will not work if thumb mode

// rasm2 -a arm -b 32 "brk #0"
pub(crate) const SW_BP: [u8; 4] = [0xfe, 0xff, 0xff, 0xea];

// rasm2 -a arm -b 32 "blx x9"
pub(crate) const CALL_TRAMP: [u8; 4] = [0x39, 0xff, 0x2f, 0xe1];

// rasm2 -a arm -b 32 "nop"
pub(crate) const NOP: [u8; 4] = [0x00, 0x00, 0xa0, 0xe1];

// rasm2 -a arm -b 32 "svc #0"
pub(crate) const SYSCALL: [u8; 4] = [0x00, 0x00, 0x00, 0xef];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub arm_r0: libc::c_ulong,
	pub arm_r1: libc::c_ulong,
	pub arm_r2: libc::c_ulong,
	pub arm_r3: libc::c_ulong,
	pub arm_r4: libc::c_ulong,
	pub arm_r5: libc::c_ulong,
	pub arm_r6: libc::c_ulong,
	pub arm_r7: libc::c_ulong,
	pub arm_r8: libc::c_ulong,
	pub arm_r9: libc::c_ulong,
	pub arm_r10: libc::c_ulong,
	pub arm_fp: libc::c_ulong,
	pub arm_ip: libc::c_ulong,
	pub arm_sp: libc::c_ulong,
	pub arm_lr: libc::c_ulong,
	pub arm_pc: libc::c_ulong,
	pub arm_cpsr: libc::c_ulong,
	pub arm_orig_r0: libc::c_ulong,
}
impl From<pete::Registers> for user_regs_struct {
	fn from(value: pete::Registers) -> user_regs_struct {
		unsafe { std::mem::transmute(value) }
	}
}

impl From<user_regs_struct> for pete::Registers {
	fn from(value: user_regs_struct) -> pete::Registers {
		unsafe { std::mem::transmute(value) }
	}
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> TargetPtr {
		todo!();
	}

	fn sp(&self) -> TargetPtr {
		todo!();
	}

	fn sysno(&self) -> TargetPtr {
		todo!();
	}

	fn arg_syscall(&self, nr: usize) -> TargetPtr {
		todo!();
	}

	fn ret_syscall(&self) -> TargetPtr {
		todo!();
	}

	fn arg_systemv(&self, nr: usize) -> TargetPtr {
		todo!();
	}

	fn ret_systemv(&self) -> crate::TargetPtr {
		todo!()
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: TargetPtr) {
		todo!();
	}

	fn set_sp(&mut self, sp: TargetPtr) {
		todo!();
	}

	fn set_sysno(&mut self, sysno: TargetPtr) {
		todo!();
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: TargetPtr) {
		todo!();
	}

	fn set_ret_syscall(&mut self, ret: TargetPtr) {
		todo!();
	}

	fn set_arg_systemv(&mut self, nr: usize, arg: crate::TargetPtr) {
		todo!();
	}

	fn set_call_func(&mut self, addr: crate::TargetPtr) {
		todo!()
	}
}

pub fn syscall_shellcode(code: &mut Vec<u8>) {
	todo!();
}
pub fn call_shellcode(code: &mut Vec<u8>) {
	todo!();
}
pub fn as_our_regs(regs: pete::Registers) -> user_regs_struct {
	todo!();
}
