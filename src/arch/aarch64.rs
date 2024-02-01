use serde::{Deserialize, Serialize};

use crate::TargetPtr;

// rasm2 -a arm -b 64 "brk #0"
pub(crate) const SW_BP: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];

// rasm2 -a arm -b 64 "blr x9"
pub(crate) const CALL_TRAMP: [u8; 4] = [0x20, 0x01, 0x3f, 0xd6];

// rasm2 -a arm -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

// rasm2 -a arm -b 64 "svc #0"
pub(crate) const SYSCALL: [u8; 4] = [0x01, 0x00, 0x00, 0xd4];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub regs: [u64; 31],
	pub sp: u64,
	pub pc: u64,
	pub pstate: u64,
}

// impl From<libc::user_regs_struct> for user_regs_struct {
// 	fn from(value: libc::user_regs_struct) -> user_regs_struct {
// 		unsafe { std::mem::transmute(value) }
// 	}
// }

// impl From<user_regs_struct> for libc::user_regs_struct {
// 	fn from(value: user_regs_struct) -> libc::user_regs_struct {
// 		unsafe { std::mem::transmute(value) }
// 	}
// }

// impl From<pete::aarch64::user_pt_regs> for user_regs_struct {
// 	fn from(value: pete::aarch64::user_pt_regs) -> user_regs_struct {
// 		unsafe { std::mem::transmute(value) }
// 	}
// }
// impl From<user_regs_struct> for pete::aarch64::user_pt_regs {
// 	fn from(value: user_regs_struct) -> pete::aarch64::user_pt_regs {
// 		unsafe { std::mem::transmute(value) }
// 	}
// }

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
		self.pc
	}

	fn sp(&self) -> TargetPtr {
		self.sp
	}

	fn sysno(&self) -> TargetPtr {
		self.regs[8]
	}

	fn arg_syscall(&self, nr: usize) -> TargetPtr {
		assert!(nr <= 5);
		self.regs[nr]
	}

	fn ret_syscall(&self) -> TargetPtr {
		self.regs[0]
	}

	fn arg_systemv(&self, nr: usize) -> TargetPtr {
		assert!(nr <= 8);
		self.regs[nr]
	}

	fn ret_systemv(&self) -> crate::TargetPtr {
		todo!()
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: TargetPtr) {
		self.pc = pc;
	}

	fn set_sp(&mut self, sp: TargetPtr) {
		self.sp = sp;
	}

	fn set_sysno(&mut self, sysno: TargetPtr) {
		self.regs[0] = sysno;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: TargetPtr) {
		assert!(nr < 8);
		self.regs[nr] = arg;
	}

	fn set_ret_syscall(&mut self, ret: TargetPtr) {
		self.regs[0] = ret;
	}

	fn set_arg_systemv(&mut self, nr: usize, arg: crate::TargetPtr) {
		assert!(nr < 8);
		self.regs[nr] = arg;
	}

	fn set_call_func(&mut self, addr: crate::TargetPtr) {
		todo!()
	}
}

pub fn syscall_shellcode(code: &mut Vec<u8>) {
	code.extend_from_slice(&NOP);
	code.extend_from_slice(&SYSCALL);
	code.extend_from_slice(&SW_BP);
}
pub fn call_shellcode(code: &mut Vec<u8>) {
	code.extend_from_slice(&NOP);
	code.extend_from_slice(&CALL_TRAMP);
	code.extend_from_slice(&SW_BP);
}
pub fn as_our_regs(regs: pete::Registers) -> user_regs_struct {
	regs.into()
}
