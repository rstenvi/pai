//! Code specific to x86_64

use serde::{Deserialize, Serialize};

// rasm2 -a x86 -b 64 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

// rasm2 -a x86 -b 64 "call r10"
pub(crate) const CALL_TRAMP: [u8; 3] = [0x41, 0xff, 0xd2];

// rasm2 -a x86 -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x90, 0x90, 0x90, 0x90];

// rasm2 -a x86 -b 64 "syscall"
pub(crate) const SYSCALL: [u8; 2] = [0x0f, 0x05];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub r15: libc::c_ulonglong,
	pub r14: libc::c_ulonglong,
	pub r13: libc::c_ulonglong,
	pub r12: libc::c_ulonglong,
	pub rbp: libc::c_ulonglong,
	pub rbx: libc::c_ulonglong,
	pub r11: libc::c_ulonglong,
	pub r10: libc::c_ulonglong,
	pub r9: libc::c_ulonglong,
	pub r8: libc::c_ulonglong,
	pub rax: libc::c_ulonglong,
	pub rcx: libc::c_ulonglong,
	pub rdx: libc::c_ulonglong,
	pub rsi: libc::c_ulonglong,
	pub rdi: libc::c_ulonglong,
	pub orig_rax: libc::c_ulonglong,
	pub rip: libc::c_ulonglong,
	pub cs: libc::c_ulonglong,
	pub eflags: libc::c_ulonglong,
	pub rsp: libc::c_ulonglong,
	pub ss: libc::c_ulonglong,
	pub fs_base: libc::c_ulonglong,
	pub gs_base: libc::c_ulonglong,
	pub ds: libc::c_ulonglong,
	pub es: libc::c_ulonglong,
	pub fs: libc::c_ulonglong,
	pub gs: libc::c_ulonglong,
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
impl From<user_regs_struct> for nix::libc::user_regs_struct {
	fn from(value: user_regs_struct) -> nix::libc::user_regs_struct {
		unsafe { std::mem::transmute(value) }
	}
}
impl From<nix::libc::user_regs_struct> for user_regs_struct {
	fn from(value: nix::libc::user_regs_struct) -> user_regs_struct {
		unsafe { std::mem::transmute(value) }
	}
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> crate::TargetPtr {
		self.rip
	}

	fn sp(&self) -> crate::TargetPtr {
		self.rsp
	}

	fn sysno(&self) -> crate::TargetPtr {
		self.orig_rax
	}

	fn arg_syscall(&self, nr: usize) -> crate::TargetPtr {
		match nr {
			0 => self.rdi,
			1 => self.rsi,
			2 => self.rdx,
			3 => self.r10,
			4 => self.r8,
			5 => self.r9,
			_ => crate::bug!("tried to get syscall arg nr {nr}"),
		}
	}

	fn arg_systemv(&self, nr: usize) -> crate::TargetPtr {
		match nr {
			0 => self.rdi,
			1 => self.rsi,
			2 => self.rdx,
			3 => self.rcx,
			4 => self.r8,
			5 => self.r9,
			_ => crate::bug!("tried to get SystemV arg nr {nr}"),
		}
	}

	fn ret_syscall(&self) -> crate::TargetPtr {
		self.rax
	}
	fn ret_systemv(&self) -> crate::TargetPtr {
		self.rax
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: crate::TargetPtr) {
		self.rip = pc;
	}

	fn set_sp(&mut self, sp: crate::TargetPtr) {
		self.rsp = sp;
	}

	fn set_sysno(&mut self, sysno: crate::TargetPtr) {
		self.rax = sysno;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: crate::TargetPtr) {
		match nr {
			0 => self.rdi = arg,
			1 => self.rsi = arg,
			2 => self.rdx = arg,
			3 => self.r10 = arg,
			4 => self.r8 = arg,
			5 => self.r9 = arg,
			_ => crate::bug!("tried to set syscall arg nr {nr}"),
		}
	}

	fn set_ret_syscall(&mut self, ret: crate::TargetPtr) {
		self.rax = ret;
	}

	fn set_arg_systemv(&mut self, nr: usize, arg: crate::TargetPtr) {
		match nr {
			0 => self.rdi = arg,
			1 => self.rsi = arg,
			2 => self.rdx = arg,
			3 => self.rcx = arg,
			4 => self.r8 = arg,
			5 => self.r9 = arg,
			_ => crate::bug!("tried to set SystemV arg nr {nr}"),
		}
	}
	fn set_call_func(&mut self, addr: crate::TargetPtr) {
		self.r10 = addr;
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
pub fn as_our_regs(regs: nix::libc::user_regs_struct) -> user_regs_struct {
	regs.into()
}
