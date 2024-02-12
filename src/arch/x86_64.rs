//! Code specific to x86_64
//!
//! ABI is here: <https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf>

use serde::{Deserialize, Serialize};

use crate::{api::CallFrame, arch::ReadRegisters, Client, Result, TargetPtr};

// rasm2 -a x86 -b 64 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

// rasm2 -a x86 -b 64 "ret"
pub(crate) const RET: [u8; 1] = [0xc3];

// rasm2 -a x86 -b 64 "call r10"
pub(crate) const CALL_TRAMP: [u8; 3] = [0x41, 0xff, 0xd2];

// rasm2 -a x86 -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x90, 0x90, 0x90, 0x90];

// rasm2 -a x86 -b 64 "syscall"
pub(crate) const SYSCALL: [u8; 2] = [0x0f, 0x05];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
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
		let loc = self.regs.sp() - 0.into();
		let v = client.read_u64(self.tid, loc)?;
		Ok(v.into())
	}
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> crate::TargetPtr {
		self.rip.into()
	}

	fn sp(&self) -> crate::TargetPtr {
		self.rsp.into()
	}

	fn sysno(&self) -> usize {
		self.orig_rax as usize
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
		.into()
	}
	fn ret_syscall(&self) -> crate::TargetPtr {
		self.rax.into()
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: crate::TargetPtr) {
		self.rip = pc.into();
	}

	fn set_sp(&mut self, sp: crate::TargetPtr) {
		self.rsp = sp.into();
	}

	fn set_sysno(&mut self, sysno: usize) {
		self.rax = sysno as libc::c_ulonglong;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: crate::TargetPtr) {
		let arg = arg.into();
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
		self.rax = ret.into();
	}
}

impl super::RegsAbiAccess for super::SystemV {
	fn get_retval(&self, regs: &crate::Registers) -> TargetPtr {
		regs.rax.into()
	}

	fn set_retval(&self, regs: &mut crate::Registers, val: TargetPtr) {
		regs.rax = val.into();
	}

	fn get_arg(&self, regs: &crate::Registers, num: usize) -> Result<TargetPtr> {
		let r = match num {
			0 => regs.rdi,
			1 => regs.rsi,
			2 => regs.rdx,
			3 => regs.rcx,
			4 => regs.r8,
			5 => regs.r9,
			_ => crate::bug!("tried to get SystemV arg nr {num}"),
		};
		Ok(r.into())
	}

	fn get_arg_ext(
		&self,
		_regs: &crate::Registers,
		_num: usize,
		_client: &mut crate::Client,
	) -> Result<TargetPtr> {
		crate::bug!("get_arg_ext on SystemV not supported")
	}

	fn set_arg(&self, regs: &mut crate::Registers, num: usize, val: TargetPtr) -> Result<()> {
		let val = val.into();
		match num {
			0 => regs.rdi = val,
			1 => regs.rsi = val,
			2 => regs.rdx = val,
			3 => regs.rcx = val,
			4 => regs.r8 = val,
			5 => regs.r9 = val,
			_ => crate::bug!("tried to get SystemV arg nr {num}"),
		}
		Ok(())
	}

	fn set_arg_ext(
		&self,
		_regs: &mut crate::Registers,
		_num: usize,
		_client: &mut crate::Client,
		_val: TargetPtr,
	) -> Result<()> {
		crate::bug!("set_arg_ext on SystemV not supported")
	}

	fn set_reg_call_tramp(&self, regs: &mut crate::Registers, val: TargetPtr) {
		regs.r10 = val.into();
	}

	fn call_trampoline(&self, code: &mut Vec<u8>) {
		code.extend_from_slice(&NOP);
		code.extend_from_slice(&CALL_TRAMP);
		code.extend_from_slice(&SW_BP);
	}
}

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
