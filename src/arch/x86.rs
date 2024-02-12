//! Code specific to x86
//!
//! ABI is here: <https://github.com/hjl-tools/x86-psABI/wiki/intel386-psABI-1.1.pdf>
use serde::{Deserialize, Serialize};

use crate::{api::CallFrame, Client, Result, TargetPtr};

use super::ReadRegisters;

// rasm2 -a x86 -b 32 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

// rasm2 -a x86 -b 32 "ret"
pub(crate) const RET: [u8; 1] = [0xc3];

// rasm2 -a x86 -b 32 "call eax"
pub(crate) const CALL_TRAMP: [u8; 2] = [0xff, 0xd0];

// rasm2 -a x86 -b 32 "nop"
pub(crate) const NOP: [u8; 4] = [0x90, 0x90, 0x90, 0x90];

// rasm2 -a x86 -b 32 "int 0x80"
pub(crate) const SYSCALL: [u8; 2] = [0xcd, 0x80];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub ebx: libc::c_long,
	pub ecx: libc::c_long,
	pub edx: libc::c_long,
	pub esi: libc::c_long,
	pub edi: libc::c_long,
	pub ebp: libc::c_long,
	pub eax: libc::c_long,
	pub xds: libc::c_long,
	pub xes: libc::c_long,
	pub xfs: libc::c_long,
	pub xgs: libc::c_long,
	pub orig_eax: libc::c_long,
	pub eip: libc::c_long,
	pub xcs: libc::c_long,
	pub eflags: libc::c_long,
	pub esp: libc::c_long,
	pub xss: libc::c_long,
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
impl CallFrame {
	pub fn return_addr(&self, client: &mut Client) -> Result<TargetPtr> {
		let loc = self.regs.sp() - 0.into();
		let v = client.read_u32(self.tid, loc)?;
		Ok(v.into())
	}
}
impl super::RegsAbiAccess for super::SystemV {
	fn get_retval(&self, regs: &crate::Registers) -> TargetPtr {
		regs.eax.into()
	}

	fn set_retval(&self, regs: &mut crate::Registers, val: TargetPtr) {
		regs.eax = val.into()
	}

	fn get_arg(&self, _regs: &crate::Registers, _num: usize) -> Result<TargetPtr> {
		Err(crate::Error::Unsupported)
	}

	fn get_arg_ext(
		&self,
		regs: &crate::Registers,
		num: usize,
		client: &mut crate::Client,
	) -> Result<TargetPtr> {
		let sp = regs.sp();
		let ptrsz = std::mem::size_of::<usize>();
		let off = ptrsz * (num + 1);
		let addr = usize::from(sp) + off;
		let tid = client.get_threads_status()?;
		let tid = tid[0].id;
		let v = client.read_u32(tid, addr.into())?;
		Ok(v.into())
		// crate::bug!("set_arg_ext on SystemV not supported")
	}

	fn set_arg(&self, regs: &mut crate::Registers, num: usize, val: TargetPtr) -> Result<()> {
		todo!()
	}

	fn set_arg_ext(
		&self,
		_regs: &mut crate::Registers,
		_num: usize,
		_client: &mut crate::Client,
		val: TargetPtr,
	) -> Result<()> {
		crate::bug!("set_arg_ext on SystemV not supported")
	}

	fn set_reg_call_tramp(&self, regs: &mut crate::Registers, val: TargetPtr) {
		regs.eax = val.into();
	}

	fn call_trampoline(&self, code: &mut Vec<u8>) {
		code.extend_from_slice(&NOP);
		code.extend_from_slice(&CALL_TRAMP);
		code.extend_from_slice(&SW_BP);
	}
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> crate::TargetPtr {
		self.eip.into()
	}

	fn sp(&self) -> crate::TargetPtr {
		self.esp.into()
	}

	fn sysno(&self) -> usize {
		self.eax as usize
	}

	fn arg_syscall(&self, nr: usize) -> crate::TargetPtr {
		match nr {
			0 => self.ebx,
			1 => self.ecx,
			2 => self.edx,
			3 => self.esi,
			4 => self.edi,
			5 => self.ebp,
			_ => crate::bug!("tried to get syscall arg nr {nr}"),
		}
		.into()
	}

	fn ret_syscall(&self) -> crate::TargetPtr {
		self.eax.into()
	}
}
impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: crate::TargetPtr) {
		self.eip = pc.into();
	}

	fn set_sp(&mut self, sp: crate::TargetPtr) {
		self.esp = sp.into();
	}

	fn set_sysno(&mut self, arg: usize) {
		self.eax = arg as libc::c_long;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: crate::TargetPtr) {
		let arg = arg.into();
		match nr {
			0 => self.ebx = arg,
			1 => self.ecx = arg,
			2 => self.edx = arg,
			3 => self.esi = arg,
			4 => self.edi = arg,
			5 => self.ebp = arg,
			_ => crate::bug!("tried to get syscall arg nr {nr}"),
		}
	}

	fn set_ret_syscall(&mut self, ret: crate::TargetPtr) {
		self.eax = ret.into();
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
