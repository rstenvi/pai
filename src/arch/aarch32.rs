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
#[derive(Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
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
impl CallFrame {
	pub fn return_addr(&self, _client: &mut crate::Client) -> Result<TargetPtr> {
		Ok(self.regs.arm_lr.into())
	}
}

impl super::RegsAbiAccess for super::SystemV {
	fn get_retval(&self, regs: &crate::Registers) -> TargetPtr {
		regs.arm_r0.into()
	}

	fn set_retval(&self, regs: &mut crate::Registers, val: TargetPtr) {
		regs.arm_r0 = val.into();
	}

	fn get_arg(&self, regs: &crate::Registers, num: usize) -> Result<TargetPtr> {
		let v = match num {
			0 => regs.arm_r0,
			1 => regs.arm_r1,
			2 => regs.arm_r2,
			3 => regs.arm_r3,
			_ => return Err(crate::Error::Unsupported),
		};
		Ok(v.into())
	}

	fn get_arg_ext(
		&self,
		regs: &crate::Registers,
		num: usize,
		client: &mut crate::Client,
	) -> Result<TargetPtr> {
		todo!()
	}

	fn set_arg(&self, regs: &mut crate::Registers, num: usize, val: TargetPtr) -> Result<()> {
		let val = val.into();
		match num {
			0 => regs.arm_r0 = val,
			1 => regs.arm_r1 = val,
			2 => regs.arm_r2 = val,
			3 => regs.arm_r3 = val,
			_ => return Err(crate::Error::Unsupported),
		}
		Ok(())
	}

	fn set_arg_ext(
		&self,
		regs: &mut crate::Registers,
		num: usize,
		client: &mut crate::Client,
		val: TargetPtr,
	) -> Result<()> {
		todo!()
	}

	fn set_reg_call_tramp(&self, regs: &mut crate::Registers, val: TargetPtr) {
		regs.arm_r9 = val.into();
	}

	fn call_trampoline(&self, code: &mut Vec<u8>) {
		code.extend_from_slice(&NOP);
		code.extend_from_slice(&CALL_TRAMP);
		code.extend_from_slice(&SW_BP);
	}
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> TargetPtr {
		self.arm_pc.into()
	}

	fn sp(&self) -> TargetPtr {
		self.arm_sp.into()
	}

	fn sysno(&self) -> usize {
		self.arm_r7 as usize
	}

	fn arg_syscall(&self, nr: usize) -> TargetPtr {
		match nr {
			0 => self.arm_r0,
			1 => self.arm_r1,
			2 => self.arm_r2,
			3 => self.arm_r3,
			4 => self.arm_r4,
			5 => self.arm_r5,
			_ => crate::bug!("tried to get syscall arg nr {nr}"),
		}
		.into()
	}

	fn ret_syscall(&self) -> TargetPtr {
		self.arm_r0.into()
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: TargetPtr) {
		self.arm_pc = pc.into();
	}

	fn set_sp(&mut self, sp: TargetPtr) {
		self.arm_sp = sp.into();
	}

	fn set_sysno(&mut self, sysno: usize) {
		self.arm_r7 = sysno as libc::c_ulong;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: TargetPtr) {
		let arg = arg.into();
		match nr {
			0 => self.arm_r0 = arg,
			1 => self.arm_r1 = arg,
			2 => self.arm_r2 = arg,
			3 => self.arm_r3 = arg,
			4 => self.arm_r4 = arg,
			5 => self.arm_r5 = arg,
			_ => crate::bug!("tried to set syscall arg nr {nr}"),
		}
	}

	fn set_ret_syscall(&mut self, ret: TargetPtr) {
		self.arm_r0 = ret.into();
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
pub(crate) fn as_our_regs(regs: pete::Registers) -> user_regs_struct {
	regs.into()
}
