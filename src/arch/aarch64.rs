//! Code specific to Aarch64
//! 
//! ABI is here: <https://github.com/ARM-software/abi-aa>
use serde::{Deserialize, Serialize};

use crate::{Result, api::CallFrame, TargetPtr};

// rasm2 -a arm -b 64 "brk #0"
pub(crate) const SW_BP: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];

// rasm2 -a arm -b 64 "ret"
pub(crate) const RET: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];

// rasm2 -a arm -b 64 "blr x9"
pub(crate) const CALL_TRAMP: [u8; 4] = [0x20, 0x01, 0x3f, 0xd6];

// rasm2 -a arm -b 64 "nop"
pub(crate) const NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

// rasm2 -a arm -b 64 "svc #0"
pub(crate) const SYSCALL: [u8; 4] = [0x01, 0x00, 0x00, 0xd4];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct user_regs_struct {
	pub regs: [u64; 31],
	pub sp: u64,
	pub pc: u64,
	pub pstate: u64,
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
	pub fn return_addr(&self, client: &mut crate::Client) -> Result<TargetPtr> {
		todo!();
	}
}
impl super::RegsAbiAccess for super::SystemV {
    fn get_retval(&self, regs: &crate::Registers) -> TargetPtr {
        todo!()
    }

    fn set_retval(&self, regs: &mut crate::Registers, val: TargetPtr) {
        todo!()
    }

    fn get_arg(&self, regs: &crate::Registers, num: usize) -> Result<TargetPtr> {
        todo!()
    }

    fn get_arg_ext(&self, regs: &crate::Registers, num: usize, client: &mut crate::Client) -> Result<TargetPtr> {
        todo!()
    }

    fn set_arg(&self, regs: &mut crate::Registers, num: usize, val: TargetPtr) -> Result<()> {
        todo!()
    }

    fn set_arg_ext(&self, regs: &mut crate::Registers, num: usize, client: &mut crate::Client, val: TargetPtr) -> Result<()> {
        todo!()
    }

    fn set_reg_call_tramp(&self, regs: &mut crate::Registers, val: TargetPtr) {
        todo!()
    }

    fn call_trampoline(&self, code: &mut Vec<u8>) {
        todo!()
    }
}

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> TargetPtr {
		self.pc.into()
	}

	fn sp(&self) -> TargetPtr {
		self.sp.into()
	}

	fn sysno(&self) -> usize {
		self.regs[8] as usize
	}

	fn arg_syscall(&self, nr: usize) -> TargetPtr {
		assert!(nr <= 5);
		self.regs[nr].into()
	}

	fn ret_syscall(&self) -> TargetPtr {
		self.regs[0].into()
	}
}

impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: TargetPtr) {
		self.pc = pc.into();
	}

	fn set_sp(&mut self, sp: TargetPtr) {
		self.sp = sp.into();
	}

	fn set_sysno(&mut self, sysno: usize) {
		self.regs[0] = sysno as u64;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: TargetPtr) {
		assert!(nr < 8);
		self.regs[nr] = arg.into();
	}

	fn set_ret_syscall(&mut self, ret: TargetPtr) {
		self.regs[0] = ret.into();
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
