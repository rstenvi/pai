//! Code specific to x86
//! 
//! ABI is here: <https://github.com/hjl-tools/x86-psABI/wiki/intel386-psABI-1.1.pdf>
use serde::{Deserialize, Serialize};

// rasm2 -a x86 -b 32 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

// rasm2 -a x86 -b 32 "ret"
pub(crate) const RET: [u8; 1] = [0xc3];

// rasm2 -a x86 -b 32 "call eax"
pub(crate) const CALL_TRAMP: [u8; 3] = [0xff, 0xd0];

// rasm2 -a x86 -b 32 "nop"
pub(crate) const NOP: [u8; 4] = [0x90, 0x90, 0x90, 0x90];

// rasm2 -a x86 -b 32 "int 0x80"
pub(crate) const SYSCALL: [u8; 1] = [0xcd, 0x80];

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

impl crate::arch::ReadRegisters for user_regs_struct {
	fn pc(&self) -> crate::TargetPtr {
		self.eip
	}

	fn sp(&self) -> crate::TargetPtr {
		self.esp
	}

	fn sysno(&self) -> crate::TargetPtr {
		self.eax
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
	}

	fn ret_syscall(&self) -> crate::TargetPtr {
		self.eax
	}

	fn arg_systemv(&self, nr: usize) -> crate::TargetPtr {
		todo!()
	}

	fn ret_systemv(&self) -> crate::TargetPtr {
		todo!()
	}
}
impl crate::arch::WriteRegisters for user_regs_struct {
	fn set_pc(&mut self, pc: crate::TargetPtr) {
		self.eip = pc;
	}

	fn set_sp(&mut self, sp: crate::TargetPtr) {
		self.esp = sp;
	}

	fn set_sysno(&mut self, arg: crate::TargetPtr) {
		self.eax = arg;
	}

	fn set_arg_syscall(&mut self, nr: usize, arg: crate::TargetPtr) {
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
		self.eax = ret;
	}

	fn set_arg_systemv(&mut self, nr: usize, arg: crate::TargetPtr) {
		todo!()
	}

	fn set_call_func(&mut self, addr: crate::TargetPtr) {
		self.eax = addr;
	}
	fn set_ret_systemv(&mut self, ret: crate::TargetPtr) {
        todo!()
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
