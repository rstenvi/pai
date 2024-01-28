use serde::{Deserialize, Serialize};

// rasm2 -a x86 -b 32 "int3"
pub(crate) const SW_BP: [u8; 1] = [0xcc];

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

impl From<libc::user_regs_struct> for user_regs_struct {
	fn from(value: libc::user_regs_struct) -> user_regs_struct {
		unsafe { std::mem::transmute(value) }
	}
}
impl From<user_regs_struct> for libc::user_regs_struct {
	fn from(value: user_regs_struct) -> libc::user_regs_struct {
		unsafe { std::mem::transmute(value) }
	}
}
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
		todo!()
	}

	fn sp(&self) -> crate::TargetPtr {
		todo!()
	}

	fn sysno(&self) -> crate::TargetPtr {
		todo!()
	}

	fn arg_syscall(&self, nr: usize) -> crate::TargetPtr {
		todo!()
	}

	fn ret_syscall(&self) -> crate::TargetPtr {
		todo!()
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
		todo!()
	}

	fn set_sp(&mut self, pc: crate::TargetPtr) {
		todo!()
	}

	fn set_sysno(&mut self, pc: crate::TargetPtr) {
		todo!()
	}

	fn set_arg_syscall(&mut self, nr: usize, pc: crate::TargetPtr) {
		todo!()
	}

	fn set_ret_syscall(&mut self, ret: crate::TargetPtr) {
		todo!()
	}

	fn set_arg_systemv(&mut self, nr: usize, arg: crate::TargetPtr) {
		todo!()
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
pub fn as_our_regs(regs: nix::libc::user_regs_struct) -> user_regs_struct {
	regs.into()
}
