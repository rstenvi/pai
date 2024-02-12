//! Architecture-specific code
use serde::{Deserialize, Serialize};

// Syscall table for different architectures
// <https://stackoverflow.com/a/38906005>

use crate::{Registers, Result, TargetPtr};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "arm")]
pub mod aarch32;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86")]
pub mod x86;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemV;

pub trait RegsAbiAccess {
	fn get_retval(&self, regs: &Registers) -> TargetPtr;
	fn set_retval(&self, regs: &mut Registers, val: TargetPtr);
	fn get_arg(&self, regs: &Registers, num: usize) -> Result<TargetPtr>;
	fn get_arg_ext(
		&self,
		regs: &Registers,
		num: usize,
		client: &mut crate::Client,
	) -> Result<TargetPtr>;
	fn set_arg(&self, regs: &mut Registers, num: usize, val: TargetPtr) -> Result<()>;
	fn set_arg_ext(
		&self,
		regs: &mut Registers,
		num: usize,
		client: &mut crate::Client,
		val: TargetPtr,
	) -> Result<()>;
	fn set_reg_call_tramp(&self, regs: &mut Registers, val: TargetPtr);
	fn call_trampoline(&self, code: &mut Vec<u8>);
}

/// Trait to read registers in an architecture-neutral manner
pub trait ReadRegisters {
	fn pc(&self) -> TargetPtr;
	fn sp(&self) -> TargetPtr;
	fn sysno(&self) -> usize;
	fn arg_syscall(&self, nr: usize) -> TargetPtr;
	fn ret_syscall(&self) -> TargetPtr;
}

/// Trait to write registers in an architecture-neutral manner
pub trait WriteRegisters {
	fn set_pc(&mut self, pc: TargetPtr);
	fn set_sp(&mut self, pc: TargetPtr);
	fn set_sysno(&mut self, pc: usize);
	fn set_arg_syscall(&mut self, nr: usize, pc: TargetPtr);
	fn set_ret_syscall(&mut self, ret: TargetPtr);
}

pub(crate) fn prep_syscall<T>(regs: &mut T, sysno: usize, args: &[TargetPtr]) -> Result<()>
where
	T: WriteRegisters,
{
	log::trace!("sysno {sysno} | args {args:?}");
	regs.set_sysno(sysno);
	for (i, arg) in args.iter().enumerate() {
		regs.set_arg_syscall(i, *arg);
	}
	Ok(())
}

pub(crate) fn bp_code() -> &'static [u8] {
	#[cfg(target_arch = "aarch64")]
	{
		&crate::arch::aarch64::SW_BP
	}

	#[cfg(target_arch = "arm")]
	{
		&crate::arch::aarch32::SW_BP
	}

	#[cfg(target_arch = "x86_64")]
	{
		&crate::arch::x86_64::SW_BP
	}

	#[cfg(target_arch = "x86")]
	{
		&crate::arch::x86::SW_BP
	}

	#[cfg(target_arch = "riscv64")]
	{
		todo!();
	}
}

pub(crate) fn syscall_shellcode(code: &mut Vec<u8>) {
	#[cfg(target_arch = "x86")]
	{
		x86::syscall_shellcode(code)
	}
	#[cfg(target_arch = "x86_64")]
	{
		x86_64::syscall_shellcode(code)
	}
	#[cfg(target_arch = "arm")]
	{
		arm::syscall_shellcode(code)
	}
	#[cfg(target_arch = "aarch64")]
	{
		x86::syscall_shellcode(code)
	}
	#[cfg(target_arch = "riscv64")]
	{
		todo!()
	}
}
pub(crate) fn call_shellcode(code: &mut Vec<u8>) {
	#[cfg(target_arch = "x86")]
	{
		x86::call_shellcode(code)
	}
	#[cfg(target_arch = "x86_64")]
	{
		x86_64::call_shellcode(code)
	}
	#[cfg(target_arch = "arm")]
	{
		arm::call_shellcode(code)
	}
	#[cfg(target_arch = "aarch64")]
	{
		x86::call_shellcode(code)
	}
	#[cfg(target_arch = "riscv64")]
	{
		todo!()
	}
}
pub(crate) fn ret_shellcode(code: &mut Vec<u8>) {
	#[cfg(target_arch = "x86")]
	{
		x86::ret_shellcode(code)
	}
	#[cfg(target_arch = "x86_64")]
	{
		x86_64::ret_shellcode(code)
	}
	#[cfg(target_arch = "arm")]
	{
		arm::ret_shellcode(code)
	}
	#[cfg(target_arch = "aarch64")]
	{
		x86::ret_shellcode(code)
	}
	#[cfg(target_arch = "riscv64")]
	{
		todo!()
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::arch::{ReadRegisters, WriteRegisters};

	#[test]
	fn test_arch() {
		let mut r = crate::Registers::default();

		assert_eq!(r.pc(), 0.into());
		r.set_pc(42.into());
		assert_eq!(r.pc(), 42.into());

		r.set_sp(4.into());
		assert_eq!(r.sp(), 4.into());

		// r.set_arg_systemv(0, 42);
		// assert_eq!(r.arg_systemv(0), 42);

		r.set_ret_syscall(43.into());
		assert_eq!(r.ret_syscall(), 43.into());
	}
}
