//! Architecture-specific code
use crate::{Result, TargetPtr};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "arm")]
pub mod aarch32;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86")]
pub mod x86;

/// Trait to read registers in an architecture-neutral manner
pub trait ReadRegisters {
	fn pc(&self) -> TargetPtr;
	fn sp(&self) -> TargetPtr;
	fn sysno(&self) -> TargetPtr;
	fn arg_syscall(&self, nr: usize) -> TargetPtr;
	fn ret_syscall(&self) -> TargetPtr;
	fn arg_systemv(&self, nr: usize) -> TargetPtr;
	fn ret_systemv(&self) -> TargetPtr;
}

/// Trait to write registers in an architecture-neutral manner
pub trait WriteRegisters {
	fn set_pc(&mut self, pc: TargetPtr);
	fn set_sp(&mut self, pc: TargetPtr);
	fn set_sysno(&mut self, pc: TargetPtr);
	fn set_arg_syscall(&mut self, nr: usize, pc: TargetPtr);
	fn set_ret_syscall(&mut self, ret: TargetPtr);
	fn set_arg_systemv(&mut self, nr: usize, arg: TargetPtr);
	fn set_ret_systemv(&mut self, ret: TargetPtr);
	fn set_call_func(&mut self, addr: TargetPtr);
}

pub(crate) fn prep_syscall<T>(regs: &mut T, sysno: TargetPtr, args: &[TargetPtr]) -> Result<()>
where
	T: WriteRegisters,
{
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
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::arch::{ReadRegisters, WriteRegisters};

	#[test]
	fn test_arch() {
		#[cfg(target_arch = "x86_64")]
		let mut r = x86_64::user_regs_struct::default();

		#[cfg(target_arch = "x86")]
		let mut r = x86::user_regs_struct::default();

		#[cfg(target_arch = "aarch64")]
		let mut r = aarch64::user_regs_struct::default();

		#[cfg(target_arch = "arm")]
		let mut r = aarch32::user_regs_struct::default();

		assert_eq!(r.pc(), 0);
		r.set_pc(42);
		assert_eq!(r.pc(), 42);

		r.set_sp(4);
		assert_eq!(r.sp(), 4);

		r.set_arg_systemv(0, 42);
		assert_eq!(r.arg_systemv(0), 42);

		r.set_ret_syscall(43);
		assert_eq!(r.ret_syscall(), 43);
	}
}
