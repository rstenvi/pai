//! Architecture-specific code
use serde::{Deserialize, Serialize};

// Syscall table for different architectures
// <https://stackoverflow.com/a/38906005>

use crate::{target::GenericCc, Registers, Result, TargetPtr};


pub mod aarch64;
pub mod aarch32;
pub mod x86_64;
pub mod x86;
pub mod riscv64;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ArchRegisters {
	X86_64(x86_64::user_regs_struct),
	X86(x86::user_regs_struct),
	Aarch32(aarch32::user_regs_struct),
	Aarch64(aarch64::user_regs_struct),
}

macro_rules! forward_reg {
	($self:ident, $func:ident, $($args:tt)*) => {
		match $self {
			ArchRegisters::X86_64(x) => x.$func($($args)*),
			ArchRegisters::X86(x) => x.$func($($args)*),
			ArchRegisters::Aarch32(x) => x.$func($($args)*),
			ArchRegisters::Aarch64(x) => x.$func($($args)*),
		}
	};
	($self:ident, $func:ident) => {
		forward_reg! { $self, $func, }
	};
}

impl NamedRegs for ArchRegisters {
	fn get_sp(&self) -> u64 {
		forward_reg! { self, get_sp }
	}

	fn get_pc(&self) -> u64 {
		forward_reg! { self, get_pc }
	}

	fn get_sysno(&self) -> usize {
		forward_reg! { self, get_sysno }
	}

	fn set_sp(&mut self, sp: u64) {
		forward_reg! { self, set_sp, sp }
	}

	fn set_pc(&mut self, pc: u64) {
		forward_reg! { self, set_pc, pc }
	}

	fn set_sysno(&mut self, sysno: usize) {
		forward_reg! { self, set_sysno, sysno }
	}

	fn offset_of(&self, regs: &str) -> Result<usize> {
		forward_reg! { self, offset_of, regs }
	}

	fn size_of(&self, regs: &str) -> Result<usize> {
		forward_reg! { self, size_of, regs }
	}

	fn get_value(&self, offset: usize, size: usize, data: &mut Vec<u8>) -> Result<()> {
		forward_reg! { self, get_value, offset, size, data }
	}

	fn set_value(&mut self, offset: usize, data: &[u8]) -> Result<()> {
		forward_reg! { self, set_value, offset, data }
	}
}

macro_rules! impl_named_regs {
	($for:ident) => {
		impl crate::arch::NamedRegs for $for {
			fn get_sp(&self) -> u64 {
				self._get_sp()
			}
			fn get_pc(&self) -> u64 {
				self._get_pc()
			}
			fn get_sysno(&self) -> usize {
				self._get_sysno()
			}
			fn set_sp(&mut self, sp: u64) {
				self._set_sp(sp)
			}
			fn set_pc(&mut self, pc: u64) {
				self._set_pc(pc)
			}
			fn set_sysno(&mut self, sysno: usize) {
				self._set_sysno(sysno)
			}
			fn offset_of(&self, regs: &str) -> Result<usize> {
				self._offset_of(regs).ok_or(crate::Error::msg(format!("reg {regs} not found")))
			}
			fn size_of(&self, regs: &str) -> Result<usize> {
				self._size_of(regs).ok_or(crate::Error::msg(format!("reg {regs} not found")))
			}
			fn get_value(&self, offset: usize, size: usize, data: &mut Vec<u8>) -> Result<()> {
				if offset + size <= std::mem::size_of::<Self>() {
					unsafe { self._get_value(offset, size, data) }
					Ok(())
				} else {
					Err(crate::Error::msg(format!("addr 0x{offset:x} + 0x{size:x} goes beyond register space")))
				}
			}
			fn set_value(&mut self, offset: usize, data: &[u8]) -> Result<()> {
				if offset + data.len() <= std::mem::size_of::<Self>() {
					unsafe { self._set_value(offset, data) }
					Ok(())
				} else {
					Err(crate::Error::msg(format!("addr 0x{offset:x} + 0x{:x} goes beyond register space", data.len())))
				}
			}
		}
	};
}
pub(crate) use impl_named_regs;

macro_rules! impl_from_pete {
	($regs:ident) => {
		impl From<$regs> for pete::Registers {
			fn from(value: user_regs_struct) -> pete::Registers {
				unsafe { std::mem::transmute(value) }
			}
		}
		impl From<pete::Registers> for $regs {
			fn from(value: pete::Registers) -> $regs {
				unsafe { std::mem::transmute(value) }
			}
		}
	};
}
pub(crate) use impl_from_pete;


macro_rules! impl_from_generic {
	($regs:ident, $ident:ident) => {
		impl From<$regs> for crate::arch::ArchRegisters {
			fn from(value: user_regs_struct) -> Self {
				Self::$ident(value)
			}
		}
		impl From<crate::arch::ArchRegisters> for $regs {
			fn from(value: crate::arch::ArchRegisters) -> Self {
				match value {
					crate::arch::ArchRegisters::$ident(reg) => reg,
					_ => panic!(""),
				}
			}
		}
	};
}
pub(crate) use impl_from_generic;

macro_rules! impl_conv_pete_generic {
	($regs:ident, $ident:ident) => {
		impl From<pete::Registers> for crate::arch::ArchRegisters {
			fn from(value: pete::Registers) -> crate::arch::ArchRegisters {
				let regs: $regs = value.into();
				Self::$ident(regs)
			}
		}
		impl From<crate::arch::ArchRegisters> for pete::Registers {
			fn from(value: crate::arch::ArchRegisters) -> Self {
				match value {
					crate::arch::ArchRegisters::$ident(reg) => reg.into(),
					_ => panic!(""),
				}
			}
		}
	};
}
pub(crate) use impl_conv_pete_generic;


pub trait NamedRegs {
	fn get_sp(&self) -> u64;
	fn get_pc(&self) -> u64;
	fn get_sysno(&self) -> usize;

	fn set_sp(&mut self, sp: u64);
	fn set_pc(&mut self, pc: u64);
	fn set_sysno(&mut self, sysno: usize);

	fn offset_of(&self, regs: &str) -> Result<usize>;
	fn size_of(&self, regs: &str) -> Result<usize>;
	fn get_value(&self, offset: usize, size: usize, data: &mut Vec<u8>) -> Result<()>;
	fn set_value(&mut self, offset: usize, data: &[u8]) -> Result<()>;
}

pub(crate) fn prep_native_syscall(regs: &mut dyn NamedRegs, sysno: usize, args: &[TargetPtr]) -> Result<()> {
	log::trace!("sysno {sysno} | args {args:?}");
	let cc = GenericCc::new_syscall_host()?;
	regs.set_sysno(sysno);
	for (i, arg) in args.iter().enumerate() {
		cc.set_arg_regonly(i, (*arg).into(), regs)?;
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
		aarch32::syscall_shellcode(code)
	}
	#[cfg(target_arch = "aarch64")]
	{
		aarch64::syscall_shellcode(code)
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
		aarch32::call_shellcode(code)
	}
	#[cfg(target_arch = "aarch64")]
	{
		aarch64::call_shellcode(code)
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
		aarch32::ret_shellcode(code)
	}
	#[cfg(target_arch = "aarch64")]
	{
		aarch64::ret_shellcode(code)
	}
	#[cfg(target_arch = "riscv64")]
	{
		todo!()
	}
}
