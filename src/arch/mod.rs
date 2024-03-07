//! Architecture-specific code
use serde::{Deserialize, Serialize};

// Syscall table for different architectures
// <https://stackoverflow.com/a/38906005>

use crate::{target::GenericCc, Registers, Result, TargetPtr};

pub mod aarch32;
pub mod aarch64;
pub mod riscv64;
pub mod x86;
pub mod x86_64;
pub mod mips32;

/// All possible register values for supported architectures.
///
/// All reading/writing of registers should be done through [RegisterAccess] or
/// [crate::target::GenericCc].
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ArchRegisters {
	X86_64(x86_64::user_regs_struct),
	X86(x86::user_regs_struct),
	Aarch32(aarch32::user_regs_struct),
	Aarch64(aarch64::user_regs_struct),
	Riscv64(riscv64::user_regs_struct),
	Mips32(mips32::user_regs_struct),
}

macro_rules! forward_reg {
	($self:ident, $func:ident, $($args:tt)*) => {
		match $self {
			ArchRegisters::X86_64(x) => x.$func($($args)*),
			ArchRegisters::X86(x) => x.$func($($args)*),
			ArchRegisters::Aarch32(x) => x.$func($($args)*),
			ArchRegisters::Aarch64(x) => x.$func($($args)*),
			ArchRegisters::Riscv64(x) => x.$func($($args)*),
			ArchRegisters::Mips32(x) => x.$func($($args)*),
		}
	};
	($self:ident, $func:ident) => {
		forward_reg! { $self, $func, }
	};
}

impl RegisterAccess for ArchRegisters {
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
		impl crate::arch::RegisterAccess for $for {
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
				self._offset_of(regs)
					.ok_or(crate::Error::msg(format!("reg {regs} not found")))
			}
			fn size_of(&self, regs: &str) -> Result<usize> {
				self._size_of(regs)
					.ok_or(crate::Error::msg(format!("reg {regs} not found")))
			}
			fn get_value(&self, offset: usize, size: usize, data: &mut Vec<u8>) -> Result<()> {
				if offset + size <= std::mem::size_of::<Self>() {
					unsafe { self._get_value(offset, size, data) }
					Ok(())
				} else {
					Err(crate::Error::msg(format!(
						"addr 0x{offset:x} + 0x{size:x} goes beyond register space"
					)))
				}
			}
			fn set_value(&mut self, offset: usize, data: &[u8]) -> Result<()> {
				if offset + data.len() <= std::mem::size_of::<Self>() {
					unsafe { self._set_value(offset, data) }
					Ok(())
				} else {
					Err(crate::Error::msg(format!(
						"addr 0x{offset:x} + 0x{:x} goes beyond register space",
						data.len()
					)))
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

macro_rules! get_def_little {
	($get:ident, $isbig:expr) => {
		if $isbig {
			let mut r = $get.clone();
			r.reverse();
			r
		} else {
			$get
		}
	};
}
pub(crate) use get_def_little;

macro_rules! gen_syscall_shellcode {
	() => {
		pub(crate) fn syscall_shellcode(code: &mut Vec<u8>) {
			let endian = crate::target::Target::endian();
			let isbig = endian.is_big();

			let nop = crate::arch::get_def_little!(NOP, isbig);
			let syscall = crate::arch::get_def_little!(SYSCALL, isbig);
			let swbp = crate::arch::get_def_little!(SW_BP, isbig);

			code.extend_from_slice(&nop);
			code.extend_from_slice(&syscall);
			code.extend_from_slice(&swbp);
		}
	};
}
pub(crate) use gen_syscall_shellcode;

macro_rules! gen_call_shellcode {
	() => {
		pub(crate) fn call_shellcode(code: &mut Vec<u8>) {
			let endian = crate::target::Target::endian();
			let isbig = endian.is_big();

			let nop = crate::arch::get_def_little!(NOP, isbig);
			let call_tramp = crate::arch::get_def_little!(CALL_TRAMP, isbig);
			let swbp = crate::arch::get_def_little!(SW_BP, isbig);

			code.extend_from_slice(&nop);
			code.extend_from_slice(&nop);
			code.extend_from_slice(&call_tramp);

			// This doesn't work correctly on mips (qemu) unless we have an
			// extra NOP after the call
			code.extend_from_slice(&nop);
			code.extend_from_slice(&swbp);
		}
	};
}
pub(crate) use gen_call_shellcode;

macro_rules! gen_ret_shellcode {
	() => {
		pub(crate) fn ret_shellcode(code: &mut Vec<u8>) {
			let endian = crate::target::Target::endian();
			let isbig = endian.is_big();

			let nop = crate::arch::get_def_little!(NOP, isbig);
			let ret = crate::arch::get_def_little!(RET, isbig);

			code.extend_from_slice(&nop);
			code.extend_from_slice(&ret);
		}
	};
}
pub(crate) use gen_ret_shellcode;

macro_rules! gen_bp_shellcode {
	() => {
		pub(crate) fn bp_shellcode(code: &mut Vec<u8>) {
			let endian = crate::target::Target::endian();
			let isbig = endian.is_big();
			let swbp = crate::arch::get_def_little!(SW_BP, isbig);
			code.extend_from_slice(&swbp);
		}
	};
}
pub(crate) use gen_bp_shellcode;


/// Architecture-neutral manner to read/write register.
///
/// ## Example
///
/// ```rust
/// // This would normally be provided through some method
/// use pai::RegisterAccess;
/// let regs = pai::arch::x86_64::user_regs_struct::default();
/// let mut regs: pai::Registers = regs.into();
///
/// // Below is the relevant code
///
/// regs.set_pc(0xdeadbeef);
/// assert_eq!(regs.get_pc(), 0xdeadbeef);
///
/// // If you need access to a specic named register, you need to
/// // get offset and sizes to the registers. You don't need to do
/// // this before every access, just do it once on some register.
/// let (off, size) = (regs.offset_of("rax").unwrap(), regs.size_of("rax").unwrap());
///
/// // We can now get the register
/// let mut rax = Vec::with_capacity(size);
/// regs.get_value(off, size, &mut rax).unwrap();
///
/// // A more convenient way to get the registers is by specifying a calling
/// // convention.
/// let cc = pai::target::GenericCc::new_syscall_target().unwrap();
/// let arg0 = cc.get_arg_regonly(0, &regs);
/// ```
pub trait RegisterAccess {
	/// Get stack pointer (SP)
	fn get_sp(&self) -> u64;

	/// Get program counter (PC)
	fn get_pc(&self) -> u64;

	/// Set syscall number to be used in system calls.
	fn get_sysno(&self) -> usize;

	/// Set stack pointer (SP)
	fn set_sp(&mut self, sp: u64);

	/// Set program counter (PC)
	fn set_pc(&mut self, pc: u64);

	/// Get syscall number used in system calls.
	fn set_sysno(&mut self, sysno: usize);

	/// Get offset of a register based on the name.
	///
	/// This can be used in later calls to [RegisterAccess::get_value] and
	/// [RegisterAccess::set_value].
	fn offset_of(&self, regs: &str) -> Result<usize>;

	/// Get size of register based on name.
	///
	/// Should be used in conjunction with [RegisterAccess::offset_of].
	fn size_of(&self, regs: &str) -> Result<usize>;

	/// Write value of register at `offset` with `size` into `data`
	fn get_value(&self, offset: usize, size: usize, data: &mut Vec<u8>) -> Result<()>;

	/// Write `data` into register at `offet`
	fn set_value(&mut self, offset: usize, data: &[u8]) -> Result<()>;
}

pub(crate) fn prep_native_syscall(
	regs: &mut dyn RegisterAccess,
	sysno: usize,
	args: &[TargetPtr],
) -> Result<()> {
	log::trace!("sysno {sysno} | args {args:?}");
	let cc = GenericCc::new_syscall_target()?;
	regs.set_sysno(sysno);
	for (i, arg) in args.iter().enumerate() {
		cc.set_arg_regonly(i, (*arg).into(), regs)?;
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use super::*;

	macro_rules! gen_test_regs_arch {
		($arch:ident) => {
			paste::paste! {
				#[test]
				pub fn [<test_regs_ $arch>]() {
					let regs = crate::arch::$arch::user_regs_struct::default();
					let sz1 = std::mem::size_of::<crate::arch::$arch::user_regs_struct>();
					let sz2 = std::mem::size_of::<pete::Registers>();
					assert_eq!(sz1, sz2);
					let mut regs: crate::Registers = regs.into();

					regs.set_pc(1);
					regs.set_sp(2);

					assert_eq!(regs.get_pc(), 1);
					assert_eq!(regs.get_sp(), 2);
				}
			}
		};
	}

	#[cfg(target_arch = "x86_64")]
	gen_test_regs_arch! { x86_64 }

	#[cfg(target_arch = "x86")]
	gen_test_regs_arch! { x86 }

	#[cfg(target_arch = "aarch64")]
	gen_test_regs_arch! { aarch64 }

	#[cfg(target_arch = "arm")]
	gen_test_regs_arch! { aarch32 }

	#[cfg(target_arch = "riscv64")]
	gen_test_regs_arch! { riscv64 }

	#[cfg(target_arch = "mips")]
	gen_test_regs_arch! { mips32 }
}
