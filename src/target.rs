//! Various code related to the specific target traced.

use serde::{Deserialize, Serialize};

use crate::arch::{self, RegisterAccess};
use crate::buildinfo::{BuildArch, BuildEndian, BuildInfo, BuildTarget};
use crate::{Error, Result};

struct TargetSizes {
	c_bool: u8,
	c_char: u8,
	c_short: u8,
	c_int: u8,
	c_long: u8,
	c_longlong: u8,
	c_ptr: u8,
}

impl TargetSizes {
	fn host() -> Self {
		use std::mem::size_of;
		Self {
			c_bool: size_of::<libc::c_char>() as u8,
			c_char: size_of::<libc::c_char>() as u8,
			c_short: size_of::<libc::c_short>() as u8,
			c_int: size_of::<libc::c_int>() as u8,
			c_long: size_of::<libc::c_long>() as u8,
			c_longlong: size_of::<libc::c_longlong>() as u8,
			c_ptr: size_of::<libc::c_void>() as u8,
		}
	}
}

/// The method for accessing an argument.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
enum ArgAccess {
	Register { regname: String, offset: usize },
	Stack { offset: usize },
}

/// The method for accessing an argument.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct CcArgAccess {
	size: usize,
	arg: ArgAccess,
}
impl CcArgAccess {
	fn from_named_reg<S: Into<String>>(reg: S, d: &dyn RegisterAccess) -> Result<Self> {
		let reg: String = reg.into();
		let offset = d.offset_of(&reg)?;
		let size = d.size_of(&reg)?;
		let arg = ArgAccess::Register {
			regname: reg,
			offset,
		};
		let ret = Self { size, arg };
		Ok(ret)
	}
	fn from_sp_offset(offset: usize, size: usize) -> Self {
		Self {
			size,
			arg: ArgAccess::Stack { offset },
		}
	}
	fn from_reg_offset<S: Into<String>>(regname: S, offset: usize, size: usize) -> Self {
		let regname = regname.into();
		Self {
			size,
			arg: ArgAccess::Register { regname, offset },
		}
	}
}

trait FromBytes: Sized {
	fn try_from_ne_bytes(bytes: &[u8]) -> Result<Self>;
	fn try_from_le_bytes(bytes: &[u8]) -> Result<Self>;
	fn try_from_be_bytes(bytes: &[u8]) -> Result<Self>;
}
trait ToBytes: Sized {
	fn try_to_ne_bytes(&self) -> Result<Vec<u8>>;
	fn try_to_le_bytes(&self) -> Result<Vec<u8>>;
	fn try_to_be_bytes(&self) -> Result<Vec<u8>>;
}

impl FromBytes for u64 {
	fn try_from_ne_bytes(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.map(u64::from_ne_bytes)
			.map_err(|_e| crate::Error::Unknown)
	}
	fn try_from_le_bytes(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.map(u64::from_le_bytes)
			.map_err(|_e| crate::Error::Unknown)
	}
	fn try_from_be_bytes(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.map(u64::from_be_bytes)
			.map_err(|_e| crate::Error::Unknown)
	}
}
impl FromBytes for u32 {
	fn try_from_ne_bytes(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.map(u32::from_ne_bytes)
			.map_err(|_e| crate::Error::Unknown)
	}
	fn try_from_le_bytes(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.map(u32::from_le_bytes)
			.map_err(|_e| crate::Error::Unknown)
	}
	fn try_from_be_bytes(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.map(u32::from_be_bytes)
			.map_err(|_e| crate::Error::Unknown)
	}
}

impl ToBytes for u64 {
	fn try_to_ne_bytes(&self) -> Result<Vec<u8>> {
		let v = u64::to_ne_bytes(*self);
		Ok(v.to_vec())
	}

	fn try_to_le_bytes(&self) -> Result<Vec<u8>> {
		let v = u64::to_le_bytes(*self);
		Ok(v.to_vec())
	}

	fn try_to_be_bytes(&self) -> Result<Vec<u8>> {
		let v = u64::to_be_bytes(*self);
		Ok(v.to_vec())
	}
}
impl ToBytes for u32 {
	fn try_to_ne_bytes(&self) -> Result<Vec<u8>> {
		let v = u32::to_ne_bytes(*self);
		Ok(v.to_vec())
	}

	fn try_to_le_bytes(&self) -> Result<Vec<u8>> {
		let v = u32::to_le_bytes(*self);
		Ok(v.to_vec())
	}

	fn try_to_be_bytes(&self) -> Result<Vec<u8>> {
		let v = u32::to_be_bytes(*self);
		Ok(v.to_vec())
	}
}

enum CcSignature {
	Unspecified,
	Fastcall,
	Thiscall,
}
impl std::str::FromStr for CcSignature {
	type Err = crate::Error;

	fn from_str(_s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
		todo!()
	}
}

#[derive(Default)]
struct UnknownCcBuilder {
	args: Vec<CcArgAccess>,
	retval: Option<CcArgAccess>,
	calltramp: Option<CcArgAccess>,
	returnaddr: Option<CcArgAccess>,
}
impl UnknownCcBuilder {
	pub fn add_arg(mut self, arg: CcArgAccess) -> Self {
		self.args.push(arg);
		self
	}
	pub fn set_retval(mut self, arg: CcArgAccess) -> Self {
		self.retval = Some(arg);
		self
	}
	pub fn build(self) -> Result<Self> {
		let _retval = self.retval.ok_or(Error::msg("return value must be set"))?;
		todo!();
	}
}

pub(crate) struct Target {}

macro_rules! target_info {
	() => {
		&crate::TARGET_INFO
			.read()
			.expect("unable to read TARGET_INFO")
			.target
	};
}

impl Target {
	pub fn arch() -> BuildArch {
		crate::TARGET_INFO
			.read()
			.expect("unable to read TARGET_INFO")
			.target
			.arch
			.clone()
	}
	#[cfg(feature = "syscalls")]
	pub fn syzarch() -> syzlang_parser::parser::Arch {
		Self::arch().into()
	}
	pub fn endian() -> BuildEndian {
		target_info!().endian.clone()
	}
	pub fn ptr_size() -> usize {
		let arch = Self::arch();
		match arch {
			BuildArch::Aarch64 | BuildArch::X86_64 | BuildArch::RiscV64 => 8,
			BuildArch::Aarch32 | BuildArch::X86 => 4,
			BuildArch::Mips => todo!(),
		}
	}
}

macro_rules! gen_shellcode_code {
	($ident:ident) => {
		pub fn $ident(code: &mut Vec<u8>) {
			let arch = Target::arch();
			match arch {
				BuildArch::Aarch64 => crate::arch::aarch64::$ident(code),
				BuildArch::Aarch32 => crate::arch::aarch32::$ident(code),
				BuildArch::X86_64 => crate::arch::x86_64::$ident(code),
				BuildArch::X86 => crate::arch::x86::$ident(code),
				BuildArch::Mips => todo!(),
				BuildArch::RiscV64 => crate::arch::riscv64::$ident(code),
			}
		}
	};
}

#[derive(Debug, Clone)]
pub(crate) struct TargetCode {}
impl TargetCode {
	gen_shellcode_code! { bp_shellcode }
	gen_shellcode_code! { syscall_shellcode }
	gen_shellcode_code! { call_shellcode }
	gen_shellcode_code! { ret_shellcode }
}

/// Access to argument(s) based on a defined calling convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericCc {
	args: Vec<CcArgAccess>,
	retval: CcArgAccess,
	calltramp: CcArgAccess,
	returnaddr: Option<CcArgAccess>,
}
impl GenericCc {
	pub(crate) fn subset_of(&self, of: &Self) -> bool {
		if self.retval == of.retval
			&& self.calltramp == of.calltramp
			&& self.returnaddr == of.returnaddr
			&& self.args.len() <= of.args.len()
		{
			for (i, arg) in self.args.iter().enumerate() {
				if *arg != of.args[i] {
					return false;
				}
			}
			return true;
		}
		false
	}
	pub fn new_syscall_target() -> Result<Self> {
		let arch = crate::TARGET_INFO.read().unwrap().target.arch.clone();
		Self::new_syscall(arch)
	}
	pub fn new_target_systemv() -> Result<Self> {
		let arch = crate::TARGET_INFO.read().unwrap().target.arch.clone();
		Self::new_systemv(arch)
	}
	fn new_syscall(arch: crate::buildinfo::BuildArch) -> Result<Self> {
		match arch {
			crate::buildinfo::BuildArch::Aarch64 => Self::new_syscall_aarch64(),
			crate::buildinfo::BuildArch::Aarch32 => Self::new_syscall_aarch32(),
			crate::buildinfo::BuildArch::X86_64 => Self::new_syscall_x86_64(),
			crate::buildinfo::BuildArch::X86 => Self::new_syscall_x86(),
			crate::buildinfo::BuildArch::Mips => todo!(),
			crate::buildinfo::BuildArch::RiscV64 => Self::new_syscall_riscv64(),
		}
	}
	fn new_systemv(arch: crate::buildinfo::BuildArch) -> Result<Self> {
		match arch {
			crate::buildinfo::BuildArch::Aarch64 => Self::new_systemv_aarch64(),
			crate::buildinfo::BuildArch::Aarch32 => Self::new_systemv_aarch32(),
			crate::buildinfo::BuildArch::X86_64 => Self::new_systemv_x86_64(),
			crate::buildinfo::BuildArch::X86 => Self::new_systemv_x86(),
			crate::buildinfo::BuildArch::Mips => todo!(),
			crate::buildinfo::BuildArch::RiscV64 => Self::new_systemv_riscv64(),
		}
	}
	fn new_systemv_x86() -> Result<Self> {
		// This is a simplification of the truth, but a baseline
		let regs = crate::arch::x86::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_sp_offset(4, 4),
			CcArgAccess::from_sp_offset(4 + 4, 4),
			CcArgAccess::from_sp_offset((2 * 4) + 4, 4),
			CcArgAccess::from_sp_offset((3 * 4) + 4, 4),
			CcArgAccess::from_sp_offset((4 * 4) + 4, 4),
			CcArgAccess::from_sp_offset((5 * 4) + 4, 4),
		];
		let retval = CcArgAccess::from_named_reg("eax", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("eax", &regs)?;
		let returnaddr = Some(CcArgAccess::from_sp_offset(0, 4));

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_systemv_riscv64() -> Result<Self> {
		let regs = crate::arch::riscv64::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("a0", &regs)?,
			CcArgAccess::from_named_reg("a1", &regs)?,
			CcArgAccess::from_named_reg("a2", &regs)?,
			CcArgAccess::from_named_reg("a3", &regs)?,
			CcArgAccess::from_named_reg("a4", &regs)?,
			CcArgAccess::from_named_reg("a5", &regs)?,
			CcArgAccess::from_named_reg("a6", &regs)?,
			CcArgAccess::from_named_reg("a7", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("a0", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("t0", &regs)?;
		let returnaddr = Some(CcArgAccess::from_named_reg("ra", &regs)?);

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_systemv_aarch32() -> Result<Self> {
		let regs = crate::arch::aarch32::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("arm_r0", &regs)?,
			CcArgAccess::from_named_reg("arm_r1", &regs)?,
			CcArgAccess::from_named_reg("arm_r2", &regs)?,
			CcArgAccess::from_named_reg("arm_r3", &regs)?,
			CcArgAccess::from_named_reg("arm_r4", &regs)?,
			CcArgAccess::from_named_reg("arm_r5", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("arm_r0", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("arm_r9", &regs)?;
		let returnaddr = Some(CcArgAccess::from_named_reg("arm_lr", &regs)?);

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_systemv_aarch64() -> Result<Self> {
		let args = vec![
			CcArgAccess::from_reg_offset("x0", 0, 8),
			CcArgAccess::from_reg_offset("x1", 8, 8),
			CcArgAccess::from_reg_offset("x2", 2 * 8, 8),
			CcArgAccess::from_reg_offset("x3", 3 * 8, 8),
			CcArgAccess::from_reg_offset("x4", 4 * 8, 8),
			CcArgAccess::from_reg_offset("x5", 5 * 8, 8),
			CcArgAccess::from_reg_offset("x6", 6 * 8, 8),
		];
		let retval = CcArgAccess::from_reg_offset("x0", 0, 8);
		let calltramp = CcArgAccess::from_reg_offset("x9", 9 * 8, 8);
		let returnaddr = Some(CcArgAccess::from_reg_offset("lr", 30 * 8, 8));

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_systemv_x86_64() -> Result<Self> {
		let regs = crate::arch::x86_64::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("rdi", &regs)?,
			CcArgAccess::from_named_reg("rsi", &regs)?,
			CcArgAccess::from_named_reg("rdx", &regs)?,
			CcArgAccess::from_named_reg("rcx", &regs)?,
			CcArgAccess::from_named_reg("r8", &regs)?,
			CcArgAccess::from_named_reg("r9", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("rax", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("r10", &regs)?;
		let returnaddr = Some(CcArgAccess::from_sp_offset(0, 8));

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_syscall_aarch64() -> Result<Self> {
		// let regs = crate::arch::x86::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_reg_offset("x0", 0, 8),
			CcArgAccess::from_reg_offset("x1", 8, 8),
			CcArgAccess::from_reg_offset("x2", 2 * 8, 8),
			CcArgAccess::from_reg_offset("x3", 3 * 8, 8),
			CcArgAccess::from_reg_offset("x4", 4 * 8, 8),
			CcArgAccess::from_reg_offset("x5", 5 * 8, 8),
			CcArgAccess::from_reg_offset("x6", 6 * 8, 8),
		];
		let retval = CcArgAccess::from_reg_offset("x0", 0, 8);
		let calltramp = CcArgAccess::from_reg_offset("x9", 9 * 8, 8);
		let returnaddr = None;

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_syscall_riscv64() -> Result<Self> {
		let regs = crate::arch::riscv64::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("a0", &regs)?,
			CcArgAccess::from_named_reg("a1", &regs)?,
			CcArgAccess::from_named_reg("a2", &regs)?,
			CcArgAccess::from_named_reg("a3", &regs)?,
			CcArgAccess::from_named_reg("a4", &regs)?,
			CcArgAccess::from_named_reg("a5", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("a0", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("t0", &regs)?;
		let returnaddr = None;

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_syscall_aarch32() -> Result<Self> {
		let regs = crate::arch::aarch32::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("arm_r0", &regs)?,
			CcArgAccess::from_named_reg("arm_r1", &regs)?,
			CcArgAccess::from_named_reg("arm_r2", &regs)?,
			CcArgAccess::from_named_reg("arm_r3", &regs)?,
			CcArgAccess::from_named_reg("arm_r4", &regs)?,
			CcArgAccess::from_named_reg("arm_r5", &regs)?,
			CcArgAccess::from_named_reg("arm_r6", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("arm_r0", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("arm_r9", &regs)?;
		let returnaddr = None;

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_syscall_x86() -> Result<Self> {
		let regs = crate::arch::x86::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("ebx", &regs)?,
			CcArgAccess::from_named_reg("ecx", &regs)?,
			CcArgAccess::from_named_reg("edx", &regs)?,
			CcArgAccess::from_named_reg("esi", &regs)?,
			CcArgAccess::from_named_reg("edi", &regs)?,
			CcArgAccess::from_named_reg("ebp", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("eax", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("eax", &regs)?;
		let returnaddr = None;

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}
	fn new_syscall_x86_64() -> Result<Self> {
		let regs = crate::arch::x86_64::user_regs_struct::default();
		let args = vec![
			CcArgAccess::from_named_reg("rdi", &regs)?,
			CcArgAccess::from_named_reg("rsi", &regs)?,
			CcArgAccess::from_named_reg("rdx", &regs)?,
			CcArgAccess::from_named_reg("r10", &regs)?,
			CcArgAccess::from_named_reg("r8", &regs)?,
			CcArgAccess::from_named_reg("r9", &regs)?,
		];
		let retval = CcArgAccess::from_named_reg("rax", &regs)?;
		let calltramp = CcArgAccess::from_named_reg("r10", &regs)?;
		let returnaddr = None;

		let ret = Self {
			args,
			retval,
			calltramp,
			returnaddr,
		};
		Ok(ret)
	}

	fn _set_arg(
		arg: &CcArgAccess,
		regs: &mut dyn RegisterAccess,
		val: u64,
		client: Option<&mut crate::Client>,
	) -> Result<()> {
		let endian = &crate::TARGET_INFO.read().unwrap().target.endian;
		let data = if arg.size == 8 {
			match endian {
				BuildEndian::Little => val.try_to_le_bytes()?,
				BuildEndian::Big => val.try_to_be_bytes()?,
				BuildEndian::Native => val.try_to_ne_bytes()?,
			}
		} else if arg.size == 4 {
			let v = (val & 0xffffffff) as u32;
			match endian {
				BuildEndian::Little => v.try_to_le_bytes()?,
				BuildEndian::Big => v.try_to_be_bytes()?,
				BuildEndian::Native => v.try_to_ne_bytes()?,
			}
		} else {
			log::error!("function does not support register size: {}", arg.size);
			return Err(Error::Unknown);
		};
		match &arg.arg {
			ArgAccess::Register { regname: _, offset } => regs.set_value(*offset, &data)?,
			ArgAccess::Stack { offset } => {
				let sp = regs.get_sp();
				let sp = sp + *offset as u64;
				let addr = sp.into();
				let client = client.ok_or(Error::Unknown)?;
				let tids = client.get_stopped_tids()?;
				let tid = tids.first().ok_or(Error::msg("No stopped thread"))?;
				client.write_bytes(*tid, addr, data)?;
			}
		}
		Ok(())
	}
	fn _get_arg(
		arg: &CcArgAccess,
		regs: &dyn RegisterAccess,
		client: Option<&mut crate::Client>,
	) -> Result<u64> {
		let endian = &crate::TARGET_INFO.read().unwrap().target.endian;
		let mut data = Vec::with_capacity(arg.size);
		match &arg.arg {
			ArgAccess::Register { regname: _, offset } => {
				regs.get_value(*offset, arg.size, &mut data)?
			}
			ArgAccess::Stack { offset } => {
				let sp = regs.get_sp();
				let addr = (sp + *offset as u64).into();
				let client = client.ok_or(Error::Unknown)?;
				let tids = client.get_stopped_tids()?;
				let tid = tids.first().ok_or(Error::msg("No stopped thread"))?;
				let mut res = client.read_bytes(*tid, addr, arg.size)?;
				data.append(&mut res);
			}
		}
		let ret = if arg.size == 4 {
			match endian {
				BuildEndian::Little => u32::try_from_le_bytes(&data)? as u64,
				BuildEndian::Big => u32::try_from_be_bytes(&data)? as u64,
				BuildEndian::Native => u32::try_from_ne_bytes(&data)? as u64,
			}
		} else if arg.size == 8 {
			match endian {
				BuildEndian::Little => u64::try_from_le_bytes(&data)?,
				BuildEndian::Big => u64::try_from_be_bytes(&data)?,
				BuildEndian::Native => u64::try_from_ne_bytes(&data)?,
			}
		} else {
			log::error!("function does not support register size: {}", arg.size);
			return Err(Error::Unknown);
		};
		Ok(ret)
	}
	pub fn get_arg(
		&self,
		num: usize,
		regs: &dyn RegisterAccess,
		client: &mut crate::Client,
	) -> Result<u64> {
		let arg = self.args.get(num).ok_or(Error::Unknown)?;
		Self::_get_arg(arg, regs, Some(client))
	}
	pub fn set_arg(
		&self,
		num: usize,
		val: u64,
		regs: &mut dyn RegisterAccess,
		client: &mut crate::Client,
	) -> Result<()> {
		let arg = self.args.get(num).ok_or(Error::Unknown)?;
		Self::_set_arg(arg, regs, val, Some(client))
	}
	pub fn get_retval(&self, regs: &dyn RegisterAccess) -> Result<u64> {
		Self::_get_arg(&self.retval, regs, None)
	}
	pub fn set_retval(&self, val: u64, regs: &mut dyn RegisterAccess) -> Result<()> {
		Self::_set_arg(&self.retval, regs, val, None)
	}
	pub fn set_reg_call_tramp(
		&self,
		regs: &mut dyn RegisterAccess,
		value: crate::TargetPtr,
	) -> Result<()> {
		Self::_set_arg(&self.calltramp, regs, value.into(), None)
	}
	pub fn set_arg_regonly(
		&self,
		num: usize,
		val: u64,
		regs: &mut dyn RegisterAccess,
	) -> Result<()> {
		let arg = self.args.get(num).ok_or(Error::Unknown)?;
		Self::_set_arg(arg, regs, val, None)
	}
	pub fn get_arg_regonly(&self, num: usize, regs: &dyn RegisterAccess) -> Result<u64> {
		let arg = self.args.get(num).ok_or(Error::Unknown)?;
		Self::_get_arg(arg, regs, None)
	}
	pub fn get_return_addr(
		&self,
		regs: &dyn RegisterAccess,
		client: &mut crate::Client,
	) -> Result<u64> {
		let arg = self.returnaddr.as_ref().ok_or(Error::unsupported())?;
		Self::_get_arg(arg, regs, Some(client))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	macro_rules! gen_test_cc_arch {
		($arch:ident) => {
			paste::paste! {
				#[test]
				pub fn [<test_cc_syscall_ $arch>]() {
					let mut regs = crate::arch::$arch::user_regs_struct::default();
					let cc = GenericCc::[<new_syscall_ $arch>]().unwrap();

					log::trace!("setting retval");
					cc.set_retval(42, &mut regs).unwrap();
					assert_eq!(cc.get_retval(&regs).unwrap(), 42);


					for i in 0..6 {
						log::trace!("setting arg[{i}]");
						cc.set_arg_regonly(i, 43 + i as u64, &mut regs).unwrap();
					}

					for i in 0..6 {
						log::trace!("setting arg[{i}]");
						let v = cc.get_arg_regonly(i, &mut regs).unwrap();
						assert_eq!(v, i as u64 + 43);
					}
				}
				#[test]
				pub fn [<test_cc_systemv_ $arch>]() {
					let mut regs = crate::arch::$arch::user_regs_struct::default();
					let cc = GenericCc::[<new_systemv_ $arch>]().unwrap();

					log::trace!("setting retval");
					cc.set_retval(42, &mut regs).unwrap();
					assert_eq!(cc.get_retval(&regs).unwrap(), 42);


					for i in 0..6 {
						log::trace!("setting arg[{i}]");
						cc.set_arg_regonly(i, 43 + i as u64, &mut regs).unwrap();
					}

					for i in 0..6 {
						log::trace!("setting arg[{i}]");
						let v = cc.get_arg_regonly(i, &mut regs).unwrap();
						assert_eq!(v, i as u64 + 43);
					}
				}
			}
		};
	}

	gen_test_cc_arch! { x86_64 }

	// Cannot run test for args on stack
	// gen_test_cc_arch! { x86 }

	gen_test_cc_arch! { aarch64 }

	gen_test_cc_arch! { aarch32 }

	gen_test_cc_arch! { riscv64 }
}
