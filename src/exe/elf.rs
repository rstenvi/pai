//! Parsing of ELF

use crate::{Error, Result, TargetPtr};
use elf::{
	endian::AnyEndian,
	string_table::StringTable,
	symbol::{Symbol, SymbolTable},
	ElfBytes,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Type of symbol, read ELF-specification for more details
#[repr(u8)]
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum SymbolType {
	NoType = 0,
	Object = 1,
	Func = 2,
	Section = 3,
	File = 4,
	Common = 5,
	Tls = 6,
	Unknown = 255,
}

impl From<u8> for SymbolType {
	fn from(value: u8) -> Self {
		match value {
			0 => Self::NoType,
			1 => Self::Object,
			2 => Self::Func,
			3 => Self::Section,
			4 => Self::File,
			5 => Self::Common,
			6 => Self::Tls,
			_ => Self::Unknown,
		}
	}
}
impl From<SymbolType> for u8 {
	fn from(value: SymbolType) -> Self {
		value as u8
	}
}

/// Symbol binding, read ELF-specification for more details
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum SymbolBind {
	Local = 0,
	Global = 1,
	Weak = 2,
	Unknown = 255,
}
impl From<u8> for SymbolBind {
	fn from(value: u8) -> Self {
		match value {
			0 => Self::Local,
			1 => Self::Global,
			2 => Self::Weak,
			_ => Self::Unknown,
		}
	}
}

#[derive(Debug, Clone)]
struct IntElfSymbol {
	sym: Symbol,
	name: String,
}
impl IntElfSymbol {
	pub fn new(sym: Symbol, name: String) -> Self {
		Self { sym, name }
	}
	pub fn symtype(&self) -> SymbolType {
		let st = self.sym.st_symtype();
		st.into()
	}
	pub fn symbind(&self) -> SymbolBind {
		let st = self.sym.st_bind();
		st.into()
	}
	pub fn value(&self) -> Result<TargetPtr> {
		Ok(self.sym.st_value.try_into()?)
	}
}

/// Details about one resolved symbol
#[derive(Clone, Serialize, Deserialize)]
pub struct ElfSymbol {
	pub name: String,
	pub value: TargetPtr,
	pub stype: SymbolType,
	pub bind: SymbolBind,
}

impl std::fmt::Debug for ElfSymbol {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ElfSymbol")
			.field("name", &self.name)
			.field("value", &format_args!("{:x}", self.value))
			.field("stype", &self.stype)
			.field("bind", &self.bind)
			.finish()
	}
}

impl ElfSymbol {
	pub fn add_value(&mut self, val: TargetPtr) {
		self.value += val;
	}
}

impl From<IntElfSymbol> for ElfSymbol {
	fn from(value: IntElfSymbol) -> Self {
		Self {
			name: value.name.clone(),
			value: value.value().expect("unable to convert value to target size"),
			stype: value.symtype(),
			bind: value.symbind(),
		}
	}
}

pub(crate) struct ElfData {
	entry: TargetPtr,
	symbols: Vec<IntElfSymbol>,
}

impl ElfData {
	pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
		let file = ElfBytes::<AnyEndian>::minimal_parse(&data)?;
		let common = file.find_common_data()?;
		let symbols = if let Some(symtab) = &common.symtab {
			if let Some(dynstr) = file.section_header_by_name(".strtab")? {
				let strtab = file.section_data_as_strtab(&dynstr)?;
				Self::symbols(&strtab, symtab)?
			} else {
				return Err(Error::msg("found no .strtab").into());
			}
		} else if let Some(symtab) = &common.dynsyms {
			if let Some(dynstr) = file.section_header_by_name(".dynstr")? {
				let strtab = file.section_data_as_strtab(&dynstr)?;
				Self::symbols(&strtab, symtab)?
			} else {
				return Err(Error::msg("found no .dynstr").into());
			}
		} else {
			Vec::new()
		};

		let entry = file.ehdr.e_entry.try_into()?;
		let r = Self { symbols, entry };
		Ok(r)
	}
	pub fn resolve(&self, name: &str) -> Option<ElfSymbol> {
		for sym in self.symbols.iter() {
			if sym.name == name {
				let a = sym.clone();
				return Some(a.into());
			}
		}
		None
	}

	fn symbols(strtab: &StringTable, symtab: &SymbolTable<AnyEndian>) -> Result<Vec<IntElfSymbol>> {
		log::debug!("getting symbols");
		let mut ret = Vec::new();
		for sym in symtab.iter() {
			// log::trace!("sym {sym:?}");
			if let Ok(n) = strtab.get(sym.st_name as usize) {
				if !n.is_empty() {
					let name = n.to_string();
					let ins = IntElfSymbol::new(sym.clone(), name);
					ret.push(ins);
				}
			}
		}
		Ok(ret)
	}
}

pub(crate) struct Elf {
	_path: PathBuf,
	data: ElfData,
}

impl Elf {
	pub fn new(path: PathBuf) -> Result<Self> {
		log::info!("creating elf from {path:?}");
		let data = std::fs::read(&path)?;
		let data = ElfData::from_bytes(data)?;
		Ok(Self { _path: path, data })
	}
	pub fn entry(&self) -> TargetPtr {
		self.data.entry
	}
	pub fn parse(self) -> Result<Self> {
		Ok(self)
	}
	pub fn resolve(&self, name: &str) -> Option<ElfSymbol> {
		self.data.resolve(name)
	}
	pub fn all_symbols(&self) -> Vec<ElfSymbol> {
		self.data.symbols.iter().map(|x| x.clone().into()).collect()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn elf_basic() {
		let f = SymbolType::File;
		assert_eq!(std::convert::Into::<u8>::into(f.clone()), 4);
		assert_eq!(std::convert::Into::<SymbolType>::into(4_u8), f);
	}

	#[test]
	fn load_elf2() {
		#[cfg(target_os = "linux")]
		const NAME: &str = "/usr/lib/x86_64-linux-gnu/libc.so.6";
		#[cfg(target_os = "android")]
		const NAME: &str = "/system/lib64/libc.so";

		let elf = Elf::new(PathBuf::from(NAME)).unwrap().parse().unwrap();
		let _m = elf.resolve("malloc").unwrap();
		assert!(elf.resolve("non_existent_").is_none());
	}
	#[test]
	fn load_elf3() {
		#[cfg(target_os = "linux")]
		const NAME: &str = "/usr/bin/cat";

		#[cfg(target_os = "android")]
		const NAME: &str = "/system/bin/cat";

		let _elf = Elf::new(PathBuf::from(NAME)).unwrap().parse().unwrap();
	}
}
