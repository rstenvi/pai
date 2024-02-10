//! Parsing of ELF

use crate::{
	api::messages::{ElfSymbol, SymbolBind, SymbolType},
	Error, Result, TargetPtr,
};
use elf::{
	endian::AnyEndian,
	string_table::StringTable,
	symbol::{Symbol, SymbolTable},
	ElfBytes,
};
use std::path::PathBuf;

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
		let v = self.sym.st_value.into();
		// #[cfg(target_pointer_width = "32")]
		// let v = v.try_into()?;
		Ok(v)
	}
}

impl From<IntElfSymbol> for ElfSymbol {
	fn from(value: IntElfSymbol) -> Self {
		Self {
			name: value.name.clone(),
			value: value
				.value()
				.expect("unable to convert value to target size"),
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
				return Err(Error::msg("found no .strtab"));
			}
		} else if let Some(symtab) = &common.dynsyms {
			if let Some(dynstr) = file.section_header_by_name(".dynstr")? {
				let strtab = file.section_data_as_strtab(&dynstr)?;
				Self::symbols(&strtab, symtab)?
			} else {
				return Err(Error::msg("found no .dynstr"));
			}
		} else {
			Vec::new()
		};

		let entry = file.ehdr.e_entry.into();
		// #[cfg(target_pointer_width = "32")]
		// let entry = entry.try_into()?;
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
	data: ElfData,
	loaded: TargetPtr,
}

impl Elf {
	pub fn new<P: Into<PathBuf>>(path: P, loaded: TargetPtr) -> Result<Self> {
		let path = path.into();
		log::info!("creating elf from {path:?}");
		let data = std::fs::read(&path)?;
		Self::from_bytes(data, loaded)
	}
	pub fn from_bytes(data: Vec<u8>, loaded: TargetPtr) -> Result<Self> {
		let data = ElfData::from_bytes(data)?;
		Ok( Self { data, loaded })
	}
	pub fn entry(&self) -> TargetPtr {
		self.data.entry + self.loaded
	}
	pub fn parse(self) -> Result<Self> {
		Ok(self)
	}
	pub fn resolve(&self, name: &str) -> Option<ElfSymbol> {
		self.data.resolve(name)
			.map(|mut x| { x.add_value(self.loaded); x })
	}
	pub fn all_symbols(&self) -> Vec<ElfSymbol> {
		self.data.symbols
			.iter()
			.map(|x| {
				let mut r: ElfSymbol = x.clone().into();
				r.add_value(self.loaded);
				r
			})
			.collect()
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

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn load_elf2() {
		#[cfg(target_os = "linux")]
		const NAME: &str = "/usr/lib/x86_64-linux-gnu/libc.so.6";
		#[cfg(target_os = "android")]
		const NAME: &str = "/system/lib64/libc.so";

		let elf = Elf::new(PathBuf::from(NAME), 0.into()).unwrap().parse().unwrap();
		let _m = elf.resolve("malloc").unwrap();
		assert!(elf.resolve("non_existent_").is_none());
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn load_elf3() {
		#[cfg(target_os = "linux")]
		const NAME: &str = "/usr/bin/cat";

		#[cfg(target_os = "android")]
		const NAME: &str = "/system/bin/cat";

		let _elf = Elf::new(PathBuf::from(NAME), 0.into()).unwrap().parse().unwrap();
	}
}
