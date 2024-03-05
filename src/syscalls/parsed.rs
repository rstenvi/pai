// This file is also included by build.rs, so don't put anything too complex in
// it.

use std::collections::HashMap;

use syzlang_parser::parser;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Syscall {
	pub ident: parser::Identifier,
	pub sysno: usize,
	pub args: Vec<parser::Argument>,
	pub output: parser::ArgType,
	pub arches: Vec<parser::Arch>,
}

impl Syscall {
	pub fn new(
		ident: parser::Identifier,
		sysno: usize,
		args: Vec<parser::Argument>,
		output: parser::ArgType,
		arches: Vec<parser::Arch>,
	) -> Self {
		Self {
			ident,
			sysno,
			args,
			output,
			arches,
		}
	}
	pub fn from_syzlang(func: parser::Function, consts: &parser::Consts) -> Vec<Self> {
		let parts = consts.find_sysno_for_any(&func.name.name);
		let mut ret = Vec::with_capacity(parts.len());
		for c in parts.into_iter() {
			let sysno = c.as_uint().unwrap() as usize;
			let arches = c.arch;
			let ins = Self::new(
				func.name.clone(),
				sysno,
				func.args.clone(),
				func.output.clone(),
				arches,
			);
			ret.push(ins);
		}
		ret
	}
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Virtuals {
	pub ioctls: HashMap<String, Syscall>,
}

impl Virtuals {
	pub fn parse_from_virtuals(&mut self, virtuals: Vec<Syscall>, _consts: &parser::Consts) {
		for virt in virtuals.into_iter() {
			if virt.ident.name == "ioctl" {
				let name = virt.ident.subname.join("_");
				self.ioctls.insert(name, virt);
			}
		}
	}
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Syscalls {
	pub syscalls: HashMap<usize, Vec<Syscall>>,
	pub parsed: parser::Parsed,
	pub virts: Virtuals,
	virtuals: HashMap<String, Vec<Syscall>>,

	// #[serde(skip)]
	pub structs: HashMap<String, parser::Struct>,

	#[serde(skip)]
	pub ioctlcache: HashMap<u64, String>,

	// #[serde(skip)]
	pub resources: HashMap<String, parser::ArgType>,
}

impl Syscalls {
	pub fn add_function(&mut self, func: parser::Function) {
		let funcs = Syscall::from_syzlang(func, &self.parsed.consts);
		for func in funcs.into_iter() {
			let sysno = func.sysno;
			if let Some(calls) = self.syscalls.get_mut(&sysno) {
				calls.push(func);
			} else {
				self.syscalls.insert(sysno, vec![func]);
			}
		}
	}
	pub fn from_syzlang(mut parsed: parser::Parsed) -> Self {
		let funcs = std::mem::take(&mut parsed.functions);
		// let structs = std::mem::take(&mut parsed.structs);
		let mut this = Self {
			syscalls: HashMap::new(),
			parsed,
			virtuals: HashMap::new(),
			virts: Virtuals::default(),
			ioctlcache: HashMap::new(),
			structs: HashMap::new(),
			resources: HashMap::new(),
		};
		for func in funcs.into_iter() {
			this.add_function(func);
		}

		this.resources = HashMap::with_capacity(this.parsed.resources.len());
		for res in std::mem::take(&mut this.parsed.resources).into_iter() {
			this.resources.insert(res.name.name, res.atype);
		}

		this.structs = HashMap::with_capacity(this.parsed.structs.len());
		for s in std::mem::take(&mut this.parsed.structs).into_iter() {
			this.structs.insert(s.identifier().name.clone(), s);
		}

		this
	}
	#[allow(dead_code)]
	fn resolve_const(arg: &parser::Argument, consts: &parser::Consts) {
		if let parser::ArgType::Ident(id) = &arg.argtype {
			let _m = consts
				.consts
				.iter()
				.filter(|x| x.name == id.name)
				.collect::<Vec<_>>();
		}
	}
	pub fn remove_virtual(&mut self) {
		for (_sysno, item) in self.syscalls.iter_mut() {
			let virts = item
				.extract_if(|x| !x.ident.subname.is_empty())
				.collect::<Vec<_>>();

			self.virts.parse_from_virtuals(virts, &self.parsed.consts);
		}

		let _ = self
			.syscalls
			.extract_if(|_, x| x.is_empty())
			.collect::<Vec<_>>();
	}
}
