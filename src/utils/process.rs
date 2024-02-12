use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::{Error, Result, TargetPtr};
use procfs::process::{MMPermissions, MMapPath};
use serde::{Deserialize, Serialize};

use super::{Location, Perms};

pub type Pid = isize;
pub type Tid = isize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryMap {
	pub loc: Location,
	pub perms: Perms,
	pub path: MMapPath,
	pub offset: u64,
}

impl MemoryMap {
	pub fn path(&self) -> Option<&PathBuf> {
		match &self.path {
			MMapPath::Path(p) => Some(p),
			_ => None,
		}
	}
	pub fn file_name_matches(&self, path: &Path) -> bool {
		if let Some(fname1) = path.file_name() {
			if let Some(sp) = self.path() {
				if let Some(fname2) = sp.file_name() {
					fname1 == fname2
				} else {
					false
				}
			} else {
				false
			}
		} else {
			false
		}
	}
	pub fn is_from_file(&self) -> bool {
		matches!(self.path, MMapPath::Path(_))
	}
	pub fn path_is(&self, name: &PathBuf) -> bool {
		match &self.path {
			MMapPath::Path(p) => *p == *name,
			_ => false,
		}
	}
	pub fn path_ends_with(&self, name: &str) -> bool {
		if let Some(path) = self.path() {
			path.ends_with(name)
		} else {
			false
		}
	}
	pub fn path_contains(&self, name: &str) -> bool {
		match &self.path {
			MMapPath::Path(p) => p.as_os_str().to_str().unwrap().contains(name),
			_ => false,
		}
	}
}

impl MemoryMap {
	fn from_linux(item: procfs::process::MemoryMap) -> Result<Self> {
		item.try_into()
	}
}

impl TryFrom<procfs::process::MemoryMap> for MemoryMap {
	type Error = crate::Error;

	fn try_from(value: procfs::process::MemoryMap) -> std::result::Result<Self, Self::Error> {
		let start = value.address.0;
		let end = value.address.1;

		let r = Self {
			loc: Location::new(start.into(), end.into()),
			perms: value.perms.into(),
			path: value.pathname,
			offset: value.offset,
		};
		Ok(r)
	}
}

#[derive(Debug)]
pub struct Process {
	pub proc: procfs::process::Process,
}

impl Process {
	pub fn current() -> Result<Self> {
		Ok(Self {
			proc: procfs::process::Process::myself()?,
		})
	}
	pub fn arg_to_pid(arg: &str) -> Result<usize> {
		if let Ok(n) = arg.parse::<usize>() {
			Ok(n)
		} else {
			let name = PathBuf::from_str(arg)?;
			let r: Vec<_> = procfs::process::all_processes()?
				.filter(|x| {
					if let Ok(x) = x {
						if let Ok(exe) = x.exe() {
							exe.ends_with(&name)
						} else {
							false
						}
					} else {
						false
					}
				})
				.filter_map(|x| x.ok())
				.map(|x| x.pid())
				.collect();
			let r = r.first().ok_or(Error::NotFound)?;
			Ok(*r as usize)
		}
	}
	pub fn procname_to_process(name: &str) -> Result<Process> {
		let r: Vec<_> = procfs::process::all_processes()?
			.filter(|x| {
				if let Ok(n) = x.as_ref() {
					if let Ok(exe) = n.cmdline() {
						exe.contains(&name.to_string())
					} else {
						false
					}
				} else {
					false
				}
			})
			.filter_map(|x| x.ok())
			.map(|x| x.pid())
			.collect();
		let Some(pid) = r.first() else {
			return Err(Error::Unknown);
		};
		let proc = Process::from_pid(*pid as u32)?;
		Ok(proc)
	}
	pub fn pid(&self) -> Pid {
		self.proc.pid() as Pid
	}
	pub fn from_pid(id: u32) -> Result<Self> {
		let id = i32::try_from(id)?;
		log::trace!("Getting process with PID {}", id);
		Ok(Self {
			proc: procfs::process::Process::new(id)?,
		})
	}
	pub fn proc_modules(&self) -> Result<Vec<MemoryMap>> {
		let r: Vec<MemoryMap> = self
			.proc
			.maps()?
			.into_iter()
			.filter_map(|x| TryInto::<MemoryMap>::try_into(x).ok())
			.filter(|x| x.is_from_file() && x.offset == 0)
			.collect();
		Ok(r)
	}
	pub fn proc_modules_contains(&self, s: &str) -> Result<Vec<MemoryMap>> {
		let r = self
			.proc_modules()?
			.into_iter()
			.filter(|x| x.path_contains(s))
			.collect();
		Ok(r)
	}
	pub fn exe_path(&self) -> Result<PathBuf> {
		Ok(self.proc.exe()?)
	}
	pub fn exact_match_path<P: Into<PathBuf>>(&self, path: P) -> Result<Option<Location>> {
		let path: PathBuf = path.into();
		let mut r = self.maps()?.into_iter().filter(|x| x.path_is(&path));
		let ret = if let Some(first) = r.next() {
			let start = first.loc.addr();
			let end = if let Some(last) = r.last() {
				last.loc.end()
			} else {
				first.loc.end()
			};
			let loc = Location::new(start, end);
			Some(loc)
		} else {
			None
		};
		Ok(ret)
	}
	// pub fn exact_match_location(&self, name: &str) -> Result<Option<Location>> {
	// 	let path = PathBuf::from(name);
	// 	let mut r = self.maps()?
	// 		.into_iter()
	// 		.filter(|x| x.name_is(name) )
	// 		;
	// 	let ret = if let Some(first) = r.next() {
	// 		let start = first.loc.addr();
	// 		let end = if let Some(last) = r.last() {
	// 			last.loc.end()
	// 		} else {
	// 			first.loc.end()
	// 		};
	// 		let loc = Location::new(start, end);
	// 		Some(loc)
	// 	} else {
	// 		None
	// 	};
	// 	Ok(ret)
	// }
	pub fn exe_module(&self) -> Result<MemoryMap> {
		let exe = self.proc.exe()?;
		let mut r: Vec<_> = self
			.proc_modules()?
			.into_iter()
			.filter(|x| x.path_is(&exe))
			.collect();

		if r.len() == 1 {
			Ok(r.remove(0))
		} else {
			Err(Error::msg("exe module not found"))
		}
	}

	pub fn tids(&self) -> Result<Vec<Tid>> {
		log::trace!("getting thread IDs for {}", self.pid());
		let r = self
			.proc
			.tasks()?
			.filter(|x| x.is_ok())
			.filter_map(|x| x.ok())
			.map(|x| x.tid as Tid)
			.collect();
		Ok(r)
	}
	pub fn maps(&self) -> Result<Vec<MemoryMap>> {
		log::trace!("getting maps for {}", self.pid());
		self.proc
			.maps()?
			.into_iter()
			.map(MemoryMap::from_linux)
			.collect()
	}
	pub fn find_space(&self, perm: Perms) -> Result<TargetPtr> {
		log::trace!("Finding space in target process {perm:?}");
		let perms: MMPermissions = perm.into();

		let r = self
			.proc
			.maps()?
			.into_iter()
			.find(|m| m.perms.contains(perms))
			.map(|m| m.address.0)
			.ok_or(crate::Error::Unknown)?
			.into();
		Ok(r)
	}
	pub fn find_exe_space(&self) -> Result<TargetPtr> {
		self.find_space(Perms::new().exec())
	}
}

impl From<&Process> for pete::Pid {
	fn from(proc: &Process) -> Self {
		Self::from_raw(proc.proc.pid())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn process_test() {
		let me = Process::current().unwrap();
		assert_eq!(Process::arg_to_pid("12").unwrap(), 12);
		assert!(Process::arg_to_pid("asdasdasd").is_err());
		assert!(Process::procname_to_process("asdasdasd").is_err());

		me.find_space(Perms::new().write()).unwrap();
		me.find_exe_space().unwrap();

		let _p: pete::Pid = (&me).into();
	}
}
