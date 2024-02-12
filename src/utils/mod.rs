//! Various utility functions not fitting in anywhere else.
//!
use bit_vec::BitVec;
use procfs::process::MMPermissions;
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	fs::FileType,
	os::unix::fs::{MetadataExt, PermissionsExt},
	path::PathBuf,
	thread::JoinHandle,
};

pub mod process;

use crate::{api::messages::ElfSymbol, Error, Result, TargetPtr};

#[derive(Default)]
pub(crate) struct MmapBuild {
	addr: TargetPtr,
	size: usize,
	prot: Perms,
	flags: i32,
	fd: i32,
	offset: usize,
}

impl MmapBuild {
	pub fn new() -> Self {
		Self::default()
	}
	pub fn build(self) -> Vec<TargetPtr> {
		vec![
			self.addr,
			self.size.into(),
			self.prot.to_libc().into(),
			self.flags.into(),
			self.fd.into(),
			self.offset.into(),
		]
	}
	pub fn sane_anonymous(size: usize, prot: Perms) -> Vec<TargetPtr> {
		Self::new()
			.size(size)
			.prot(prot)
			.anonymous()
			.private()
			.fd(-1)
			.build()
	}
	pub fn addr(mut self, addr: TargetPtr) -> Self {
		self.addr = addr;
		self
	}
	pub fn size(mut self, size: usize) -> Self {
		self.size = size;
		self
	}
	pub fn prot(mut self, prot: Perms) -> Self {
		self.prot = prot;
		self
	}
	pub fn anonymous(mut self) -> Self {
		self.flags |= libc::MAP_ANONYMOUS;
		self
	}
	pub fn private(mut self) -> Self {
		self.flags |= libc::MAP_PRIVATE;
		self
	}
	pub fn flags(mut self, flags: i32) -> Self {
		self.flags = flags;
		self
	}
	pub fn fd(mut self, fd: i32) -> Self {
		self.fd = fd;
		self
	}
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Location {
	start: TargetPtr,
	end: TargetPtr,
}
impl std::fmt::Debug for Location {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Location")
			.field("start", &format_args!("0x{:x}", self.start))
			.field("end", &format_args!("0x{:x}", self.end))
			.finish()
	}
}
impl Location {
	pub fn new(start: TargetPtr, end: TargetPtr) -> Self {
		Self { start, end }
	}
	pub fn end(&self) -> TargetPtr {
		self.end
	}
	pub fn size(&self) -> usize {
		(self.end - self.start).into()
	}
	pub fn addr(&self) -> TargetPtr {
		self.start
	}
	pub fn contains(&self, addr: TargetPtr) -> bool {
		addr >= self.start && addr <= self.end
	}
}

pub(crate) struct AllocedMemory {
	loc: Location,
	bm: BitVec,
	alloc: HashMap<TargetPtr, usize>,
	// bm: Bitmap<SIZE>,
}
impl AllocedMemory {
	pub fn new(loc: Location) -> Self {
		let size = loc.size();
		let entries = size / Self::blocksize();
		let bm = BitVec::from_elem(entries, false);
		let alloc = HashMap::new();
		Self { loc, bm, alloc }
	}
	fn blocksize() -> usize {
		std::mem::size_of::<TargetPtr>()
	}
	fn num_blocks(sz: usize) -> usize {
		let blocks = sz / Self::blocksize();
		if sz % Self::blocksize() == 0 {
			blocks
		} else {
			blocks + 1
		}
	}

	fn set_idxs(&mut self, start: usize, count: usize, val: bool) {
		for i in 0..count {
			self.bm.set(start + i, val);
		}
	}
	pub fn free(&mut self, addr: TargetPtr) -> Result<()> {
		let blocks = self.alloc.remove(&addr).ok_or(Error::msg(format!(
			"tried to free unallocated memory {addr:x}"
		)))?;
		let off: usize = (addr - self.loc.addr()).into();
		let blkidx = off / Self::blocksize();
		self.set_idxs(blkidx, blocks, false);
		Ok(())
	}
	pub fn alloc(&mut self, size: usize) -> Result<TargetPtr> {
		let blocks = Self::num_blocks(size);
		let mut found_cnt = 0;
		let mut found_idx = None;
		for (i, b) in self.bm.iter().enumerate() {
			if !b {
				found_cnt += 1;
				if found_cnt >= blocks {
					found_idx = Some(i + 1 - found_cnt);
					break;
				}
			} else {
				found_cnt = 0;
			}
		}
		let start = found_idx.ok_or(Error::NotFound)?;
		self.set_idxs(start, blocks, true);
		let off = start * Self::blocksize();
		let addr = self.loc.addr() + off.into();
		self.alloc.insert(addr, blocks);
		Ok(addr)
	}
}

#[derive(Debug, Default, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Perms {
	r: bool,
	w: bool,
	x: bool,
}

impl Perms {
	pub fn new() -> Self {
		Self::default()
	}
	pub fn read(mut self) -> Self {
		self.r = true;
		self
	}
	pub fn write(mut self) -> Self {
		self.w = true;
		self
	}
	pub fn exec(mut self) -> Self {
		self.x = true;
		self
	}
	pub fn to_libc(&self) -> i32 {
		let mut ret = 0;
		if self.x {
			ret |= libc::PROT_EXEC;
		}
		if self.w {
			ret |= libc::PROT_WRITE;
		}
		if self.r {
			ret |= libc::PROT_READ;
		}
		ret
	}
	pub fn from_mode(mode: u32) -> Self {
		let r = mode & 0b100 != 0;
		let w = mode & 0b010 != 0;
		let x = mode & 0b001 != 0;
		Self { r, w, x }
	}
}

impl From<procfs::process::MMPermissions> for Perms {
	fn from(value: procfs::process::MMPermissions) -> Self {
		let r = value.contains(MMPermissions::READ);
		let w = value.contains(MMPermissions::WRITE);
		let x = value.contains(MMPermissions::EXECUTE);
		Self { r, w, x }
	}
}
impl From<Perms> for procfs::process::MMPermissions {
	fn from(value: Perms) -> Self {
		let mut v = procfs::process::MMPermissions::NONE;
		if value.r {
			v |= procfs::process::MMPermissions::READ;
		}
		if value.w {
			v |= procfs::process::MMPermissions::WRITE;
		}
		if value.x {
			v |= procfs::process::MMPermissions::EXECUTE;
		}
		v
	}
}

#[derive(Debug, Clone)]
pub struct FilePerm {
	pub owner: Perms,
	pub group: Perms,
	pub other: Perms,
}

impl From<std::fs::Permissions> for FilePerm {
	fn from(value: std::fs::Permissions) -> Self {
		let mut mode = value.mode();
		let other = Perms::from_mode(mode & 0b111);
		mode >>= 3;
		let group = Perms::from_mode(mode & 0b111);
		mode >>= 3;
		let owner = Perms::from_mode(mode & 0b111);

		Self {
			owner,
			group,
			other,
		}
	}
}

#[derive(Debug, Clone)]
pub struct SelinuxObject {
	pub object: String,
}
impl SelinuxObject {
	pub fn new<S: Into<String>>(object: S) -> Self {
		let object = object.into();
		// Comes with trailing NULL-byte when read via xattr
		let object = object.trim_matches('\x00').into();
		Self { object }
	}
}

#[derive(Debug, Clone)]
pub struct FileAccess {
	pub ftype: FileType,
	pub uid: u32,
	pub gid: u32,
	pub perm: FilePerm,
	pub selinux: Option<SelinuxObject>,
}

impl FileAccess {
	pub fn from_path(path: &PathBuf) -> Result<Self> {
		log::debug!("FileAccess {path:?}");
		let meta = std::fs::metadata(path)?;
		let ftype = meta.file_type();
		let uid = meta.uid();
		let gid = meta.gid();
		let perm = meta.permissions();
		let perm = perm.into();

		let selinux = if let Some(selinux) = xattr::get(path, "security.selinux")? {
			log::trace!("selinux: {selinux:?}");
			let str = std::str::from_utf8(&selinux)?;
			Some(SelinuxObject::new(str))
		} else {
			None
		};

		let ret = Self {
			ftype,
			uid,
			gid,
			perm,
			selinux,
		};
		log::debug!("returning {ret:?}");
		Ok(ret)
	}
}

pub struct ModuleSymbols {
	pub name: PathBuf,
	pub symbols: HashMap<String, ElfSymbol>,
}
impl ModuleSymbols {
	pub fn new(name: PathBuf, base: TargetPtr, insymbols: Vec<ElfSymbol>) -> Self {
		let mut symbols = HashMap::new();
		for mut symbol in insymbols.into_iter() {
			if symbol.value != 0.into() {
				symbol.add_value(base);
				symbols.insert(symbol.name.clone(), symbol);
			}
		}
		Self { name, symbols }
	}
	pub fn resolve(&self, name: &str) -> Option<&ElfSymbol> {
		self.symbols.get(name)
	}
}

#[cfg(feature = "plugins")]
#[derive(Debug, Clone)]
pub(crate) enum LoadDependency {
	Manual,
	Plugins(Vec<usize>),
}

#[cfg(feature = "plugins")]
pub(crate) struct LoadedPlugin {
	pub id: usize,
	pub load: LoadDependency,
	pub handle: JoinHandle<Result<()>>,
}

#[cfg(feature = "plugins")]
impl LoadedPlugin {
	pub fn new(id: usize, load: LoadDependency, handle: JoinHandle<Result<()>>) -> Self {
		Self { id, load, handle }
	}

	// Returns true if this plugin can also be removed
	pub fn id_removed(&mut self, id: usize) -> bool {
		match &mut self.load {
			LoadDependency::Plugins(a) => {
				if let Some(idx) = a.iter().position(|x| *x == id) {
					a.remove(idx);
				}
				a.is_empty()
			}
			_ => false,
		}
	}
	pub fn update_dependency(&mut self, dep: &LoadDependency) {
		if matches!(dep, LoadDependency::Manual) {
			self.load = dep.clone();
		} else {
			todo!();
		}
	}
	pub fn add_dependency(&mut self, id: usize) {
		#[allow(clippy::single_match)]
		match &mut self.load {
			LoadDependency::Plugins(a) => {
				if let Some(_idx) = a.iter().position(|x| *x == id) {
					log::warn!("already contained id");
				}
				a.push(id);
			}
			_ => {}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn utils0() {
		assert_eq!(Location::new(0.into(), 4.into()).size(), 4);
		assert_eq!(Location::new(4.into(), 12.into()).size(), 8);
	}

	#[test]
	fn file_access() {
		#[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
		let _f = FileAccess::from_path(&"/".into()).unwrap();
		let f = FileAccess::from_path(&"/nonexistent/path".into());
		assert!(f.is_err());
	}
}
