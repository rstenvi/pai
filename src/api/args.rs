//! A client can use [Args] object to control behaviour in trace controllers
//! components.
use crate::api::messages::Cont;
use crate::utils::process::Tid;
use crate::{Result, TargetPtr};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::messages::{RegEvent, Stop};

#[derive(Default, Debug)]
struct Breakpoint {
	// numhit: usize,
}

/// Decide behaviour when syscall is detected and how much enrichment of
/// arguments to perform.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Enrich {
	/// This is called None, but it does do some parsing:
	/// 
	/// - Detect system call name
	/// - Detect number of arguments
	/// - Find name of argument
	#[default]
	None,

	/// In addition to steps taken in [Enrich::None], also:
	/// 
	/// - Annotate with metadata about argument
	/// - Find out which flag values int resolves to
	Basic,

	/// In addition to steps taken in [Enrich::Basic], also:
	/// 
	/// - Read data from pointers to construct strings, objects, integers, etc.
	Full,
}
impl std::str::FromStr for Enrich {
	type Err = crate::Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"none" => Ok(Self::None),
			"basic" => Ok(Self::Basic),
			"full" => Ok(Self::Full),
			_ => Err(crate::Error::NotFound),
		}
	}
}
impl std::fmt::Display for Enrich {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{:?}", self))
	}
}

macro_rules! bool_access {
	($name:ident) => {
		pub fn $name(&self, tid: Tid) -> bool {
			if let Some(args) = self.threads.get(&tid) {
				args.$name
			} else {
				self.global.$name
			}
		}
	};
}

macro_rules! builder_set_bool {
	($name:ident) => {
		pub fn $name(mut self) -> Self {
			self.args.$name = true;
			self.dirty = true;
			self
		}
		paste::paste! {
			pub fn [<set_ $name>](&mut self, value: bool) {
				self.dirty = true;
				self.args.$name = value;
			}
		}
	};
}

// use paste::paste;
macro_rules! builder_push_val {
	($name:ident, $arg:ident, $argtype:tt) => {
		paste::paste! {
			pub fn [<push_ $name>](mut self, $arg: $argtype) -> Self {
				log::trace!("pusing {:?}", $arg);
				if !self.args.$name.contains(&$arg) {
					self.dirty = true;
					self.args.$name.push($arg);
				}
				self
			}
		}
		paste::paste! {
			pub fn [<add_ $name>](&mut self, $arg: $argtype) {
				log::trace!("pusing {:?}", $arg);
				if !self.args.$name.contains(&$arg) {
					self.dirty = true;
					self.args.$name.push($arg);
				}
			}
		}
		paste::paste! {
			pub fn [<remove_ $name>](&mut self, $arg: $argtype) {
				log::trace!("pusing {:?}", $arg);
				if let Some(index) = self.args.$name.iter().position(|x| *x == $arg) {
					self.args.$name.remove(index);
					self.dirty = true;
				}
			}
		}
	};
}

/// Construct [Args]
///
/// ## Example
///
/// Below is an example to intercept all system calls.
///
/// ```rust
/// use pai::api::ArgsBuilder;
/// let args = ArgsBuilder::new()
///   .handle_steps()
///   .finish()
///   .expect("unable to construct args");
///
/// ```
#[derive(Default, Clone)]
pub struct ArgsBuilder {
	args: Args,
	dirty: bool,
}
impl ArgsBuilder {
	pub fn new() -> Self {
		Self::default()
	}
	pub fn new_dirty() -> Self {
		Self {
			args: Args::default(),
			dirty: true,
		}
	}
	pub fn finish(self) -> Result<Args> {
		self.args.sanity_check()?;
		Ok(self.args)
	}
	pub fn borrow_finish(&mut self) -> Result<Args> {
		let args = self.args.clone();
		args.sanity_check()?;
		self.dirty = false;
		Ok(args)
	}
	pub fn is_dirty(&self) -> bool {
		self.dirty
	}
	pub fn enrich_default(mut self, enrich: Enrich) -> Self {
		if enrich != self.args.enrich_default {
			self.args.enrich_default = enrich;
			self.dirty = true;
		}
		self
	}
	pub(crate) fn set_enrich_default(&mut self, enrich: Enrich) {
		if enrich != self.args.enrich_default {
			self.args.enrich_default = enrich;
			self.dirty = true;
		}
	}
	pub fn enrich_sysno(mut self, sysno: usize, enrich: Enrich) -> Self {
		let v = self.args.enrich_sysno.insert(sysno, enrich.clone());

		// Only set dirty flag if we actually made a change
		let dirty = if let Some(e) = v { e != enrich } else { true };

		self.dirty = dirty;
		self
	}
	builder_set_bool! { intercept_all_syscalls }

	#[cfg(feature = "syscalls")]
	builder_set_bool! { transform_syscalls }

	#[cfg(feature = "syscalls")]
	builder_set_bool! { only_notify_syscall_exit }

	#[cfg(feature = "syscalls")]
	builder_set_bool! { patch_ioctl_virtual }

	builder_set_bool! { handle_steps }
	builder_set_bool! { handle_exec }

	builder_push_val! { syscall_traced, sysno, usize }
	builder_push_val! { signal_traced, signal, i32 }

	builder_push_val! { registered, reg, RegEvent }
}

/// Object used by trace controllers to decide behaviour when tracing the
/// target. Construct with [ArgsBuilder]
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Args {
	intercept_all_syscalls: bool,
	// intercept_attached: bool,
	// intercept_clone: bool,
	syscall_traced: Vec<usize>,

	signal_traced: Vec<i32>,

	handle_steps: bool,

	handle_exec: bool,

	enrich_default: Enrich,
	enrich_sysno: HashMap<usize, Enrich>,

	/// If we should transform [Stop::SyscallEnter] and [Stop::SyscallExit] to
	/// [Event::Syscall]
	transform_syscalls: bool,

	/// Only notify when syscall has completed, when used with
	/// [Self::transform_syscalls], the caller still get all the argument.
	only_notify_syscall_exit: bool,

	patch_ioctl_virtual: bool,

	registered: Vec<RegEvent>,
	// attach_threads: bool,
}

impl Args {
	pub(crate) fn forward_master(mut self) -> Self {
		if (self.intercept_all_syscalls || !self.syscall_traced.is_empty())
			&& self.transform_syscalls
		{
			// To transform the syscalls, the proxy needs to receive enter as
			// well, so force it to be false
			self.only_notify_syscall_exit = false;
		}
		self
	}
	fn sanity_check(&self) -> Result<()> {
		if !self.intercept_all_syscalls
			&& !self.syscall_traced.is_empty()
			&& !self.transform_syscalls
		{
			Err(crate::Error::msg("for us to trace certain syscall we have to transform them to know the syscall number"))
		} else {
			Ok(())
		}
	}
	fn get_cont(&self) -> Cont {
		log::trace!("{:?}", self.syscall_traced);
		if self.intercept_all_syscalls || !self.syscall_traced.is_empty() {
			Cont::Syscall
		} else {
			Cont::Cont
		}
	}
	fn handles_syscall_enter(&self) -> bool {
		self.intercept_all_syscalls || !self.syscall_traced.is_empty()
	}
	fn handles_syscall_exit(&self) -> bool {
		self.intercept_all_syscalls || !self.syscall_traced.is_empty()
	}

	#[cfg(feature = "syscalls")]
	/// Returns true ifm we handle this syscall or all syscalls
	fn handles_syscall_sysno(&self, sysno: usize) -> bool {
		self.intercept_all_syscalls || self.syscall_traced.contains(&sysno)
	}
	#[cfg(feature = "syscalls")]
	fn enrich_syscall_sysno(&self, sysno: usize) -> Enrich {
		if let Some(enrich) = self.enrich_sysno.get(&sysno) {
			enrich.clone()
		} else {
			self.enrich_default.clone()
		}
	}
	fn handles_signal(&self, signal: i32) -> bool {
		self.signal_traced.contains(&signal)
	}

	pub(crate) fn handles_regevent(&self, reg: &RegEvent) -> bool {
		self.registered.contains(reg)
	}

	pub(crate) fn handles_stop(&self, stop: &Stop) -> Option<bool> {
		let r = match stop {
			Stop::SyscallEnter => Some(self.handles_syscall_enter()),
			Stop::SyscallExit => Some(self.handles_syscall_exit()),

			// We always return exit
			Stop::Exit { code: _ } => Some(true),
			Stop::Signal { signal, group: _ } => Some(self.handles_signal(*signal)),
			Stop::Clone { pid: _ } => Some(self.registered.contains(&RegEvent::Clone)),
			Stop::Attach => Some(self.registered.contains(&RegEvent::Attached)),
			Stop::Breakpoint { pc: _ } => None,
			Stop::Fork { newpid: _ } => Some(self.registered.contains(&RegEvent::Fork)),
			Stop::Step { pc: _ } => Some(self.handle_steps),
			Stop::Exec { old: _ } => Some(self.handle_exec),
			_ => {
				log::warn!("unimplemented signal {stop:?}");
				None
			}
		};
		log::debug!("handles stop {stop:?} => {r:?}");
		r
	}
}

#[derive(Default, Debug)]
pub(crate) struct ClientArgs {
	global: Args,
	threads: HashMap<Tid, Args>,
	/// All breakpoints this client is controlling
	bps: HashMap<TargetPtr, Breakpoint>,
}

impl ClientArgs {
	pub fn new(global: Args) -> Self {
		Self {
			global,
			threads: HashMap::new(),
			bps: HashMap::new(),
		}
	}
	pub fn get_cont(&self, tid: Tid) -> Cont {
		if let Some(args) = self.threads.get(&tid) {
			args.get_cont()
		} else {
			self.global.get_cont()
		}
	}
	pub fn detach_thread(&mut self, tid: Tid) {
		self.threads.insert(tid, Args::default());
	}
	pub fn clone_config(&self, tid: Option<Tid>) -> Option<Args> {
		if let Some(tid) = tid {
			self.threads.get(&tid).cloned()
		} else {
			Some(self.global.clone())
		}
	}
	pub fn insert_bp(&mut self, addr: TargetPtr) {
		// Breakpoints are always global
		let ins = Breakpoint::default();
		self.bps.insert(addr, ins);
	}
	fn handles_breakpint(&self, pc: TargetPtr) -> bool {
		self.bps.contains_key(&pc)
	}
	pub fn replace_config(&mut self, config: Args) {
		self.global = config;
	}
	pub fn replace_config_thread(&mut self, tid: Tid, config: Args) {
		self.threads.insert(tid, config);
	}

	#[cfg(feature = "syscalls")]
	bool_access! { intercept_all_syscalls }

	#[cfg(feature = "syscalls")]
	bool_access! { transform_syscalls }

	#[cfg(feature = "syscalls")]
	bool_access! { patch_ioctl_virtual }

	bool_access! { only_notify_syscall_exit }
	#[cfg(feature = "syscalls")]
	pub fn enrich_syscall_sysno(&self, tid: Tid, sysno: usize) -> Enrich {
		if let Some(args) = self.threads.get(&tid) {
			args.enrich_syscall_sysno(sysno)
		} else {
			self.global.enrich_syscall_sysno(sysno)
		}
	}

	#[cfg(feature = "syscalls")]
	pub fn handles_syscall_sysno(&self, tid: Tid, sysno: usize) -> bool {
		if let Some(args) = self.threads.get(&tid) {
			args.handles_syscall_sysno(sysno)
		} else {
			self.global.handles_syscall_sysno(sysno)
		}
	}
	pub fn handles_regevent(&self, reg: &RegEvent) -> bool {
		self.global.handles_regevent(reg)
	}

	pub fn handles_stop(&mut self, tid: Tid, stop: &Stop) -> bool {
		let handles = if let Some(args) = self.threads.get(&tid) {
			log::trace!("checking for tid {tid}");
			args.handles_stop(stop)
		} else {
			log::trace!("checking global");
			self.global.handles_stop(stop)
		};

		if let Some(ret) = handles {
			ret
		} else {
			// Breakpoint are always global, so we check this here instead
			if let Stop::Breakpoint { pc } = stop {
				self.handles_breakpint(*pc)
			} else {
				false
			}
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[cfg(feature = "syscalls")]
	#[test]
	fn test_args1() {
		let args = ArgsBuilder::new()
			.handle_steps()
			.only_notify_syscall_exit()
			.finish()
			.unwrap();
		assert!(args.handle_steps);
		assert!(args.only_notify_syscall_exit);
		assert!(!args.handles_syscall_enter());
	}

	#[cfg(feature = "syscalls")]
	#[test]
	fn test_args2() {
		let args = ArgsBuilder::new()
			.intercept_all_syscalls()
			.finish()
			.unwrap();
		assert!(args.handles_syscall_enter());
		assert!(args.handles_syscall_exit());
		assert!(args.handles_syscall_sysno(1));
		assert!(args.intercept_all_syscalls);

		let cargs = ClientArgs::new(args);
		assert!(cargs.intercept_all_syscalls(1));
	}
}
