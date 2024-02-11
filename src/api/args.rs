//! A client can use and [Args] object to control behaviour in trace controllers
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
			self
		}
	};
}

// use paste::paste;
macro_rules! builder_push_val {
	($name:ident, $arg:ident, $argtype:tt) => {
		paste::paste! {
			pub fn [<push_ $name>](mut self, $arg: $argtype) -> Self {
				log::trace!("pusing {:?}", $arg);
				self.args.$name.push($arg);
				self
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
#[derive(Default)]
pub struct ArgsBuilder {
	args: Args,
}
impl ArgsBuilder {
	pub fn new() -> Self {
		Self::default()
	}
	pub fn finish(self) -> Result<Args> {
		self.args.sanity_check()?;
		Ok(self.args)
	}
	// #[cfg(feature = "syscalls")]
	builder_set_bool! { intercept_all_syscalls }

	#[cfg(feature = "syscalls")]
	builder_set_bool! { transform_syscalls }

	#[cfg(feature = "syscalls")]
	builder_set_bool! { enrich_all_syscalls }

	builder_set_bool! { only_notify_syscall_exit }
	builder_set_bool! { handle_steps }
	builder_set_bool! { handle_exec }

	builder_push_val! { syscall_traced, sysno, usize }
	builder_push_val! { signal_traced, signal, i32 }

	#[cfg(feature = "syscalls")]
	builder_push_val! { enrich_syscalls, sysno, usize }
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

	/// If we should transform [Stop::SyscallEnter] and [Stop::SyscallExit] to
	/// [Event::Syscall]
	transform_syscalls: bool,

	/// If we should enrich with more detailed data in [Event::Syscall]
	enrich_all_syscalls: bool,

	/// Specific syscalls we should enrich
	enrich_syscalls: Vec<usize>,

	/// Only notify when syscall has completed, when used with
	/// [Self::transform_syscalls], the caller still get all the argument.
	only_notify_syscall_exit: bool,

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
	/// Returns true if we handle this syscall or all syscalls
	fn handles_syscall_sysno(&self, sysno: usize) -> bool {
		self.intercept_all_syscalls || self.syscall_traced.contains(&sysno)
	}
	#[cfg(feature = "syscalls")]
	fn enrich_syscall_sysno(&self, sysno: usize) -> bool {
		self.enrich_all_syscalls || self.enrich_syscalls.contains(&sysno)
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
			Stop::Breakpoint { pc: _, clients: _ } => None,
			Stop::Fork { newpid: _ } => Some(self.registered.contains(&RegEvent::Fork)),
			Stop::Step { pc: _ } => Some(self.handle_steps),
			Stop::Exec { old: _ } => Some(self.handle_exec),
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

	bool_access! { only_notify_syscall_exit }

	#[cfg(feature = "syscalls")]
	pub fn enrich_syscall_sysno(&self, tid: Tid, sysno: usize) -> bool {
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
			if let Stop::Breakpoint { pc, clients: _ } = stop {
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
