use crate::{
	api::messages::{Cont, Stop, Stopped, Thread, ThreadStatus, TrampType},
	arch::{self, prep_syscall, ReadRegisters, RegsAbiAccess, SystemV, WriteRegisters},
	utils::process::Pid,
	utils::{AllocedMemory, MmapBuild},
};
use std::{collections::HashMap, process::Command};

use memfd_exec::MemFdExecutable;
use nix::{sys::ptrace, unistd::ForkResult};
use pete::{Restart, Signal, Tracee};
use procfs::process::MMPermissions;

use crate::{
	utils::process::{MemoryMap, Process, Tid},
	utils::{Location, Perms},
	Error, Registers, Result, TargetPtr,
};

use super::SwBp;

struct TraceError {
	tracee: Option<Tracee>,
	error: crate::Error,
}
impl TraceError {
	pub fn new(tracee: Tracee, error: crate::Error) -> Self {
		Self {
			tracee: Some(tracee),
			error,
		}
	}
	pub fn new_fatal(error: crate::Error) -> Self {
		Self {
			tracee: None,
			error,
		}
	}
}
type TraceResult<T> = std::result::Result<T, TraceError>;

use crate::arch::{call_shellcode, ret_shellcode, syscall_shellcode};

// #[cfg(target_arch = "arm")]
// use crate::arch::aarch32::{as_our_regs, call_shellcode, ret_shellcode, syscall_shellcode};
// #[cfg(target_arch = "aarch64")]
// use crate::arch::aarch64::{as_our_regs, call_shellcode, ret_shellcode, syscall_shellcode};
// #[cfg(target_arch = "x86")]
// use crate::arch::x86::{as_our_regs, call_shellcode, ret_shellcode, syscall_shellcode};
// #[cfg(target_arch = "x86_64")]
// use crate::arch::x86_64::{as_our_regs, call_shellcode, ret_shellcode, syscall_shellcode};

impl From<pete::Stop> for Stop {
	fn from(value: pete::Stop) -> Self {
		match value {
			pete::Stop::Attach => Self::Attach,
			pete::Stop::SignalDelivery { signal } => Self::Signal {
				signal: signal as i32,
				group: false,
			},
			pete::Stop::Group { signal } => Self::Signal {
				signal: signal as i32,
				group: true,
			},
			pete::Stop::SyscallEnter => Self::SyscallEnter,
			pete::Stop::SyscallExit => Self::SyscallExit,
			pete::Stop::Clone { new } => {
				let pid: i32 = new.into();
				let pid = pid as Tid;
				Self::Clone { pid }
			}
			pete::Stop::Fork { new } => Self::Fork {
				newpid: new.as_raw() as Tid,
			},
			pete::Stop::Exec { old } => {
				let old: i32 = old.into();
				let old = old as Tid;
				Self::Exec { old }
			}
			pete::Stop::Exiting { exit_code } => Self::Exit { code: exit_code },
			pete::Stop::Signaling {
				signal: _,
				core_dumped: _,
			} => todo!(),
			pete::Stop::Vfork { new: _ } => todo!(),
			pete::Stop::VforkDone { new: _ } => todo!(),
			pete::Stop::Seccomp { data: _ } => todo!(),
		}
	}
}

pub struct TraceStop {
	pub tracee: Tracee,
	pub regs: Registers,
}

impl TraceStop {
	pub fn new(tracee: Tracee) -> Result<Self> {
		let regs = tracee.registers()?;
		let regs = regs.into();
		Ok(Self { tracee, regs })
	}
}

pub struct Tracer {
	proc: Process,
	tracer: pete::ptracer::Ptracer,
	swbps: HashMap<TargetPtr, SwBp>,
	mmapped: Vec<(TargetPtr, usize)>,
	trampcode: HashMap<TrampType, Vec<u8>>,
	tramps: HashMap<TrampType, TargetPtr>,
	tracee: HashMap<Tid, TraceStop>,
	scratch: HashMap<Perms, AllocedMemory>,
	lastaction: HashMap<Tid, Cont>,
	pendingswbps: HashMap<Tid, SwBp>,

	// No way for the end-user to override this with a completely custom one.
	cc: Box<dyn RegsAbiAccess + Send + 'static>,
}

impl Tracer {
	fn new(proc: Process, tracer: pete::Ptracer) -> Result<Self> {
		let pid = proc.pid();

		log::debug!("creating tracer for pid {pid:?}");
		let swbps = HashMap::new();
		let tracee = HashMap::new();
		let tramps = HashMap::new();
		let mmapped = Vec::new();
		let scratch = HashMap::new();
		let lastaction = HashMap::new();
		let pendingswbps = HashMap::new();
		let cc = Box::new(SystemV::default());
		let trampcode = Self::default_trampcode();
		let s = Self {
			proc,
			tracer,
			swbps,
			tracee,
			tramps,
			trampcode,
			mmapped,
			scratch,
			lastaction,
			pendingswbps,
			cc,
		};
		Ok(s)
	}
	fn default_trampcode() -> HashMap<TrampType, Vec<u8>> {
		let mut ret = HashMap::new();
		let mut code = Vec::new();
		syscall_shellcode(&mut code);
		ret.insert(TrampType::Syscall, std::mem::take(&mut code));
		assert!(code.is_empty());

		call_shellcode(&mut code);
		ret.insert(TrampType::Call, std::mem::take(&mut code));

		ret_shellcode(&mut code);
		ret.insert(TrampType::Ret, std::mem::take(&mut code));

		ret
	}
	pub fn cont(&mut self, tid: Tid, cont: Cont) -> Result<()> {
		log::debug!("cont {tid} {cont:?}");
		self.lastaction.insert(tid, cont);
		let mut tracee = self.remove_tracee(tid)?;

		#[cfg(not(target_arch = "arm"))]
		let restart = cont.into();

		// arm doesn't support single steps, see:
		// <https://stackoverflow.com/a/25268484> We therefore insert a
		// breakpoint on the next instruction instead.
		#[cfg(target_arch = "arm")]
		let restart = if cont == Cont::Step {
			let pc: usize = tracee.regs.pc().into();
			// No support for Thumb mode yet
			assert!(pc & 0b11 == 0);
			self.insert_single_sw_bp(0, tid, &mut tracee, (pc + 8).into())?;
			Cont::Cont.into()
		} else {
			cont.into()
		};

		log::trace!("setting options");
		tracee.tracee.set_options(
			pete::ptracer::Options::PTRACE_O_TRACESYSGOOD
				| pete::ptracer::Options::PTRACE_O_TRACECLONE
				| pete::ptracer::Options::PTRACE_O_TRACEVFORK
				| pete::ptracer::Options::PTRACE_O_TRACEFORK
				| pete::ptracer::Options::PTRACE_O_TRACEEXEC,
		)?;
		log::debug!("sending restart {restart:?} to {tid}");
		self.tracer.restart(tracee.tracee, restart)?;
		log::trace!("restart sent");
		Ok(())
	}
	fn cleanup(&mut self, mut tracee: Tracee) -> Result<Tracee> {
		let swbps = std::mem::take(&mut self.swbps);
		for (addr, swbp) in swbps.into_iter() {
			log::debug!("removing swbp @{addr:x}");
			self.remove_swbp(&mut tracee, &swbp)?;
		}

		// TODO:
		// - We should unmap what we've mmapped, but then we will also unmap our
		//   trampoline code while we're running on that trampoline code.
		// - Can fix this by doing the [Self::init_tramps] method again

		// for (addr, len) in std::mem::take(&mut self.mmapped).into_iter() {
		// 	log::debug!("unmapping {addr:x} {len:x}");
		// 	let args = vec![
		// 		addr, len as u64
		// 	];
		// 	let r = self._perform_syscall(
		// 		tracee, libc::SYS_munmap as u64, &args, 1
		// 	)?;
		// 	tracee = r.1;
		// }
		Ok(tracee)
	}

	// TODO; Makes more sense to have this in pete crate
	fn _detach(&mut self, tracee: Tracee) -> Result<()> {
		let Tracee { pid, pending, .. } = tracee;
		let signal = pending.unwrap_or(Signal::SIGCONT);

		// TODO:
		// - If we update to newer nix crate, this is one way to bypass type
		//   check.
		// - This is really ugly, but the problem is that we use Pid and Signal
		//   re-exported from Pete and this is detected as a different type than
		//   the actual ones in nix crate let pid = unsafe {
		// std::mem::transmute(pid) }; let signal: nix::sys::signal::Signal =
		// unsafe { std::mem::transmute(signal) };
		nix::sys::ptrace::detach(pid, Some(signal))?;
		Ok(())
	}

	pub fn detach(&mut self, tid: Tid) -> Result<()> {
		let tracee = self.remove_tracee(tid)?;
		let tracee = self.cleanup(tracee.tracee)?;
		self._detach(tracee)?;
		Ok(())
	}
	pub fn get_pid(&self) -> Result<Pid> {
		Ok(self.proc.pid())
	}
	pub fn get_tids(&self) -> Result<Vec<Tid>> {
		let mut r = self.proc.tids()?;
		r.sort();
		Ok(r)
	}
	pub fn get_libc_regs(&self, tid: Tid) -> Result<Registers> {
		let n = self.get_tracee(tid)?;
		Ok(n.regs.clone())
	}
	pub fn set_libc_regs(&mut self, tid: Tid, regs: crate::Registers) -> Result<()> {
		log::debug!("setting regs {tid} | {regs:?}");
		let n = self.get_tracee_mut(tid)?;
		n.regs = regs.clone();
		n.tracee.set_registers(regs.into())?;
		Ok(())
	}
	fn _get_trampoline_addr(
		&mut self,
		tid: Tid,
		t: TrampType,
		maxattempts: usize,
	) -> Result<TargetPtr> {
		if let Some(addr) = self.tramps.get(&t) {
			Ok(*addr)
		} else if maxattempts > 0 {
			let tracee = self.remove_tracee(tid)?;
			let tracee = self.init_tramps(tracee.tracee).map_err(|x| {
				self.fix_non_fatal(&x);
				x.error
			})?;
			let v = self._get_trampoline_addr(tid, t, maxattempts - 1);
			let tracee = TraceStop::new(tracee)?;
			self.tracee.insert(tid, tracee);
			v
		} else {
			Err(Error::msg("too many attempts"))
		}
	}
	pub fn get_trampoline_addr(&mut self, tid: Tid, t: TrampType) -> Result<TargetPtr> {
		self._get_trampoline_addr(tid, t, 1)
		// self.tramps.get(&t).ok_or(Error::msg("addr has not been set"))
	}
	pub fn set_trampoline_code(&mut self, t: TrampType, code: Vec<u8>) -> Result<()> {
		// No point in setting trampoline code if we've already written it to
		// memory. We could re-write, but would have to implement it.
		if self.tramps.get(&t).is_some() {
			return Err(Error::msg("trampoline has already been written to memory"));
		}
		self.trampcode.insert(t, code);
		Ok(())
	}
	pub fn get_threads_status(&self) -> Result<Vec<Thread>> {
		log::debug!("threads_status");
		let mut ret = Vec::new();
		let mut tids = self.get_tids()?;

		for (key, tracee) in self.tracee.iter() {
			if let Ok(idx) = tids.binary_search(key) {
				tids.remove(idx);
			} else {
				todo!();
			}
			let stop: Stop = tracee.tracee.stop.into();
			let status = ThreadStatus::Stopped(stop);
			let ins = Thread::new(*key, status);
			ret.push(ins);
		}
		for val in tids.into_iter() {
			let status = ThreadStatus::Running;
			let ins = Thread::new(val, status);
			ret.push(ins);
		}
		log::debug!("-> {ret:?}");
		Ok(ret)
	}
	pub fn attach(proc: Process) -> Result<Self> {
		log::info!("attaching {proc:?}");
		let mut tracer = pete::Ptracer::new();
		*tracer.poll_delay_mut() = std::time::Duration::ZERO;

		tracer.attach((&proc).into())?;
		Self::new(proc, tracer)
	}
	pub fn attach_children(&mut self) -> Result<Vec<Tid>> {
		let threads = self.proc.tids()?;
		let currpid = self.proc.pid();
		log::trace!("Attaching to {} child threads of target", threads.len() - 1);
		threads
			.iter()
			.filter(|&tid| *tid != currpid)
			.try_for_each(|&tid| {
				log::debug!("sending attach to {tid:?}");
				self.tracer.attach(pete::Pid::from_raw(tid as i32))?;
				Ok::<(), crate::Error>(())
			})?;
		Ok(threads)
	}
	pub fn spawn<C: Into<Command>>(cmd: C) -> Result<Self> {
		let cmd = cmd.into();
		log::info!("spawning {cmd:?}");
		let mut tracer = pete::Ptracer::new();
		*tracer.poll_delay_mut() = std::time::Duration::ZERO;

		let child = tracer.spawn(cmd)?;
		let pid = child.id();
		let proc = Process::from_pid(pid)?;
		Self::new(proc, tracer)
	}
	pub fn spawn_in_mem<V: Into<Vec<String>>>(
		name: &str,
		data: Vec<u8>,
		args: V,
	) -> Result<(Self, Tid)> {
		let args: Vec<String> = args.into();
		match unsafe { nix::unistd::fork() } {
			Ok(ForkResult::Child) => {
				let mut memfd = MemFdExecutable::new(name, &data);
				memfd.args(args);
				// ptrace::traceme().unwrap();
				// TODO: Hacky, but allows parent some time for attach
				std::thread::sleep(std::time::Duration::from_millis(20));
				let err = memfd.exec(memfd_exec::Stdio::inherit());
				panic!("should never return from exec {err:?}");
			}
			Ok(ForkResult::Parent { child }) => {
				log::debug!("child {child:?}");
				let tid: Tid = child.as_raw() as Tid;
				let mut tracer = pete::Ptracer::new();
				*tracer.poll_delay_mut() = std::time::Duration::ZERO;
				tracer.attach(child)?;
				let proc = Process::from_pid(child.as_raw() as u32)?;
				let r = Self::new(proc, tracer)?;
				Ok((r, tid))
			}

			Err(err) => {
				panic!("fork() failed: {err}");
			}
		}
	}
	pub fn get_modules(&self) -> Result<Vec<MemoryMap>> {
		Ok(self
			.proc
			.maps()?
			.into_iter()
			.filter(|x| x.is_from_file() && x.offset == 0)
			.collect())
	}
	#[cfg(any())]
	pub fn try_wait(&mut self) -> Result<Option<Stopped>> {
		self._wait(false)
	}
	pub fn wait(&mut self) -> Result<Stopped> {
		self._wait(true)?.ok_or(Error::TargetStopped)
	}
	fn _wait(&mut self, force: bool) -> Result<Option<Stopped>> {
		let tracee = if force {
			self.tracer.wait()?
		} else {
			todo!();
			// self.tracer.wait_if_ready()?
		};
		if let Some(tracee) = tracee {
			log::debug!("stop {:?} | pid {:?}", tracee.stop, tracee.pid);

			let pid: i32 = tracee.pid.into();
			let tid = pid as Tid;

			let mut tracee = TraceStop::new(tracee)?;

			let pc = tracee.regs.pc();
			let stop = tracee.tracee.stop;
			let stop = self.handle_wait(&mut tracee, stop, tid)?;
			if let Some(swbp) = self.pendingswbps.remove(&tid) {
				log::debug!("insering previously set pending {tid}");
				self._insert_single_sw_bp(&mut tracee, swbp)?;
			}

			self.tracee.insert(tid, tracee);
			let ret = Stopped::new(pc, stop, tid);
			log::debug!("rstop {ret:?}");
			Ok(Some(ret))
		} else if force {
			log::debug!("target stopped");
			Err(Error::TargetStopped)
		} else {
			log::trace!("no tracee found on soft wait");
			Ok(None)
		}
	}
	fn check_if_swbp(
		&mut self,
		tracee: &mut TraceStop,
		tid: Tid,
		pc: TargetPtr,
	) -> Result<Option<Stop>> {
		let ret = if let Some(mut swbp) = self.swbps.remove(&pc) {
			log::trace!("hit bp {swbp:?}");
			swbp.hit();
			tracee.regs.set_pc(pc);
			tracee.tracee.set_registers(tracee.regs.clone().into())?;

			let clients = swbp.clients.clone();
			if swbp.should_remove() {
				tracee
					.tracee
					.write_memory(swbp.addr.into(), &swbp.oldcode)?;
			} else {
				self.swbps.insert(pc, swbp);
			}

			#[cfg(target_arch = "arm")]
			if let Some(Cont::Step) = self.lastaction.get(&tid) {
				return Ok(Some(Stop::Step { pc }));
			}

			log::trace!("returning breakpoint");
			let stop = Stop::Breakpoint { pc, clients };
			Some(stop)
		} else if let Some(Cont::Step) = self.lastaction.get(&tid) {
			let ret = Stop::Step { pc };
			Some(ret)
		} else {
			None
		};
		Ok(ret)
	}
	fn handle_wait_signal(
		&mut self,
		tracee: &mut TraceStop,
		signal: pete::Signal,
		tid: Tid,
	) -> Result<Stop> {
		let pc = tracee.regs.pc();
		log::trace!("signal @ {pc:x}");
		if signal == pete::Signal::SIGTRAP {
			// The program counter can either point to BP instruction or next
			// instruction
			#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
			let pc = pc - arch::bp_code().len().into();

			if let Some(stop) = self.check_if_swbp(tracee, tid, pc)? {
				return Ok(stop);
			}
		} else if signal == pete::Signal::SIGBUS {
			#[cfg(target_arch = "arm")]
			if let Some(stop) = self.check_if_swbp(tracee, tid, pc)? {
				return Ok(stop);
			}
		}
		let signal = signal as i32;
		Ok(Stop::Signal {
			signal,
			group: false,
		})
	}
	fn handle_wait(&mut self, tracee: &mut TraceStop, stop: pete::Stop, tid: Tid) -> Result<Stop> {
		log::trace!("handle wait {stop:?}");
		match stop {
			pete::Stop::SignalDelivery { signal } => self.handle_wait_signal(tracee, signal, tid),
			pete::Stop::Signaling {
				signal,
				core_dumped: _,
			} => self.handle_wait_signal(tracee, signal, tid),
			_ => Ok(stop.into()),
		}
	}
	pub fn insert_single_bp(&mut self, cid: usize, tid: Tid, pc: TargetPtr) -> Result<()> {
		let mut tracee = self.remove_tracee(tid)?;
		self.insert_single_sw_bp(cid, tid, &mut tracee, pc)?;
		self.tracee.insert(tid, tracee);
		Ok(())
	}
	// pub fn remove_bp(&mut self, tid: Tid, pc: TargetPtr) -> Result<()> {
	// 	let mut tracee = self.remove_tracee(tid)?;
	// 	let bp = self
	// 		.swbps
	// 		.remove(&pc)
	// 		.ok_or(Error::msg(format!("no breakpoint stored at {pc:x}")))?;
	// 	self.remove_swbp(&mut tracee.tracee, &bp)?;
	// 	self.tracee.insert(tid, tracee);
	// 	Ok(())
	// }

	fn _alloc_and_write_bp(
		&mut self,
		cid: usize,
		tid: Tid,
		maxattemts: usize,
	) -> Result<TargetPtr> {
		let prot = Perms::new().read().exec();
		let bp = arch::bp_code();
		let len = bp.len();
		if let Some(alloc) = self.scratch.get_mut(&prot) {
			let addr = alloc.alloc(len)?;
			self.write_memory(tid, addr, bp)?;
			let mut bp = SwBp::new_recurr(addr, bp.to_vec());
			bp.add_client(cid);
			self.swbps.insert(addr, bp);
			Ok(addr)
		} else if maxattemts > 0 {
			self.alloc_scratch(tid, 4, prot)?;
			self._alloc_and_write_bp(cid, tid, maxattemts - 1)
		} else {
			Err(Error::TooManyAttempts)
		}
	}
	pub fn alloc_and_write_bp(&mut self, cid: usize, tid: Tid) -> Result<TargetPtr> {
		self._alloc_and_write_bp(cid, tid, 1)
	}
	pub fn write_memory(&mut self, tid: Tid, addr: TargetPtr, data: &[u8]) -> Result<usize> {
		log::debug!("writing {data:?} to {addr:x}");
		let tracee = self.get_tracee_mut(tid)?;
		let r = tracee.tracee.write_memory(addr.into(), data)?;
		Ok(r)
	}
	pub fn read_memory(&mut self, tid: Tid, addr: TargetPtr, len: usize) -> Result<Vec<u8>> {
		log::trace!("reading {addr:x} {len}");
		let tracee = self.get_tracee_mut(tid)?;
		let r = tracee.tracee.read_memory(addr.into(), len)?;
		Ok(r)
	}

	/// Read up-until NULL-byte, but don't read the actual NULL-byte
	fn read_until_null_byte(
		&mut self,
		tracee: &mut Tracee,
		mut addr: u64,
		output: &mut Vec<u8>,
	) -> Result<()> {
		const READSZ: usize = 32;
		let mut data = Vec::with_capacity(READSZ);
		data.resize(READSZ, 0);

		let mut done = false;
		while !done {
			let len = tracee.read_memory_mut(addr, &mut data)?;
			for b in data[0..len].iter() {
				if *b == 0x00 {
					done = true;
					break;
				}
				output.push(*b);
			}
			data.resize(READSZ, 0);
			addr += len as u64;

			if !done && len < READSZ {
				return Err(Error::Unknown);
			}
		}
		Ok(())
	}
	pub fn read_c_string(&mut self, tid: Tid, addr: TargetPtr) -> Result<String> {
		let mut output = Vec::with_capacity(64);
		let mut tracee = self.remove_tracee(tid)?;
		let res = self.read_until_null_byte(&mut tracee.tracee, addr.into(), &mut output);
		self.tracee.insert(tid, tracee);

		// Trigger potential error after we've inserted the tracee back in
		res?;
		let ret = std::str::from_utf8(&output)?;
		Ok(ret.to_string())
	}

	fn _insert_single_sw_bp(&mut self, tracee: &mut TraceStop, bp: SwBp) -> Result<()> {
		let code = arch::bp_code();

		tracee.tracee.write_memory(bp.addr.into(), code)?;
		self.swbps.insert(bp.addr, bp);
		Ok(())
	}

	fn insert_single_sw_bp(
		&mut self,
		cid: usize,
		tid: Tid,
		tracee: &mut TraceStop,
		addr: TargetPtr,
	) -> Result<()> {
		let code = arch::bp_code();

		if let Some(bp) = self.swbps.get_mut(&addr) {
			bp.add_client(cid);
		} else {
			log::debug!("writing SWBP {code:?} @ {addr:x}");
			let oldcode = tracee.tracee.read_memory(addr.into(), code.len())?;
			let mut bp = SwBp::new_limit(addr, oldcode, 1);
			bp.add_client(cid);
			if tracee.regs.pc() == addr {
				log::debug!("setting BP as pending");
				self.pendingswbps.insert(tid, bp);
			} else {
				self._insert_single_sw_bp(tracee, bp)?;
			}
		}
		Ok(())
	}
	// fn _call_func(
	// 	&mut self,
	// 	mut tracee: Tracee,
	// 	addr: TargetPtr,
	// 	args: &[TargetPtr],
	// 	maxattempts: usize,
	// ) -> Result<(TargetPtr, Tracee)> {
	// 	if let Some(pc) = self.tramps.get(&TrampType::Call) {
	// 		log::info!("calling with tramp at {pc:x}");
	// 		let oregs = tracee.registers()?;
	// 		let mut regs = as_our_regs(oregs);
	// 		regs.set_pc(*pc + 4);
	// 		for (i, arg) in args.iter().enumerate() {
	// 			log::debug!("arg[{i}]: = {arg:x}");
	// 			self.cc.set_arg(&mut regs, i, *arg)?;
	// 			// regs.set_arg_systemv(i, *arg);
	// 		}
	// 		self.cc.set_reg_call_tramp(&mut regs, addr);
	// 		// regs.set_call_func(addr);
	// 		log::debug!("regs {regs:?}");
	// 		tracee.set_registers(regs.into())?;
	// 		log::debug!("running until call to {addr:x} is over");
	// 		let (mut tracee, err) = self.run_until(tracee, Self::cb_stop_is_trap)?;
	// 		if let Some(error) = err {
	// 			log::error!("got error when executing call, target may be in an unstable state, err: {error:?}");
	// 			let tid = tracee.pid.as_raw() as Tid;
	// 			let tracee = TraceStop::new(tracee)?;
	// 			self.tracee.insert(tid, tracee);
	// 			Err(error)
	// 		} else {
	// 			let regs = as_our_regs(tracee.registers()?);
	// 			let ret = self.cc.get_retval(&regs);
	// 			// let ret = regs.ret_systemv();
	// 			tracee.set_registers(oregs)?;
	// 			Ok((ret, tracee))
	// 		}
	// 	} else if maxattempts > 0 {
	// 		let tracee = self.init_tramps(tracee)?;
	// 		self._call_func(tracee, addr, args, maxattempts - 1)
	// 	} else {
	// 		log::warn!("unable to call function, returning error");
	// 		Ok((TargetPtr::MAX, tracee))
	// 	}
	// }
	// pub fn call_func(
	// 	&mut self,
	// 	tid: Tid,
	// 	addr: TargetPtr,
	// 	args: &[TargetPtr],
	// ) -> Result<TargetPtr> {
	// 	let tracee = self.remove_tracee(tid)?;
	// 	let (ret, tracee) = self._call_func(tracee.tracee, addr, args, 1)?;
	// 	let pid: i32 = tracee.pid.into();
	// 	let tid = pid as Tid;
	// 	let tracee = TraceStop::new(tracee)?;
	// 	self.tracee.insert(tid, tracee);
	// 	Ok(ret)
	// }
	fn fix_non_fatal(&mut self, error: &TraceError) {
		if let Some(tracee) = error.tracee {
			let tid = tracee.pid.as_raw() as Tid;
			let tracee = TraceStop::new(tracee).expect("unable to create new TraceStop");
			self.tracee.insert(tid, tracee);
		} else {
			log::error!("tracee on tid was fatal, tid probably exited or crashed");
		}
	}
	pub fn run_until_trap(&mut self, tid: Tid) -> Result<()> {
		log::debug!("running until trap on {tid}");
		let tracee = self.remove_tracee(tid)?;
		let tracee = self
			.run_until(tracee.tracee, Self::cb_stop_is_bkpt)
			.map_err(|x| {
				self.fix_non_fatal(&x);
				x.error
			})?;
		let tid = tracee.pid.as_raw() as Tid;
		let tracee = TraceStop::new(tracee)?;
		self.tracee.insert(tid, tracee);
		Ok(())
	}
	fn remove_tracee(&mut self, tid: Tid) -> Result<TraceStop> {
		self.tracee.remove(&tid).ok_or(Error::tid_not_found(tid))
	}
	fn get_tracee_mut(&mut self, tid: Tid) -> Result<&mut TraceStop> {
		self.tracee.get_mut(&tid).ok_or(Error::tid_not_found(tid))
	}
	fn get_tracee(&self, tid: Tid) -> Result<&TraceStop> {
		self.tracee.get(&tid).ok_or(Error::tid_not_found(tid))
	}
	fn alloc_scratch(&mut self, tid: Tid, pages: usize, prot: Perms) -> Result<Location> {
		let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
		let size = page_sz * pages;
		let addr = self.exec_sys_anon_mmap(tid, size as usize, prot.clone())?;
		let loc = Location::new(addr, addr + size.into());
		let alloc = AllocedMemory::new(loc.clone());
		self.scratch.insert(prot, alloc);
		Ok(loc)
	}
	fn _scratch_write_bytes(
		&mut self,
		tid: Tid,
		bytes: Vec<u8>,
		attempts: usize,
	) -> Result<TargetPtr> {
		if attempts > 0 {
			let prot = Perms::new().read().write();
			if let Some(alloc) = self.scratch.get_mut(&prot) {
				let memory = alloc.alloc(bytes.len())?;
				self.write_memory(tid, memory, &bytes)?;
				Ok(memory)
			} else {
				self.alloc_scratch(tid, 4, prot)?;
				self._scratch_write_bytes(tid, bytes, attempts - 1)
			}
		} else {
			Err(Error::TooManyAttempts)
		}
	}
	pub fn scratch_write_bytes(&mut self, tid: Tid, bytes: Vec<u8>) -> Result<TargetPtr> {
		// Call sub-function to avoid possibility of endless loop
		self._scratch_write_bytes(tid, bytes, 2)
	}
	pub fn scratch_write_c_str(&mut self, tid: Tid, str: String) -> Result<TargetPtr> {
		let mut bytes = str.as_bytes().to_vec();
		bytes.push(0x00);
		self.scratch_write_bytes(tid, bytes)
	}
	pub fn scratch_free_addr(&mut self, _tid: Tid, addr: TargetPtr) -> Result<()> {
		let prot = Perms::new().read().write();
		let alloc = self
			.scratch
			.get_mut(&prot)
			.ok_or(Error::scratch_addr_not_found(addr))?;
		alloc.free(addr)?;
		Ok(())
	}
	pub fn exec_sys_getpid(&mut self, tid: Tid) -> Result<libc::pid_t> {
		let r = self.exec_syscall(tid, libc::SYS_getpid as usize, &[])?;
		Ok(r.into())
	}
	pub fn exec_sys_anon_mmap(&mut self, tid: Tid, size: usize, prot: Perms) -> Result<TargetPtr> {
		#[cfg(any(target_arch = "x86", target_arch = "arm"))]
		let (sysno, size) = (libc::SYS_mmap2 as usize, size / 4096);

		#[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
		let (sysno, size) = (libc::SYS_mmap as usize, size);

		let args = MmapBuild::sane_anonymous(size, prot);
		let r = self.exec_syscall(tid, sysno, &args)?;
		let c: *const libc::c_void = r.into();

		if c != libc::MAP_FAILED {
			Ok(r)
		} else {
			Err(Error::Unknown)
		}
	}
	fn __exec_ret(
		&mut self,
		mut tracee: Tracee,
		mut regs: Registers,
		pc: TargetPtr,
	) -> TraceResult<Tracee> {
		regs.set_pc(pc);
		tracee
			.set_registers(regs.into())
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		Ok(tracee)
	}
	fn _exec_ret(
		&mut self,
		tracee: Tracee,
		regs: Registers,
		maxattempts: usize,
	) -> TraceResult<Tracee> {
		if let Some(pc) = self.tramps.get(&TrampType::Ret) {
			self.__exec_ret(tracee, regs, *pc)
		} else if maxattempts > 0 {
			let tracee = self.init_tramps(tracee)?;
			self._exec_ret(tracee, regs, maxattempts - 1)
		} else {
			todo!();
		}
	}
	pub fn exec_ret(&mut self, tid: Tid) -> Result<()> {
		let tracee = self.remove_tracee(tid)?;
		let regs = tracee.regs.clone();
		let tracee = self._exec_ret(tracee.tracee, regs, 1).map_err(|x| {
			self.fix_non_fatal(&x);
			x.error
		})?;
		let pid: i32 = tracee.pid.into();
		let tid = pid as Tid;
		let tracee = TraceStop::new(tracee)?;
		self.tracee.insert(tid, tracee);
		Ok(())
	}
	fn __exec_syscall(
		&mut self,
		mut tracee: Tracee,
		tramp: TargetPtr,
		sysno: usize,
		args: &[TargetPtr],
	) -> TraceResult<(Tracee, TargetPtr)> {
		// Get original register we need to restore later
		let restoreregs = tracee
			.registers()
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		let mut regs: Registers = restoreregs.into();

		// Modify registers to to syscall
		regs.set_pc(tramp);
		prep_syscall(&mut regs, sysno, args).map_err(|x| TraceError::new(tracee, x.into()))?;

		// Write registers to tracee
		tracee
			.set_registers(regs.into())
			.map_err(|x| TraceError::new(tracee, x.into()))?;

		// Run until we hit our inserted breakboint
		let mut tracee = self.run_until(tracee, Self::cb_stop_is_bkpt)?;

		// Read register and get return value
		let regs = tracee
			.registers()
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		let regs: Registers = regs.into();
		log::trace!("regs after {regs:?}");
		let ret = regs.ret_syscall();

		// Restore original registers
		tracee
			.set_registers(restoreregs)
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		Ok((tracee, ret))
	}
	fn _exec_syscall(
		&mut self,
		tracee: Tracee,
		sysno: usize,
		args: &[TargetPtr],
		maxattempts: usize,
	) -> TraceResult<(Tracee, TargetPtr)> {
		log::debug!("exec syscall {sysno}");
		if let Some(pc) = self.tramps.get(&TrampType::Syscall) {
			log::debug!("found syscall tramp @ {pc:x}");
			self.__exec_syscall(tracee, *pc + 4.into(), sysno, args)
		} else if maxattempts > 0 {
			log::debug!("init tramps {maxattempts}");
			let tracee = self.init_tramps(tracee)?;
			self._exec_syscall(tracee, sysno, args, maxattempts - 1)
		} else {
			log::error!("unable to perform syscall, returning error");
			Err(TraceError::new(tracee, Error::TooManyAttempts))
		}
	}
	pub fn exec_syscall(
		&mut self,
		tid: Tid,
		sysno: usize,
		args: &[TargetPtr],
	) -> Result<TargetPtr> {
		log::debug!("syscall[{tid}]: {sysno} {args:?}");
		let tracee = self.remove_tracee(tid)?;
		let (tracee, ret) = self
			._exec_syscall(tracee.tracee, sysno, args, 1)
			.map_err(|x| {
				self.fix_non_fatal(&x);
				x.error
			})?;
		let pid: i32 = tracee.pid.into();
		let tid = pid as Tid;
		let tracee = TraceStop::new(tracee)?;
		self.tracee.insert(tid, tracee);
		if usize::from(ret) == usize::MAX {
			Err(Error::msg("syscall returned error"))
		} else {
			Ok(ret)
		}
	}
	fn remove_swbp(&self, tracee: &mut Tracee, bp: &SwBp) -> Result<()> {
		tracee.write_memory(bp.addr.into(), &bp.oldcode)?;
		Ok(())
	}
	fn run_until(
		&mut self,
		tracee: Tracee,
		dostop: fn(&pete::Stop) -> Result<bool>,
	) -> TraceResult<Tracee> {
		log::debug!("entered run_until");
		let regs = tracee
			.registers()
			.map_err(|x| TraceError::new(tracee, x.into()))?;

		// log::debug!("regs {:?}", as_our_regs(regs));
		self.tracer
			.restart(tracee, Restart::Continue)
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		while let Some(tracee) = self
			.tracer
			.wait()
			.map_err(|x| TraceError::new(tracee, x.into()))?
		{
			log::trace!("run_until: got stop {:?} {:?}", tracee.pid, tracee.stop);
			if dostop(&tracee.stop).map_err(|x| TraceError::new(tracee, x.into()))? {
				return Ok(tracee);
			} else {
				match &tracee.stop {
					pete::Stop::SignalDelivery { signal } => {
						if *signal as i32 == Signal::SIGSEGV as i32 {
							let err = Error::msg("received SIGSEGV");
							return Err(TraceError::new(tracee, err));
						}
					}
					_ => log::warn!("unexpected stop, trying to continue {:?}", tracee.stop),
				}
			}
			self.tracer
				.restart(tracee, Restart::Continue)
				.map_err(|x| TraceError::new(tracee, x.into()))?;
		}
		log::error!("tracer wait ended in none");
		Err(TraceError::new_fatal(Error::TargetStopped))
	}
	fn signal_is_bkpt(signal: &pete::Signal) -> Result<bool> {
		match signal {
			Signal::SIGHUP => todo!(),
			Signal::SIGINT => todo!(),
			Signal::SIGQUIT => todo!(),
			Signal::SIGILL => Err(Error::Signal {
				signal: *signal as i32,
			}),
			Signal::SIGTRAP => Ok(true),
			Signal::SIGABRT => todo!(),
			Signal::SIGBUS => todo!(),
			Signal::SIGFPE => todo!(),
			Signal::SIGKILL => todo!(),
			Signal::SIGUSR1 => todo!(),
			Signal::SIGSEGV => Err(Error::Signal {
				signal: *signal as i32,
			}),
			Signal::SIGUSR2 => todo!(),
			Signal::SIGPIPE => todo!(),
			Signal::SIGALRM => todo!(),
			Signal::SIGTERM => todo!(),
			Signal::SIGSTKFLT => todo!(),
			Signal::SIGCHLD => todo!(),
			Signal::SIGCONT => todo!(),
			Signal::SIGSTOP => todo!(),
			Signal::SIGTSTP => todo!(),
			Signal::SIGTTIN => todo!(),
			Signal::SIGTTOU => todo!(),
			Signal::SIGURG => todo!(),
			Signal::SIGXCPU => todo!(),
			Signal::SIGXFSZ => todo!(),
			Signal::SIGVTALRM => todo!(),
			Signal::SIGPROF => todo!(),
			Signal::SIGWINCH => todo!(),
			Signal::SIGIO => todo!(),
			Signal::SIGPWR => todo!(),
			Signal::SIGSYS => todo!(),
			_ => todo!(),
		}
	}
	fn cb_stop_is_bkpt(stop: &pete::Stop) -> Result<bool> {
		log::trace!("check if bkpt: stop {stop:?}");
		#[allow(clippy::match_like_matches_macro)]
		match stop {
			pete::Stop::SignalDelivery { signal } => Self::signal_is_bkpt(signal),
			pete::Stop::Signaling {
				signal,
				core_dumped: _,
			} => Self::signal_is_bkpt(signal),
			pete::Stop::Attach => todo!(),
			pete::Stop::Group { signal: _ } => todo!(),
			pete::Stop::SyscallEnter => todo!(),
			pete::Stop::SyscallExit => todo!(),
			pete::Stop::Clone { new } => todo!(),
			pete::Stop::Fork { new } => todo!(),
			pete::Stop::Exec { old } => todo!(),
			pete::Stop::Exiting { exit_code } => todo!(),
			pete::Stop::Vfork { new } => todo!(),
			pete::Stop::VforkDone { new } => todo!(),
			pete::Stop::Seccomp { data } => todo!(),
		}
	}
	fn find_executable_space(&self) -> Result<TargetPtr> {
		let r = self
			.proc
			.proc
			.maps()?
			.into_iter()
			.find(|m| m.perms.contains(MMPermissions::EXECUTE))
			.map(|m| m.address.0)
			.ok_or(crate::Error::Unknown)?;

		Ok(r.into())
	}

	// Initialize some executable memory where we can place our trampolines
	fn init_tramps(&mut self, mut tracee: Tracee) -> TraceResult<Tracee> {
		log::info!("initializing tramps");
		// First step is to find some executable space we can write to and write
		// our syscall tramp to that region
		let exespace = self
			.find_executable_space()
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		let shellcode = self
			.trampcode
			.get(&TrampType::Syscall)
			.expect("TrampType::Syscall was not set");
		let len = shellcode.len();
		let orig = tracee
			.read_memory(exespace.into(), len)
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		tracee
			.write_memory(exespace.into(), &shellcode)
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		log::debug!("wrote executable memory {exespace:x} | {shellcode:?}");

		// Get the registers, both so we can modify them to run our syscall
		// trampoline and so that we can restore this when everything is done
		// for.
		let oregs = tracee
			.registers()
			.map_err(|x| TraceError::new(tracee, x.into()))?;

		// Get registers we can modify and prepare mmap() syscall
		let mut svc_regs: Registers = oregs.into();
		log::debug!("regs {svc_regs:?}");

		// let mut psize: TargetPtr = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.into();

		#[cfg(any(target_arch = "x86", target_arch = "arm"))]
		let (psize, sysno) = (1.into(), libc::SYS_mmap2);

		#[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
		let (psize, sysno) = (
			unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.into(),
			libc::SYS_mmap,
		);

		svc_regs.set_pc(exespace + 4.into());
		let mmap_args = vec![
			0.into(), // addr
			psize,    // len
			(libc::PROT_READ /*| libc::PROT_WRITE */| libc::PROT_EXEC).into(),
			(libc::MAP_ANONYMOUS | libc::MAP_PRIVATE).into(),
			usize::MAX.into(), // fd
			0.into(),          // offset
		];
		log::debug!("mmap args {mmap_args:?}");
		prep_syscall(&mut svc_regs, sysno as usize, &mmap_args)
			.map_err(|x| TraceError::new(tracee, x.into()))?;

		log::debug!("regs2 {svc_regs:?}");
		tracee
			.set_registers(svc_regs.into())
			.map_err(|x| TraceError::new(tracee, x.into()))?;

		// Run until we hit our trap at the end of the trampoline code
		log::debug!("running to complete mmap");
		let mut tracee = self.run_until(tracee, Self::cb_stop_is_bkpt)?;

		// Get registers again so that we can verify return code and check what
		// the address we actually mmapp'ed
		let nregs = tracee
			.registers()
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		let mut svc_regs: Registers = nregs.into();
		let addr = svc_regs.ret_syscall();
		log::debug!("addr {addr:x}");
		let naddr: usize = addr.into();
		let _ntracee = if naddr < usize::MAX - 100 {
			log::debug!("mmapped {addr:x}");

			// Store the mmapped-region so that we can free it when we detach
			let mmapped = (addr, psize.into());
			self.mmapped.push(mmapped);

			// Prepare all our tramps and store the individual location of them
			let syscalltramp = addr;
			let mut inscode = Vec::new();
			let a = self.trampcode.get(&TrampType::Syscall).unwrap();
			inscode.extend(a);
			// syscall_shellcode(&mut inscode);

			let calltramp = addr + inscode.len().into();
			// call_shellcode(&mut inscode);
			let a = self.trampcode.get(&TrampType::Call).unwrap();
			inscode.extend(a);

			let rettramp = addr + inscode.len().into();
			// ret_shellcode(&mut inscode);
			let a = self.trampcode.get(&TrampType::Ret).unwrap();
			inscode.extend(a);

			// Write the tramps to memory
			log::debug!("writing real tramps to {addr:x} | {inscode:?}");
			tracee
				.write_memory(addr.into(), &inscode)
				.map_err(|x| TraceError::new(tracee, x.into()))?;

			// Everything succeeded and we can insert our tramps
			self.tramps.insert(TrampType::Syscall, syscalltramp);
			self.tramps.insert(TrampType::Call, calltramp);
			self.tramps.insert(TrampType::Ret, rettramp);
			tracee
		} else {
			log::error!("mmap returned MAP_FAILED {naddr}");
			tracee
		};

		// Regardless of whether we succeed or not, we should write back
		// original code and set the registers back to original.
		log::info!("init_tramps over, restoring state");
		tracee
			.write_memory(exespace.into(), &orig)
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		tracee
			.set_registers(oregs)
			.map_err(|x| TraceError::new(tracee, x.into()))?;
		Ok(tracee)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ::test::Bencher;
	use serial_test::serial;
	use std::{fs::OpenOptions, io::Read, path::PathBuf};

	const PROGNAME: &str = "true";

	fn fullpath(name: &str) -> String {
		let mut c = Command::new("which");
		c.arg(name);

		let out = c.output().expect("unable to spawn which");

		let stdout = std::str::from_utf8(&out.stdout).unwrap();
		let stdout = stdout.strip_suffix('\n').expect("msg");
		stdout.to_string()
	}

	fn spawn() -> Result<(Tracer, Tid)> {
		let cmd = Command::new(PROGNAME);
		let mut tracer = Tracer::spawn(cmd).unwrap();

		// Ensure only one thread running
		let tids = tracer.get_tids().unwrap();
		assert_eq!(tids.len(), 1);

		// Wait until proper stop
		let stop = tracer.wait().unwrap();
		log::debug!("stop {stop:?}");
		assert!(stop.stop == Stop::SyscallExit);

		Ok((tracer, tids[0]))
	}

	#[bench]
	fn bench_baseline_true(b: &mut Bencher) {
		b.iter(|| {
			assert!(std::process::Command::new("true")
				.stdout(std::process::Stdio::piped())
				.spawn()
				.unwrap()
				.wait()
				.is_ok())
		});
	}

	#[cfg(target_os = "linux")]
	#[bench]
	fn bench_baseline_strace(b: &mut Bencher) {
		// Test environment doesn't necessarily have strace
		let out = std::process::Command::new("which")
			.arg("strace")
			.status()
			.unwrap();
		if out.success() {
			b.iter(|| {
				let mut cmd = std::process::Command::new("strace");
				cmd.arg("true");
				assert!(cmd
					.stdout(std::process::Stdio::piped())
					.stderr(std::process::Stdio::piped())
					.spawn()
					.unwrap()
					.wait()
					.is_ok())
			});
		}
	}

	#[bench]
	fn bench_trace_inner(b: &mut Bencher) {
		b.iter(|| {
			trace1();
		});
	}

	#[bench]
	fn bench_trace_read_c_str(b: &mut Bencher) {
		let (mut tracer, tid) = spawn().unwrap();

		// Check a simple syscall
		let pid = tracer
			.exec_syscall(tid, libc::SYS_getpid as usize, &[])
			.unwrap();
		assert_eq!(pid, tid.into());

		// Try and allocate some memory
		let _addr = tracer
			.exec_sys_anon_mmap(tid, 4096, Perms::new().read().write())
			.unwrap();

		// Read and write to scratch region
		let wrote = String::from("Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World!");
		let addr = tracer.scratch_write_c_str(tid, wrote.clone()).unwrap();

		b.iter(|| {
			read_c_str(&mut tracer, tid, addr, wrote.as_str());
		});

		tracer.scratch_free_addr(tid, addr).unwrap();

		tracer.detach(tid).unwrap();
	}

	#[test]
	fn trace0() {
		let (mut tracer, tid) = spawn().unwrap();

		tracer.detach(tid).unwrap();

		let stop = tracer.wait();
		assert!(stop.is_err());
	}

	#[test]
	fn trace1() {
		let (mut tracer, tid) = spawn().unwrap();

		// Just send continue and wait until stop
		tracer.cont(tid, Cont::Cont).unwrap();
		let stop = tracer.wait();
		log::trace!("stop {stop:?}");
	}

	#[cfg(not(target_arch = "arm"))]
	#[test]
	fn trace2() {
		let (mut tracer, tid) = spawn().unwrap();

		// Single step for a while
		let mut lastpc: usize = 0;
		for _i in 0..10 {
			tracer.cont(tid, Cont::Step).unwrap();
			let stop = tracer.wait().unwrap();

			assert!(matches!(stop.stop, Stop::Step { pc: _ }));
			assert!(usize::from(stop.pc) != lastpc);
			lastpc = stop.pc.into();
		}

		// Continue until exit
		tracer.cont(tid, Cont::Cont).unwrap();
		let stop = tracer.wait();
		log::trace!("stop {stop:?}");
	}

	#[test]
	fn trace3() {
		let (mut tracer, tid) = spawn().unwrap();

		// Trace all syscalls
		loop {
			tracer.cont(tid, Cont::Syscall).unwrap();
			let stop = tracer.wait();
			match stop {
				Ok(stop) => {
					assert!(
						matches!(stop.stop, Stop::SyscallEnter)
							|| matches!(stop.stop, Stop::SyscallExit)
					);
					let w = format!("{stop}");
					log::trace!("STOP: {w}");
				}
				Err(err) => {
					assert!(matches!(err, Error::TargetStopped));
					break;
				}
			}
		}
	}

	#[test]
	fn trace4() {
		let (mut tracer, tid) = spawn().unwrap();

		let searchbin = fullpath(PROGNAME);
		let searchbin = PathBuf::from(searchbin);
		#[cfg(target_os = "android")]
		let searchbin = PathBuf::from("/system/bin/toybox");

		let main = tracer.proc.exe_module().unwrap();

		let elf = crate::exe::elf::Elf::new(searchbin, 0.into())
			.unwrap()
			.parse()
			.unwrap();
		let entry = elf.entry();
		let runentry = entry + main.loc.addr();
		log::trace!("entry {entry:x} {runentry:x}");

		let d = tracer.read_memory(tid, runentry, 4).unwrap();
		log::trace!("bytes {d:?}");

		tracer.insert_single_bp(0, tid, runentry).unwrap();
		let d = tracer.read_memory(tid, runentry, 4).unwrap();
		log::trace!("bytes {d:?}");

		tracer.cont(tid, Cont::Cont).unwrap();
		let stop = tracer.wait().unwrap();
		log::trace!("stop1 {stop:?}");

		tracer.cont(tid, Cont::Cont).unwrap();
		let _stop = tracer.wait();
	}

	fn read_c_str(tracer: &mut Tracer, tid: Tid, addr: TargetPtr, wrote: &str) {
		let read = tracer.read_c_string(tid, addr).unwrap();
		assert_eq!(read, wrote);
	}

	#[test]
	fn trace5() {
		let (mut tracer, tid) = spawn().unwrap();

		// Check a simple syscall
		let pid = tracer
			.exec_syscall(tid, libc::SYS_getpid as usize, &[])
			.unwrap();
		assert_eq!(pid, tid.into());

		// Try and allocate some memory
		let _addr = tracer
			.exec_sys_anon_mmap(tid, 4096, Perms::new().read().write())
			.unwrap();

		// Read and write to scratch region
		let wrote = String::from("Hello World!");
		let addr = tracer.scratch_write_c_str(tid, wrote.clone()).unwrap();
		let read = tracer.read_c_string(tid, addr).unwrap();
		assert_eq!(read, wrote);
		tracer.scratch_free_addr(tid, addr).unwrap();

		tracer.detach(tid).unwrap();
	}

	#[test]
	fn trace_err() {
		let (mut tracer, tid) = spawn().unwrap();
		let t = tid + 42;
		let r = tracer.cont(t, Cont::Cont);
		log::debug!("err {r:?}");
		assert!(r.is_err());
		assert!(tracer.detach(t).is_err());
		assert!(tracer.get_libc_regs(t).is_err());

		assert!(tracer.insert_single_bp(0, t, 42.into()).is_err());
		// assert!(tracer.remove_bp(t, 42).is_err());
		assert!(tracer.write_memory(t, 42.into(), &[]).is_err());
		assert!(tracer.read_memory(t, 42.into(), 42).is_err());
		let err = tracer.read_c_string(tid, 42.into());
		log::debug!("err {err:?}");
		assert!(err.is_err());

		// assert!(tracer.call_func(t, 42, &[]).is_err());

		tracer.detach(tid).unwrap();
	}

	fn setup_in_mem(p: &str) -> Result<(Tracer, Tid)> {
		let mut file = OpenOptions::new().read(true).open(p)?;
		let mut data = Vec::new();
		file.read_to_end(&mut data)?;
		let (mut tracer, tid) = Tracer::spawn_in_mem(p, data, [])?;
		let stop = tracer.wait().unwrap();
		log::debug!("stop {stop:?}");
		Ok((tracer, tid))
	}

	#[serial]
	#[test]
	fn trace_in_mem0() {
		let bin = fullpath("true");
		let (mut tracer, tid) = setup_in_mem(&bin).unwrap();
		tracer.detach(tid).unwrap();
	}

	#[serial]
	#[test]
	fn trace_in_mem1() {
		let bin = fullpath("true");
		let (mut tracer, tid) = setup_in_mem(&bin).unwrap();

		loop {
			tracer.cont(tid, Cont::Syscall).unwrap();
			let stop = tracer.wait();
			match stop {
				Ok(stop) => {
					// assert!(
					// 	matches!(stop.stop,
					// 		Stop::SyscallEnter| Stop::SyscallExit | Stop::Exec { old }
					// 	)
					// );
					let w = format!("{stop}");
					log::trace!("STOP: {w}");
				}
				Err(err) => {
					assert!(matches!(err, Error::TargetStopped));
					break;
				}
			}
		}
	}
}
