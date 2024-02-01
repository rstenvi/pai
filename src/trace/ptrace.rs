use crate::{
	api::messages::{Cont, Thread, ThreadStatus},
	arch::{self, prep_syscall, ReadRegisters, WriteRegisters},
	utils::process::Pid,
	utils::{AllocedMemory, MmapBuild},
	UntrackedResult,
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

use super::{Stop, Stopped, SwBp};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::{as_our_regs, call_shellcode, syscall_shellcode};
#[cfg(target_arch = "arm")]
use crate::arch::aarch32::{as_our_regs, call_shellcode, syscall_shellcode};
#[cfg(target_arch = "x86")]
use crate::arch::x86::{as_our_regs, call_shellcode, syscall_shellcode};
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{as_our_regs, call_shellcode, syscall_shellcode};

impl From<pete::Stop> for Stop {
	fn from(value: pete::Stop) -> Self {
		match value {
			pete::Stop::Attach => Self::Attach,
			pete::Stop::SignalDelivery { signal } => Self::Signal {
				signal: signal as i32,
				group: false,
			},
			pete::Stop::Group { signal } => {
				log::error!("group signal {signal:?}");
				Self::Signal {
					signal: signal as i32,
					group: true,
				}
			}
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
			pete::Stop::Exec { old: _ } => todo!(),
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
	#[cfg(target_arch = "x86_64")]
	pub regs: arch::x86_64::user_regs_struct,
	#[cfg(target_arch = "x86")]
	pub regs: arch::x86::user_regs_struct,
	#[cfg(target_arch = "aarch64")]
	pub regs: arch::aarch64::user_regs_struct,
	#[cfg(target_arch = "arm")]
	pub regs: arch::aarch32::user_regs_struct,
}

impl TraceStop {
	pub fn new(tracee: Tracee) -> Result<Self> {
		let regs = tracee.registers()?;
		let regs = regs.into();
		Ok(Self { tracee, regs })
	}
}

#[derive(Eq, PartialEq, Hash)]
enum TrampType {
	Syscall,
	Call,
}

pub struct Tracer {
	proc: Process,
	tracer: pete::ptracer::Ptracer,
	swbps: HashMap<TargetPtr, SwBp>,
	mmapped: Vec<(TargetPtr, usize)>,
	tramps: HashMap<TrampType, TargetPtr>,
	tracee: HashMap<Tid, TraceStop>,
	scratch: HashMap<Perms, AllocedMemory>,
	lastaction: HashMap<Tid, Cont>,
	pendingswbps: HashMap<Tid, SwBp>,
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
		let s = Self {
			proc,
			tracer,
			swbps,
			tracee,
			tramps,
			mmapped,
			scratch,
			lastaction,
			pendingswbps,
		};
		Ok(s)
	}
	pub fn cont(&mut self, tid: Tid, cont: Cont) -> UntrackedResult<()> {
		log::debug!("cont {tid} {cont:?}");
		let restart = cont.into();
		self.lastaction.insert(tid, cont);
		if let Some(mut tracee) = self.tracee.remove(&tid) {
			log::trace!("setting options");
			tracee.tracee.set_options(
				pete::ptracer::Options::PTRACE_O_TRACESYSGOOD
					| pete::ptracer::Options::PTRACE_O_TRACECLONE
					| pete::ptracer::Options::PTRACE_O_TRACEVFORK
					| pete::ptracer::Options::PTRACE_O_TRACEFORK,
			)?;
			log::debug!("sending restart {restart:?} to {tid}");
			self.tracer.restart(tracee.tracee, restart)?;
			Ok(())
		} else {
			Err(Error::TidNotFound { tid })
		}
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

	pub fn detach(&mut self, tid: Tid) -> UntrackedResult<()> {
		if let Some(tracee) = self.tracee.remove(&tid) {
			let tracee = self.cleanup(tracee.tracee)?;
			self._detach(tracee)?;
			// self.tracer.detach(tracee)?;
			Ok(())
		} else {
			Err(Error::TidNotFound { tid })
		}
	}
	pub fn get_pid(&self) -> UntrackedResult<Pid> {
		Ok(self.proc.pid())
	}
	pub fn get_tids(&self) -> UntrackedResult<Vec<Tid>> {
		let mut r = self.proc.tids()?;
		r.sort();
		Ok(r)
	}
	pub fn get_libc_regs(&self, tid: Tid) -> UntrackedResult<Registers> {
		if let Some(n) = self.tracee.get(&tid) {
			// let regs = n.regs.into();
			Ok(n.regs.clone())
		} else {
			Err(Error::TidNotFound { tid })
		}
	}
	pub fn get_threads_status(&self) -> UntrackedResult<Vec<Thread>> {
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
	fn spawn_in_mem(name: &str, data: Vec<u8>) -> Result<(Self, Tid)> {
		match unsafe{nix::unistd::fork()} {
			Ok(ForkResult::Child) => {
				let mut memfd = MemFdExecutable::new(name, &data);
				ptrace::traceme().unwrap();
				let err = memfd.exec(memfd_exec::Stdio::inherit());
				panic!("should never return from exec {err:?}");
			}
			Ok(ForkResult::Parent {child}) => {
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
	pub fn get_modules(&self) -> UntrackedResult<Vec<MemoryMap>> {
		Ok(self
			.proc
			.maps()?
			.into_iter()
			.filter(|x| x.is_from_file() && x.offset == 0)
			.collect())
	}
	pub fn try_wait(&mut self) -> UntrackedResult<Option<Stopped>> {
		self._wait(false)
	}
	pub fn wait(&mut self) -> UntrackedResult<Stopped> {
		self._wait(true)?.ok_or(Error::TargetStopped)
	}
	fn _wait(&mut self, force: bool) -> UntrackedResult<Option<Stopped>> {
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
			Ok(Some(ret))
		} else if force {
			Err(Error::TargetStopped)
		} else {
			Ok(None)
		}
	}
	fn handle_wait_signal(
		&mut self,
		tracee: &mut TraceStop,
		signal: pete::Signal,
		tid: Tid,
	) -> UntrackedResult<Stop> {
		if signal == pete::Signal::SIGTRAP {
			let pc = tracee.regs.pc();
			let pc = pc - Self::sw_bp_len() as TargetPtr;

			if let Some(mut swbp) = self.swbps.remove(&pc) {
				swbp.hit();
				tracee.regs.set_pc(pc);
				tracee.tracee.set_registers(tracee.regs.clone().into())?;
				tracee.tracee.write_memory(swbp.addr as u64, &swbp.oldcode)?;

				assert!(swbp.should_remove());
				let stop = Stop::Breakpoint {
					pc,
					clients: swbp.clients,
				};
				return Ok(stop);
			} else if let Some(Cont::Step) = self.lastaction.get(&tid) {
				let ret = Stop::Step { pc };
				return Ok(ret);
			}
		}
		let signal = signal as i32;
		Ok(Stop::Signal {
			signal,
			group: false,
		})
	}
	fn handle_wait(&mut self, tracee: &mut TraceStop, stop: pete::Stop, tid: Tid) -> UntrackedResult<Stop> {
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
	pub fn insert_single_bp(&mut self, cid: usize, tid: Tid, pc: TargetPtr) -> UntrackedResult<()> {
		if let Some(mut tracee) = self.tracee.remove(&tid) {
			self.insert_single_sw_bp(cid, tid, &mut tracee, pc)?;
			self.tracee.insert(tid, tracee);
			Ok(())
		} else {
			Err(Error::Unknown.into())
		}
	}
	pub fn remove_bp(&mut self, tid: Tid, pc: TargetPtr) -> UntrackedResult<()> {
		if let Some(mut tracee) = self.tracee.remove(&tid) {
			if let Some(bp) = self.swbps.remove(&pc) {
				self.remove_swbp(&mut tracee.tracee, &bp)?;
			} else {
				log::warn!("unable to find a breakpoint stored at {pc:x}");
			}
			self.tracee.insert(tid, tracee);
			Ok(())
		} else {
			Err(Error::Unknown.into())
		}
	}

	pub fn write_memory(&mut self, tid: Tid, addr: TargetPtr, data: &[u8]) -> UntrackedResult<usize> {
		if let Some(tracee) = self.tracee.get_mut(&tid) {
			let r = tracee.tracee.write_memory(addr as u64, data)?;
			Ok(r)
		} else {
			Err(Error::TidNotFound { tid })
		}
	}
	pub fn read_memory(&mut self, tid: Tid, addr: TargetPtr, len: usize) -> UntrackedResult<Vec<u8>> {
		log::trace!("reading {addr:x} {len}");
		if let Some(tracee) = self.tracee.get_mut(&tid) {
			let r = tracee.tracee.read_memory(addr as u64, len)?;
			Ok(r)
		} else {
			Err(Error::TidNotFound { tid })
		}
	}
	pub fn read_c_string(&mut self, tid: Tid, addr: TargetPtr) -> UntrackedResult<String> {
		// TODO Really slow, should do better
		let mut ret = String::from("");
		let mut off = 0;
		loop {
			let v = self.read_memory(tid, addr + off, 1)?;
			let v = v[0];
			if v == 0 {
				break;
			}
			off += 1;
			ret.push(v as char);
		}
		Ok(ret)
	}

	fn sw_bp_len() -> usize {
		arch::bp_code().len()
	}
	fn _insert_single_sw_bp(
		&mut self,
		tracee: &mut TraceStop,
		bp: SwBp,
	) -> UntrackedResult<()> {
		let code = arch::bp_code();

		tracee.tracee.write_memory(bp.addr as u64, &code)?;
		self.swbps.insert(bp.addr, bp);
		Ok(())
	}

	fn insert_single_sw_bp(
		&mut self,
		cid: usize,
		tid: Tid,
		tracee: &mut TraceStop,
		addr: TargetPtr,
	) -> UntrackedResult<()> {
		let code = arch::bp_code();

		if let Some(bp) = self.swbps.get_mut(&addr) {
			bp.add_client(cid);
		} else {
			log::debug!("writing SWBP {code:?}");
			let oldcode = tracee.tracee.read_memory(addr as u64, code.len())?;
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
	fn _call_func(
		&mut self,
		mut tracee: Tracee,
		addr: TargetPtr,
		args: &[TargetPtr],
		maxattempts: usize,
	) -> UntrackedResult<(TargetPtr, Tracee)> {
		if let Some(pc) = self.tramps.get(&TrampType::Call) {
			log::info!("calling with tramp at {pc:x}");
			let oregs = tracee.registers()?;
			let mut regs = as_our_regs(oregs.clone());
			regs.set_pc(*pc + 4);
			for (i, arg) in args.iter().enumerate() {
				log::debug!("arg[{i}]: = {arg:x}");
				regs.set_arg_systemv(i, *arg);
			}
			regs.set_call_func(addr);
			log::debug!("regs {regs:?}");
			tracee.set_registers(regs.into())?;
			log::debug!("running until call to {addr:x} is over");
			let (mut tracee, err) = self.run_until(tracee, Self::cb_stop_is_trap)?;
			if let Some(error) = err {
				log::error!("got error when executing call, target may be in an unstable state, err: {error:?}");
				let tid = tracee.pid.as_raw() as Tid;
				let tracee = TraceStop::new(tracee)?;
				self.tracee.insert(tid, tracee);
				Err(error)
			} else {
				let regs = as_our_regs(tracee.registers()?);
				let ret = regs.ret_systemv();
				tracee.set_registers(oregs)?;
				Ok((ret, tracee))
			}
		} else if maxattempts > 0 {
			let tracee = self.init_tramps(tracee)?;
			self._call_func(tracee, addr, args, maxattempts - 1)
		} else {
			log::error!("unable to call function, returning error");
			Ok((TargetPtr::MAX, tracee))
		}
	}
	pub fn call_func(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		args: &[TargetPtr],
	) -> UntrackedResult<TargetPtr> {
		if let Some(tracee) = self.tracee.remove(&tid) {
			let (ret, tracee) = self._call_func(tracee.tracee, addr, args, 1)?;
			let pid: i32 = tracee.pid.into();
			let tid = pid as Tid;
			let tracee = TraceStop::new(tracee)?;
			self.tracee.insert(tid, tracee);
			Ok(ret)
		} else {
			Err(Error::TidNotFound { tid })
		}
	}
	pub fn scratch_write_bytes(&mut self, tid: Tid, bytes: Vec<u8>) -> UntrackedResult<TargetPtr> {
		let prot = Perms::new().read().write();
		if let Some(alloc) = self.scratch.get_mut(&prot) {
			let memory = alloc.alloc(bytes.len())?;
			self.write_memory(tid, memory, &bytes)?;
			Ok(memory)
		} else {
			let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
			let size = page_sz * 4;
			let addr = self.exec_sys_anon_mmap(tid, size as usize, prot.clone())?;
			let loc = Location::new(addr, addr + size as TargetPtr);
			let alloc = AllocedMemory::new(loc);
			self.scratch.insert(prot, alloc);
			self.scratch_write_bytes(tid, bytes)
		}
	}
	pub fn scratch_write_c_str(&mut self, tid: Tid, str: String) -> UntrackedResult<TargetPtr> {
		let mut bytes = str.as_bytes().to_vec();
		bytes.push(0x00);
		self.scratch_write_bytes(tid, bytes)
	}
	pub fn scratch_free_addr(&mut self, _tid: Tid, addr: TargetPtr) -> UntrackedResult<()> {
		let prot = Perms::new().read().write();
		if let Some(alloc) = self.scratch.get_mut(&prot) {
			alloc.free(addr)?;
			Ok(())
		} else {
			log::error!("unable to find scratch addr {addr:x}");
			Err(Error::NotFound)
		}
	}
	pub fn exec_sys_getpid(&mut self, tid: Tid) -> UntrackedResult<libc::pid_t> {
		let r = self.exec_syscall(tid, libc::SYS_getpid as TargetPtr, &[])?;
		Ok(r as libc::pid_t)
	}
	#[cfg(not(target_arch = "arm"))]
	pub fn exec_sys_anon_mmap(
		&mut self,
		tid: Tid,
		size: usize,
		prot: Perms,
	) -> UntrackedResult<TargetPtr> {
		let sysno = libc::SYS_mmap as TargetPtr;
		let args = MmapBuild::sane_anonymous(size, prot);
		let r = self.exec_syscall(tid, sysno, &args)?;

		if r as *const libc::c_void != libc::MAP_FAILED {
			Ok(r)
		} else {
			Err(Error::Unknown.into())
		}
	}
	#[cfg(target_arch = "arm")]
	pub fn exec_sys_anon_mmap(
		&mut self,
		tid: Tid,
		size: usize,
		prot: Perms,
	) -> UntrackedResult<TargetPtr> {
		Err(Error::msg("mmap not implemented yet on the target architecture"))
	}
	
	fn __exec_syscall(
		&mut self,
		mut tracee: Tracee,
		tramp: TargetPtr,
		sysno: TargetPtr,
		args: &[TargetPtr],
		_maxattempts: usize,
	) -> UntrackedResult<(TargetPtr, Tracee)> {
		let oregs = tracee.registers()?;
		let mut regs = as_our_regs(oregs.clone());
		regs.set_pc(tramp);
		prep_syscall(&mut regs, sysno, args)?;
		tracee.set_registers(regs.into())?;
		let (mut tracee, err) = self.run_until(tracee, Self::cb_stop_is_trap)?;
		if let Some(error) = err {
			let tid = tracee.pid.as_raw() as Tid;
			let tracee = TraceStop::new(tracee)?;
			self.tracee.insert(tid, tracee);
			Err(error.into())
		} else {
			let regs = as_our_regs(tracee.registers()?);
			let ret = regs.ret_syscall();
			tracee.set_registers(oregs)?;
			Ok((ret, tracee))
		}
	}
	fn _exec_syscall(
		&mut self,
		tracee: Tracee,
		sysno: TargetPtr,
		args: &[TargetPtr],
		maxattempts: usize,
	) -> UntrackedResult<(TargetPtr, Tracee)> {
		if let Some(pc) = self.tramps.get(&TrampType::Syscall) {
			self.__exec_syscall(tracee, *pc, sysno, args, maxattempts)
		} else if maxattempts > 0 {
			let tracee = self.init_tramps(tracee)?;
			self._exec_syscall(tracee, sysno, args, maxattempts)
		} else {
			log::error!("unable to call function, returning error");
			Ok((TargetPtr::MAX, tracee))
		}
	}

	pub fn exec_syscall(
		&mut self,
		tid: Tid,
		sysno: TargetPtr,
		args: &[TargetPtr],
	) -> UntrackedResult<TargetPtr> {
		log::debug!("syscall {tid} {sysno} {args:?}");
		if let Some(tracee) = self.tracee.remove(&tid) {
			let (ret, tracee) = self._exec_syscall(tracee.tracee, sysno, args, 1)?;
			let pid: i32 = tracee.pid.into();
			let tid = pid as Tid;
			let tracee = TraceStop::new(tracee)?;
			self.tracee.insert(tid, tracee);
			Ok(ret)
		} else {
			Err(Error::TidNotFound { tid })
		}
	}
	fn remove_swbp(&self, tracee: &mut Tracee, bp: &SwBp) -> UntrackedResult<()> {
		tracee.write_memory(bp.addr as u64, &bp.oldcode)?;
		Ok(())
	}
	fn run_until(
		&mut self,
		tracee: Tracee,
		dostop: fn(&pete::Stop) -> bool,
	) -> Result<(Tracee, Option<crate::Error>)> {
		self.tracer.restart(tracee, Restart::Continue)?;
		while let Some(tracee) = self.tracer.wait()? {
			let regs = tracee.registers()?;
			log::trace!("got stop {:?} {:?}", tracee.pid, tracee.stop);
			// log::trace!("regs {regs:?}");
			if dostop(&tracee.stop) {
				return Ok((tracee, None));
			} else {
				match &tracee.stop {
					pete::Stop::SignalDelivery { signal } => {
						if *signal as i32 == Signal::SIGSEGV as i32 {
							let err = Error::msg("received SIGSEGV");
							return Ok((tracee, Some(err)));
						}
					}
					_ => log::warn!("unexpected stop, trying to continue {:?}", tracee.stop),
				}
			}
			self.tracer.restart(tracee, Restart::Continue)?;
		}
		todo!();
	}
	fn cb_stop_is_trap(stop: &pete::Stop) -> bool {
		#[allow(clippy::match_like_matches_macro)]
		match stop {
			pete::Stop::SignalDelivery {
				signal: pete::Signal::SIGTRAP,
			} => true,
			_ => false,
		}
	}
	fn find_executable_space(&self) -> UntrackedResult<TargetPtr> {
		let r = self
			.proc
			.proc
			.maps()?
			.into_iter()
			.find(|m| m.perms.contains(MMPermissions::EXECUTE))
			.map(|m| m.address.0)
			.ok_or(crate::Error::Unknown)?;
		Ok(r.try_into()?)
	}

	
	#[cfg(target_arch = "arm")]
	fn init_tramps(&mut self, _tracee: Tracee) -> Result<Tracee> {
		Err(Error::msg("init_tramps not supported on target architecture"))
	}

	#[cfg(not(target_arch = "arm"))]
	// Initialize some executable memory where we can place our trampolines
	fn init_tramps(&mut self, mut tracee: Tracee) -> Result<Tracee> {
		log::info!("initializing tramps");
		// First step is to find some executable space we can write to and write
		// our syscall tramp to that region
		let exespace = self.find_executable_space()?;
		let mut code = Vec::new();
		syscall_shellcode(&mut code);
		let len = code.len();
		let orig = tracee.read_memory(exespace as u64, len)?;
		tracee.write_memory(exespace as u64, &code)?;
		log::debug!("wrote executable memory");

		// Get the registers, both so we can modify them to run our syscall
		// trampoline and so that we can restore this when everything is done
		// for.
		let oregs = tracee.registers()?;

		// Get registers we can modify and prepare mmap() syscall
		let mut svc_regs = as_our_regs(oregs.clone());

		let psize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as TargetPtr;
		svc_regs.set_pc(exespace + 4);
		let mmap_args = vec![
			0,     // addr
			psize, // len
			(libc::PROT_READ | libc::PROT_WRITE) as TargetPtr,
			(libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as TargetPtr,
			TargetPtr::MAX, // fd
			0,        // offset
		];
		prep_syscall(&mut svc_regs, libc::SYS_mmap as TargetPtr, &mmap_args)?;

		tracee.set_registers(svc_regs.into())?;

		// Run until we hit our trap at the end of the trampoline code
		log::debug!("running to complete mmap");
		let (mut tracee, err) = self.run_until(tracee, Self::cb_stop_is_trap)?;
		if let Some(error) = err {
			log::error!("unable to run until trap {error:?}");
			return Ok(tracee);
		}

		// Get registers again so that we can verify return code and check what
		// the address we actually mmapp'ed
		let nregs = tracee.registers()?;
		let mut svc_regs = as_our_regs(nregs);
		let addr = svc_regs.ret_syscall();
		let _ntracee = if addr as *const libc::c_void != libc::MAP_FAILED {
			log::debug!("mmapped {addr:x}");

			// Store the mmapped-region so that we can free it when we detach
			let mmapped = (addr, psize as usize);
			self.mmapped.push(mmapped);

			// Prepare all our tramps and store the individual location of them
			let syscalltramp = addr;
			let mut inscode = Vec::new();
			syscall_shellcode(&mut inscode);
			let calltramp = addr + inscode.len() as TargetPtr;
			call_shellcode(&mut inscode);

			// Write the tramps to memory
			log::debug!("writing real tramps to {addr:x} | {inscode:?}");
			tracee.write_memory(addr as u64, &inscode)?;

			// The code is now written, no we need to make the memory executable
			// This is done in two steps, because some systems may complain
			// about writable and executable memory regions.
			svc_regs.set_pc(exespace + 4);
			let mprotect_args = vec![addr, psize, (libc::PROT_READ | libc::PROT_EXEC) as TargetPtr];
			prep_syscall(
				&mut svc_regs,
				libc::SYS_mprotect as TargetPtr,
				&mprotect_args,
			)?;
			tracee.set_registers(svc_regs.into())?;
			log::debug!("running until mprotect is done");
			let (tracee, err) = self.run_until(tracee, Self::cb_stop_is_trap)?;
			if let Some(error) = err {
				log::error!("unable to run until trap {error:?}");
				tracee
			} else {
				// Get registers and check return val again
				let nregs = tracee.registers()?;
				let svc_regs = as_our_regs(nregs);
				let ret = svc_regs.ret_syscall();
				if ret == 0 {
					log::debug!("mprotect succeeded");
					// Everything succeeded and we can insert our tramps
					self.tramps.insert(TrampType::Syscall, syscalltramp);
					self.tramps.insert(TrampType::Call, calltramp);
					tracee
				} else {
					log::error!("mprotect returned {ret:x}");
					tracee
				}
			}
		} else {
			log::error!("mmap returned MAP_FAILED");
			tracee
		};

		// Regardless of whether we succeed or not, we should write back
		// original code and set the registers back to original.
		log::info!("init_tramps over, restoring state");
		tracee.write_memory(exespace as u64, &orig)?;
		tracee.set_registers(oregs)?;
		Ok(tracee)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use serial_test::serial;
use ::test::Bencher;
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
	fn bench_trace_baseline(b: &mut Bencher) {
		b.iter(|| {
			assert!(std::process::Command::new("true")
				.stdout(std::process::Stdio::piped())
				.spawn()
				.unwrap()
				.wait()
				.is_ok())
		});
	}

	#[bench]
	fn bench_trace_inner(b: &mut Bencher) {
		b.iter(|| {
			trace1();
		});
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

	#[test]
	fn trace2() {
		let (mut tracer, tid) = spawn().unwrap();

		// Single step for a while
		let mut lastpc = 0;
		for _i in 0..10 {
			tracer.cont(tid, Cont::Step).unwrap();
			let stop = tracer.wait().unwrap();

			assert!(matches!(stop.stop, Stop::Step { pc: _ }));
			assert!(stop.pc != lastpc);
			lastpc = stop.pc;
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
						matches!(stop.stop, Stop::SyscallEnter) || matches!(stop.stop, Stop::SyscallExit)
					);
					let w = format!("{stop}");
					log::trace!("STOP: {w}");
				},
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

		let mods = tracer.get_modules().unwrap();
		log::trace!("mods {mods:?}");
		let mods: Vec<_> = mods.iter().filter(|x| x.name_is(&searchbin)).collect();
		log::trace!("mods {mods:?}");
		assert!(mods.len() == 1);
		let main = mods[0];

		let elf = crate::exe::elf::Elf::new(PathBuf::from(searchbin))
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

	#[test]
	fn trace5() {
		let (mut tracer, tid) = spawn().unwrap();

		// Check a simple syscall
		let pid = tracer
			.exec_syscall(tid, libc::SYS_getpid as TargetPtr, &[])
			.unwrap();
		assert_eq!(pid, tid as TargetPtr);

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
		assert!(r.is_err());
		assert!(tracer.detach(t).is_err());
		assert!(tracer.get_libc_regs(t).is_err());

		assert!(tracer.insert_single_bp(0, t, 42).is_err());
		assert!(tracer.remove_bp(t, 42).is_err());
		assert!(tracer.write_memory(t, 42, &[]).is_err());
		assert!(tracer.read_memory(t, 42, 42).is_err());
		assert!(tracer.read_c_string(t, 42).is_err());
		assert!(tracer.call_func(t, 42, &[]).is_err());

		tracer.detach(tid).unwrap();
	}

	fn setup_in_mem(p: &str) -> Result<(Tracer, Tid)> {
		let mut file = OpenOptions::new().read(true).open(p)?;
		let mut data = Vec::new();
		file.read_to_end(&mut data)?;
		let (mut tracer, tid) = Tracer::spawn_in_mem(p, data)?;
		let stop = tracer.wait().unwrap();
		log::debug!("stop {stop:?}");
		Ok((tracer, tid))
	}

	#[serial]
	#[test]
	fn trace_in_mem0() {
		let (mut tracer, tid) = setup_in_mem("/usr/bin/true").unwrap();
		tracer.detach(tid).unwrap();
	}

	#[serial]
	#[test]
	fn trace_in_mem1() {
		let (mut tracer, tid) = setup_in_mem("/usr/bin/true").unwrap();

		loop {
			tracer.cont(tid, Cont::Syscall).unwrap();
			let stop = tracer.wait();
			match stop {
				Ok(stop) => {
					assert!(
						matches!(stop.stop, Stop::SyscallEnter) || matches!(stop.stop, Stop::SyscallExit)
					);
					let w = format!("{stop}");
					log::trace!("STOP: {w}");
				},
				Err(err) => {
					assert!(matches!(err, Error::TargetStopped));
					break;
				}
			}
		}
	}
}
