use std::io::{BufReader, BufWriter};
use std::thread::JoinHandle;
use std::{collections::HashMap, path::PathBuf};

use crate::api::messages::{ElfSymbol, Stop, Stopped, SymbolType};
use crate::api::CallFrame;
use crate::arch::{ReadRegisters, RegsAbiAccess, SystemV, WriteRegisters};
use crate::exe::elf::Elf;
#[cfg(feature = "plugins")]
use crate::plugin::{plugins::*, Plugin};

#[cfg(feature = "plugins")]
use crate::utils::{LoadDependency, LoadedPlugin};

#[cfg(feature = "syscalls")]
use crate::syscalls::SyscallItem;

#[cfg(feature = "plugins")]
use crate::api::messages::EventInner;

use crate::utils::ModuleSymbols;
use crate::{
	api::{messages::Event, Client, ClientCmd, Command, Response},
	ctrl::ReqNewClient,
	utils::process::{MemoryMap, Process, Tid},
	Error, Result, TargetPtr,
};

pub type SignalCb<T, Err> = fn(&mut Secondary<T, Err>, nix::sys::signal::Signal);
#[cfg(feature = "syscalls")]
pub type SyscallCb<T, Err> = fn(&mut Secondary<T, Err>, SyscallItem) -> Result<()>;

pub type BreakpointCb<T, Err> = fn(&mut Secondary<T, Err>, Tid, TargetPtr) -> Result<bool>;
pub type HookEntryCb<T, Err> = fn(&mut Secondary<T, Err>, &CallFrame) -> Result<(bool, Option<TargetPtr>)>;
pub type HookExitCb<T, Err> = fn(&mut Secondary<T, Err>, &CallFrame) -> Result<Option<TargetPtr>>;

pub type EventCb<T, Err> = fn(&mut Secondary<T, Err>, Event) -> Result<()>;
pub type StoppedCb<T, Err> = fn(&mut Secondary<T, Err>, Stopped) -> Result<()>;
pub type RawSyscallCb<T, Err> = fn(&mut Secondary<T, Err>, Tid, bool) -> Result<()>;
pub type StepCb<T, Err> =
	fn(&mut Secondary<T, Err>, Tid, TargetPtr) -> std::result::Result<(), Err>;

/// Each connected client will get access  to this context object.
///
/// This object will always belong to a [super::Main] and will never be created
/// on its own.
pub struct Secondary<T, Err>
where
	Err: Into<crate::Error>,
{
	/// Can be used to query information from OS about the process.
	pub proc: Process,
	client: Client<Command, Response>,

	#[cfg(feature = "plugins")]
	pub(crate) plugins: HashMap<Plugin, crate::utils::LoadedPlugin>,

	pub(crate) data: T,

	signalcbs: HashMap<i32, SignalCb<T, Err>>,
	#[cfg(feature = "syscalls")]
	syscallcb: Option<SyscallCb<T, Err>>,
	eventcb: Option<EventCb<T, Err>>,
	stepcb: Option<StepCb<T, Err>>,
	bpcbs: HashMap<TargetPtr, BreakpointCb<T, Err>>,

	callframes: HashMap<(Tid, TargetPtr), CallFrame>,

	funcentrycbs: HashMap<TargetPtr, (HookEntryCb<T, Err>, HookExitCb<T, Err>)>,

	#[cfg(feature = "syscalls")]
	syscallcbs: HashMap<TargetPtr, SyscallCb<T, Err>>,

	stoppedcb: Option<StoppedCb<T, Err>>,

	raw_syscall_cb: Option<RawSyscallCb<T, Err>>,

	resolved: HashMap<PathBuf, ModuleSymbols>,
	pub(crate) req: Option<ReqNewClient>,

	cc: Box<dyn RegsAbiAccess + Send + 'static>,
}
impl<T, Err> Secondary<T, Err>
where
	Err: Into<crate::Error>,
{
	pub(crate) fn new(
		mut client: Client<Command, Response>,
		data: T,
		req: Option<ReqNewClient>,
	) -> Result<Self> {
		let signalcbs = HashMap::new();
		let bpcbs = HashMap::new();
		let pid = client.get_pid()?;
		let proc = Process::from_pid(pid as u32)?;
		let resolved = HashMap::new();
		let funcentrycbs = HashMap::new();
		let callframes = HashMap::new();
		let cc = Box::new(SystemV::default());
		let r = Self {
			data,
			client,
			eventcb: None,
			signalcbs,
			funcentrycbs,
			callframes,
			#[cfg(feature = "syscalls")]
			syscallcb: None,
			proc,
			bpcbs,
			#[cfg(feature = "syscalls")]
			syscallcbs: HashMap::new(),
			#[cfg(feature = "plugins")]
			plugins: HashMap::new(),
			req,
			resolved,
			stoppedcb: None,
			raw_syscall_cb: None,
			stepcb: None,
			cc
		};
		Ok(r)
	}

	fn empty_hook_func_entry(&mut self, frame: &CallFrame) -> Result<(bool, Option<TargetPtr>)> {
		log::debug!("called empty hook function entry {frame:?}");
		Ok((true, None))
	}
	fn empty_hook_func_exit(&mut self, frame: &CallFrame) -> Result<Option<TargetPtr>> {
		log::debug!("called empty hook function entry {frame:?}");
		Ok(None)
	}
	/// Get a reference to [Client]
	pub fn client(&self) -> &Client<Command, Response> {
		&self.client
	}

	/// Get a mutable reference to [Client]
	pub fn client_mut(&mut self) -> &mut Client<Command, Response> {
		&mut self.client
	}

	/// Get a reference to stored data
	pub fn data(&self) -> &T {
		&self.data
	}

	/// Override with a custom implementation of the ABI
	pub fn set_cc(&mut self, cc: Box<dyn RegsAbiAccess + Send + 'static>) {
		self.cc = cc;
	}

	/// Get a mutable reference to stored data
	pub fn data_mut(&mut self) -> &mut T {
		&mut self.data
	}
	pub(crate) fn new_second(client: Client<Command, Response>, data: T) -> Result<Self> {
		Self::new(client, data, None)
	}
	pub(crate) fn new_remote_plugin(data: T) -> Result<Self> {
		let stdin = std::io::stdin();
		let stdin = BufReader::new(stdin);
		let stdout = std::io::stdout();
		let stdout = BufWriter::new(stdout);
		let client = Client::new_remote(0, stdin, stdout);
		let ctx = Secondary::new_second(client, data)?;
		Ok(ctx)
	}
	pub(crate) fn new_master(
		client: Client<Command, Response>,
		data: T,
		req: ReqNewClient,
	) -> Result<Self> {
		Self::new(client, data, Some(req))
	}
	fn all_symbols_mod(&self, module: &MemoryMap) -> Result<Vec<ElfSymbol>> {
		let p = module
			.path()
			.ok_or(Error::msg("unable to find path in module"))?;
		let elf = Elf::new(p)?;
		let r = elf.all_symbols();
		Ok(r)
	}
	fn store_symbols(&mut self, path: PathBuf, base: TargetPtr, symbols: Vec<ElfSymbol>) {
		let mods = ModuleSymbols::new(path.clone(), base, symbols);
		self.resolved.insert(path, mods);
	}

	/// Get a [MemoryMap] which exactly matches the name in `pbuf`
	pub fn get_module(&mut self, pbuf: &PathBuf) -> Result<MemoryMap> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		let mods = self.proc.proc_modules()?;
		let mut mods: Vec<_> = mods.iter().filter(|x| x.file_name_matches(&pbuf)).collect();
		if mods.len() == 1 {
			Ok(mods.remove(0).clone())
		} else {
			Err(Error::msg(format!(
				"found incorrect modules matching {pbuf:?}"
			)))
		}
	}
	fn symbols_init(&mut self, pbuf: &PathBuf) -> Result<()> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		if self.resolved.get(&pbuf).is_some() {
			log::info!("already gathered symbols for '{pbuf:?}'");
			Ok(())
		} else {
			log::info!("symbols for {pbuf:?} not retrieved, gathering");
			let mods = self.proc.proc_modules()?;
			let mut mods: Vec<_> = mods.iter().filter(|x| x.file_name_matches(&pbuf)).collect();
			if mods.len() == 1 {
				let m = mods.remove(0);
				let mods = self.all_symbols_mod(m)?;
				self.store_symbols(pbuf.clone(), m.loc.addr(), mods);
				Ok(())
			} else {
				let msg = format!("found no modules matching {pbuf:?}");
				Err(Error::msg(msg))
			}
		}
	}

	/// Try and locate the symbol `name` in any of the loaded executables.
	///
	/// This function will not search in the order they are retrieved, which
	/// should not be considered deterministic. If a symbol is defined multiple
	/// times, there is no guarantee on which is returned.
	pub fn lookup_symbol(&mut self, name: &str) -> Result<Option<ElfSymbol>> {
		let paths = self
			.proc
			.proc_modules()?
			.iter()
			.map(|x| x.path())
			.filter(|x| x.is_some())
			.map(|x| x.expect("impossible").clone())
			.collect::<Vec<PathBuf>>();

		for path in paths.iter() {
			if let Ok(Some(n)) = self.resolve_symbol(path, name) {
				return Ok(Some(n));
			}
		}
		Ok(None)
	}
	fn resolve_pathbuf(&self, path: &PathBuf) -> Result<&ModuleSymbols> {
		self.resolved
			.get(path)
			.ok_or(Error::msg(format!("found no modules matching '{path:?}'")))
	}

	/// Resolve a given symbol `name` in a given module with path `pbuf`
	pub fn resolve_symbol(&mut self, pbuf: &PathBuf, name: &str) -> Result<Option<ElfSymbol>> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		log::info!("resolving  in {pbuf:?}");
		self.symbols_init(&pbuf)?;
		let res = self.resolve_pathbuf(&pbuf)?;
		log::info!("already gathered symbols for '{pbuf:?}'");
		let sym = res.resolve(name).cloned();
		Ok(sym)
	}

	/// Enumerate all symbols of the given type. See [SymbolType] for more
	/// details on type of symbols.
	pub fn symbols_of_type(
		&mut self,
		pbuf: &PathBuf,
		symtype: SymbolType,
	) -> Result<Vec<ElfSymbol>> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		self.symbols_init(&pbuf)?;
		let res = self.resolve_pathbuf(&pbuf)?;
		let r: Vec<_> = res
			.symbols
			.values()
			.filter(|x| x.stype == symtype)
			.cloned()
			.collect();
		Ok(r)
	}
	pub fn symbols_functions(&mut self, pbuf: &PathBuf) -> Result<Vec<ElfSymbol>> {
		self.symbols_of_type(pbuf, SymbolType::Func)
	}
	fn start_plugin<X: Send + 'static>(
		mut plugin: Secondary<X, crate::Error>,
	) -> Result<JoinHandle<Result<()>>> {
		let handle = std::thread::spawn(move || -> Result<()> {
			log::info!("Creating plugin and entering loop");
			plugin.loop_until_exit()?;
			Ok(())
		});
		Ok(handle)
	}
	#[cfg(feature = "plugins")]
	fn load_dependencies(&mut self, plugins: &[Plugin], id: usize) -> Result<()> {
		for plugin in plugins.iter() {
			if let Some(pl) = self.plugins.get_mut(plugin) {
				pl.add_dependency(id);
			} else {
				let dep = LoadDependency::Plugins(vec![id]);
				self._new_plugin(plugin, dep)?;
			}
		}
		Ok(())
	}
	fn new_regular(&self) -> Result<Client<Command, Response>> {
		log::debug!("req {:?}", self.req);
		let req = self.req.as_ref().ok_or(Error::msg("req was not set"))?;
		req.new_regular()
	}
	#[cfg(feature = "plugins")]
	fn _new_plugin(&mut self, plugin: &Plugin, dep: LoadDependency) -> Result<()> {
		log::info!("creating plugin for {plugin:?}");
		self.client.prepare_load_client()?;
		if let Some(pl) = self.plugins.get_mut(plugin) {
			pl.update_dependency(&dep);
			Err(Error::msg(format!(
				"tried to double-register plugin {plugin:?}"
			)))
		} else {
			let client = self.new_regular()?;
			let nid = client.id();
			log::info!("Created new client");
			let h = match plugin {
				#[cfg(feature = "syscalls")]
				Plugin::DlopenDetect => {
					self.load_dependencies(DlopenDetect::dependecies(), nid)?;
					let dl = DlopenDetect::init(client)?;
					Self::start_plugin(dl)?
				}
				#[cfg(feature = "syscalls")]
				Plugin::Files => {
					self.load_dependencies(Files::dependecies(), nid)?;
					let dl = Files::init(client)?;
					Self::start_plugin(dl)?
				}
				#[cfg(feature = "syscalls")]
				Plugin::Mmap => {
					self.load_dependencies(Mmap::dependecies(), nid)?;
					let dl = Mmap::init(client)?;
					Self::start_plugin(dl)?
				}
				#[cfg(feature = "syscalls")]
				Plugin::Prctl => {
					self.load_dependencies(Prctl::dependecies(), nid)?;
					let dl = Prctl::init(client)?;
					Self::start_plugin(dl)?
				}
				_ => todo!(),
			};
			let event = EventInner::PluginLoad {
				ptype: plugin.clone(),
				id: nid,
			};
			let event = Event::new(event);
			self.client.send_event(event)?;
			let ins = LoadedPlugin::new(nid, dep, h);
			self.plugins.insert(plugin.clone(), ins);
			Ok(())
		}
	}
	#[cfg(feature = "plugins")]
	pub fn new_plugin(&mut self, plugin: &Plugin, reglisten: bool) -> Result<()> {
		self._new_plugin(plugin, LoadDependency::Manual)?;
		if reglisten {
			log::error!("reqlisten = true is not yet supported");
		}
		assert!(!reglisten);
		// if reglisten {
		// 	match plugin {
		// 		Plugin::DlopenDetect => self.client.register_event(RegEvent::Dlopen)?,
		// 		Plugin::Files => self.client.register_event(RegEvent::Files)?,
		// 	}
		// }
		Ok(())
	}

	/// Remove a plugin with the identifier in `plugin`
	#[cfg(feature = "plugins")]
	pub fn remove_plugin(&mut self, plugin: &Plugin) -> Result<()> {
		log::info!("removing {plugin:?}");
		if let Some(cid) = self.plugins.remove(plugin) {
			self.client.remove_client(cid.id)?;
			self.notify_id_removed(cid.id)?;
		} else {
			log::warn!("tried to remove plugin which hasn't been loaded");
		}
		Ok(())
	}
	#[cfg(feature = "plugins")]
	fn notify_id_removed(&mut self, id: usize) -> Result<()> {
		log::info!("removing all plugins which only was needed by {id}");
		let mut rem = Vec::new();
		for (p, plugin) in self.plugins.iter_mut() {
			if plugin.id_removed(id) {
				rem.push(p.clone());
			}
		}
		for p in rem.into_iter() {
			self.remove_plugin(&p)?;
		}
		Ok(())
	}

	/// Send in an arbitrary [Command] and have it handled at the appropriate
	/// level.
	///
	/// This function is mostly useful when we have a client in a different
	/// process/thread/machine from this context object. Data must then be
	/// serialized somehow and the [Command] object is used for this.
	pub fn handle_cmd(&mut self, cmd: Command) -> Result<Response> {
		match cmd {
			Command::Client { tid, cmd } => self.handle_client_cmd(tid, cmd),
			_ => self.client.write_read(cmd),
		}
	}

	/// Should only be used when the client is fully remote and cannot call the
	/// functions directly
	fn handle_client_cmd(&mut self, _tid: Tid, cmd: ClientCmd) -> Result<Response> {
		let ret = match cmd {
			ClientCmd::ResolveEntry => {
				let ins = self.resolve_entry();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::StoppedTids => {
				let ins = self.get_stopped_tids();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::FirstStoppedTid => {
				let ins = self.get_first_stopped();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::GetModule { path } => {
				let ins = self.get_module(&path);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::ResolveSymbol { path, symbol } => {
				let ins = self.resolve_symbol(&path, &symbol);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::SymbolsOfType { path, symtype } => {
				let ins = self.symbols_of_type(&path, symtype);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
		};
		Ok(ret)
	}

	/// Get all [Tid]s which have stopped
	pub fn get_stopped_tids(&mut self) -> Result<Vec<Tid>> {
		let r: Vec<Tid> = self
			.client
			.get_threads_status()?
			.into_iter()
			.filter(|x| x.status.is_stopped())
			.map(|x| x.id)
			.collect();
		Ok(r)
	}

	/// Get a single [Tid] which has stopped.
	///
	/// This is useful in the beginning as some commands need to operate on a
	/// specific [Tid].
	pub fn get_first_stopped(&mut self) -> Result<Tid> {
		let a = self.get_stopped_tids()?;
		let n = a.first().ok_or(Error::msg("No stopped thread"))?;
		Ok(*n)
	}

	/// Get entry point of program
	pub fn resolve_entry(&self) -> Result<TargetPtr> {
		let exe = self.proc.exe_path()?;
		let elf = Elf::new(exe)?.parse()?;
		let entry = elf.entry();
		let mainmod = self.proc.exe_module()?;

		Ok(entry + mainmod.loc.addr())
	}
	pub fn call_func(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		args: &[TargetPtr],
	) -> Result<TargetPtr> {
		let mut regs = self.client.get_libc_regs(tid)?;
		for (i, arg) in args.iter().enumerate() {
			log::debug!("arg[{i}]: = {arg:x}");
			self.cc.set_arg(&mut regs, i, *arg)?;
			// regs.set_arg_systemv(i, *arg);
		}
		self.cc.set_reg_call_tramp(&mut regs, addr);
		self.client.set_libc_regs(tid, regs)?;
		
		todo!();
	}

	pub fn set_step_handler(&mut self, cb: StepCb<T, Err>) {
		self.stepcb = Some(cb);
	}
	#[cfg(feature = "syscalls")]
	pub fn set_specific_syscall_handler(&mut self, sysno: TargetPtr, cb: SyscallCb<T, Err>) {
		self.syscallcbs.insert(sysno, cb);
	}
	pub fn set_raw_syscall_handler(&mut self, cb: RawSyscallCb<T, Err>) {
		self.raw_syscall_cb = Some(cb);
	}
	pub fn set_stop_handler(&mut self, cb: StoppedCb<T, Err>) {
		self.stoppedcb = Some(cb);
	}
	#[cfg(feature = "syscalls")]
	pub fn set_generic_syscall_handler(&mut self, cb: SyscallCb<T, Err>) {
		self.syscallcb = Some(cb);
	}
	pub fn register_function_hook(&mut self, tid: Tid, addr: TargetPtr, cbentry: HookEntryCb<T, Err>, cbexit: HookExitCb<T, Err>) -> Result<()> {
		self.client.insert_bp(tid, addr)?;
		self.funcentrycbs.insert(addr, (cbentry, cbexit));
		Ok(())
	}
	pub fn register_function_hook_entry(&mut self, tid: Tid, addr: TargetPtr, cbentry: HookEntryCb<T, Err>) -> Result<()> {
		self.client.insert_bp(tid, addr)?;
		self.funcentrycbs.insert(addr, (cbentry, Self::empty_hook_func_exit));
		Ok(())
	}
	pub fn register_function_hook_exit(&mut self, tid: Tid, addr: TargetPtr, cbexit: HookExitCb<T, Err>) -> Result<()> {
		self.client.insert_bp(tid, addr)?;
		self.funcentrycbs.insert(addr, (Self::empty_hook_func_entry, cbexit));
		Ok(())
	}
	pub fn register_breakpoint_handler(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		cb: BreakpointCb<T, Err>,
	) -> Result<()> {
		self.client.insert_bp(tid, addr)?;
		self.bpcbs.insert(addr, cb);
		Ok(())
	}
	pub fn set_event_handler(&mut self, cb: EventCb<T, Err>) {
		self.eventcb = Some(cb);
	}
	fn event_signal(&mut self, signal: i32) -> Result<()> {
		let sig = nix::sys::signal::Signal::try_from(signal)?;
		let mut r = self.signalcbs.remove(&signal);
		if let Some(cb) = std::mem::take(&mut r) {
			cb(self, sig);
			self.signalcbs.insert(signal, cb);
		}
		Ok(())
	}
	#[cfg(feature = "syscalls")]
	fn handle_syscall(&mut self, syscall: SyscallItem) -> Result<()> {
		let sysno = syscall.sysno;
		log::debug!("event syscall {sysno} {}", syscall.tid);
		let mut r = self.syscallcbs.remove(&sysno);
		if let Some(cb) = std::mem::take(&mut r) {
			match cb(self, syscall) {
				Ok(_) => {}
				Err(e) => log::warn!("syscall cb resulted in error: '{e:?}'"),
			}
			self.syscallcbs.insert(sysno, cb);
		} else if let Some(cb) = &self.syscallcb {
			match cb(self, syscall) {
				Ok(_) => {}
				Err(e) => log::warn!("syscall cb resulted in error: '{e:?}'"),
			}
		}
		Ok(())
	}
	fn event_breakpoint(&mut self, tid: Tid, addr: TargetPtr) -> Result<()> {
		let mut r = self.bpcbs.remove(&addr);
		if let Some(cb) = std::mem::take(&mut r) {
			log::debug!("found regular BP at {addr:x}");
			let r = cb(self, tid, addr);
			match r {
				Ok(true) => {
					// We need to do a single step and insert breakpoint after
					// that. These steps will not actually happen the way it
					// looks here. The tracer will detect that we're trying to
					// insert a BP at the current location we've hit. It will
					// then set it as a pending breakpoint to be inserted at the
					// next stop. When we set a step here, we don't actually do
					// a step, we just mark that a step should be done next.
					self.client.step_ins(tid, 1)?;
					self.client.insert_bp(tid, addr)?;
					self.bpcbs.insert(addr, cb);
				}
				Ok(false) => {
					log::debug!("bp has already been removed");
				}
				Err(e) => {
					log::error!("bp callback triggered error: '{e:?}' | bp will be removed");
				}
			}
		} else if let Some(mut frame) = std::mem::take( &mut self.callframes.remove(&(tid, addr))) {
			log::debug!("found function exit BP at {addr:x}");
			if let Some((entry, exit)) = std::mem::take(&mut self.funcentrycbs.remove(&frame.func)) {
				// if let Some(exit) = std::mem::take(&mut exit) {

				// We maintain the same callframe so that the user can parse
				// arguments as before. But we will in output so that the
				// user can also parse the result.
				//
				// It is the users responsibility to use this properly. If
				// the argument is a pointer and the function modifies the
				// data the pointer points to, it is the users
				// responsibility to understand that they're reading output
				// and not input. This code simply supplies the values as
				// they were when the function call was made.
				let mut regs = self.client.get_libc_regs(tid)?;
				let retval = self.cc.get_retval(&regs);
				// let retval = regs.ret_systemv();
				frame.set_output(retval);
				match exit(self, &frame) {
					Ok(Some(ret)) => {
						self.cc.set_retval(&mut regs, ret);
						// regs.set_ret_systemv(ret);
						self.client.set_libc_regs(tid, regs)?;
					},
					Ok(None) => { },
					Err(e) => {
						log::error!("callback triggered error {e:?}");
					},
				}
				self.funcentrycbs.insert(frame.func, (entry, exit));
			}
		} else if let Some((entry, exit)) = std::mem::take(&mut self.funcentrycbs.remove(&addr)) {
			log::debug!("found function entry BP at {addr:x}");
			let regs = self.client.get_libc_regs(tid)?;
			let mut frame = CallFrame::new(tid, addr, regs);
			let retaddr = frame.return_addr(&mut self.client)?;
			let (skipexit, remove) = match entry(self, &frame) {
				Ok((dorem, retval)) => {
					if let Some(retval) = retval {
						self.cc.set_retval(&mut frame.regs, retval);
						// frame.regs.set_ret_systemv(retval);
						self.client.set_libc_regs(tid, frame.regs.clone())?;
						self.client.exec_ret(tid)?;
						(true, dorem)
					} else {
						(false, dorem)
					}
				},
				Err(e) => {
					log::error!("callback triggered error {e:?}");
					(true, false)
				},
			};
			if !skipexit {
				#[cfg(debug_assertions)]
				let cond = true;
				#[cfg(not(debug_assertions))]
				let cond = exit != Self::empty_hook_func_exit;

				if cond {
					// Store a callframe so that we can detect this callframe later
					self.callframes.insert((tid, retaddr), frame);
					self.client.insert_bp(tid, retaddr)?;
				}
			}
			if !remove {
				self.client.step_ins(tid, 1)?;
				self.client.insert_bp(tid, addr)?;
				self.funcentrycbs.insert(addr, (entry, exit));
			}
		} else {
			log::warn!("no registered BP at {addr:x}");
		}
		Ok(())
	}

	fn handle_step(&mut self, tid: Tid, pc: TargetPtr) -> Result<()> {
		if let Some(cb) = self.stepcb {
			match cb(self, tid, pc) {
				Ok(_) => log::trace!("callback for step succeeeded"),
				Err(e) => {
					let e: Error = e.into();
					log::error!("callback step resulted in error: '{e:?}'")
				}
			}
		}
		Ok(())
	}
	fn handle_event(&mut self, evt: Event) -> Result<()> {
		if let Some(cb) = self.eventcb {
			// To print proper error we must either clone Event or create error
			// str here
			let evtstr = format!("{evt:?}");
			match cb(self, evt) {
				Ok(_) => {}
				Err(e) => log::error!("callback for event '{evtstr}' resulted in error: '{e:?}'"),
			}
		}
		Ok(())
	}
	fn handle_stopped(&mut self, stopped: Stopped) -> Result<()> {
		log::debug!("stop {stopped:?}");
		match stopped.stop {
			Stop::SyscallEnter | Stop::SyscallExit => {
				let entry = matches!(stopped.stop, Stop::SyscallEnter);
				if let Some(cb) = self.raw_syscall_cb {
					cb(self, stopped.tid, entry)?;
				}
			}
			Stop::Signal { signal, group: _ } => self.event_signal(signal)?,
			Stop::Breakpoint { pc, clients: _ } => self.event_breakpoint(stopped.tid, pc)?,
			Stop::Step { pc } => self.handle_step(stopped.tid, pc)?,
			_ => {
				if let Some(cb) = self.stoppedcb {
					cb(self, stopped)?;
				}
			}
		}
		Ok(())
	}

	fn loop_until_empty_cb(_rsp: &Response) -> Result<bool> {
		Ok(false)
	}
	fn loop_until_exit_cb(rsp: &Response) -> Result<bool> {
		let r = matches!(rsp, Response::TargetExit | Response::Removed);
		Ok(r)
	}

	/// Run until, ether `cb` returns `true`, the target exits or we are
	/// detached.
	pub fn loop_until(&mut self, cb: impl Fn(&Response) -> Result<bool>) -> Result<Response> {
		let mut ret = None;
		while ret.is_none() {
			let rsp = self.client.wait()?;
			log::debug!("response {rsp:?}");
			let mut done = match cb(&rsp) {
				Ok(n) => n,
				Err(err) => {
					log::error!("loop_until callback returned error: {err:?}");
					true
				}
			};

			// We always need to check for exit
			if !done {
				done = Self::loop_until_exit_cb(&rsp)?;
			}

			// Still not done, we do all the callback
			if !done {
				match rsp {
					Response::Event(evt) => self.handle_event(evt)?,
					Response::Stopped(stopped) => self.handle_stopped(stopped)?,
					#[cfg(feature = "syscalls")]
					Response::Syscall(syscall) => self.handle_syscall(syscall)?,
					Response::TargetExit => panic!("TargetExit was not handled by callback"),
					Response::Removed => panic!("Removed was not handled by callback"),
					_ => crate::bug!(
						"unexpected response {rsp:?} in loop, client probably forgot to read something"
					),
				}
			} else {
				ret = Some(rsp);
			}
		}
		Ok(ret.expect("impossible"))
	}

	/// Run until a given address has been hit
	pub fn run_until_addr(&mut self, addr: TargetPtr) -> Result<Option<TargetPtr>> {
		let tid = self.get_first_stopped()?;
		self.client.insert_bp(tid, addr)?;
		let ret = self.loop_until(|rsp| {
			let ret = if let Response::Stopped(stopped) = rsp {
				if let Stop::Breakpoint { pc, clients: _ } = &stopped.stop {
					*pc == addr
				} else {
					false
				}
			} else {
				false
			};
			Ok(ret)
		})?;
		let ret = if let Response::Stopped(stopped) = ret {
			if let Stop::Breakpoint { pc, clients: _ } = stopped.stop {
				Some(pc)
			} else {
				None
			}
		} else {
			None
		};
		Ok(ret)
	}

	/// Run until we hit program entry and then return control to caller.
	pub fn run_until_entry(&mut self) -> Result<Option<TargetPtr>> {
		let entry = self.resolve_entry()?;
		self.run_until_addr(entry)
	}

	/// Run until a given syscall number has been hit
	///
	/// **NB!** This assumes that syscall transformation has been configured.
	#[cfg(feature = "syscalls")]
	pub fn run_until_sysno(&mut self, sysno: TargetPtr) -> Result<Response> {
		let ret = self.loop_until(|rsp| {
			let ret = if let Response::Syscall(sys) = rsp {
				sys.sysno == sysno
			} else {
				false
			};
			Ok(ret)
		})?;
		Ok(ret)
	}

	/// Run until program exits or the tracer is detached.
	pub fn loop_until_exit(&mut self) -> Result<Response> {
		log::info!("looping until exit");
		self.loop_until(Self::loop_until_empty_cb)
	}
}
