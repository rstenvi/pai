use std::io::{BufReader, BufWriter};
use std::thread::JoinHandle;
use std::{collections::HashMap, path::PathBuf};

use crate::api::messages::EventInner;
use crate::exe::elf::{Elf, SymbolType};
use crate::plugin::plugins::*;
use crate::trace::Stop;
use crate::utils::{LoadDependency, LoadedPlugin, ModuleSymbols};
use crate::{
	api::{messages::Event, Client, ClientCmd, Command, Response},
	ctrl::ReqNewClient,
	exe::elf::ElfSymbol,
	plugin::Plugin,
	syscalls::SyscallItem,
	trace::Stopped,
	utils::process::{MemoryMap, Process, Tid},
	Error, Result, TargetPtr,
};

pub type SignalCb<T> = fn(&mut Secondary<T>, nix::sys::signal::Signal);
pub type SyscallCb<T> = fn(&mut Secondary<T>, SyscallItem) -> Result<()>;
pub type BreakpointCb<T> = fn(&mut Secondary<T>, Tid, TargetPtr) -> Result<bool>;
pub type EventCb<T> = fn(&mut Secondary<T>, Event) -> Result<()>;
pub type StoppedCb<T> = fn(&mut Secondary<T>, Stopped) -> Result<()>;
pub type RawSyscallCb<T> = fn(&mut Secondary<T>, Tid, bool) -> Result<()>;

pub struct Secondary<T> {
	client: Client<Command, Response>,
	pub proc: Process,
	pub(crate) plugins: HashMap<Plugin, LoadedPlugin>,

	pub data: T,

	signalcbs: HashMap<i32, SignalCb<T>>,
	syscallcb: Option<SyscallCb<T>>,
	eventcb: Option<EventCb<T>>,
	bpcbs: HashMap<TargetPtr, BreakpointCb<T>>,
	syscallcbs: HashMap<TargetPtr, SyscallCb<T>>,

	stoppedcb: Option<StoppedCb<T>>,

	raw_syscall_cb: Option<RawSyscallCb<T>>,

	resolved: HashMap<PathBuf, ModuleSymbols>,
	pub(crate) req: Option<ReqNewClient>,
}
impl<T> Secondary<T> {
	pub(crate) fn new(
		mut client: Client<Command, Response>,
		data: T,
		req: Option<ReqNewClient>,
	) -> Result<Self> {
		let signalcbs = HashMap::new();
		let bpcbs = HashMap::new();
		let syscallcbs = HashMap::new();
		let pid = client.get_pid()?;
		let proc = Process::from_pid(pid as u32)?;
		let plugins = HashMap::new();
		let resolved = HashMap::new();
		let r = Self {
			data,
			client,
			eventcb: None,
			signalcbs,
			syscallcb: None,
			proc,
			bpcbs,
			syscallcbs,
			plugins,
			req,
			resolved,
			stoppedcb: None,
			raw_syscall_cb: None,
		};
		Ok(r)
	}
	pub fn client(&self) -> &Client<Command, Response> {
		&self.client
	}
	pub fn client_mut(&mut self) -> &mut Client<Command, Response> {
		&mut self.client
	}
	pub fn new_second(client: Client<Command, Response>, data: T) -> Result<Self> {
		Self::new(client, data, None)
	}
	pub fn new_remote_plugin(data: T) -> Result<Self> {
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
		if let Some(p) = module.path() {
			let elf = Elf::new(p.clone())?;
			let r = elf.all_symbols();
			Ok(r)
		} else {
			log::warn!("unable to find path in module");
			Err(Error::Unknown.into())
		}
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
			Err(Error::msg(format!("found incorrect modules matching {pbuf:?}")).into())
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
				Err(Error::msg(msg).into())
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

	/// Resolve a given symbol `name` in a given module with path `pbuf`
	pub fn resolve_symbol(&mut self, pbuf: &PathBuf, name: &str) -> Result<Option<ElfSymbol>> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		log::info!("resolving  in {pbuf:?}");
		self.symbols_init(&pbuf)?;
		if let Some(res) = self.resolved.get(&pbuf) {
			log::info!("already gathered symbols for '{pbuf:?}'");
			let sym = res.resolve(name).cloned();
			Ok(sym)
		} else {
			log::info!("symbols for '{pbuf:?}' not retrieved, gathering");
			Err(Error::msg(format!("found no modules matching '{pbuf:?}'")).into())
		}
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
		if let Some(res) = self.resolved.get(&pbuf) {
			let r: Vec<_> = res
				.symbols
				.values()
				.filter(|x| x.stype == symtype)
				.cloned()
				.collect();
			Ok(r)
		} else {
			Err(Error::msg(format!("found no modules matching '{pbuf:?}'")).into())
		}
	}
	pub fn symbols_functions(&mut self, pbuf: &PathBuf) -> Result<Vec<ElfSymbol>> {
		self.symbols_of_type(pbuf, SymbolType::Func)
	}
	fn start_plugin<X: Send + 'static>(mut plugin: Secondary<X>) -> Result<JoinHandle<Result<()>>> {
		let handle = std::thread::spawn(move || -> Result<()> {
			log::info!("Creating plugin and entering loop");
			plugin.loop_until_exit()?;
			Ok(())
		});
		Ok(handle)
	}
	pub fn load_dependencies(&mut self, plugins: &[Plugin], id: usize) -> Result<()> {
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
		if let Some(req) = &self.req {
			req.new_regular()
		} else {
			Err(Error::Unknown.into())
		}
	}
	fn _new_plugin(&mut self, plugin: &Plugin, dep: LoadDependency) -> Result<()> {
		log::info!("creating plugin for {plugin:?}");
		self.client.prepare_load_client()?;
		if let Some(pl) = self.plugins.get_mut(plugin) {
			pl.update_dependency(&dep);
			Err(Error::msg(format!("tried to double-register plugin {plugin:?}")).into())
		} else {
			let client = self.new_regular()?;
			let nid = client.id;
			log::info!("Created new client");
			let h = match plugin {
				Plugin::DlopenDetect => {
					self.load_dependencies(DlopenDetect::dependecies(), nid)?;
					let dl = DlopenDetect::init(client)?;
					Self::start_plugin(dl)?
				}
				Plugin::Files => {
					self.load_dependencies(Files::dependecies(), nid)?;
					let dl = Files::init(client)?;
					Self::start_plugin(dl)?
				}
				Plugin::Mmap => {
					self.load_dependencies(Mmap::dependecies(), nid)?;
					let dl = Mmap::init(client)?;
					Self::start_plugin(dl)?
				}
				Plugin::Prctl => {
					self.load_dependencies(Prctl::dependecies(), nid)?;
					let dl = Prctl::init(client)?;
					Self::start_plugin(dl)?
				}
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
	pub fn new_plugin(&mut self, plugin: &Plugin, reglisten: bool) -> Result<()> {
		self._new_plugin(plugin, LoadDependency::Manual)?;
		assert!(!reglisten);
		// if reglisten {
		// 	match plugin {
		// 		Plugin::DlopenDetect => self.client.register_event(RegEvent::Dlopen)?,
		// 		Plugin::Files => self.client.register_event(RegEvent::Files)?,
		// 	}
		// }
		Ok(())
	}
	pub fn data(&self) -> &T {
		&self.data
	}
	pub fn data_mut(&mut self) -> &mut T {
		&mut self.data
	}
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
	pub fn handle_cmd(&mut self, cmd: Command) -> Result<Response> {
		match cmd {
			Command::Client { tid, cmd } => self.handle_client_cmd(tid, cmd),
			_ => self.client.write_read(cmd),
		}
	}

	/// Should only be used when the client is fully remote and cannot call the
	/// functions directly
	// #[cfg(feature = "unstable")]
	pub fn handle_client_cmd(&mut self, _tid: Tid, cmd: ClientCmd) -> Result<Response> {
		let ret = match cmd {
			ClientCmd::ResolveEntry => {
				let ins = self
					.resolve_entry()
					.map_err(|x| Into::<crate::RemoteError>::into(x));
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::StoppedTids => {
				let ins = self
					.get_stopped_tids()
					.map_err(|x| Into::<crate::RemoteError>::into(x));
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::FirstStoppedTid => {
				let ins = self
					.get_first_stopped()
					.map_err(|x| Into::<crate::RemoteError>::into(x));
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::GetModule { path } => {
				let ins = self
					.get_module(&path)
					.map_err(|x| Into::<crate::RemoteError>::into(x));
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::ResolveSymbol { path, symbol } => {
				let ins = self
					.resolve_symbol(&path, &symbol)
					.map_err(|x| Into::<crate::RemoteError>::into(x));
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::SymbolsOfType { path, symtype } => {
				let ins = self
					.symbols_of_type(&path, symtype)
					.map_err(|x| Into::<crate::RemoteError>::into(x));
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
		};
		Ok(ret)
	}

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
	pub fn get_first_stopped(&mut self) -> Result<Tid> {
		if let Some(n) = self.get_stopped_tids()?.first() {
			Ok(*n)
		} else {
			Err(Error::msg("No stopped thread").into())
		}
	}
	pub fn resolve_entry(&self) -> Result<TargetPtr> {
		let exe = self.proc.exe_path()?;
		let elf = Elf::new(exe)?.parse()?;
		let entry = elf.entry();
		let mainmod = self.proc.exe_module()?;

		Ok(entry + mainmod.loc.addr())
	}
	pub fn set_specific_syscall_handler(&mut self, sysno: TargetPtr, cb: SyscallCb<T>) {
		self.syscallcbs.insert(sysno, cb);
	}
	pub fn set_raw_syscall_handler(&mut self, cb: RawSyscallCb<T>) {
		self.raw_syscall_cb = Some(cb);
	}
	pub fn set_stop_handler(&mut self, cb: StoppedCb<T>) {
		self.stoppedcb = Some(cb);
	}
	pub fn set_generic_syscall_handler(&mut self, cb: SyscallCb<T>) -> Result<()> {
		self.syscallcb = Some(cb);
		Ok(())
	}
	pub fn register_breakpoint_handler(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		cb: BreakpointCb<T>,
	) -> Result<()> {
		self.client.insert_bp(tid, addr)?;
		self.bpcbs.insert(addr, cb);
		Ok(())
	}
	pub fn set_event_handler(&mut self, cb: EventCb<T>) {
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
			let r = cb(self, tid, addr);
			match r {
				Ok(true) => {
					log::debug!("breakpoint will be reinserted again");
					self.client.insert_bp(tid, addr)?;
					self.bpcbs.insert(addr, cb);
				}
				Ok(false) => {
					log::debug!("bp has already been removed");
				}
				Err(e) => {
					log::error!("bp callback triggered error: '{e:?}' | will be removed");
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
			_ => {
				if let Some(cb) = self.stoppedcb {
					cb(self, stopped)?;
				}
			}
		}
		Ok(())
	}
	pub fn loop_until_exit(&mut self) -> Result<()> {
		log::info!("looping until exit");
		loop {
			let rsp = self.client.wait()?;
			log::debug!("response {rsp:?}");
			match rsp {
				Response::Event(evt) => {
					self.handle_event(evt)?;
				}
				Response::TargetExit => {
					log::info!("target exited");
					break;
				}
				Response::Removed => {
					log::info!("we were removed");
					break;
				}
				Response::Stopped(stopped) => self.handle_stopped(stopped)?,
				Response::Syscall(syscall) => self.handle_syscall(syscall)?,
				_ => crate::bug!(
					"unexpected response {rsp:?} in loop, client probably forgot to read something"
				),
			}
		}
		Ok(())
	}
}
