use std::io::{BufReader, BufWriter};
use std::thread::JoinHandle;
use std::{collections::HashMap, path::PathBuf};

use crate::api::args::Enrich;
use crate::api::messages::{BpRet, CbAction, ElfSymbol, Stop, Stopped, SymbolType, TrampType};
use crate::api::{ArgsBuilder, CallFrame};
use crate::arch::RegisterAccess;
use crate::exe::elf::Elf;
#[cfg(feature = "plugins")]
use crate::plugin::{plugins::*, Plugin};

use crate::target::GenericCc;
#[cfg(feature = "plugins")]
use crate::utils::{LoadDependency, LoadedPlugin};

#[cfg(feature = "syscalls")]
use crate::api::messages::SyscallItem;

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

pub type BreakpointCb<T, Err> = fn(&mut Secondary<T, Err>, Tid, TargetPtr) -> Result<BpRet>;
pub type HookEntryCb<T, Err> = fn(&mut Secondary<T, Err>, &CallFrame) -> Result<CbAction>;
pub type HookExitCb<T, Err> = fn(&mut Secondary<T, Err>, &CallFrame) -> Result<CbAction>;

#[cfg(feature = "syscalls")]
pub type SyscallEntryCb<T, Err> = fn(&mut Secondary<T, Err>, &SyscallItem) -> Result<CbAction>;
#[cfg(feature = "syscalls")]
pub type SyscallExitCb<T, Err> = fn(&mut Secondary<T, Err>, &SyscallItem) -> Result<CbAction>;

pub type EventCb<T, Err> = fn(&mut Secondary<T, Err>, Event) -> Result<()>;
pub type StoppedCb<T, Err> = fn(&mut Secondary<T, Err>, Stopped) -> Result<()>;
pub type RawSyscallCb<T, Err> = fn(&mut Secondary<T, Err>, Tid, bool) -> Result<()>;
pub type StepCb<T, Err> =
	fn(&mut Secondary<T, Err>, Tid, TargetPtr) -> std::result::Result<(), Err>;

struct GotHook<T, Err>
where
	Err: Into<crate::Error>,
{
	real: TargetPtr,
	fake: TargetPtr,
	lazylink: bool,
	func: Callback<HookEntryCb<T, Err>, HookExitCb<T, Err>>,
	frame: Option<CallFrame>,
}
impl<T, Err> GotHook<T, Err>
where
	Err: Into<crate::Error>,
{
	pub fn new(
		real: TargetPtr,
		fake: TargetPtr,
		lazylink: bool,
		func: Callback<HookEntryCb<T, Err>, HookExitCb<T, Err>>,
	) -> Self {
		Self {
			real,
			fake,
			lazylink,
			func,
			frame: None,
		}
	}
}
struct Callback<Entry, Exit> {
	pub entry: Entry,
	pub exit: Exit,
}

impl<Entry, Exit> Callback<Entry, Exit> {
	fn new(entry: Entry, exit: Exit) -> Self {
		Self { entry, exit }
	}
}

type StoredHook<T, Err> = Callback<HookEntryCb<T, Err>, HookExitCb<T, Err>>;

#[cfg(feature = "syscalls")]
type SyscallHook<T, Err> = Callback<SyscallEntryCb<T, Err>, SyscallExitCb<T, Err>>;

/// Each connected client will get access  to this context object.
///
/// This object will always belong to a [crate::ctx::Main] and will never be
/// created on its own.
pub struct Secondary<T, Err>
where
	Err: Into<crate::Error>,
{
	/// Can be used to query information from OS about the process.
	///
	/// This is exposed here as a convenience.
	pub proc: Process,
	client: crate::Client,

	#[cfg(feature = "plugins")]
	pub(crate) plugins: HashMap<Plugin, crate::utils::LoadedPlugin>,

	pub(crate) data: T,

	signalcbs: HashMap<i32, SignalCb<T, Err>>,

	#[cfg(feature = "syscalls")]
	syscallcb: Option<SyscallHook<T, Err>>,

	eventcb: Option<EventCb<T, Err>>,
	stepcb: Option<StepCb<T, Err>>,
	bpcbs: HashMap<TargetPtr, BreakpointCb<T, Err>>,

	callframes: HashMap<(Tid, TargetPtr), CallFrame>,

	funcentrycbs: HashMap<TargetPtr, StoredHook<T, Err>>,
	#[cfg(feature = "syscalls")]
	syscallcbs: HashMap<usize, SyscallHook<T, Err>>,

	stoppedcb: Option<StoppedCb<T, Err>>,

	gothooks: HashMap<TargetPtr, GotHook<T, Err>>,

	raw_syscall_cb: Option<RawSyscallCb<T, Err>>,

	resolved: HashMap<PathBuf, Elf>,
	pub(crate) req: Option<ReqNewClient>,

	// cc: Box<dyn RegsAbiAccess + Send + 'static>,
	cc: GenericCc,

	args: ArgsBuilder,
}
impl<T, Err> Secondary<T, Err>
where
	Err: Into<crate::Error>,
{
	pub(crate) fn new(
		mut client: crate::Client,
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
		// let cc = Box::new(SystemV);
		let cc = GenericCc::new_target_systemv().unwrap();
		let args = ArgsBuilder::default();
		let gothooks = HashMap::new();

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
			cc,
			args,
			gothooks,
		};
		Ok(r)
	}

	pub(crate) fn set_main_exe<V: Into<Vec<u8>>>(&mut self, addr: TargetPtr, exe: V) -> Result<()> {
		let exe: Vec<u8> = exe.into();
		let elf = Elf::from_bytes(exe, addr)?;
		let path = self.proc.exe_path()?;
		self.resolved.insert(path, elf);
		Ok(())
	}
	fn empty_hook_func_entry(&mut self, frame: &CallFrame) -> Result<CbAction> {
		log::debug!("called empty hook function entry {frame:?}");
		Ok(CbAction::None)
	}
	fn empty_hook_func_exit(&mut self, frame: &CallFrame) -> Result<CbAction> {
		log::debug!("called empty hook function entry {frame:?}");
		Ok(CbAction::None)
	}
	#[cfg(feature = "syscalls")]
	fn empty_hook_syscall_entry(&mut self, sys: &SyscallItem) -> Result<CbAction> {
		log::debug!("called empty hook function entry {sys:?}");
		Ok(CbAction::None)
	}
	#[cfg(feature = "syscalls")]
	fn empty_hook_syscall_exit(&mut self, sys: &SyscallItem) -> Result<CbAction> {
		log::debug!("called empty hook function entry {sys:?}");
		Ok(CbAction::None)
	}
	/// Get a reference to [Client]
	pub fn client(&self) -> &crate::Client {
		&self.client
	}

	/// Get a mutable reference to [Client]
	pub fn client_mut(&mut self) -> &mut crate::Client {
		&mut self.client
	}

	/// Get a reference to stored data
	pub fn data(&self) -> &T {
		&self.data
	}

	/// Get a mutable reference to stored data
	pub fn data_mut(&mut self) -> &mut T {
		&mut self.data
	}

	/// Take ownership over the [ArgsBuilder].
	///
	/// This is usually done to make more custom changes to it, you probably
	/// want to call [Self::set_args_builder] afterwards so that we still keep
	/// track of changes.
	pub fn take_args_builder(&mut self) -> ArgsBuilder {
		std::mem::take(&mut self.args)
	}

	/// Get a mutable reference to the [ArgsBuilder].
	pub fn args_builder_mut(&mut self) -> &mut ArgsBuilder {
		&mut self.args
	}

	/// Set a custom [ArgsBuilder].
	pub fn set_args_builder(&mut self, args: ArgsBuilder) {
		self.args = args;
	}

	/// Write the config we've been tracking to the tracee so that it takes
	/// effect.
	///
	/// **NB!** This is generally not necessary, if the config has been
	/// modified, this function will be called when the client is done
	/// interacting with the target.
	pub fn write_config(&mut self) -> Result<()> {
		log::trace!("writing new config");
		let args = self.args.borrow_finish()?;
		self.client.set_config(args)?;
		Ok(())
	}
	pub(crate) fn new_second(client: crate::Client, data: T) -> Result<Self> {
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
	pub(crate) fn new_master(client: crate::Client, data: T, req: ReqNewClient) -> Result<Self> {
		Self::new(client, data, Some(req))
	}

	/// Get a [MemoryMap] which exactly matches the name in `pbuf`
	pub fn get_memory_map_exact(&mut self, pbuf: &PathBuf) -> Result<MemoryMap> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		let mods = self.proc.proc_modules()?;
		let mut mods: Vec<_> = mods.iter().filter(|x| x.file_name_matches(&pbuf)).collect();
		match mods.len() {
			0 => Err(Error::NotFound),
			1 => Ok(mods.remove(0).clone()),
			_ => Err(Error::TooManyMatches),
		}
	}

	/// Try and locate the symbol `name` in any of the loaded executables.
	///
	/// This function will not search in the order they are retrieved, which
	/// should not be considered deterministic. If a symbol is defined multiple
	/// times, there is no guarantee on which is returned.
	pub fn lookup_symbol_in_any(&mut self, name: &str) -> Result<Option<ElfSymbol>> {
		log::trace!("searching for {name:?}");
		let paths = self
			.proc
			.proc_modules()?
			.iter()
			.map(|x| x.path())
			.filter(|x| x.is_some())
			.map(|x| x.expect("impossible").clone())
			.collect::<Vec<PathBuf>>();

		for path in paths.iter() {
			log::trace!("searching for {name:?} in {path:?}");
			if let Ok(Some(n)) = self.resolve_symbol_in_mod(path, name) {
				log::trace!("found {name:?} in {path:?}");
				return Ok(Some(n));
			}
		}
		log::debug!("no match found for {name:?}");
		Ok(None)
	}
	fn ensure_elf_exists(&mut self, pbuf: &PathBuf) -> Result<()> {
		let loc = self
			.proc
			.exact_match_path(pbuf)?
			.ok_or(Error::msg("unable to find path"))?;
		let elf = Elf::new(pbuf, loc.addr())?;
		self.resolved.insert(pbuf.clone(), elf);
		Ok(())
	}

	/// Resolve a given symbol `name` in a given module with path `pbuf`
	pub fn resolve_symbol_in_mod(
		&mut self,
		pbuf: &PathBuf,
		name: &str,
	) -> Result<Option<ElfSymbol>> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		self.ensure_elf_exists(&pbuf)?;
		log::info!("resolving  in {pbuf:?}");
		let elf = self.resolved.get(&pbuf).ok_or(Error::NotFound)?;
		Ok(elf.resolve(name))
	}

	/// Resolve a given GOT symbol `name` in a given module with path `pbuf`
	pub fn resolve_symbol_got(&mut self, pbuf: &PathBuf, name: &str) -> Result<TargetPtr> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		self.ensure_elf_exists(&pbuf)?;
		let elf = self.resolved.get(&pbuf).ok_or(Error::NotFound)?;
		elf.resolve_got(name).ok_or(Error::NotFound)
	}

	/// Insert a hook to be executed every time the function `name` in `pbuf` is
	/// called.
	pub fn hook_got_entry(
		&mut self,
		tid: Tid,
		pbuf: &PathBuf,
		name: &str,
		cbentry: HookEntryCb<T, Err>,
	) -> Result<()> {
		self.hook_got(tid, pbuf, name, cbentry, Self::empty_hook_func_exit)
	}
	pub fn hook_got_exit(
		&mut self,
		tid: Tid,
		pbuf: &PathBuf,
		name: &str,
		cbexit: HookExitCb<T, Err>,
	) -> Result<()> {
		self.hook_got(tid, pbuf, name, Self::empty_hook_func_entry, cbexit)
	}
	pub fn hook_got(
		&mut self,
		tid: Tid,
		pbuf: &PathBuf,
		name: &str,
		cbentry: HookEntryCb<T, Err>,
		cbexit: HookExitCb<T, Err>,
	) -> Result<()> {
		// A couple of different states the GOT entry can be in:
		// - Completely unlinked (contains offset from start of current file)
		//   - Could either to lazy linking of pre-linking in the future
		// - Lazy linked (contains real memory address to PLT code in current
		//   file)
		//   - Will call `_dl_runtime_resolve_xsavec` when used
		// - Linked (contains real memory address to targeted function)
		//   - Has gone through `_dl_relocate_object`
		//
		// Main problem being that anything we write before linking will be
		// overwritten.

		let addr = self.resolve_symbol_got(pbuf, name)?;
		let before = self.client.read_u64(tid, addr)?;
		let before: TargetPtr = before.into();
		if !self.proc.addr_is_in_maps(before)? {
			return Err(Error::msg(
				"hooking GOT before linking is not (yet) supported, run until EXE entry point",
			));
		}
		let exepath = self.proc.exe_path()?;
		let loc = self.proc.exact_match_path(exepath)?.ok_or(Error::Unknown)?;
		let lazylink = if loc.contains(before) {
			log::warn!("overriding in-file link, we will be overwritten on next resolve");
			true
		} else {
			false
		};

		let bpaddr = self.client.alloc_and_write_bp(tid)?;
		self.client.write_int(tid, addr, usize::from(bpaddr))?;
		#[cfg(debug_assertions)]
		{
			let wrote = self.client.read_u64(tid, addr)?;
			assert_eq!(wrote, u64::from(bpaddr));
		}

		let callback = Callback::new(cbentry, cbexit);
		let ins = GotHook::new(before, bpaddr, lazylink, callback);
		self.gothooks.insert(bpaddr, ins);

		Ok(())
	}

	pub fn overwrite_got_symbol(
		&mut self,
		tid: Tid,
		pbuf: &PathBuf,
		name: &str,
		value: TargetPtr,
	) -> Result<()> {
		let addr = self.resolve_symbol_got(pbuf, name)?;
		self.client.write_int(tid, addr, usize::from(value))?;
		#[cfg(debug_assertions)]
		{
			let wrote = self.client.read_u64(tid, addr)?;
			assert_eq!(wrote, u64::from(value));
		}
		Ok(())
	}

	/// Enumerate all symbols of the given type. See [SymbolType] for more
	/// details on type of symbols.
	pub fn enumerate_symbols_of_type(
		&mut self,
		pbuf: &PathBuf,
		symtype: SymbolType,
	) -> Result<Vec<ElfSymbol>> {
		let pbuf = std::fs::canonicalize(pbuf)?;
		self.ensure_elf_exists(&pbuf)?;
		let elf = self.resolved.get(&pbuf).ok_or(Error::Unknown)?;
		Ok(elf
			.all_symbols()
			.iter()
			.filter(|x| x.stype == symtype)
			.cloned()
			.collect())
	}
	pub fn enumerate_functions(&mut self, pbuf: &PathBuf) -> Result<Vec<ElfSymbol>> {
		self.enumerate_symbols_of_type(pbuf, SymbolType::Func)
	}
	#[cfg(feature = "plugins")]
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
	pub(crate) fn new_regular(&self) -> Result<crate::Client> {
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
				#[cfg(not(feature = "syscalls"))]
				_ => panic!("called plugin not implemented yet: {plugin:?}"),
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
	pub(crate) fn new_plugin(&mut self, plugin: &Plugin, reglisten: bool) -> Result<()> {
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
	pub(crate) fn remove_plugin(&mut self, plugin: &Plugin) -> Result<()> {
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
	pub(crate) fn handle_cmd(&mut self, cmd: Command) -> Result<Response> {
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
			ClientCmd::FirstStoppedTid => {
				let ins = self.get_first_stopped();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::GetModule { path } => {
				let ins = self.get_memory_map_exact(&path);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::ResolveSymbol { path, symbol } => {
				let ins = self.resolve_symbol_in_mod(&path, &symbol);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ClientCmd::SymbolsOfType { path, symtype } => {
				let ins = self.enumerate_symbols_of_type(&path, symtype);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
		};
		Ok(ret)
	}

	/// Get a single [Tid] which has stopped.
	///
	/// This is useful in the beginning as some commands need to operate on a
	/// specific [Tid].
	pub fn get_first_stopped(&mut self) -> Result<Tid> {
		let a = self.client.get_stopped_tids()?;
		let n = a.first().ok_or(Error::msg("No stopped thread"))?;
		Ok(*n)
	}
	fn _resolve_entry(&mut self, exe: &PathBuf, maxattempts: usize) -> Result<TargetPtr> {
		if let Some(elf) = self.resolved.get(exe) {
			Ok(elf.entry())
		} else if maxattempts > 0 {
			let mainmod = self.proc.exe_module()?;
			let elf = Elf::new(exe.clone(), mainmod.loc.addr())?.parse()?;
			// let entry = elf.entry();
			self.resolved.insert(exe.clone(), elf);
			self._resolve_entry(exe, maxattempts - 1)
		} else {
			Err(Error::msg("too many attempts to read exe"))
		}
	}
	pub fn try_find_libc_so(&mut self) -> Result<PathBuf> {
		let mut mods = self
			.proc
			.proc_modules()?
			.into_iter()
			.filter(|x| {
				if let Some(path) = x.path() {
					path.ends_with("libc.so")
						|| path.ends_with("libc-2.31.so")
						|| path.ends_with("libc.so.6")
				} else {
					false
				}
			})
			.collect::<Vec<MemoryMap>>();
		if mods.len() == 1 {
			Ok(mods
				.remove(0)
				.path()
				.expect("no path after matching path")
				.clone())
		} else {
			Err(Error::NotFound)
		}
	}

	/// Get entry point of program
	pub fn resolve_entry(&mut self) -> Result<TargetPtr> {
		let exe = self.proc.exe_path()?;
		self._resolve_entry(&exe, 1)
	}

	/// Call the function at `addr` with the arguments in `args`. The return
	/// value is what we got from the tracee.
	pub fn call_func(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		args: &[TargetPtr],
	) -> Result<TargetPtr> {
		let mut regs = self.client.get_registers(tid)?;
		let oregs = regs.clone();
		log::debug!("interrupted @ pc {:x}", oregs.get_pc());
		for (i, arg) in args.iter().enumerate() {
			log::debug!("arg[{i}]: = {arg:x}");
			self.cc
				.set_arg(i, (*arg).into(), &mut regs, &mut self.client)?;
		}
		let pc = self.client.get_trampoline_addr(tid, TrampType::Call)?;
		log::debug!("setting pc {pc:x}");
		let pc = pc + 4.into();
		regs.set_pc(pc.into());
		log::debug!("setting pc {pc:x}");
		self.cc.set_reg_call_tramp(&mut regs, addr)?;
		self.client.set_registers(tid, regs)?;
		self.client.run_until_trap(tid)?;

		let regs = self.client.get_registers(tid)?;
		let ret = self.cc.get_retval(&regs)?;

		log::debug!("setting back oregs");
		self.client.set_registers(tid, oregs)?;

		Ok(ret.into())
	}

	pub fn set_step_handler(&mut self, cb: StepCb<T, Err>) {
		self.args.set_handle_steps(true);
		self.stepcb = Some(cb);
	}
	pub fn remove_step_handler(&mut self) {
		self.args.set_handle_steps(false);
		self.stepcb = None;
	}
	pub fn set_raw_syscall_handler(&mut self, cb: RawSyscallCb<T, Err>) {
		self.raw_syscall_cb = Some(cb);
		self.args.set_intercept_all_syscalls(true);
	}
	pub fn set_stop_handler(&mut self, cb: StoppedCb<T, Err>) {
		self.stoppedcb = Some(cb);
	}
	#[cfg(feature = "syscalls")]
	pub fn enrich_syscalls(&mut self, enrich: Enrich) {
		self.args.set_enrich_default(enrich);
	}
	#[cfg(feature = "syscalls")]
	pub fn set_generic_syscall_handler(
		&mut self,
		cbentry: SyscallEntryCb<T, Err>,
		cbexit: SyscallExitCb<T, Err>,
	) {
		self.syscallcb = Some(Callback::new(cbentry, cbexit));
		self.args.set_intercept_all_syscalls(true);
		self.args.set_transform_syscalls(true);
	}
	#[cfg(feature = "syscalls")]
	pub fn set_generic_syscall_handler_entry(&mut self, cbentry: SyscallEntryCb<T, Err>) {
		self.set_generic_syscall_handler(cbentry, Self::empty_hook_syscall_exit)
	}
	#[cfg(feature = "syscalls")]
	pub fn set_generic_syscall_handler_exit(&mut self, cbexit: SyscallExitCb<T, Err>) {
		self.set_generic_syscall_handler(Self::empty_hook_syscall_entry, cbexit)
	}
	#[cfg(feature = "syscalls")]
	pub fn set_syscall_hook(
		&mut self,
		sysno: usize,
		cbentry: SyscallEntryCb<T, Err>,
		cbexit: SyscallExitCb<T, Err>,
	) {
		self.syscallcbs
			.insert(sysno, Callback::new(cbentry, cbexit));
		self.args.add_syscall_traced(sysno);
		self.args.set_transform_syscalls(true);
	}
	#[cfg(feature = "syscalls")]
	pub fn set_syscall_hook_entry(&mut self, sysno: usize, cbentry: SyscallEntryCb<T, Err>) {
		self.set_syscall_hook(sysno, cbentry, Self::empty_hook_syscall_exit);
	}
	#[cfg(feature = "syscalls")]
	pub fn set_syscall_hook_exit(&mut self, sysno: usize, cbexit: SyscallExitCb<T, Err>) {
		self.set_syscall_hook(sysno, Self::empty_hook_syscall_entry, cbexit);
	}

	pub fn register_function_hook(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		cbentry: HookEntryCb<T, Err>,
		cbexit: HookExitCb<T, Err>,
	) -> Result<()> {
		self.client.insert_bp(tid, addr)?;
		self.funcentrycbs
			.insert(addr, Callback::new(cbentry, cbexit));
		Ok(())
	}
	pub fn register_function_hook_entry(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		cbentry: HookEntryCb<T, Err>,
	) -> Result<()> {
		self.register_function_hook(tid, addr, cbentry, Self::empty_hook_func_exit)
	}
	pub fn register_function_hook_exit(
		&mut self,
		tid: Tid,
		addr: TargetPtr,
		cbexit: HookExitCb<T, Err>,
	) -> Result<()> {
		self.register_function_hook(tid, addr, Self::empty_hook_func_entry, cbexit)
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
			let ret = if syscall.is_entry() {
				(cb.entry)(self, &syscall)
			} else {
				(cb.exit)(self, &syscall)
			};
			let remove = match ret {
				Ok(action) => match action {
					CbAction::None => false,
					CbAction::Remove => true,
					CbAction::EarlyRet { ret: _ } => {
						log::error!("EarlyRet for syscalls not implemented yet");
						return Err(Error::Unsupported);
					}
				},
				Err(e) => {
					log::error!("syscall callback on {sysno} returned error: {e:?}");
					false
				}
			};
			if !remove {
				self.syscallcbs.insert(sysno, cb);
			}
		} else if let Some(cb) = &self.syscallcb {
			let ret = if syscall.is_entry() {
				(cb.entry)(self, &syscall)
			} else {
				(cb.exit)(self, &syscall)
			};
			let remove = match ret {
				Ok(action) => match action {
					CbAction::None => false,
					CbAction::Remove => true,
					CbAction::EarlyRet { ret: _ } => {
						log::error!("EarlyRet for syscalls not implemented yet");
						return Err(Error::Unsupported);
					}
				},
				Err(e) => {
					log::warn!("syscall cb resulted in error: '{e:?}'");
					false
				}
			};
			if remove {
				self.args.set_intercept_all_syscalls(false);
			}
		} else {
			log::trace!("no syscall handler for {sysno}");
		}
		Ok(())
	}
	fn event_breakpoint(&mut self, tid: Tid, addr: TargetPtr) -> Result<()> {
		log::debug!("hit bp @ {addr:x}");
		let mut r = self.bpcbs.remove(&addr);
		if let Some(cb) = std::mem::take(&mut r) {
			log::debug!("found regular BP at {addr:x}");
			let r = cb(self, tid, addr);
			match r {
				Ok(BpRet::Keep) => {
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
				Ok(BpRet::Remove) => {
					log::debug!("bp has already been removed");
				}
				Err(e) => {
					log::error!("bp callback triggered error: '{e:?}' | bp will be removed");
				}
			}
		} else if let Some(mut frame) = std::mem::take(&mut self.callframes.remove(&(tid, addr))) {
			log::debug!("found function exit BP at {addr:x}");
			if let Some(cb) =
				std::mem::take(&mut self.funcentrycbs.remove(&frame.function_addr().into()))
			{
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
				let mut regs = self.client.get_registers(tid)?;
				let retval = self.cc.get_retval(&regs)?;
				frame.set_output(retval.into());
				match (cb.exit)(self, &frame) {
					Ok(action) => match action {
						CbAction::None => {}
						CbAction::Remove => {
							log::error!("Remove from function entry not implemented yet");
							return Err(Error::Unsupported);
						}
						CbAction::EarlyRet { ret } => {
							self.cc.set_retval(ret.into(), &mut regs)?;
							self.client.set_registers(tid, regs)?;
						}
					},
					Err(e) => {
						log::error!("callback triggered error {e:?}");
					}
				}
				self.funcentrycbs.insert(frame.function_addr().into(), cb);
			}
		} else if let Some(cb) = std::mem::take(&mut self.funcentrycbs.remove(&addr)) {
			log::debug!("found function entry BP at {addr:x}");
			let regs = self.client.get_registers(tid)?;
			let retaddr = self.cc.get_return_addr(&regs, &mut self.client)?;
			let mut frame = CallFrame::new(tid, addr.into(), regs);
			let (skipexit, remove) = match (cb.entry)(self, &frame) {
				Ok(action) => match action {
					CbAction::None => (false, false),
					CbAction::Remove => (true, true),
					CbAction::EarlyRet { ret } => {
						self.cc.set_retval(ret.into(), &mut frame.regs)?;
						frame.set_output(ret);
						self.client.set_registers(tid, frame.regs.clone())?;
						self.client.exec_ret(tid)?;
						let rem2 = match (cb.exit)(self, &frame) {
							Ok(a) => match a {
								CbAction::None => false,
								CbAction::Remove => true,
								CbAction::EarlyRet { ret: _ } => {
									log::warn!(
										"got second early ret, but already parsed from entry"
									);
									false
								}
							},
							Err(e) => {
								log::error!("got error on exit callback {e:?}");
								false
							}
						};

						(true, rem2)
					}
				},
				Err(e) => {
					log::error!("callback triggered error {e:?}");
					(true, false)
				}
			};
			if !skipexit {
				self.callframes.insert((tid, retaddr.into()), frame);
				self.client.insert_bp(tid, retaddr.into())?;
			}
			if !remove {
				self.client.step_ins(tid, 1)?;
				self.client.insert_bp(tid, addr)?;
				self.funcentrycbs.insert(addr, cb);
			}
		} else if let Some(mut got) = self.gothooks.remove(&addr) {
			log::debug!("hit gothook {addr:x} | real: {:x}", got.real);
			let mut regs = self.client.get_registers(tid)?;

			if let Some(mut frame) = std::mem::take(&mut got.frame) {
				// Function exit
				log::trace!("got exit");
				let retval = self.cc.get_retval(&regs)?;
				frame.set_output(retval.into());
				let ret = (got.func.exit)(self, &frame);

				let ins = match ret {
					Ok(action) => match action {
						CbAction::None => true,
						CbAction::Remove => false,
						CbAction::EarlyRet { ret } => {
							self.cc.set_retval(ret.into(), &mut regs)?;
							self.client.set_registers(tid, regs.clone())?;
							true
						}
					},
					Err(e) => {
						log::error!("got cg -> {e:?}");
						true
					}
				};
				if ins && !got.lazylink {
					log::debug!("[exit]: inserting hook back in");
					self.gothooks.insert(got.fake, got);
				} else {
					log::debug!("[exit]: hook will not be hit again");
				}
			} else {
				// Function entry
				log::trace!("got entry");

				// Make sure we execute from real func when we continue
				regs.set_pc(got.real.into());
				self.client.set_registers(tid, regs.clone())?;

				let mut frame = CallFrame::new(tid, addr.into(), regs.clone());
				let retaddr = self.cc.get_return_addr(&regs, &mut self.client)?;
				let ret = (got.func.entry)(self, &frame);

				let ins = match ret {
					Ok(action) => match action {
						CbAction::None => true,
						CbAction::Remove => false,
						CbAction::EarlyRet { ret } => {
							self.cc.set_retval(ret.into(), &mut regs)?;
							frame.set_output(ret);
							self.client.set_registers(tid, regs.clone())?;
							self.client.exec_ret(tid)?;
							false
						}
					},
					Err(e) => {
						log::error!("got cb error -> {e:?}");
						true
					}
				};
				if ins {
					got.frame = Some(frame);
					log::debug!("[entry]: insert bp @ {retaddr:x}");
					self.client.insert_bp(tid, retaddr.into())?;
					self.gothooks.insert(retaddr.into(), got);
				} else if !got.lazylink {
					log::debug!("[entry]: inserting hook back in");
					self.gothooks.insert(addr, got);
				}
			}
		} else {
			// TODO: Should be able to recover from this
			panic!("no registered BP at {addr:x}");
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
			Stop::Breakpoint { pc } => self.event_breakpoint(stopped.tid, pc)?,
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
			// The client may change the config at any point where they have
			// control, so check if it has been modified every time.
			if self.args.is_dirty() {
				self.write_config()?;
			}
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
					Response::TargetExit => crate::bug!("TargetExit was not handled by callback"),
					Response::Removed => crate::bug!("Removed was not handled by callback"),
					Response::Error(e) => log::error!("got error: {e:?} | trying to continue"),
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

	/// Run until target has stopped.
	pub fn run_until_stop(&mut self) -> Result<Stopped> {
		log::info!("running until stop");
		let rsp = self.loop_until(|rsp| Ok(matches!(rsp, Response::Stopped(_))))?;
		let stop: Stopped = rsp.try_into()?;
		Ok(stop)
	}

	/// Run until target hits an exec
	pub fn run_until_exec(&mut self) -> Result<Tid> {
		log::info!("running until exec");
		loop {
			let stop = self.run_until_stop()?;
			if let Stop::Exec { old } = stop.stop {
				return Ok(old);
			}
		}
	}

	/// Run until a given address has been hit
	pub fn run_until_addr(&mut self, addr: TargetPtr) -> Result<Option<TargetPtr>> {
		let tid = self.get_first_stopped()?;
		self.client.insert_bp(tid, addr)?;
		let ret = self.loop_until(|rsp| {
			let ret = if let Response::Stopped(stopped) = rsp {
				if let Stop::Breakpoint { pc } = &stopped.stop {
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
			if let Stop::Breakpoint { pc } = stopped.stop {
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
	pub fn run_until_sysno(&mut self, sysno: usize) -> Result<Response> {
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
