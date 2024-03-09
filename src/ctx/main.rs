use crate::api::{Args, ArgsBuilder, Response};
use crate::ctrl::tracer::CtrlTracer;
use crate::ctrl::ReqNewClient;
use crate::ctx;
use crate::trace::ptrace::Tracer;
use crate::utils::process::Process;
use crate::Result;
use std::thread::JoinHandle;

/// Main context object which is initially created when attaching/starting the
/// tracee.
///
/// Subsequent clients will get a [ctx::Secondary] object.
///
/// The generic `T` is an arbitrary value the caller can store and get a mutable
/// reference to whenever a callback is called. This value is stored in
/// [ctx::Secondary].
///
/// The generic `Err` is the error value returned by the callbacks implemented.
/// This could be [crate::Error], [anyhow::Error] or some other specific error
/// which can be converted into [crate::Error].
pub struct Main<T, Err>
where
	Err: Into<crate::Error>,
{
	ctx: ctx::Secondary<T, Err>,
	handle: JoinHandle<Result<()>>,
}
impl<T, Err> Main<T, Err>
where
	Err: Into<crate::Error>,
{
	fn new(ctx: ctx::Secondary<T, Err>, handle: JoinHandle<Result<()>>) -> Self {
		Self { ctx, handle }
	}

	/// Create new, either by attaching to existing or by spawning program in
	/// `args`
	///
	/// This is the main entry point to use if you create a tool where the user
	/// should specify which attachment method. If you know you always want to
	/// attach or spawn, you could use [Self::new_attach] or [Self::new_spawn],
	/// respectively.
	pub fn new_main(attach: bool, prog: String, args: Vec<String>, state: T) -> Result<Self> {
		let ctx = if attach {
			if !args.is_empty() {
				log::warn!("extra args '{args:?}' will be ignored");
			}
			let pid = Process::arg_to_pid(&prog)?;
			let proc = Process::from_pid(pid as u32)?;
			Self::new_attach(proc, state)?
		} else {
			// let name = args.remove(0);
			let mut cmd = std::process::Command::new(prog);
			cmd.args(args);
			Self::new_spawn(cmd, state)?
		};
		Ok(ctx)
	}

	#[cfg(not(target_arch = "arm"))]
	/// Spawn from a process in memory.
	///
	/// This is mainly implemented because we want to use it in testing, but
	/// including it in release because it may have some other uses.
	///
	/// Args:
	///
	/// - `name` - arbitrary name that will be given to the process
	/// - `elf` - ELF executable file
	/// - `data` - Arbitrary data which may be included
	///
	/// **NB!** This is disabled on arm, because we do not receive the the Exec
	/// notification. Unsure why this bug happens, but disabled until it's
	/// figured out.
	pub fn spawn_in_mem<S: Into<String>, V: Into<Vec<String>>>(
		name: S, elf: Vec<u8>, args: V, data: T,
	) -> Result<Self> {
		let name: String = name.into();
		let args: Vec<String> = args.into();
		let (req, acc) = ReqNewClient::new();

		let nelf = elf.clone();
		let handle = std::thread::spawn(move || -> Result<()> {
			let (tracer, _tid) = Tracer::spawn_in_mem(&name, nelf, args)?;
			let mgr = CtrlTracer::new(tracer, acc)?;
			mgr.scheduler()?;
			Ok(())
		});
		let client = req.new_regular()?;
		log::info!("ready to send commands to target");

		let mut ctx = ctx::Secondary::new_master(client, data, req)?;

		// Need to set a temporary config so that we can handle exec
		let args = ArgsBuilder::new().handle_exec();
		ctx.set_args_builder(args);
		let tid = ctx.get_first_stopped()?;
		let old = ctx.run_until_exec()?;
		assert!(tid == old);

		let mainloc = ctx
			.proc
			.exact_match_path("/memfd:rust_exec (deleted)")?
			.expect("unable to location of main binary");

		ctx.set_main_exe(mainloc.addr(), elf)?;

		// Restore back default config and set to dirty so that it's written on
		// next round
		ctx.set_args_builder(ArgsBuilder::new_dirty());

		Ok(Self::new(ctx, handle))
	}

	/// Get reference to [ctx::Secondary] context object
	pub fn secondary(&self) -> &ctx::Secondary<T, Err> {
		&self.ctx
	}

	/// Get mutable reference to [ctx::Secondary] context object
	pub fn secondary_mut(&mut self) -> &mut ctx::Secondary<T, Err> {
		&mut self.ctx
	}

	/// Create new by attaching to `pid`
	pub fn new_attach_pid(pid: u32, data: T) -> Result<Self> {
		let proc = Process::from_pid(pid)?;
		Self::new_attach(proc, data)
	}

	/// Create new by attaching to process `name`
	pub fn new_attach_procname(name: &str, data: T) -> Result<Self> {
		let proc = Process::procname_to_process(name)?;
		Self::new_attach(proc, data)
	}

	/// Create new by spawning the command `cmd`
	pub fn new_spawn(cmd: std::process::Command, data: T) -> Result<Self> {
		let (req, acc) = ReqNewClient::new();

		let handle = std::thread::spawn(move || -> Result<()> {
			let tracer = Tracer::spawn(cmd)?;
			let mgr = CtrlTracer::new(tracer, acc)?;
			mgr.scheduler()?;
			Ok(())
		});
		let client = req.new_regular()?;
		log::info!("ready to send commands to target");

		let ctx = ctx::Secondary::new_master(client, data, req)?;
		Ok(Self::new(ctx, handle))
	}

	// pub fn register_new_client(&mut self) -> Result<crate::Client> {
	// 	let req = self.ctx.req
	// 		.as_mut()
	// 		.ok_or(Error::msg("new_client called, but request channel not configured"))?;
	// 	let r = req.new_regular()?;
	// 	Ok(r)
	// }

	/// Loop until some type of exit and return final [Response] and state data
	/// when finished.
	///
	/// If any of the threads exited with [crate::Error], this function will
	/// return a new error which combines those errors.
	pub fn loop_until_exit(mut self) -> Result<(Response, T)> {
		log::info!("looping until exit");
		let rsp = self.ctx.loop_until_exit()?;
		let (t, err) = self.join()?;
		if !err.is_empty() {
			let err = err.join(" | ");
			Err(crate::Error::msg(format!("errors: {err}")))
		} else {
			Ok((rsp, t))
		}
	}

	/// Detach completely from the target.
	pub fn detach(mut self) -> Result<(T, Vec<String>)> {
		self.ctx.client_mut().detach()?;
		let t = self.join()?;
		Ok(t)
	}

	/// When all [ctx::Secondary] contexts are detached, call this to join all
	/// threads and return final state data.
	///
	/// If you use [Self::loop_until_exit], this is called at the end. That is
	/// the recommended method to use.
	///
	/// The returned value from this is the `state` supplied and fatal errors
	/// which happened.
	pub fn join(self) -> Result<(T, Vec<String>)> {
		log::info!("joining all threads");
		let mut errs = Vec::new();
		#[cfg(feature = "plugins")]
		for (key, plugin) in self.ctx.plugins.into_iter() {
			log::debug!("witing for plugin {key:?}");
			let done = plugin.handle.join();
			// .unwrap_or_else(|_| panic!("plugin thread {key} failed"))?;
			if let Err(e) = done {
				let err = format!("plugin thread {key} failed: {e:?}");
				errs.push(err);
			}
		}
		if let Err(e) = self.handle.join() {
			let err = format!("thread handle failed: {e:?}");
			errs.push(err);
		}
		Ok((self.ctx.data, errs))
	}

	/// Attach to the process described by `proc`
	pub fn new_attach(proc: Process, data: T) -> Result<Self> {
		let (req, acc) = ReqNewClient::new();

		let handle = std::thread::spawn(move || -> Result<()> {
			let tracer = Tracer::attach(proc)?;
			let mgr = CtrlTracer::new(tracer, acc)?;
			mgr.scheduler()?;
			Ok(())
		});
		let client = req.new_regular()?;
		log::info!("ready to send commands to target");

		let ctx = ctx::Secondary::new_master(client, data, req)?;
		Ok(Self::new(ctx, handle))
	}
}
