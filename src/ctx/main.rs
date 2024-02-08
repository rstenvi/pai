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
/// reference to whenever a callback is called.
///
/// The generic `Err` is the error value returned by the callbacks implemented.
/// This could [crate::Error], [anyhow::Error] or some other specific error
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

	/// Create new, either by attaching to existing or by spawning program in `args`
	pub fn new_main(attach: bool, mut args: Vec<String>, state: T) -> Result<Self> {
		let ctx = if attach {
			let name = args.remove(0);
			if !args.is_empty() {
				log::warn!("extra args '{args:?}' will be ignored");
			}
			let pid = Process::arg_to_pid(&name)?;
			let proc = Process::from_pid(pid as u32)?;
			Self::new_attach(proc, state)?
		} else {
			let name = args.remove(0);
			let mut cmd = std::process::Command::new(name);
			cmd.args(args);
			Self::new_spawn(cmd, state)?
		};
		Ok(ctx)
	}
	pub fn spawn_in_mem<S: Into<String>, V: Into<Vec<String>>>(
		name: S,
		elf: Vec<u8>,
		args: V,
		data: T,
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

		let args = ArgsBuilder::new()
			.handle_exec()
			.finish()?;
		ctx.client_mut().set_config(args)?;
		let tid = ctx.get_first_stopped()?;
		let old = ctx.run_until_exec()?;
		assert!(tid == old);

		let mainloc = ctx.proc.exact_match_path("/memfd:rust_exec (deleted)")?
			.expect("unable to location of main binary");

		ctx.set_main_exe(mainloc.addr(), elf)?;

		// Restore back default config
		ctx.client_mut().set_config(Args::default())?;

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
	pub fn loop_until_exit(mut self) -> Result<(Response, T)> {
		log::info!("looping until exit");
		let rsp = self.ctx.loop_until_exit()?;
		let t = self.join()?;
		Ok((rsp, t))
	}

	/// When all [ctx::Secondary] contexts are detached, call this to join all
	/// threads and return final state data.
	///
	/// If you use [Self::loop_until_exit], this is called at the end.
	pub fn join(self) -> Result<T> {
		log::info!("joining all threads");
		#[cfg(feature = "plugins")]
		for (key, plugin) in self.ctx.plugins.into_iter() {
			log::debug!("witing for plugin {key:?}");
			plugin
				.handle
				.join()
				.unwrap_or_else(|_| panic!("plugin thread {key} failed"))?;
		}
		self.handle.join().expect("thread for handle failed")?;
		Ok(self.ctx.data)
	}

	fn new_attach(proc: Process, data: T) -> Result<Self> {
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
