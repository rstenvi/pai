use crate::api::{Client, Command, Response};
use crate::ctrl::tracer::CtrlTracer;
use crate::ctrl::{self, ReqNewClient};
use crate::ctx;
use crate::trace::ptrace::Tracer;
use crate::utils::process::Process;
use crate::{Error, Result, TargetPtr};
use std::thread::JoinHandle;
pub struct Master<T> {
	// TODO: Remove pub here
	pub ctx: ctx::Secondary<T>,
	handle: JoinHandle<Result<()>>,
}
impl<T> Master<T> {
	pub fn get_new(attach: bool, mut args: Vec<String>, state: T) -> Result<Self> {
		let ctx = if attach {
			let name = args.remove(0);
			if !args.is_empty() {
				log::warn!("extra args '{args:?}' will be ignored");
			}
			let pid = Process::arg_to_pid(&name)?;
			let proc = Process::from_pid(pid as u32)?;
			Self::attach(proc, state)?
		} else {
			let name = args.remove(0);
			let mut cmd = std::process::Command::new(name);
			cmd.args(args);
			Self::spawn(cmd, state)?
		};
		Ok(ctx)
	}
	pub fn new(ctx: ctx::Secondary<T>, handle: JoinHandle<Result<()>>) -> Self {
		Self { ctx, handle }
	}
	pub fn ctx_mut(&mut self) -> &mut ctx::Secondary<T> {
		&mut self.ctx
	}
	pub fn ctx(&self) -> &ctx::Secondary<T> {
		&self.ctx
	}
	pub fn attach_pid(pid: u32, data: T) -> Result<Self> {
		let proc = Process::from_pid(pid)?;
		Self::attach(proc, data)
	}

	pub fn attach_procname(name: &str, data: T) -> Result<Self> {
		let proc = Process::procname_to_process(name)?;
		Self::attach(proc, data)
	}
	pub fn attach(proc: Process, data: T) -> Result<Self> {
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
	pub fn spawn(cmd: std::process::Command, data: T) -> Result<Self> {
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
	pub fn new_client(&mut self) -> Result<Client<Command, Response>> {
		if let Some(req) = &mut self.ctx.req {
			let r = req.new_regular()?;
			Ok(r)
		} else {
			Err(Error::Unknown.into())
		}
	}

	pub fn loop_until_exit(mut self) -> Result<T> {
		log::info!("looping until exit");
		self.ctx.loop_until_exit()?;

		self.join()
	}

	pub fn join(self) -> Result<T> {
		log::info!("joining all threads");
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
}
