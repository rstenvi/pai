use crate::{
	api::{client::IdWrapper, messages::Stopped}, arch::NamedRegs, evtlog::Loggers, target::GenericCc, utils::process::Tid, Result
};
use crossbeam_channel::{Receiver, Sender};

#[cfg(feature = "syscalls")]
use crate::api::messages::Stop;
#[cfg(feature = "syscalls")]
use crate::syscalls::SyscallItem;

use crate::api::{
	args::{Args, ClientArgs},
	messages::{ClientProxy, Command, Event, ManagerCmd, MasterComm, Response},
	Client,
};

/// Running on separate thread which handles all communication with the real
/// client.
pub(crate) struct ClientThread {
	/// ID of this client
	id: usize,

	client: Client<MasterComm, Response>,

	/// Receive command from client
	rx: Receiver<Command>,

	/// Send respons to client
	tx: Sender<Response>,

	args: ClientArgs,

	done: bool,

	/// Syscall where we've gotten [Stop::SyscallEnter], but not
	/// [Stop::SyscallExit]
	#[cfg(feature = "syscalls")]
	pending_syscalls: std::collections::HashMap<Tid, SyscallItem>,

	loggers: Loggers,

	syscallcc: GenericCc,
}

impl ClientThread {
	pub fn new(
		id: usize,
		mtx: Sender<MasterComm>,
		mrx: Receiver<Response>,
		rx: Receiver<Command>,
		tx: Sender<Response>,
	) -> Self {
		let wrap = IdWrapper::new(id);
		let wrap = Box::new(wrap);
		let client = Client::new_master_comm(mtx, mrx, wrap);
		let args = ClientArgs::default();
		let loggers = Loggers::default();
		let syscallcc = GenericCc::new_syscall_host().unwrap();
		Self {
			id,
			client,
			rx,
			tx,
			args,
			#[cfg(feature = "syscalls")]
			pending_syscalls: std::collections::HashMap::new(),
			done: false,
			loggers,
			syscallcc,
		}
	}
	fn set_config(&mut self, config: Args) -> Option<MasterComm> {
		let next = config.clone();
		self.args.replace_config(config);
		let config = next.forward_master();
		Some(MasterComm::new(
			self.id,
			Command::Manager {
				cmd: ManagerCmd::SetConfig { config },
			},
		))
	}
	fn set_config_thread(&mut self, tid: Tid, config: Args) -> Option<MasterComm> {
		let next = config.clone();
		self.args.replace_config_thread(tid, config);
		let config = next.forward_master();
		Some(MasterComm::new(
			self.id,
			Command::Manager {
				cmd: ManagerCmd::SetConfigThread { tid, config },
			},
		))
	}
	fn send_config(&self, tid: Option<Tid>) -> Result<()> {
		let config = self.args.clone_config(tid);
		let value = serde_json::to_value(config)?;
		self.tx.send(Response::Value(value))?;
		Ok(())
	}
	#[cfg(feature = "syscalls")]
	fn resolve_sysno(&self, name: &str) -> Result<Response> {
		let ret = crate::PARSED
			.read()
			.expect("unable to lock parsed")
			.consts
			.find_sysno(name, &crate::syzarch());
		let r = serde_json::to_value(ret)?;
		Ok(Response::Value(r))
	}
	fn handle_client_proxy(&mut self, cmd: ClientProxy) -> Result<Option<MasterComm>> {
		match cmd {
			ClientProxy::SetConfig { config } => Ok(self.set_config(config)),
			ClientProxy::SetConfigThread { tid, config } => Ok(self.set_config_thread(tid, config)),
			ClientProxy::GetConfig => {
				self.send_config(None)?;
				Ok(None)
			}
			ClientProxy::GetConfigThread { tid } => {
				self.send_config(Some(tid))?;
				Ok(None)
			}
			#[cfg(feature = "syscalls")]
			ClientProxy::ResolveSyscall(name) => {
				let r = self.resolve_sysno(&name)?;
				self.tx.send(r)?;
				Ok(None)
			}
			ClientProxy::Detach => {
				self.done = true;
				let r = MasterComm::new(
					self.id,
					Command::Manager {
						cmd: ManagerCmd::Detach,
					},
				);
				Ok(Some(r))
			},
    		ClientProxy::AddLogger { format, output } => {
				self.loggers.add_logger(format, output)?;
				self.tx.send(Response::Ack)?;
				Ok(None)
			},
		}
	}
	fn next_client_command(&mut self) -> Result<Option<MasterComm>> {
		log::debug!("recv next from client");
		let r = self.rx.recv()?;
		self.loggers.log_command(&r)?;
		log::debug!("got {r:?}");
		match r {
			Command::ClientProxy { cmd } => self.handle_client_proxy(cmd),
			_ => {
				Ok(Some(MasterComm::new(self.id, r)))
			},
		}
	}

	fn process_event(&self, event: Event) -> Result<Option<Response>> {
		Ok(Some(Response::Event(event)))
	}
	#[cfg(feature = "syscalls")]
	fn enrich(
		&mut self,
		sysno: usize,
		sys: &mut SyscallItem,
		dir: crate::syscalls::Direction,
	) -> Result<()> {
		use crate::api::args::Enrich;
		let enrich = self.args.enrich_syscall_sysno(sys.tid, sysno);
		match enrich {
			Enrich::None => {}
			Enrich::Basic => sys.enrich_values()?,
			Enrich::Full => sys.parse_deep(sys.tid, &mut self.client, dir)?,
		}
		Ok(())
	}
	fn fill_syscall_regs(args: &mut Vec<u64>, cc: &GenericCc, regs: &dyn NamedRegs) -> Result<()> {
		let len = args.capacity();
		for i in 0..len {
			let ins = cc.get_arg_regonly(i, regs)?;
			args.push(ins);
		}
		Ok(())
	}
	#[cfg(feature = "syscalls")]
	fn transform_syscall(&mut self, tid: Tid, entry: bool) -> Result<Option<Response>> {
		use crate::{api::args::Enrich, arch::NamedRegs, syscalls::Direction};
		log::trace!("transform syscall {tid} {entry}");
		let regs = self.client.get_libc_regs(tid)?;
		if entry {
			let sysno = regs.get_sysno();
			if self.args.handles_syscall_sysno(tid, sysno) {
				let mut args = Vec::with_capacity(6);
				Self::fill_syscall_regs(&mut args, &self.syscallcc, &regs)?;
				let mut ins = SyscallItem::from_regs(tid, sysno, &args);
				self.enrich(sysno, &mut ins, Direction::In)?;
				let resp = if !self.args.only_notify_syscall_exit(tid) {
					Some(Response::Syscall(ins.clone()))
				} else {
					None
				};
				self.pending_syscalls.insert(tid, ins);
				Ok(resp)
			} else {
				Ok(None)
			}
		} else if let Some(mut syscall) = self.pending_syscalls.remove(&tid) {
			let retval = self.syscallcc.get_retval(&regs)?;
			syscall.fill_in_output(retval.into());
			self.enrich(syscall.sysno, &mut syscall, Direction::Out)?;
			let ret = Some(Response::Syscall(syscall));
			Ok(ret)
		} else {
			log::debug!("syscall exit, but no preceeding syscall entry");
			Ok(None)
		}
	}
	fn process_stopped(&mut self, s: Stopped) -> Result<Option<Response>> {
		log::trace!("process stop {s:?}");
		match &s.stop {
			#[cfg(feature = "syscalls")]
			Stop::SyscallEnter | Stop::SyscallExit => {
				if self.args.transform_syscalls(s.tid) {
					let r = self.transform_syscall(s.tid, matches!(s.stop, Stop::SyscallEnter))?;
					Ok(r)
				} else if self.args.intercept_all_syscalls(s.tid) {
					Ok(Some(Response::Stopped(s)))
				} else {
					Ok(None)
				}
			}
			_ => Ok(Some(Response::Stopped(s))),
		}
	}
	fn process_response(&mut self, resp: Response) -> Result<Option<Response>> {
		log::trace!("processing {resp:?}");
		match resp.clone() {
			Response::Ack => Ok(Some(resp)),
			Response::Removed | Response::TargetExit => {
				log::info!("client is removed {}", self.id);
				self.done = true;
				Ok(Some(resp))
			}
			Response::Value(_v) => Ok(Some(resp)),
			Response::Event(e) => self.process_event(e),
			Response::Stopped(s) => self.process_stopped(s),
			#[cfg(feature = "syscalls")]
			Response::Syscall(_) => todo!(),
		}
	}

	pub fn enter_loop(mut self) -> Result<()> {
		log::info!("entering loop");
		while !self.done {
			let mut r = None;
			while r.is_none() {
				r = self.next_client_command()?;
			}
			let r = r.expect("cmd is somehow None");
			log::debug!("sending {r:?}");
			self.client.write(r)?;
			loop {
				let r = self.client.read()?;
				if let Some(r) = self.process_response(r)? {
					log::debug!("sending to clients {r:?}");
					self.loggers.log_response(&r)?;
					self.tx.send(r)?;
					break;
				} else {
					let msg = MasterComm::new(self.id, Command::wait());
					log::debug!("sending wait back {msg:?}");
					self.client.write(msg)?;
				}
			}
		}
		self.loggers.finish()?;
		log::info!("{}: exiting loop", self.id);
		Ok(())
	}
}
