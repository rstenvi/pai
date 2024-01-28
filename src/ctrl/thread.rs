use crate::{
	api::client::IdWrapper,
	arch::ReadRegisters,
	syscalls::SyscallItem,
	syzarch,
	trace::{Stop, Stopped},
	utils::process::Tid,
	Result,
};
use crossbeam_channel::{Receiver, Sender};
use std::collections::HashMap;

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
	pending_syscalls: HashMap<Tid, SyscallItem>,
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
		let pending_syscalls = HashMap::new();
		Self {
			id,
			client,
			rx,
			tx,
			args,
			pending_syscalls,
			done: false,
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
	fn resolve_sysno(&self, name: &str) -> Result<Response> {
		let ret = crate::PARSED
			.read()
			.expect("unable to lock parsed")
			.consts
			.find_sysno(name, &syzarch());
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
			}
		}
	}
	fn next_client_command(&mut self) -> Result<Option<MasterComm>> {
		log::debug!("recv next from client");
		let r = self.rx.recv()?;
		log::debug!("got {r:?}");
		match r {
			Command::ClientProxy { cmd } => self.handle_client_proxy(cmd),
			_ => Ok(Some(MasterComm::new(self.id, r))),
		}
	}

	fn process_event(&self, event: Event) -> Result<Option<Response>> {
		Ok(Some(Response::Event(event)))
	}
	fn transform_syscall(&mut self, tid: Tid, entry: bool) -> Result<Option<Response>> {
		log::trace!("transform syscall {tid} {entry}");
		let regs = self.client.get_libc_regs(tid)?;
		if entry {
			let sysno = regs.sysno();
			if self.args.intercept_all_syscalls(tid) || self.args.handles_syscall_sysno(tid, sysno)
			{
				let ins = SyscallItem::from_regs(tid, &regs);
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
			syscall.fill_in_output(&regs);
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
					self.tx.send(r)?;
					break;
				} else {
					let msg = MasterComm::new(self.id, Command::wait());
					log::debug!("sending wait back {msg:?}");
					self.client.write(msg)?;
				}
			}
		}
		log::info!("{}: exiting loop", self.id);
		Ok(())
	}
}
