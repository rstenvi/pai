use crate::{
	api::{
		args::ClientArgs,
		messages::{Cont, Event, ExecSyscall, MasterComm, NewClientReq, RegEvent, Stopped},
		Client, Command, ManagerCmd, ProcessCmd, RemoteCmd, Response, ThreadCmd,
	},
	ctrl::ClientState,
	trace::ptrace::Tracer,
	utils::process::Tid,
	Error, Result,
};
use crossbeam_channel::{unbounded, Receiver, Sender};
use std::{collections::HashMap, thread::JoinHandle};

use super::{thread::ClientThread, AcceptNewClient, ClientType};

#[derive(Default)]
pub struct CtrlTracerConfig {
	init_is_over: bool,
	no_attach_children: bool,
}

pub struct CtrlTracer {
	lastclientid: usize,
	clients: HashMap<usize, ClientMaster>,
	acc: AcceptNewClient,
	tracer: Tracer,
	check_new_client: usize,

	/// Shared receiver for all clients
	rx: Receiver<MasterComm>,

	/// Other end of [Self::rx], need to clone this when creating a new client
	mtx: Sender<MasterComm>,

	threads_stopped: Vec<Tid>,

	config: CtrlTracerConfig,
}

impl CtrlTracer {
	pub fn new(tracer: Tracer, acc: AcceptNewClient) -> Result<Self> {
		let lastclientid = 0; // This will give 1 to the first one
		let clients = HashMap::new();
		let (mtx, rx) = unbounded();
		let config = CtrlTracerConfig::default();
		let threads_stopped = Vec::new();
		let r = Self {
			lastclientid,
			clients,
			acc,
			tracer,
			rx,
			mtx,
			config,
			threads_stopped,
			check_new_client: 0,
		};
		Ok(r)
	}

	/// Where all of the work in the master is performed
	pub fn scheduler(mut self) -> Result<()> {
		log::info!("entering scheduler");

		// Usually we attach to all children
		if !self.config.no_attach_children {
			self.attach_children()?;
		} else {
			// Optionally, we can only wait for the initial attach
			let s = self.wait_stop()?;
			if s.is_none() {
				log::warn!("target stopped before we entered loop");
				return Ok(());
			}
		}
		log::info!("Got initial attach for {:?}", self.threads_stopped);

		// Before we can contionue, we must at least get one client
		self.new_client(true)?;
		while !self.clients.is_empty() && !self.threads_stopped.is_empty() {
			log::debug!("entered loop");

			// Every blocking client must send their command before we can continue
			while self.num_clients_blocking() > 0 {
				self.get_from_clients()?;
				if self.check_new_client > 0 {
					self.new_client(true)?;
					self.check_new_client -= 1;
				}

				// If client has gone into NotBlocking state, we check if they
				// have any pending events to be sent to them. This might
				// transition them into Blocking state.
				for (_id, c) in self.clients.iter_mut() {
					if c.state == ClientState::NotBlocking {
						if let Some(pending) = c.pending.pop() {
							c.send(pending)?;
						}
					}
				}
			}

			log::debug!("all clients done {:?}", self.threads_stopped);
			for tid in std::mem::take(&mut self.threads_stopped).into_iter() {
				let cont = self.find_cont(tid);
				self.tracer.cont(tid, cont)?;
			}

			// Check for new clients if master has not indicated that init is
			// over
			// TODO: Probably don't need this
			if !self.config.init_is_over {
				// self.new_client(false)?;
			}

			// Remove all clients put into Detaching state
			self.remove_detached()?;

			// Only wait for next if there are any clients left
			if !self.clients.is_empty() {
				log::trace!("clients {:?}", self.clients);
				if let Some(stop) = self.wait_stop()? {
					self.handle_stop(stop)?;
				} else {
					log::info!("breaking because of targetexit");
					break;
				}
			}
		}
		// Give the user some details about why loop ended
		log::info!(
			"scheduler ended clients: {} | threads_stopped: {}",
			self.clients.len(),
			self.threads_stopped.len()
		);
		self.remove_detached()?;

		// If all clients have exited, but we still have threads left, send a
		// final detach
		for tid in std::mem::take(&mut self.threads_stopped).into_iter() {
			self.tracer.detach(tid)?;
		}

		// If we have no more threads, but we do have clients, we send a
		// TargetExit message
		for (i, mut client) in self.clients.into_iter() {
			client.send(Response::TargetExit)?;
			client
				.handle
				.join()
				.unwrap_or_else(|_| panic!("thread for client {i} failed"))?;
		}
		Ok(())
	}

	fn remove_detached(&mut self) -> Result<()> {
		let removed: Vec<ClientMaster> = self
			.clients
			.extract_if(|_x, y| y.state == ClientState::Detaching)
			.map(|(_x, y)| y)
			.collect();
		log::debug!("removed {} clients", removed.len());
		for client in removed.into_iter() {
			client
				.handle
				.join()
				.unwrap_or_else(|_| panic!("thread for client {} failed", client.id))?;
		}
		Ok(())
	}
	fn attach_children(&mut self) -> Result<()> {
		let mut kids = self.tracer.attach_children()?;
		log::info!("attaching to kids: {kids:?}");
		while !kids.is_empty() {
			let stop = self.wait_stop()?;
			log::trace!("got stop {stop:?}");
			let r = kids
				.extract_if(|x| {
					if let Some(s) = &stop {
						*x == s.tid
					} else {
						false
					}
				})
				.collect::<Vec<_>>();
			assert!(r.len() == 1);
		}
		Ok(())
	}

	fn wait_stop(&mut self) -> Result<Option<Stopped>> {
		let stop = self.tracer.wait();
		match stop {
			Ok(s) => {
				self.threads_stopped.push(s.tid);
				Ok(Some(s))
			}
			Err(Error::TargetStopped) => Ok(None),
			Err(e) => Err(e),
		}
	}
	fn num_clients_blocking(&self) -> usize {
		log::debug!("clients {} {:?}", self.clients.len(), self.clients);
		let num = self
			.clients
			.iter()
			.filter(|(_, x)| matches!(x.state, ClientState::Blocking))
			.count();
		log::debug!("num blocking {num}");
		num
	}
	fn handle_stop(&mut self, stop: Stopped) -> Result<()> {
		log::debug!("stop {stop:?}");
		for (_, client) in self.clients.iter_mut() {
			if client.args.handles_stop(stop.tid, &stop.stop) {
				client.send_stop(stop.clone())?;
			}
		}
		Ok(())
	}
	fn find_cont(&mut self, tid: Tid) -> Cont {
		let mut ret = Cont::Cont;
		for (key, client) in self.clients.iter_mut() {
			let c: Cont = client.get_cont(tid);
			log::debug!("cont {key} {tid} {c:?}");
			if c > ret {
				ret = c;
			}
		}
		ret
	}
	fn remove_client(&mut self, id: usize) -> Result<ClientMaster> {
		self.clients.remove(&id).ok_or(Error::client_not_found(id))
	}
	fn get_from_clients(&mut self) -> Result<()> {
		log::trace!("getting command from clients");
		let r = self.rx.recv()?;
		log::trace!("command {r:?}");
		let mut client = self.remove_client(r.client)?;

		// Cannot trigger error until we've inserted the client back in
		let res = self.handle_cmd(&mut client, r.cmd);
		log::trace!("inserting client back in");
		self.clients.insert(client.id, client);
		res
	}
	fn handle_cmd(&mut self, client: &mut ClientMaster, ocmd: Command) -> Result<()> {
		log::debug!("got cmd {ocmd:?}");
		let resp = match ocmd {
			Command::Tracer { cmd } => self.handle_cmd_remote(client, cmd)?,
			Command::Manager { cmd } => self.handle_cmd_manager(client, cmd)?,
			Command::ClientProxy { cmd: _ } => {
				crate::bug!("Command::ClientProxy should not be forwarded to master")
			}
			Command::Client { tid: _, cmd: _ } => {
				crate::bug!("Command::Client should not be forwarded to master")
			}
		};

		if let Some(resp) = resp {
			client.send_answer(resp)?;
		} else {
			client.set_state_noresp()?;
		}

		Ok(())
	}
	fn handle_cmd_remote_process(
		&mut self,
		_client: &mut ClientMaster,
		cmd: ProcessCmd,
	) -> Result<Option<Response>> {
		let r = match cmd {
			ProcessCmd::GetTids => {
				let ins = self.tracer.get_tids();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ProcessCmd::GetThreadsStatus => {
				let ins = self.tracer.get_threads_status();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ProcessCmd::GetPid => {
				let ins = self.tracer.get_pid();
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ProcessCmd::SetTrampolineCode { tramp, code } => {
				let ins = self.tracer.set_trampoline_code(tramp, code);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
		};
		Ok(Some(r))
	}
	fn handle_cmd_remote_thread(
		&mut self,
		client: &mut ClientMaster,
		tid: Tid,
		cmd: ThreadCmd,
	) -> Result<Option<Response>> {
		let r = match cmd {
			ThreadCmd::GetLibcRegs => {
				let ins = self.tracer.get_libc_regs(tid);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::SetLibcRegs { regs } => {
				let ins = self.tracer.set_libc_regs(tid, regs);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::ReadCString { addr } => {
				let ins = self.tracer.read_c_string(tid, addr);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::ReadBytes { addr, count } => {
				let ins = self.tracer.read_memory(tid, addr, count);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::InsertBp { addr } => {
				let ins = self.tracer.insert_single_bp(client.id, tid, addr);
				if ins.is_ok() {
					client.args.insert_bp(addr);
				}
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			},
			ThreadCmd::AllocAndWriteBp => {
				let ins = self.tracer.alloc_and_write_bp(client.id, tid);
				if let Ok(addr) = &ins {
					client.args.insert_bp(*addr);
				}
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			},
			// ThreadCmd::RemoveBp { addr } => {
			// 	let ins = self.tracer.remove_bp(tid, addr);
			// 	let val = serde_json::to_value(ins)?;
			// 	Response::Value(val)
			// }
			// ThreadCmd::GetAgnosticReg { reg: _ } => todo!(),
			ThreadCmd::WriteBytes { addr, bytes } => {
				let ins = self.tracer.write_memory(tid, addr, &bytes);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			// ThreadCmd::CallFunc { func, args } => {
			// 	let ins = self.tracer.call_func(tid, func, &args);
			// 	let val = serde_json::to_value(ins)?;
			// 	Response::Value(val)
			// }
			ThreadCmd::ExecRawSyscall { sysno, args } => {
				let ins = self.tracer.exec_syscall(tid, sysno, &args);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::WriteScratchBytes { bytes } => {
				let ins = self.tracer.scratch_write_bytes(tid, bytes);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::WriteScratchString { string } => {
				let ins = self.tracer.scratch_write_c_str(tid, string);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::FreeScratchAddr { addr } => {
				let ins = self.tracer.scratch_free_addr(tid, addr);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::StepIns { count } => {
				log::debug!("setting step for {tid}");
				client.set_step_ins(tid, count);
				Response::Ack
			}
			ThreadCmd::ExecRet => {
				let ins = self.tracer.exec_ret(tid);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::ExecSyscall { syscall } => {
				let val = match syscall {
					ExecSyscall::Getpid => {
						let ins = self.tracer.exec_sys_getpid(tid);
						serde_json::to_value(ins)?
					}
					ExecSyscall::MmapAnon { size, prot } => {
						let ins = self.tracer.exec_sys_anon_mmap(tid, size, prot);
						serde_json::to_value(ins)?
					}
				};
				Response::Value(val)
			}
			ThreadCmd::GetTrampolineAddr { tramp } => {
				let ins = self.tracer.get_trampoline_addr(tid, tramp);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
			ThreadCmd::RunUntilTrap => {
				let ins = self.tracer.run_until_trap(tid);
				let val = serde_json::to_value(ins)?;
				Response::Value(val)
			}
		};
		Ok(Some(r))
	}
	fn handle_cmd_remote(
		&mut self,
		client: &mut ClientMaster,
		rcmd: RemoteCmd,
	) -> Result<Option<Response>> {
		match rcmd {
			RemoteCmd::Process { cmd } => self.handle_cmd_remote_process(client, cmd),
			RemoteCmd::Thread { tid, cmd } => self.handle_cmd_remote_thread(client, tid, cmd),
		}
	}
	fn cmd_remove_client(&mut self, cid: usize) -> Result<()> {
		if let Some(client) = self.clients.get_mut(&cid) {
			client.send(Response::Removed)?;
		}
		Ok(())
	}

	fn handle_cmd_manager(
		&mut self,
		client: &mut ClientMaster,
		cmd: ManagerCmd,
	) -> Result<Option<Response>> {
		match cmd {
			ManagerCmd::Wait => {
				let r = client.pending.pop();
				log::debug!("pending {r:?}");
				Ok(r)
			}
			ManagerCmd::Detach => {
				client.state = ClientState::Detaching;
				Ok(Some(Response::Ack))
			}
			ManagerCmd::InitDone => {
				self.config.init_is_over = true;
				Ok(Some(Response::Ack))
			}
			ManagerCmd::SendEvent { event } => {
				self.handle_cmd_send_event(client, event)?;
				Ok(Some(Response::Ack))
			}
			ManagerCmd::RemoveClient { cid } => {
				self.cmd_remove_client(cid)?;
				Ok(Some(Response::Ack))
			}
			ManagerCmd::SetConfig { config } => {
				client.args.replace_config(config);
				Ok(Some(Response::Ack))
			}
			ManagerCmd::SetConfigThread { tid, config } => {
				client.args.replace_config_thread(tid, config);
				Ok(Some(Response::Ack))
			}
			ManagerCmd::PrepareLoadClient => {
				self.check_new_client += 1;
				Ok(Some(Response::Ack))
			}
			ManagerCmd::DetachThread { tid } => {
				client.detach_thread(tid);
				Ok(Some(Response::Ack))
			}
		}
	}

	fn handle_cmd_send_event(
		&mut self,
		client: &mut ClientMaster,
		event: Event,
	) -> Result<Response> {
		let reg = RegEvent::from_event(&event.event);
		for (_i, client) in self.clients.iter_mut() {
			if client.args.handles_regevent(&reg) {
				// client.send_event(event.clone())?;
				client.add_pending(Response::Event(event.clone()));
			}
		}

		// We need to keep the responses in order, so add as pending. The event
		// will be sent after we send this answer
		if client.args.handles_regevent(&reg) {
			client.add_pending(Response::Event(event));
		}
		Ok(Response::Ack)
	}
	fn create_new_client(&mut self, ctype: ClientType) -> Result<crate::Client> {
		self.lastclientid += 1;
		let nid = self.lastclientid;

		// Lots of different channels
		let (tx1, rx1) = unbounded();
		let (tx2, rx2) = unbounded();
		let (tx3, rx3) = unbounded();

		let client_thread = ClientThread::new(nid, self.mtx.clone(), rx1, rx2, tx3);

		let handle = std::thread::spawn(move || -> Result<()> {
			client_thread.enter_loop()?;
			Ok(())
		});

		let client_us = ClientMaster::new(nid, ctype, tx1, handle);

		let client_send = Client::new_client(nid, tx2, rx3);
		self.clients.insert(nid, client_us);
		Ok(client_send)
	}
	fn handle_new_client(&mut self, req: NewClientReq) -> Result<crate::Client> {
		let cl = match req {
			NewClientReq::Regular => self.create_new_client(ClientType::Regular)?,
		};

		Ok(cl)
	}
	fn new_client(&mut self, force: bool) -> Result<()> {
		log::debug!("checking new client force={force}");
		let req = if force {
			log::info!("waiting for new client");
			self.acc.recv()?
		} else if let Some(n) = self.acc.try_recv()? {
			n
		} else {
			return Ok(());
		};
		log::info!("new client req {req:?}");
		let cl = self.handle_new_client(req)?;
		self.acc.send(cl)?;
		Ok(())
	}
}

impl std::fmt::Debug for ClientMaster {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Client")
			.field("id", &self.id)
			.field("ctype", &self.ctype)
			.field("state", &self.state)
			.finish()
	}
}

/// Held on the master thread.
pub struct ClientMaster {
	pub id: usize,
	pub tx: Sender<Response>,
	ctype: ClientType,
	state: ClientState,
	pending: Vec<Response>,
	handle: JoinHandle<Result<()>>,
	args: ClientArgs,
	single_cont: HashMap<Tid, (Cont, usize)>,
}

impl ClientMaster {
	pub fn new(
		id: usize,
		ctype: ClientType,
		tx: Sender<Response>,
		handle: JoinHandle<Result<()>>,
	) -> Self {
		// let registered = Vec::new();
		let args = ClientArgs::default();
		let state = ctype.initial_state();
		let pending = Vec::new();
		let single_cont = HashMap::new();
		Self {
			id,
			ctype,
			tx,
			handle,
			args,
			state,
			pending,
			single_cont,
		}
	}
	pub fn detach_thread(&mut self, tid: Tid) {
		self.args.detach_thread(tid);
	}
	fn set_state_sent_event(&mut self) {
		self.state = match self.ctype {
			ClientType::Regular => ClientState::Blocking,
		};
	}
	fn set_state_noresp(&mut self) -> Result<()> {
		self.state = ClientState::NotBlocking;
		Ok(())
	}

	#[cfg(feature = "syscalls")]
	fn set_state_sent_syscall(&mut self) {
		self.state = match self.ctype {
			ClientType::Regular => ClientState::Blocking,
		};
	}
	fn set_state_response_from_cmd(&mut self) {
		self.state = match self.ctype {
			ClientType::Regular => ClientState::Blocking,
		};
	}
	fn set_state_removed(&mut self) {
		self.state = ClientState::Detaching;
	}
	fn set_state_target_exit(&mut self) {
		self.state = ClientState::Detaching;
	}
	fn set_state_stopped(&mut self) {
		self.state = ClientState::Blocking;
	}
	pub fn set_state_response(&mut self, rsp: &Response) {
		match rsp {
			Response::Ack => self.set_state_response_from_cmd(),
			Response::Value(_) => self.set_state_response_from_cmd(),
			Response::Event(_) => self.set_state_sent_event(),
			#[cfg(feature = "syscalls")]
			Response::Syscall(_) => self.set_state_sent_syscall(),
			Response::Stopped(_) => self.set_state_stopped(),
			Response::TargetExit => self.set_state_target_exit(),
			Response::Removed => self.set_state_removed(),
		}
	}

	pub fn set_step_ins(&mut self, tid: Tid, count: usize) {
		self.single_cont.insert(tid, (Cont::Step, count));
	}
	fn _get_cont(&mut self, tid: Tid) -> Cont {
		match self.state {
			ClientState::Detaching => Cont::default(),
			_ => self.args.get_cont(tid),
		}
	}
	pub fn get_cont(&mut self, tid: Tid) -> Cont {
		let ret = if let Some((c, mut count)) = self.single_cont.remove(&tid) {
			count -= 1;
			if count == 0 {
				c
			} else {
				self.single_cont.insert(tid, (c, count));
				self._get_cont(tid)
			}
		} else {
			self._get_cont(tid)
		};
		log::debug!("{tid}: cont {ret:?}");
		ret
	}

	// pub fn send_event(&mut self, event: Event) -> Result<()> {
	// 	self.send(Response::Event(event))?;
	// 	Ok(())
	// }
	pub fn send_stop(&mut self, stop: Stopped) -> Result<()> {
		log::debug!("sending stop {stop:?}");
		self.send(Response::Stopped(stop))?;
		Ok(())
	}
	pub fn send(&mut self, rsp: Response) -> Result<()> {
		if self.state != ClientState::Detaching {
			self.set_state_response(&rsp);
		}
		self.tx.send(rsp)?;
		Ok(())
	}
	pub fn send_answer(&mut self, rsp: Response) -> Result<()> {
		self.send(rsp)?;
		Ok(())
	}
	pub fn add_pending(&mut self, rsp: Response) {
		self.pending.insert(0, rsp);
	}
}
