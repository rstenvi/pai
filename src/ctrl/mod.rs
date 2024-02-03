use crate::{
	api::{messages::NewClientReq, Client, Command, Response},
	Result,
};
use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

pub mod thread;
pub mod tracer;

#[derive(Debug)]
pub struct ReqNewClient {
	tx: Sender<NewClientReq>,
	rx: Receiver<Client<Command, Response>>,
}

impl ReqNewClient {
	pub fn new() -> (Self, AcceptNewClient) {
		let (tx1, rx1) = unbounded();
		let (tx2, rx2) = unbounded();
		let s = Self { tx: tx1, rx: rx2 };
		let s2 = AcceptNewClient::new(tx2, rx1);
		(s, s2)
	}
	pub fn new_regular(&self) -> Result<Client<Command, Response>> {
		self.tx.send(NewClientReq::Regular)?;
		let r = self.rx.recv()?;
		Ok(r)
	}
}
pub struct AcceptNewClient {
	tx: Sender<Client<Command, Response>>,
	rx: Receiver<NewClientReq>,
}
impl AcceptNewClient {
	pub fn new(tx: Sender<Client<Command, Response>>, rx: Receiver<NewClientReq>) -> Self {
		Self { tx, rx }
	}
	pub fn recv(&self) -> Result<NewClientReq> {
		Ok(self.rx.recv()?)
	}
	pub fn try_recv(&self) -> Result<Option<NewClientReq>> {
		match self.rx.recv_timeout(Duration::from_millis(10)) {
			Ok(n) => Ok(Some(n)),
			Err(RecvTimeoutError::Timeout) => Ok(None),
			Err(RecvTimeoutError::Disconnected) => todo!(),
		}
	}
	pub fn send(&self, client: Client<Command, Response>) -> Result<()> {
		self.tx
			.send(client)
			.map_err(|x| crate::Error::msg(format!("unable to send client {x:?}")))?;
		Ok(())
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ClientState {
	/// The client is currently blocking a thread from continuing
	Blocking,

	/// The client has sent in their [Wait] and is not blocking any thread
	NotBlocking,
	Detaching,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ClientType {
	/// Regular injected point which receives messages meant for them and must
	/// send response back.
	Regular,
}

impl ClientType {
	pub fn initial_state(&self) -> ClientState {
		match self {
			ClientType::Regular => ClientState::Blocking,
		}
	}
	// pub fn sends_ack(&self) -> bool {
	// 	*self == Self::Regular
	// }
	// pub fn no_ack(&self) -> bool {
	// 	!self.sends_ack()
	// }
}
