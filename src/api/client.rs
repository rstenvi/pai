//! Code relevant to sending a command to a different thread/process/machine.

use crate::api::messages::{LogFormat, LogOutput};
use std::{
	io::{BufReader, BufWriter, Write},
	net::TcpStream,
};

use crate::{
	api::Command,
	bug_assert,
	utils::process::{Pid, Tid},
	Error, Result, TargetPtr,
};
use crossbeam_channel::{Receiver, Sender};

use super::{
	messages::{Event, MasterComm, Thread, TrampType},
	Args, ManagerCmd, RemoteCmd, Response, ThreadCmd,
};

macro_rules! client_read_int {
	($name:ident, $val:ty) => {
		pub fn $name(&mut self, tid: Tid, addr: TargetPtr) -> Result<$val> {
			let bytes = std::mem::size_of::<$val>();
			let cmd = RemoteCmd::read_bytes(tid, addr, bytes);
			let r = self.write_remote(cmd)?;
			let v = TryInto::<serde_json::Value>::try_into(r)?;
			let v: Result<Vec<u8>> = serde_json::from_value(v)?;
			match v {
				Ok(vec) => {
					let slice = vec.try_into().expect(&format!(
						"unable to convert to byteslice of fixed length {bytes}"
					));
					let r = <$val>::from_ne_bytes(slice);
					Ok(r)
				}
				Err(e) => Err(e),
			}
		}
	};
}

pub(crate) trait ApiWrapper<S, T> {
	fn wrap(&self, cmd: RemoteCmd) -> (usize, S);
	fn is_match(&self, id: usize, rsp: &T) -> bool;
	fn unwrap(&self, rsp: T) -> Response;
}
#[derive(Default)]
pub(crate) struct ClientGen;

impl ApiWrapper<Command, Response> for ClientGen {
	fn wrap(&self, cmd: RemoteCmd) -> (usize, Command) {
		(0, Command::Tracer { cmd })
	}
	fn is_match(&self, _id: usize, _rsp: &Response) -> bool {
		true
	}
	fn unwrap(&self, rsp: Response) -> Response {
		rsp
	}
}

trait ClientApi<TX, RX> {
	fn write(&mut self, tx: TX) -> Result<()>;
	fn read(&mut self) -> Result<RX>;
	fn write_read(&mut self, tx: TX) -> Result<RX>;
}

pub(crate) struct ClientTcpStream {
	stream:
		serde_json::Deserializer<serde_json::de::IoRead<std::io::BufReader<std::net::TcpStream>>>,
	writer: BufWriter<TcpStream>,
}
impl ClientTcpStream {
	pub fn new(stream: TcpStream) -> Result<Self> {
		let reader = BufReader::new(stream.try_clone().unwrap());
		let writer = BufWriter::new(stream);
		let stream = serde_json::Deserializer::from_reader(reader);
		Ok(Self { stream, writer })
	}
}

impl<TX: serde::Serialize, RX: serde::de::DeserializeOwned> ClientApi<TX, RX> for ClientTcpStream {
	fn write(&mut self, tx: TX) -> Result<()> {
		let v = serde_json::to_string(&tx)?;
		log::info!("writing {v:?}");
		self.writer.write_all(v.as_bytes())?;
		self.writer.flush()?;
		Ok(())
	}
	fn read(&mut self) -> Result<RX> {
		log::info!("trying to read");
		let v = RX::deserialize(&mut self.stream)?;
		Ok(v)
	}
	fn write_read(&mut self, tx: TX) -> Result<RX> {
		let v = serde_json::to_string(&tx)?;
		self.writer.write_all(v.as_bytes())?;
		let v = RX::deserialize(&mut self.stream)?;
		Ok(v)
	}
}

struct ClientThread<TX, RX> {
	tx: Sender<TX>,
	rx: Receiver<RX>,
}

impl<TX, RX> ClientThread<TX, RX> {
	fn new(tx: Sender<TX>, rx: Receiver<RX>) -> Self {
		Self { tx, rx }
	}
}

impl<TX, RX> ClientApi<TX, RX> for ClientThread<TX, RX>
where
	crate::Error: From<crossbeam_channel::SendError<TX>>,
{
	fn write(&mut self, tx: TX) -> Result<()> {
		self.tx.send(tx)?;
		Ok(())
	}
	fn read(&mut self) -> Result<RX> {
		let r = self.rx.recv()?;
		Ok(r)
	}
	fn write_read(&mut self, tx: TX) -> Result<RX> {
		self.write(tx)?;
		self.read()
	}
}

pub(crate) struct ClientStream<W: std::io::Write, R: std::io::Read> {
	stream: serde_json::Deserializer<serde_json::de::IoRead<std::io::BufReader<R>>>,
	writer: BufWriter<W>,
}
impl<W: std::io::Write, R: std::io::Read> ClientStream<W, R> {
	pub fn new(reader: BufReader<R>, writer: BufWriter<W>) -> Self {
		let stream = serde_json::Deserializer::from_reader(reader);
		Self { stream, writer }
	}
}
impl<
		TX: serde::Serialize,
		RX: serde::de::DeserializeOwned,
		W: std::io::Write,
		R: std::io::Read,
	> ClientApi<TX, RX> for ClientStream<W, R>
{
	fn write(&mut self, tx: TX) -> Result<()> {
		let v = serde_json::to_string(&tx)?;
		log::info!("writing {v:?}");
		self.writer.write_all(v.as_bytes())?;
		self.writer.flush()?;
		Ok(())
	}

	fn read(&mut self) -> Result<RX> {
		log::info!("trying to read");
		let v = RX::deserialize(&mut self.stream)?;
		Ok(v)
	}

	fn write_read(&mut self, tx: TX) -> Result<RX> {
		let v = serde_json::to_string(&tx)?;
		self.writer.write_all(v.as_bytes())?;
		let v = RX::deserialize(&mut self.stream)?;
		Ok(v)
	}
}

/// Object to send [Command] to different thread/process/machine where the
/// tracer is running.
///
/// You should not construct this directly, access is provided through
/// [crate::ctx::Secondary].
pub struct Client<TX: Send, RX: Send> {
	id: usize,
	wrap: Box<dyn ApiWrapper<TX, RX> + Send>,
	stream: Box<dyn ClientApi<TX, RX> + Send>,
}
impl<TX: Send + 'static, RX: Send + 'static> Client<TX, RX>
where
	crate::Error: From<crossbeam_channel::SendError<TX>>,
{
	pub(crate) fn new(
		id: usize, tx: Sender<TX>, rx: Receiver<RX>, wrap: Box<dyn ApiWrapper<TX, RX> + Send>,
	) -> Self {
		let stream = Box::new(ClientThread::new(tx, rx));
		Self { id, wrap, stream }
	}

	/// The ID which this client has been given by the trace controller.
	pub fn id(&self) -> usize {
		self.id
	}
	pub(crate) fn read(&mut self) -> Result<RX> {
		self.stream.read()
	}
	pub(crate) fn write(&mut self, val: TX) -> Result<()> {
		self.stream.write(val)
	}
	fn write_remote(&mut self, cmd: RemoteCmd) -> crate::Result<Response> {
		let (id, cmd) = self.wrap.wrap(cmd);
		self.stream.write(cmd)?;
		loop {
			let rsp = self.stream.read()?;
			if self.wrap.is_match(id, &rsp) {
				return Ok(self.wrap.unwrap(rsp));
			}
		}
	}
	pub(crate) fn write_read(&mut self, cmd: TX) -> crate::Result<RX> {
		self.stream.write(cmd)?;
		log::trace!("{}: reading response", self.id);
		let r = self.stream.read()?;
		Ok(r)
	}
}

impl<TX: Send + 'static> Client<TX, Response>
where
	crate::Error: From<crossbeam_channel::SendError<TX>>,
{
	// fn wr_value<R: serde::de::DeserializeOwned>(&mut self, cmd: TX) -> Result<R> {
	// 	let r = self.write_read(cmd)?;
	// 	let v = TryInto::<serde_json::Value>::try_into(r)?;
	// 	let v: Result<R> = serde_json::from_value(v)?;
	// 	v
	// }
	fn wr_value_remote<R: serde::de::DeserializeOwned>(&mut self, cmd: RemoteCmd) -> Result<R> {
		let r = self.write_remote(cmd)?;
		let v = TryInto::<serde_json::Value>::try_into(r)?;
		let v: Result<R> = serde_json::from_value(v)?;
		v
	}
	fn wr_ack(&mut self, cmd: TX) -> Result<()> {
		let r = self.write_read(cmd)?;
		bug_assert!(r == Response::Ack);
		Ok(())
	}

	/// Execute a syscall with the given `sysno` and `args`
	pub fn exec_raw_syscall<S: Into<Vec<TargetPtr>>>(
		&mut self, tid: Tid, sysno: usize, args: S,
	) -> Result<TargetPtr> {
		let cmd = RemoteCmd::syscall(tid, sysno, args.into());
		self.wr_value_remote(cmd)
	}
	/// Get all [Tid]s which have stopped
	pub fn get_stopped_tids(&mut self) -> Result<Vec<Tid>> {
		let r: Vec<Tid> = self
			.get_threads_status()?
			.into_iter()
			.filter(|x| x.status.is_stopped())
			.map(|x| x.id)
			.collect();
		Ok(r)
	}
	pub fn get_registers(&mut self, tid: Tid) -> Result<crate::Registers> {
		let cmd = RemoteCmd::get_registers(tid);
		self.wr_value_remote(cmd)
	}
	pub fn get_trampoline_addr(&mut self, tid: Tid, tramp: TrampType) -> Result<TargetPtr> {
		let cmd = RemoteCmd::get_trampoline_addr(tid, tramp);
		self.wr_value_remote(cmd)
	}
	pub fn run_until_trap(&mut self, tid: Tid) -> Result<()> {
		let cmd = RemoteCmd::run_until_trap(tid);
		self.wr_value_remote(cmd)
	}
	pub fn set_trampoline_code(&mut self, tramp: TrampType, code: Vec<u8>) -> Result<()> {
		let cmd = RemoteCmd::set_trampoline_code(tramp, code);
		self.wr_value_remote(cmd)
	}
	pub fn set_registers(&mut self, tid: Tid, regs: crate::Registers) -> Result<()> {
		let cmd = RemoteCmd::set_registers(tid, regs);
		self.wr_value_remote(cmd)
	}
	pub fn get_pid(&mut self) -> Result<Pid> {
		log::info!("get_pid started");
		let cmd = RemoteCmd::get_pid();
		let v = self.wr_value_remote(cmd);
		log::info!("get_pid over");
		v
	}
	pub fn get_tids(&mut self) -> Result<Vec<Tid>> {
		let cmd = RemoteCmd::get_tids();
		self.wr_value_remote(cmd)
	}
	pub fn get_threads_status(&mut self) -> Result<Vec<Thread>> {
		let cmd = RemoteCmd::get_threads_status();
		self.wr_value_remote(cmd)
	}
	pub fn read_c_string(&mut self, tid: Tid, addr: TargetPtr) -> Result<String> {
		let cmd = RemoteCmd::read_c_string(tid, addr);
		self.wr_value_remote(cmd)
	}
	pub fn exec_ret(&mut self, tid: Tid) -> Result<()> {
		let cmd = RemoteCmd::exec_ret(tid);
		self.wr_value_remote(cmd)
	}
	pub fn read_bytes(&mut self, tid: Tid, addr: TargetPtr, bytes: usize) -> Result<Vec<u8>> {
		let cmd = RemoteCmd::read_bytes(tid, addr, bytes);
		self.wr_value_remote(cmd)
	}
	pub fn write_bytes<B: Into<Vec<u8>>>(
		&mut self, tid: Tid, addr: TargetPtr, bytes: B,
	) -> Result<usize> {
		let cmd = RemoteCmd::write_bytes(tid, addr, bytes);
		self.wr_value_remote(cmd)
	}
	// pub fn call_func<T: Into<Vec<TargetPtr>>>(
	// 	&mut self,
	// 	tid: Tid,
	// 	func: TargetPtr,
	// 	args: T,
	// ) -> Result<TargetPtr> {
	// 	let cmd = RemoteCmd::call_func(tid, func, args.into());
	// 	self.wr_value_remote(cmd)
	// }
	client_read_int! { read_u8, u8 }
	client_read_int! { read_i8, i8 }
	client_read_int! { read_u16, u16 }
	client_read_int! { read_i16, i16 }
	client_read_int! { read_u32, u32 }
	client_read_int! { read_i32, i32 }
	client_read_int! { read_u64, u64 }
	client_read_int! { read_i64, i64 }

	client_read_int! { read_u128, u128 }
	client_read_int! { read_i128, i128 }

	pub fn write_int<T: num_traits::ops::bytes::ToBytes>(
		&mut self, tid: Tid, addr: TargetPtr, val: T,
	) -> Result<usize> {
		let bytes = val.to_ne_bytes().as_ref().to_vec();
		let cmd = RemoteCmd::write_bytes(tid, addr, bytes);
		self.wr_value_remote(cmd)
	}
	pub fn insert_bp(&mut self, tid: Tid, addr: TargetPtr) -> Result<()> {
		let cmd = RemoteCmd::insert_bp(tid, addr);
		self.wr_value_remote(cmd)
	}
	pub fn alloc_and_write_bp(&mut self, tid: Tid) -> Result<TargetPtr> {
		let cmd = RemoteCmd::alloc_and_write_bp(tid);
		self.wr_value_remote(cmd)
	}
	// pub fn remove_bp(&mut self, tid: Tid, addr: TargetPtr) -> Result<()> {
	// 	let cmd = RemoteCmd::remove_bp(tid, addr);
	// 	self.wr_value_remote(cmd)
	// }
	pub fn write_scratch_string<S: Into<String>>(
		&mut self, tid: Tid, string: S,
	) -> Result<TargetPtr> {
		let cmd = RemoteCmd::write_scratch_string(tid, string);
		self.wr_value_remote(cmd)
	}
	pub fn write_scratch_bytes<S: Into<Vec<u8>>>(
		&mut self, tid: Tid, bytes: S,
	) -> Result<TargetPtr> {
		let cmd = RemoteCmd::write_scratch_bytes(tid, bytes);
		self.wr_value_remote(cmd)
	}
	pub fn free_scratch_addr(&mut self, tid: Tid, addr: TargetPtr) -> Result<()> {
		let cmd = RemoteCmd::free_scratch_addr(tid, addr);
		self.wr_value_remote(cmd)
	}
}

impl Client<MasterComm, Response> {
	pub(crate) fn new_master_comm(
		tx: Sender<MasterComm>, rx: Receiver<Response>,
		wrap: Box<dyn ApiWrapper<MasterComm, Response> + Send>,
	) -> Self {
		Self::new(0, tx, rx, wrap)
	}
}

impl Client<Command, Response> {
	pub(crate) fn new_client(id: usize, tx: Sender<Command>, rx: Receiver<Response>) -> Self {
		let wrap = ClientGen;
		let wrap = Box::new(wrap);
		Self::new(id, tx, rx, wrap)
	}
	pub(crate) fn new_remote<
		R: std::io::Read + Send + 'static,
		W: std::io::Write + Send + 'static,
	>(
		id: usize, reader: BufReader<R>, writer: BufWriter<W>,
	) -> Self {
		let wrap = ClientGen;
		let wrap = Box::new(wrap);
		let stream = ClientStream::new(reader, writer);
		let stream = Box::new(stream);
		Self { id, wrap, stream }
	}
	pub(crate) fn prepare_load_client(&mut self) -> Result<()> {
		let cmd = Command::prepare_load_client();
		self.wr_ack(cmd)
	}

	/// Step one instruction forward, one time.
	///
	/// Because single-stepping is so slow, this should not be used as a
	/// solution to search for a program state. This should only be used when we
	/// need to advance one instruction and then take some steps. Re-inserting a
	/// SW breakpoint is one example; on break we must write original
	/// instruction, advance one step, and write back breakpoint instruction.
	///
	/// **NB!** The caller will not receive a callback from this unless they
	/// have registered for `SIGTRAP` signals.
	pub fn step_ins(&mut self, tid: Tid, count: usize) -> Result<()> {
		let cmd = ThreadCmd::StepIns { count };
		let cmd = RemoteCmd::Thread { tid, cmd };
		let cmd = Command::Tracer { cmd };
		self.wr_ack(cmd)?;
		Ok(())
	}
	pub fn send_event(&mut self, event: Event) -> Result<()> {
		log::debug!("sending event {event:?}");
		let cmd = Command::send_event(event);
		self.wr_ack(cmd)
	}
	pub fn init_done(&mut self) -> Result<()> {
		let cmd = Command::init_done();
		self.wr_ack(cmd)
	}
	pub fn detach(&mut self) -> Result<()> {
		log::debug!("Sending detach");
		let cmd = Command::detach();
		self.wr_ack(cmd)
	}
	pub fn add_logger(&mut self, format: LogFormat, output: LogOutput) -> Result<()> {
		let cmd = Command::add_logger(format, output);
		self.wr_ack(cmd)?;
		Ok(())
	}
	pub fn detach_thread(&mut self, tid: Tid) -> Result<()> {
		log::debug!("Sending detach");
		let cmd = Command::detach_thread(tid);
		self.wr_ack(cmd)
	}
	pub fn set_config(&mut self, config: Args) -> Result<()> {
		let cmd = Command::set_config(config);
		self.wr_ack(cmd)
	}
	pub fn set_config_thread(&mut self, tid: Tid, config: Args) -> Result<()> {
		let cmd = Command::set_config_thread(tid, config);
		self.wr_ack(cmd)
	}
	pub fn get_config(&mut self) -> Result<Option<Args>> {
		let cmd = Command::get_config();
		let r = self.write_read(cmd)?;
		let v: serde_json::Value = TryInto::<serde_json::Value>::try_into(r)?;
		let v: Option<Args> = serde_json::from_value(v)?;
		Ok(v)
	}
	pub fn get_config_thread(&mut self, tid: Tid) -> Result<Option<Args>> {
		let cmd = Command::get_config_thread(tid);
		let r = self.write_read(cmd)?;
		let v: serde_json::Value = TryInto::<serde_json::Value>::try_into(r)?;
		let v: Option<Args> = serde_json::from_value(v)?;
		Ok(v)
	}
	#[cfg(feature = "syscalls")]
	pub fn resolve_syscall<S: Into<String>>(&mut self, name: S) -> Result<usize> {
		let name: String = name.into();
		let cmd = Command::resolve_syscall(name);
		let r = self.write_read(cmd)?;
		let r: Option<usize> = match r {
			Response::Value(v) => serde_json::from_value(v)?,
			_ => {
				log::warn!("got unexpected value {r:?} when resolving syscall");
				None
			}
		};
		let r = r.ok_or(Error::NotFound)?;
		Ok(r)
	}
	#[cfg(not(feature = "syscalls"))]
	pub fn resolve_syscall<S: Into<String>>(&mut self, _name: S) -> Result<usize> {
		Err(Error::unsupported())
	}
	pub(crate) fn remove_client(&mut self, cid: usize) -> Result<()> {
		let cmd = Command::remove_client(cid);
		self.wr_ack(cmd)
	}
	pub fn wait(&mut self) -> Result<Response> {
		log::trace!("sending Wait command");
		let cmd = Command::Manager {
			cmd: ManagerCmd::Wait,
		};
		let r = self.write_read(cmd)?;
		Ok(r)
	}
}

pub(crate) struct IdWrapper {
	id: usize,
}
impl IdWrapper {
	pub fn new(id: usize) -> Self {
		Self { id }
	}
}
impl ApiWrapper<MasterComm, Response> for IdWrapper {
	fn wrap(&self, cmd: RemoteCmd) -> (usize, MasterComm) {
		let ocmd = Command::Tracer { cmd };
		(self.id, MasterComm::new(self.id, ocmd))
	}
	fn is_match(&self, _id: usize, _rsp: &Response) -> bool {
		true
	}
	fn unwrap(&self, rsp: Response) -> Response {
		rsp
	}
}
