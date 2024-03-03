use crate::{
	api::{
		messages::{Event, LogFormat, LogOutput, RegEvent},
		Command, Response,
	},
	Result,
};
use std::{
	fs::{File, OpenOptions},
	io::{BufWriter, Write},
	net::{SocketAddr, TcpStream},
	path::PathBuf,
};

trait Matches {
	fn cmd_matches(&self, cmd: &Command) -> Option<bool>;
	fn rsp_matches(&self, rsp: &Response) -> Option<bool>;
}

pub enum SyscallFilter {
	Any,
	Sysno { sysno: usize },
	Name { name: String },
}
impl Matches for SyscallFilter {
	fn cmd_matches(&self, _cmd: &Command) -> Option<bool> {
		todo!()
	}

	fn rsp_matches(&self, _rsp: &Response) -> Option<bool> {
		todo!()
	}
}

struct CheckEntry<T> {
	want: Vec<T>,
	nowant: Vec<T>,
}
impl<T> CheckEntry<T>
where
	T: Matches,
{
	fn add_want(&mut self, want: T) {
		self.want.push(want);
	}
	fn cmd_matches(&self, cmd: &Command) -> bool {
		self.want.last().unwrap().cmd_matches(cmd).unwrap()
	}
}

pub enum EventFilter {}

struct LogFilter {
	ignore_unmatch: bool,
	syscalls: CheckEntry<SyscallFilter>,
	// syscalls: Vec<SyscallFilter>,
	events: Vec<RegEvent>,
}
impl LogFilter {
	pub fn cmd_matches(&self, cmd: &Command) -> bool {
		if self.syscalls.cmd_matches(cmd) {
			true
		} else {
			!self.ignore_unmatch
		}
	}
}

trait LogSerializer {
	fn response(&mut self, val: &Response, out: &mut String) -> Result<()>;
	fn command(&mut self, val: &Command, out: &mut String) -> Result<()>;
	fn finish(&mut self, out: &mut String) -> Result<()>;
}

impl From<LogFormat> for Box<dyn LogSerializer> {
	fn from(value: LogFormat) -> Self {
		match value {
			LogFormat::Display => Box::<Display>::default(),
			LogFormat::Json => Box::new(Json::new_valid()),
		}
	}
}

#[derive(Default, Debug)]
pub struct Display;

impl LogSerializer for Display {
	fn response(&mut self, val: &Response, out: &mut String) -> Result<()> {
		let s = format!("{val:?}");
		out.push_str(s.as_str());
		Ok(())
	}
	fn command(&mut self, val: &Command, out: &mut String) -> Result<()> {
		let s = format!("{val:?}");
		out.push_str(s.as_str());
		Ok(())
	}
	fn finish(&mut self, _out: &mut String) -> Result<()> {
		Ok(())
	}
}

#[derive(Default, Debug)]
pub struct Json {
	started: bool,
	valid_json: bool,
	pending: Vec<char>,
}
impl Json {
	pub fn new_valid() -> Self {
		Self {
			started: false,
			valid_json: true,
			pending: Vec::new(),
		}
	}
	fn pre_run(&mut self, out: &mut String) {
		if !self.started {
			if self.valid_json {
				out.push('[');
			}
			self.started = true;
		}
		for c in std::mem::take(&mut self.pending).into_iter() {
			out.push(c);
		}
		if self.valid_json {
			self.pending.push(',');
		}
	}
	fn _finish(&mut self, out: &mut String) {
		out.push(']');
	}
}
impl LogSerializer for Json {
	fn response(&mut self, val: &Response, out: &mut String) -> Result<()> {
		self.pre_run(out);
		let val = serde_json::json!({"response": val});
		let s = serde_json::to_string(&val)?;
		out.push_str(s.as_str());
		Ok(())
	}
	fn command(&mut self, val: &Command, out: &mut String) -> Result<()> {
		self.pre_run(out);
		let val = serde_json::json!({"command": val});
		let s = serde_json::to_string(&val)?;
		out.push_str(s.as_str());
		Ok(())
	}
	fn finish(&mut self, out: &mut String) -> Result<()> {
		self._finish(out);
		Ok(())
	}
}

#[derive(Default)]
pub struct Loggers {
	loggers: Vec<Box<dyn Logger>>,
}
impl Loggers {
	pub fn add_logger(&mut self, format: LogFormat, output: LogOutput) -> Result<()> {
		let r = match output {
			LogOutput::File { path } => {
				Box::new(RealLogger::new_file(path, format)?) as Box<dyn Logger>
			}
			LogOutput::Tcp { addr } => {
				Box::new(RealLogger::new_connect(addr, format)?) as Box<dyn Logger>
			}
		};
		self.loggers.push(r);
		Ok(())
	}
	pub fn finish(&mut self) -> Result<()> {
		for log in self.loggers.iter_mut() {
			log.finish()?;
		}
		Ok(())
	}
	pub fn log_response(&mut self, rsp: &Response) -> Result<()> {
		for log in self.loggers.iter_mut() {
			log.log_response(rsp)?;
		}
		Ok(())
	}
	pub fn log_command(&mut self, cmd: &Command) -> Result<()> {
		for log in self.loggers.iter_mut() {
			log.log_cmd(cmd)?;
		}
		Ok(())
	}
}

pub trait Logger {
	fn log_cmd(&mut self, cmd: &Command) -> Result<()>;
	fn log_response(&mut self, rsp: &Response) -> Result<()>;
	fn finish(&mut self) -> Result<()>;
}

impl<W: std::io::Write> Logger for RealLogger<W> {
	fn log_cmd(&mut self, cmd: &Command) -> Result<()> {
		let mut s = String::new();
		self.serialize.command(cmd, &mut s)?;
		self.write.write_all(s.as_bytes())?;
		Ok(())
	}

	fn log_response(&mut self, rsp: &Response) -> Result<()> {
		let mut s = String::new();
		self.serialize.response(rsp, &mut s)?;
		self.write.write_all(s.as_bytes())?;
		Ok(())
	}
	fn finish(&mut self) -> Result<()> {
		let mut s = String::new();
		self.serialize.finish(&mut s)?;
		self.write.write_all(s.as_bytes())?;
		self.write.flush()?;
		Ok(())
	}
}

pub struct RealLogger<W: ?Sized + std::io::Write> {
	serialize: Box<dyn LogSerializer>,
	write: BufWriter<W>,
}

impl RealLogger<TcpStream> {
	pub fn new_connect(addr: SocketAddr, format: LogFormat) -> Result<Self> {
		let serialize = format.into();
		let stream = TcpStream::connect(addr)?;
		let write = BufWriter::new(stream);
		let ret = Self { serialize, write };
		Ok(ret)
	}
}
impl RealLogger<File> {
	pub fn new_file(path: PathBuf, format: LogFormat) -> Result<Self> {
		let serialize = format.into();
		let file = OpenOptions::new()
			.create(true)
			.truncate(true)
			.write(true)
			.open(path)?;
		let write = BufWriter::new(file);
		let ret = Self { serialize, write };
		Ok(ret)
	}
}
impl RealLogger<Vec<u8>> {
	pub fn new_in_mem(format: LogFormat) -> Result<Self> {
		let serialize = format.into();
		let file = Vec::new();
		let write = BufWriter::new(file);
		let ret = Self { serialize, write };
		Ok(ret)
	}
	pub fn get_written(self) -> Result<Vec<u8>> {
		let v = self.write.into_inner().unwrap();
		Ok(v)
	}
}
