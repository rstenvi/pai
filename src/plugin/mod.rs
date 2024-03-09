//! All the plugins which exist in code tree
//!
//! **NB!** This API is unstable and very unfinished, you probably don't want to
//! use it.

use crate::{
	api::{Client, Command, Response},
	ctx, Result,
};
use serde::{Deserialize, Serialize};
use std::{
	io::{BufReader, BufWriter, Read, Write},
	net::TcpStream,
	process::{self, Stdio},
	thread::JoinHandle,
};

pub mod plugins;

/// The different plugins supported
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub enum Plugin {
	#[cfg(feature = "syscalls")]
	DlopenDetect,
	#[cfg(feature = "syscalls")]
	Files,
	#[cfg(feature = "syscalls")]
	Mmap,
	#[cfg(feature = "syscalls")]
	Prctl,
	// External { name: String },
}
impl std::str::FromStr for Plugin {
	type Err = crate::Error;

	fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			#[cfg(feature = "syscalls")]
			"dlopen-detect" => Ok(Self::DlopenDetect),

			#[cfg(feature = "syscalls")]
			"files" => Ok(Self::Files),

			#[cfg(feature = "syscalls")]
			"mmap" => Ok(Self::Mmap),

			#[cfg(feature = "syscalls")]
			"prctl" => Ok(Self::Prctl),
			_ => Err(crate::Error::msg(format!("unkown plugin {}", s))),
		}
	}
}
impl std::fmt::Display for Plugin {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{self:?}"))
	}
}

macro_rules! plugin_enter_loop {
	() => {
		fn enter_loop(mut self) -> Result<()> {
			log::info!("entering loop");
			let stream = serde_json::Deserializer::from_reader(self.reader);

			for item in stream.into_iter::<Command>() {
				log::info!("item {item:?}");
				match item {
					Ok(cmd) => {
						let r = self.client.handle_cmd(cmd)?;
						let v = serde_json::to_string(&r)?;
						self.writer.write_all(v.as_bytes())?;
						self.writer.flush()?;
					}
					Err(e) => {
						log::error!("got error on input {e:?}");
						return Err(e.into());
					}
				}
			}
			Ok(())
		}
	};
}

struct PluginExtStream {
	reader: BufReader<TcpStream>,
	writer: BufWriter<TcpStream>,
	client: ctx::Secondary<(), crate::Error>,
}

impl PluginExtStream {
	fn new(stream: TcpStream, client: ctx::Secondary<(), crate::Error>) -> Self {
		// TODO:
		// - I don't know why this can't be forced to BufReader<Read> and
		//   BufWriter<Write>, but I can't get it to work
		// - Solved it with a macro instead, not the cleanest solution, but
		//   works
		let reader = BufReader::new(stream.try_clone().unwrap());
		let writer = BufWriter::new(stream);
		Self {
			reader,
			writer,
			client,
		}
	}
	plugin_enter_loop! {}
}

struct PluginExt<R, W: std::io::Write> {
	reader: BufReader<R>,
	writer: BufWriter<W>,
	client: ctx::Secondary<(), crate::Error>,
}
impl<R: std::io::Read, W: std::io::Write> PluginExt<R, W> {
	fn new(
		reader: BufReader<R>, writer: BufWriter<W>, client: ctx::Secondary<(), crate::Error>,
	) -> Self {
		log::info!("creating plugin mgr");
		Self {
			reader,
			writer,
			client,
		}
	}
	plugin_enter_loop! {}
}

pub struct PluginExec;

impl PluginExec {
	pub fn spawn(
		mut cmd: process::Command, client: crate::Client,
	) -> Result<JoinHandle<Result<()>>> {
		let handle = std::thread::spawn(move || -> Result<()> {
			let client = ctx::Secondary::new_second(client, ())?;
			let cmd = cmd.stdin(Stdio::piped());
			let cmd = cmd.stdout(Stdio::piped());
			let cmd = cmd.stderr(Stdio::piped());

			log::info!("spawning cmd {cmd:?}");
			let mut child = cmd.spawn()?;
			log::info!("got child {child:?}");

			let stdout = child.stdout.as_mut().expect("unable to get plugin stdout");
			let stdout = BufReader::new(stdout);

			let stdin = child.stdin.as_mut().expect("unable to get plugin stdin");
			let stdin = BufWriter::new(stdin);

			let stderr = child.stderr.as_mut().expect("unable to get plugin stderr");
			let mut stderr = BufReader::new(stderr);

			let plugin = PluginExt::new(stdout, stdin, client);
			plugin.enter_loop()?;

			let mut buf = String::new();
			stderr.read_to_string(&mut buf)?;
			println!("{buf}");

			Ok(())
		});
		Ok(handle)
	}
	pub fn connect_tcp_stream(
		stream: TcpStream, client: crate::Client,
	) -> Result<JoinHandle<Result<()>>> {
		let handle = std::thread::spawn(move || -> Result<()> {
			let client = ctx::Secondary::new_second(client, ())?;
			let plugin = PluginExtStream::new(stream, client);
			plugin.enter_loop()?;
			Ok(())
		});
		Ok(handle)
	}

	pub fn get_num_incoming_tcp<A: std::net::ToSocketAddrs>(
		ctx: ctx::Secondary<(), crate::Error>, addr: A, num: usize,
	) -> Result<Vec<JoinHandle<Result<()>>>> {
		let mut rets = Vec::new();
		let listener = std::net::TcpListener::bind(addr)?;

		for stream in listener.incoming() {
			let stream = stream.unwrap();
			let client = ctx.new_regular()?;
			let handle = Self::connect_tcp_stream(stream, client)?;
			rets.push(handle);
			if rets.len() >= num {
				break;
			}
		}
		Ok(rets)
	}
}

#[cfg(test)]
mod test {
	#[cfg(feature = "syscalls")]
	use std::str::FromStr;

	#[test]
	#[cfg(feature = "syscalls")]
	fn plugin_test() {
		assert_eq!(
			crate::plugin::Plugin::from_str("Files").unwrap(),
			crate::plugin::Plugin::Files
		);
		assert_eq!(
			crate::plugin::Plugin::from_str("MMAP").unwrap(),
			crate::plugin::Plugin::Mmap
		);
		assert!(crate::plugin::Plugin::from_str("qwerttyui").is_err());
	}
}
