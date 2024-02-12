#!/usr/bin/env rust-script
//! Run qemu instance
//!
//! ```cargo
//! [dependencies]
//! clap = { version = "4", features = ["derive"] }
//! anyhow = "1"
//! log = "0.4"
//! pretty_env_logger = "0.4"
//! timeout-readwrite = "0.3.3"
//! clap-verbosity-flag = { version = "2" }
//! # memfd-exec = "2.1.0"
//! # qemu = { version = "0.1.10", features = ["qemu-system-aarch64"] }
//! ```

use std::fs::OpenOptions;
use timeout_readwrite::TimeoutReader;
use clap::Parser;
use std::path::PathBuf;
use std::process::Child;
use std::process::ChildStdout;
use std::process::ChildStdin;
use std::process::ChildStderr;
use std::io::Read;
use std::process::Command;
use std::io::BufRead;
use std::io::{BufWriter, BufReader};
use anyhow::Result;
use std::io::Write;
use std::process::Stdio;
use timeout_readwrite::TimeoutReadExt;
use std::time::Duration;

#[derive(Debug, Clone, Eq, PartialEq)]
enum Arch {
	X86,
	X86_64,
	Aarch64,
	ArmEabi,
}
impl Arch {
	fn qemu_from_arch(&self) -> String {
		match self {
			Self::ArmEabi => String::from("qemu-system-arm"),
			Self::X86 => String::from("qemu-system-i386"),
			Self::X86_64 => String::from("qemu-system-x86_64"),
			Self::Aarch64 => String::from("qemu-system-aarch64"),
		}
	}
}
impl std::str::FromStr for Arch {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"armeabi" => Ok(Self::ArmEabi),
			"x86" => Ok(Self::X86),
			"x86_64" => Ok(Self::X86_64),
			"aarch64" => Ok(Self::Aarch64),
			_ => Err(anyhow::Error::msg("unsupported arch")),
		}
	}
}
impl std::fmt::Display for Arch {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{:?}", self))
	}
}


#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[command(flatten)]
	verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::WarnLevel>,

	#[arg(long)]
	arch: Arch,

	#[arg(long)]
	kernel: PathBuf,

	#[arg(long)]
	disk: PathBuf,

	#[arg(long)]
	identity: PathBuf,

	#[arg(long)]
	pubkey: PathBuf,

	#[arg(long)]
	upload: Option<String>,

	#[arg(long, default_value_t = String::from("root"))]
	user: String,

	#[arg(long, default_value_t = 10023)]
	port: usize,

	#[arg(long)]
	no_snapshot: bool,

	#[arg(trailing_var_arg = true, allow_hyphen_values = true)]
	args: Vec<String>,
}

struct RunQemu {
	args: Args,
	child: Child,
	stderr: ChildStderr,
	stdin: ChildStdin,
	stdout: TimeoutReader<ChildStdout>,
	useradded: bool,
	prog: Option<String>,
	progargs: Vec<String>,
}
impl RunQemu {
	
	pub fn new(mut args: Args) -> Result<Self> {
		let mut cargs = std::mem::take(&mut args.args);

		let prog = if !cargs.is_empty() {
			Some(cargs.remove(0))
		} else {
			None
		};
		let qemubin = args.arch.qemu_from_arch();
		let mut c = Command::new(qemubin);
		let c = c.stdin(Stdio::piped());
		let c = c.stdout(Stdio::piped());
		let mut c = c.stderr(Stdio::piped());
		c.arg("-nographic");
		if !args.no_snapshot {
			c.arg("-snapshot");
		}
		c.arg("-smp");
		c.arg("4");
		c.arg("-m");
		c.arg("1G");
		c.arg("-kernel");
		c.arg(&args.kernel);

		match args.arch {
			Arch::Aarch64 => {
				c.arg("-hda");
				c.arg(&args.disk);
				c.arg("-net");
				c.arg("nic");
				c.arg("-machine");
				c.arg("virt");
				c.arg("-cpu");
				c.arg("max");
				c.arg("-append");
				c.arg("'console=ttyAMA0 root=/dev/vda earlyprintk=serial page_alloc.shuffle selinux=0 nokaslr'");
			},
			Arch::X86 => {
				c.arg("-drive");
				c.arg(format!("file={},if=virtio", args.disk.display()));
				c.arg("-net");
				c.arg("nic,model=virtio");
				c.arg("-M");
				c.arg("pc");
				c.arg("-append");
				c.arg("rootwait root=/dev/vda console=tty1 console=ttyS0");
			},
			Arch::ArmEabi => {
				c.arg("-M");
				c.arg("vexpress-a9");
				c.arg("-drive");
				c.arg(format!("file={},if=sd", args.disk.display()));
				c.arg("-append");
				c.arg("rootwait console=ttyAMA0,115200 root=/dev/mmcblk0");
				c.arg("-net");
				c.arg("nic,model=lan9118");
				c.arg("-dtb");
				c.arg("scripts/images/arm-linux-gnueabi/vexpress-v2p-ca9.dtb");
			},
			_ => todo!(),
		}

		c.arg("-net");
		c.arg(format!("user,hostfwd=tcp::{}-:22", args.port));
		log::debug!("spawning {c:?}");
		

		let mut child = c.spawn().expect("unable to spawn qemu");
		let stdout = child.stdout.take()
			.expect("no stdout")
			.with_timeout(
				Duration::new(45, 0)
			);
		let stderr = child.stderr.take().expect("");
		let stdin = child.stdin.take().expect("");
		let r = Self { args, child, stdout, stdin, stderr, useradded: false, prog, progargs: cargs };
		Ok(r)
	}
	fn ssh_copy(&mut self, from: &str, to: &str) -> Result<()> {
		log::debug!("copying {from} -> {to}");
		let out = Command::new("scp")
			.arg("-o")
			.arg("StrictHostKeyChecking=no")
			.arg("-o")
			.arg("UserKnownHostsFile=/dev/null")
			.arg("-P")
			.arg(format!("{}", self.args.port))
			.arg("-i")
			.arg(&self.args.identity)
			.arg(from)
			.arg(format!("{}@localhost:{to}", self.args.user))
			.output()
			.expect("");
		log::trace!("out {out:?}");
		std::thread::sleep(std::time::Duration::from_millis(100));
		Ok(())
	}
	fn ssh_exec(&mut self, cmd: &str, args: &[String]) -> Result<String> {
		log::info!("ssh exec {cmd} {args:?}");
		let out = Command::new("ssh")
			.arg("-q")	// quiet
			.arg("-o")	// Set option
			.arg("BatchMode=yes")
			.arg("-o")	// Set option
			.arg("StrictHostKeyChecking=no")
			.arg("-o")	// Set option
			.arg("UserKnownHostsFile=/dev/null")
			.arg("-p")
			.arg(format!("{}", self.args.port))
			.arg("-i")
			.arg(&self.args.identity)
			.arg(format!("{}@localhost", self.args.user))
			.arg(format!("'{cmd}'"))
			.args(args)
			.output()
			.expect("unable to exec '{cmd}'");
		let outstr = std::str::from_utf8(&out.stdout)?;
		let errstr = std::str::from_utf8(&out.stderr)?;
		let err = if errstr != "" {
			log::warn!("err {errstr}");
			Some(errstr.to_string())
		} else {
			None
		};

		let succ = out.status.success();
		if succ {
			Ok(outstr.to_string())
		} else {
			let err = format!("cmd err {err:?}");
			Err(anyhow::Error::msg(err))
		}
	}
	fn is_alive(&mut self) -> bool {
		match self.child.try_wait() {
			Ok(Some(status)) => false,
			Ok(None) => true,
			Err(e) => {
				log::debug!("error attempting to wait: {e}");
				false
			}
		}
	}
	fn read_stderr(&mut self) -> Result<String> {
		let mut data = Vec::new();
		self.stderr.read_to_end(&mut data)?;
		let data = std::str::from_utf8(&data)?;
		Ok(data.to_string())
	}
	fn run_until(mut self) -> Result<()> {
		log::debug!("run until {:?}", self.child);
		if !self.is_alive() {
			let err = self.read_stderr()?;
			log::debug!("err {err}");
			return Err(anyhow::Error::msg(err));
		}

		self.run_until_out("buildroot login: ")?;
		self.write_cmd("root")?;

		self.useradded = self.ensure_user()?;

		let ret = self.ssh_exec("id", &[]);
		if let Ok(id) = ret {
			log::info!("id '{id}'");
		} else {
			log::warn!("unable to run id command, trying to add pubkey");
			self.write_pubkey()?;
			let id = self.ssh_exec("id", &[])?;
			log::info!("id {id:?}");
		}

		if let Some(upload) = &self.args.upload {
			let upload = upload.clone();
			let mut home = self.remote_home();
			home.push('/');
			self.ssh_copy(&upload, &home)?;
		}

		if let Some(prog) = &self.prog {
			let prog = prog.clone();
			let out = self.ssh_exec(&prog, &self.progargs.clone())?;
			log::info!("FINAL: {out}");
		} else {
			log::warn!("no command supplied");
		}

		log::debug!("powering off");
		self.write_child("poweroff\n")?;

		// Some Qemu instances will hang at the end
		log::debug!("stopping qemu");
		for i in 0..20 {
			if let Some(n) = self.child.try_wait()? {
				break;
			} else {
				log::trace!("[{i}]: target not done yet");
				std::thread::sleep(std::time::Duration::from_millis(1500));
			}
		}
		Ok(())
	}
	fn write_child(&mut self, value: &str) -> Result<()> {
		self.stdin.write_all(value.as_bytes())?;
		self.stdin.flush()?;
		Ok(())
	}
	fn ensure_user(&mut self) -> Result<bool> {
		let cmd = format!("su {}", self.args.user);
		let mut lines = self.write_cmd(&cmd)?;
		log::debug!("lines {lines:?}");
		assert!(lines.remove(0).starts_with(&cmd));
		assert_eq!(lines.pop().expect(""), "# ");

		if lines.is_empty() {
			let cmd = format!("exit");
			let _lines = self.write_cmd(&cmd)?;
			Ok(false)
		} else {
			self.add_user()?;
			Ok(true)
		}
	}
	fn delete_user(&mut self) -> Result<()> {
		let cmd = format!("deluser --remove-home {}", self.args.user);
		let lines = self.write_cmd(&cmd)?;
		log::debug!("lines {lines:?}");
		Ok(())
	}
	fn add_user(&mut self) -> Result<()> {
		let user = self.args.user.clone();

		// Ensure home directory exists
		let cmd = format!(r#"mkdir -p /home"#);
		let mut lines = self.write_cmd(&cmd)?;
		log::debug!("lines {lines:?}");

		let cmd = format!(r#"adduser --disabled-password --gecos "" {user}"#);
		let mut lines = self.write_cmd(&cmd)?;
		log::debug!("lines {lines:?}");

		let cmd = format!(r#"passwd -u {user}"#);
		let mut lines = self.write_cmd(&cmd)?;
		log::debug!("lines {lines:?}");
		Ok(())
	}
	fn remote_home(&self) -> String {
		if self.args.user == "root" {
			String::from("/root")
		} else {
			format!("/home/{}", self.args.user)
		}
	}
	fn write_pubkey(&mut self) -> Result<()> {
		let key = &self.args.pubkey;
		let home = self.remote_home();
		let mut file = OpenOptions::new().read(true).open(key)?;
		let mut data = Vec::new();
		file.read_to_end(&mut data)?;
		let data = std::str::from_utf8(&data)?;

		let cmd = format!(r#"mkdir {home}/.ssh"#);
		self.write_cmd(&cmd)?;

		let cmd = format!(r#"echo "{data}" >> {home}/.ssh/authorized_keys"#);
		self.write_cmd(&cmd)?;

		let cmd = format!(r#"chown {}:{} {home}/.ssh/authorized_keys"#, self.args.user, self.args.user);
		self.write_cmd(&cmd)?;

		let cmd = format!(r#"chmod 400 {home}/.ssh/authorized_keys"#);
		self.write_cmd(&cmd)?;
		Ok(())
	}
	fn write_cmd(&mut self, value: &str) -> Result<Vec<String>> {
		log::debug!("cmd {value}");
		self.stdin.write_all(value.as_bytes())?;
		self.stdin.write_all(b"\n")?;
		self.stdin.flush()?;
		let v = self.run_until_out("# ")?;
		Ok(v)
	}
	fn run_until_out(&mut self, check: &str) -> Result<Vec<String>> {
		let mut ret = Vec::new();
		let mut data = [0; 1];
		let mut line = String::new();
		loop {
			match self.stdout.read_exact(&mut data) {
				Ok(_) => {},
				Err(e) => {
					log::debug!("got err {e:?}");
					return Err(e)?;
				},
			}
			let v = data[0];
			if v == b'\n' {
				log::debug!("L '{line:?}'");
				ret.push(std::mem::take(&mut line));
				line.clear();
			} else if v == b'\r' {
			} else {
				line.push(v as char);
				if line == check {
					break;
				}
			}
		}
		ret.push(line);
		Ok(ret)
	}
}

impl Drop for RunQemu {
    fn drop(&mut self) {
		// Ensure we don't leave any qemu instances hanging around
        log::debug!("Dropping");
		self.child.kill().unwrap();
		log::debug!("waiting after drop");
		self.child.wait().unwrap();
    }
}

fn main() -> Result<()> {
	let args = Args::parse();
	pretty_env_logger::formatted_builder()
        .filter_level(args.verbose.log_level_filter())
        .init();
	log::info!("starting");

	let mut qemu = RunQemu::new(args)?;
	std::thread::sleep(std::time::Duration::from_millis(100));
	qemu.run_until()?;

	Ok(())
}
