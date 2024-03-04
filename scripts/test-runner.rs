#!/usr/bin/env rust-script
//! Run qemu instance
//!
//! ```cargo
//! [dependencies]
//! clap = { version = "4", features = ["derive"] }
//! anyhow = "1"
//! log = "0.4"
//! pretty_env_logger = "0.4"
//! # timeout-readwrite = "0.3.3"
//! clap-verbosity-flag = { version = "2" }
//! toml = "0.8.10"
//! serde = { version = "1.0", features = ["derive"]}
//! serde_json = "1.0"
//! ```

use std::collections::HashMap;
use clap::Parser;
use std::path::PathBuf;
use anyhow::{Result, Error};
use std::process::Command;

#[derive(Clone, Debug, serde::Deserialize)]
struct SshArgs {
	user: String,
	host: String,
	port: u16,
	identity: PathBuf,
	adb: Option<String>,
}
impl SshArgs {
	fn run(&self, _arch: String, bin: PathBuf, args: Vec<String>) -> Result<()> {
		let mut ssh = Ssh::new(self.clone());
		let _ = ssh.exec("id", &[])?;
		ssh.copy_to(&bin, "~/")?;
		let name = bin.file_name().unwrap().to_str().unwrap();
		let mut fpath = format!("/home/{}/", self.user);
		fpath.push_str(name);
		if let Some(adb) = &self.adb {
			let base = vec![
				String::from("-s"),
				adb.clone(),
			];
			let mut eargs = base.clone();
			let ins = vec![
				String::from("push"),
				fpath.clone(),
				String::from("/data/local/tmp/"),
			];
			eargs.extend(ins);
			ssh.exec("adb", &eargs)?;

			let mut eargs = base.clone();
			let ins = vec![
				String::from("shell"),
				String::from("RUST_TEST_TIME_UNIT=50000,50000"),
				format!("/data/local/tmp/{name}"),
				String::from("-Zunstable-options"),
				String::from("--ensure-time"),
			];
			eargs.extend(ins);
			eargs.extend(args);
			ssh.exec("adb", &eargs)?;
		} else {
			let cmd = format!("RUST_TEST_TIME_UNIT=50000,50000");
			let mut eargs = vec![
				fpath.clone(),
				String::from("-Zunstable-options"),
				String::from("--ensure-time")
			];
			eargs.extend(args);
			let nargs = eargs.join(" ");

			let mut s = Command::new("ssh");
			s.arg("-o");
			s.arg("BatchMode=yes");
			s.arg("-o");
			s.arg("StrictHostKeyChecking=no");
			s.arg("-o");
			s.arg("UserKnownHostsFile=/dev/null");
			s.arg("-p");
			s.arg(format!("{}", self.port));
			s.arg("-i");
			s.arg(&self.identity);
			s.arg(format!("{}@{}", self.user, self.host));
			s.arg(format!("{cmd}"));
			s.arg(format!("{nargs}"));

			let out = s.output()
				.expect("unable to exec");
			let outstr = std::str::from_utf8(&out.stdout)?;
			log::debug!("out {outstr}");
			let errstr = std::str::from_utf8(&out.stderr)?;
			let _err = if errstr != "" {
				log::warn!("err {errstr}");
				Some(errstr.to_string())
			} else {
				None
			};

			let succ = out.status.success();
			if !succ {
				return Err(Error::msg("failed to exec cmd"));
			}
		}
		Ok(())
	}
}

struct Ssh {
	args: SshArgs,
}

impl Ssh {
	fn new(args: SshArgs) -> Self {
		Self { args }
	}
	fn copy_to(&mut self, from: &PathBuf, to: &str) -> Result<()> {
		log::debug!("copying {from:?} -> {to}");
		let out = Command::new("scp")
			.arg("-P")
			.arg(format!("{}", self.args.port))
			.arg("-i")
			.arg(&self.args.identity)
			.arg(from)
			.arg(format!("{}@{}:{to}", self.args.user, self.args.host))
			.output()
			.expect("");
		log::trace!("out {out:?}");
		// TODO: See if this helps against error on chmod +x <to/prog>
		std::thread::sleep(std::time::Duration::from_millis(100));
		Ok(())
	}
	fn exec(&mut self, cmd: &str, args: &[String]) -> Result<(String, Option<String>)> {
		log::info!("exec {cmd} {args:?}");
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
			.arg(format!("{}@{}", self.args.user, self.args.host))
			.arg(format!("'{cmd}'"))
			.args(args)
			.output()
			.expect("unable to exec '{cmd}'");
		let outstr = std::str::from_utf8(&out.stdout)?;
		log::debug!("out {outstr}");
		let errstr = std::str::from_utf8(&out.stderr)?;
		let err = if errstr != "" {
			log::warn!("err {errstr}");
			Some(errstr.to_string())
		} else {
			None
		};

		let succ = out.status.success();
		if succ {
			Ok((outstr.to_string(), err))
		} else {
			Err(Error::msg("failed to exec cmd"))
		}
	}	
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[command(flatten)]
	verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::WarnLevel>,

	#[arg(long, default_value = "runner_config.toml")]
	config: String,

	#[arg(long, default_value = "output")]
	target_dir: String,

	#[arg(long)]
	features: Vec<String>,

	#[arg(long)]
	all_features: bool,

	#[arg(long)]
	target: Vec<String>,

	#[arg(long)]
	no_run: bool,

	#[arg(trailing_var_arg = true, allow_hyphen_values = true)]
	pub args: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct HostArgs {
	adb: Option<String>,
}
impl HostArgs {
	fn run(&self, _arch: String, bin: PathBuf, args: Vec<String>) -> Result<()> {
		// Not implemented yet
		assert!(self.adb.is_none());
		log::debug!("running on host {bin:?} | {args:?}");
		let out = Command::new(bin)
			.env("RUST_TEST_TIME_UNIT", "50000,50000")
			.arg("-Zunstable-options")
			.arg("--ensure-time")
			.args(args)
			.output()?;
		if !out.status.success() {
			let err = std::str::from_utf8(&out.stderr)?;
			log::error!("Not success stderr: {err:?}");
			return Err(Error::msg("host: cmd returned error code"))
		} else {
			let stdout = std::str::from_utf8(&out.stdout)?;
			println!("stdout {stdout}");
			Ok(())
		}
	}
}

#[derive(Debug, serde::Deserialize)]
struct QemuArgs {
	user: String,
	disk: PathBuf,
	kernel: PathBuf,
	identity: PathBuf,
	pubkey: PathBuf,
	arch: String,
}
impl QemuArgs {
	fn run(&self, _arch: String, bin: PathBuf, args: Vec<String>) -> Result<()> {
		let fname = bin.file_name().unwrap().to_str().unwrap();
		log::info!("running {bin:?} in Qemu");
		let mut cmd = Command::new("rust-script");
		cmd.arg("./scripts/qemu-runner.rs");
		cmd.arg("-v");
		cmd.arg("--arch");
		cmd.arg(&self.arch);
		cmd.arg("--kernel"); 
		cmd.arg(&self.kernel);
		cmd.arg("--disk");
		cmd.arg(&self.disk);
		cmd.arg("--identity");
		cmd.arg(&self.identity);
		cmd.arg("--pubkey");
		cmd.arg(&self.pubkey);
		cmd.arg("--user");
		cmd.arg(&self.user);
		cmd.arg("--upload");
		cmd.arg(&bin);
		cmd.arg(format!("/home/{}/{fname}", self.user));
		cmd.args(args);
		log::info!("qemu command: {cmd:?}");

		let out = cmd.output().expect("qemu test failed");
		let stdout = std::str::from_utf8(&out.stdout)?;
		let stderr = std::str::from_utf8(&out.stderr)?;
		log::error!("OUT: {stdout}");
		log::error!("ERR: {stderr}");
	
		if !out.status.success() {
			Err(Error::msg("qemu test failed"))
		} else {
			Ok(())
		}
	}
}

#[derive(Debug, serde::Deserialize)]
struct Config {
	ssh: Option<HashMap<String,SshArgs>>,
	host: Option<HashMap<String, HostArgs>>,
	qemu: Option<HashMap<String, QemuArgs>>,
}

impl Config {
	fn run(&self, arch: String, bin: PathBuf, args: Vec<String>) -> Result<()> {
		log::info!("running {arch}: {bin:?}");
		if let Some(host) = self.host.as_ref() {
			if let Some(h) = host.get(&arch) {
				h.run(arch, bin, args)?;
				return Ok(());
			}
		}
		if let Some(ssh) = self.ssh.as_ref() {
			if let Some(s) = ssh.get(&arch) {
				s.run(arch, bin, args)?;
				return Ok(());
			}
		}
		if let Some(qemu) = self.qemu.as_ref() {
			if let Some(q) = qemu.get(&arch) {
				q.run(arch, bin, args)?;
				return Ok(());
			}
		}
		return Err(Error::msg(format!("no configured test runner for {arch}")));
	}
}

fn main() -> anyhow::Result<()> {
	let mut args = Args::parse();
	pretty_env_logger::formatted_builder()
		.filter_level(args.verbose.log_level_filter())
		.init();
	log::info!("starting");
	let config = std::fs::read(&args.config)?;
	let config = std::str::from_utf8(&config)?;
	let config: Config = toml::from_str(&config)?;
	log::debug!("config {config:?}");

	let mut cmd = Command::new("cross");
	cmd.arg("test");
	cmd.arg("--message-format=json");
	cmd.arg("--no-run");
	cmd.arg("--quiet");
	cmd.arg(format!("--target-dir={}", args.target_dir));
	for feature in args.features.iter() {
		cmd.arg(format!("--features={feature}"));
	}
	if args.all_features {
		cmd.arg(format!("--all-features"));
	}
	for target in args.target.iter() {
		cmd.arg(format!("--target={target}"));
	}
	let testpaths = exec_test(cmd)?;

	log::debug!("testing {testpaths:?}");
	let mut realtests = Vec::new();
	let base = PathBuf::from(args.target_dir.clone());
	for path in testpaths.into_iter() {
		let p = PathBuf::from(path);
		let p = p.strip_prefix("/target/").unwrap();
		let out = base.join(p);
		assert!(out.is_file());
		realtests.push(out);
	}

	if !args.no_run {
		let cargs = std::mem::take(&mut args.args);

		for path in realtests.into_iter() {
			let target = extract_arch(&path);
			config.run(target, path, cargs.clone())?;
		}
	} else {
		log::info!("no_run set, not executing");
	}
	log::info!("everything succeeded");
	Ok(())
}

fn extract_arch<P: Into<PathBuf>>(buf: P) -> String {
	let buf: PathBuf = buf.into();
	let mut comps = buf.components();
	let _out = comps.next().unwrap();
	let target = comps.next().unwrap();
	target.as_os_str().to_str().unwrap().to_string()

}

fn exec_test(mut cmd: Command) -> Result<Vec<String>> {
	log::debug!("cmd = {cmd:?}");
	let out = cmd.output().expect("cross test failed");

	let mut testpaths = Vec::new();
	let stdout = std::str::from_utf8(&out.stdout)?;

	if !out.status.success() {
		println!("{stdout}");
		return Err(Error::msg("failed compile tests"));
	}
	
	for line in stdout.split('\n') {
		if !line.is_empty() {
			log::trace!("{line}");
			let v: serde_json::Value = serde_json::from_str(line)?;
			log::trace!("{v}");
			if let Some(reason) = v.get("reason") {
				if reason == "build-finished" {
					let succ = v.get("success")
						.unwrap()
						.as_bool()
						.unwrap();
					assert!(succ);
				} else if reason == "compiler-artifact" {
					let exe = v.get("executable").unwrap();
					let target = v.get("target").unwrap();
					let test = target.get("test")
						.unwrap()
						.as_bool()
						.unwrap();
					if exe.is_string() && test {
						testpaths.push(
							exe.as_str().unwrap().to_string()
						);
					}
				} else if reason == "compiler-message" || reason == "build-script-executed" {
					continue;
				} else {
					log::trace!("reason {reason}");
				}
			}
			
		}
	}
	
	Ok(testpaths)
}