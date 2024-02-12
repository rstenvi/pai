use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs::File, io::Write};

#[cfg(feature = "syscalls")]
use syzlang_parser::parser::{
	Arch, ArgOpt, ArgType, Argument, Const, Direction, Flag, Function, Parsed, Value,
};

include!("src/buildinfo.rs");

impl BuildVersion {
	fn new(s: &str) -> Self {
		let mut vs = Vec::new();
		for part in s.split('.') {
			if let Ok(n) = part.parse::<usize>() {
				vs.push(n);
			}
		}
		assert!(vs.len() == 3);
		let major = vs.remove(0);
		let minor = vs.remove(0);
		let patch = vs.remove(0);
		Self {
			major,
			minor,
			patch,
		}
	}
}

impl BuildInfo {
	fn new<S1: Into<String>, S2: Into<String>>(
		linker: S1,
		version: BuildVersion,
		target: BuildTarget,
		triple: S2,
		githash: Option<String>,
	) -> Self {
		let linker = linker.into();
		let triple = triple.into();
		Self {
			linker,
			version,
			target,
			triple,
			githash,
		}
	}
}

impl BuildTarget {
	pub fn new(
		arch: BuildArch,
		os: BuildOs,
		endian: BuildEndian,
		ptrwidth: usize,
		abi: BuildAbi,
		env: BuildEnv,
	) -> Self {
		Self {
			arch,
			os,
			endian,
			ptrwidth,
			abi,
			env,
		}
	}
	fn cross_compile(&self) -> String {
		let os = match &self.os {
			BuildOs::Linux => "linux-",
			BuildOs::Android => "linux-android",
		};
		let env = if self.os == BuildOs::Linux {
			match self.env {
				BuildEnv::Undefined => "",
				BuildEnv::Gnu => "gnu",
				BuildEnv::Musl => "musl",
			}
		} else {
			""
		};

		let arch = match &self.arch {
			BuildArch::Aarch64 => "aarch64",
			BuildArch::Aarch32 => match &self.os {
				BuildOs::Linux => "arm",
				BuildOs::Android => "armv7a",
			},
			BuildArch::X86_64 => "x86_64",
			BuildArch::X86 => "i686",
			BuildArch::Mips => "mips",
			BuildArch::RiscV64 => "riscv64",
		};
		let abi = match &self.abi {
			BuildAbi::Undefined => "",
			BuildAbi::Eabi => "eabi",
			BuildAbi::Eabihf => "eabihf",
		};
		let sdklevel = "";
		//  = if self.os == BuildOs::Android {
		// 	""
		// } else { "" };
		format!("{arch}-{os}{env}{abi}{sdklevel}-")
	}
}

fn target_triple() -> String {
	let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
	let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

	let os = match os.as_str() {
		"linux" => "unknown-linux-gnu",
		"android" => "linux-android",
		_ => panic!("unsupported os {os}"),
	};
	let arch = match arch.as_str() {
		"x86_64" => "x86_64",
		"aarch64" => "aarch64",
		"arm" => "aarch32",
		"x86" => "i686",
		"mips" => "mips",
		"riscv64" => "riscv64",
		_ => panic!("unsupported arch {arch}"),
	};
	format!("{arch}-{os}")
}
fn target_cc(target: &BuildTarget) -> String {
	match &target.os {
		BuildOs::Linux => String::from("gcc"),
		BuildOs::Android => String::from("clang"),
	}
}

fn get_build_info() -> anyhow::Result<BuildInfo> {
	let version = env!("CARGO_PKG_VERSION");
	let version = BuildVersion::new(version);
	let manifest = env!("CARGO_MANIFEST_DIR");

	let manifest = std::path::PathBuf::from(manifest);
	let mut buf = manifest.clone();
	buf.push(".cargo");
	buf.push("config.toml");

	let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
	let arch = BuildArch::from_str(&arch).unwrap();
	let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
	let os = BuildOs::from_str(&os).unwrap();
	let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap();
	let endian = BuildEndian::from_str(&endian).unwrap();

	let abi = std::env::var("CARGO_CFG_TARGET_ABI").unwrap();
	let abi = BuildAbi::from_str(&abi).unwrap();

	let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();
	let env = BuildEnv::from_str(&env).unwrap();

	let ptrwidth = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
	let ptrwidth = ptrwidth.parse::<usize>().unwrap();
	let btarget = BuildTarget::new(arch, os, endian, ptrwidth, abi, env);

	let hash = std::env::var("CARGO_MAKE_GIT_HEAD_LAST_COMMIT_HASH_PREFIX");

	let hash: Option<String> = hash.ok();
	let triple = target_triple();

	let linker = format!("{}{}", btarget.cross_compile(), target_cc(&btarget));
	Ok(BuildInfo::new(linker, version, btarget, triple, hash))
}

fn compile_testdata(scratch: &Path, info: &BuildInfo) -> anyhow::Result<PathBuf> {
	let cc = target_cc(&info.target);
	let cross_compile = info.target.cross_compile();

	let mut out = scratch.to_path_buf();
	out.push("testdata");
	out.push(&info.triple);
	if !out.exists() {
		std::fs::create_dir_all(&out)?;
	}

	let manifest = env!("CARGO_MANIFEST_DIR");
	let mut manifest = std::path::PathBuf::from(manifest);
	manifest.push("testdata");

	let ldflags = if info.target.os == BuildOs::Linux {
		"-lpthread"
	} else {
		""
	};
	let mut cmd = std::process::Command::new("make");
	let s = manifest.as_os_str();
	let s = s.to_str().expect("");
	cmd.args(["-C", s, "all"]);
	cmd.env("CC", cc);
	cmd.env("CROSS_COMPILE", cross_compile);
	cmd.env("OUT", &out);
	cmd.env("LDFLAGS", ldflags);
	println!("cmd {cmd:?}");

	let mut child = cmd.spawn().expect("make command failed");
	let r = child.wait().expect("wait on child failed");
	if !r.success() {
		// Ignore the error here because we don't want to fail compilation when
		// the user doesn't care about the tests. The actual tests will
		// eventually fail because the necessary files didn't exist.
		println!("WARN: failed to run make command, some tests might fail");
	}
	Ok(out)
}

#[cfg(feature = "syscalls")]
fn add_functions(parsed: &mut Parsed) {
	let args = vec![
		Argument::new("option", "int32", vec![]),
		Argument::new("arg2", "intptr", vec![]),
		Argument::new("arg3", "intptr", vec![]),
		Argument::new("arg4", "intptr", vec![]),
		Argument::new("arg5", "intptr", vec![]),
	];
	let prctl = Function::new("prctl".into(), args, ArgType::Int32);
	parsed.functions.push(prctl);

	let args = vec![
		Argument::new(
			"code",
			"flags",
			vec![ArgOpt::Ident("arch_prctl_flags".into())],
		),
		Argument::new("addr", "intptr", vec![]),
	];

	let arch_prctl = Function::new("arch_prctl".into(), args, ArgType::Int32);
	parsed.functions.push(arch_prctl);

	parsed.consts.add_if_new(Const::new(
		"ARCH_CET_STATUS",
		Value::Int(0x3001),
		vec![Arch::X86_64],
	));

	let flag = Flag::new(
		"arch_prctl_flags",
		vec![
			Value::Ident("ARCH_GET_FS".into()),
			Value::Ident("ARCH_ENABLE_TAGGED_ADDR".into()),
			Value::Ident("ARCH_FORCE_TAGGED_SVA".into()),
			Value::Ident("ARCH_GET_CPUID".into()),
			Value::Ident("ARCH_GET_GS".into()),
			Value::Ident("ARCH_GET_MAX_TAG_BITS".into()),
			Value::Ident("ARCH_GET_UNTAG_MASK".into()),
			Value::Ident("ARCH_GET_XCOMP_GUEST_PERM".into()),
			Value::Ident("ARCH_GET_XCOMP_PERM".into()),
			Value::Ident("ARCH_GET_XCOMP_SUPP".into()),
			Value::Ident("ARCH_MAP_VDSO_32".into()),
			Value::Ident("ARCH_MAP_VDSO_64".into()),
			Value::Ident("ARCH_MAP_VDSO_X32".into()),
			Value::Ident("ARCH_REQ_XCOMP_GUEST_PERM".into()),
			Value::Ident("ARCH_SET_CPUID".into()),
			Value::Ident("ARCH_SET_FS".into()),
			Value::Ident("ARCH_SET_GS".into()),
			Value::Ident("ARCH_SHSTK_DISABLE".into()),
			Value::Ident("ARCH_SHSTK_ENABLE".into()),
			Value::Ident("ARCH_SHSTK_LOCK".into()),
			Value::Ident("ARCH_SHSTK_STATUS".into()),
			Value::Ident("ARCH_SHSTK_UNLOCK".into()),
			Value::Ident("ARCH_CET_STATUS".into()),
		],
	);
	parsed.flags.push(flag);

	let a = ArgType::Ident("filename".into());
	let opts = vec![];
	let inarg = Argument::new_fake(a, opts);
	let args = vec![
		Argument::new(
			"filename",
			"ptr",
			vec![ArgOpt::Dir(Direction::In), ArgOpt::FullArg(Box::new(inarg))],
		),
		Argument::new("mode", "flags", vec![ArgOpt::Ident("access_flag".into())]),
	];
	let access = Function::new("access".into(), args, ArgType::Int32);
	parsed.consts.add_if_new(Const::new(
		"__NR_access",
		Value::Int(21),
		vec![Arch::X86_64],
	));

	parsed
		.consts
		.add_if_new(Const::new("R_OK", Value::Int(4), vec![Arch::X86_64]));
	parsed
		.consts
		.add_if_new(Const::new("W_OK", Value::Int(2), vec![Arch::X86_64]));
	parsed
		.consts
		.add_if_new(Const::new("X_OK", Value::Int(1), vec![Arch::X86_64]));

	let flag = Flag::new(
		"access_flag",
		vec![
			Value::Ident("X_OK".into()),
			Value::Ident("W_OK".into()),
			Value::Ident("R_OK".into()),
		],
	);
	parsed.flags.push(flag);

	parsed.functions.push(access);
}

#[cfg(feature = "syscalls")]
fn get_syscall_data(build: &BuildInfo) -> anyhow::Result<String> {
	let syzarch = match &build.target.arch {
		BuildArch::Aarch64 => syzlang_parser::parser::Arch::Aarch64,
		BuildArch::Aarch32 => syzlang_parser::parser::Arch::Aarch32,
		BuildArch::X86_64 => syzlang_parser::parser::Arch::X86_64,
		BuildArch::X86 => syzlang_parser::parser::Arch::X86,
		BuildArch::Mips => todo!(),
		BuildArch::RiscV64 => syzlang_parser::parser::Arch::Riscv64,
	};

	let data = syzlang_data::linux::PARSED
		.read()
		.expect("unable to acquire lock");
	let mut data = data.clone();

	add_functions(&mut data);

	data.insert_builtin().expect("unable to insert builtins");
	data.postprocess().expect("unable to postprocess");

	// data.consts.filter_arch(&syzarch);
	data.remove_virtual_functions();
	data.remove_func_no_sysno(&syzarch);
	data.remove_subfunctions();
	data.remove_aliases();
	data.remove_templates();
	data.remove_defines();
	data.remove_unions();
	data.remove_structs();

	let out = serde_json::to_string(&data)?;
	Ok(out)
}

fn acquire_lock(scratch: &Path) -> anyhow::Result<File> {
	let mut lock = PathBuf::from(scratch);
	lock.push("build.lock");
	let lock = std::fs::OpenOptions::new()
		.create(true)
		.write(true)
		.open(lock)
		.unwrap();
	let fd = lock.as_raw_fd();
	nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusive)?;
	Ok(lock)
}

fn main() -> anyhow::Result<()> {
	let scratch = scratch::path("pai");
	// for (key, value) in std::env::vars() {
	// 	if key.starts_with("CARGO_") {
	// 		println!("{}: {:?}", key, value);
	// 	}
	// }

	// For now, we do exclusive access of whole thing
	let lock = acquire_lock(&scratch)?;

	let build = get_build_info()?;
	let testdata = compile_testdata(&scratch, &build)?;
	println!("wroute testdata to {testdata:?}");

	#[cfg(feature = "syscalls")]
	let out = get_syscall_data(&build)?;
	#[cfg(not(feature = "syscalls"))]
	let out = String::from("");

	let outname = std::env::var_os("OUT_DIR").expect("unable to find OUT_DIR env variable");
	let mut outname = PathBuf::from(outname);

	outname.push("syscalls.json");
	println!("outname {outname:?}");
	std::fs::write(&outname, out.clone())?;
	outname.pop();
	outname.push("syscalls.json.gz");
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(out.as_bytes())?;
	let bytes = encoder.finish()?;
	std::fs::write(&outname, bytes)?;

	let info = serde_json::to_string(&build)?;
	outname.pop();
	outname.push("build_info.json");
	std::fs::write(&outname, info)?;

	// <https://rust-lang-nursery.github.io/rust-cookbook/compression/tar.html>
	outname.pop();
	outname.push("testdata.tar.gz");

	let tar_gz = std::fs::File::create(outname)?;
	let enc = flate2::write::GzEncoder::new(tar_gz, flate2::Compression::default());
	let mut tar = tar::Builder::new(enc);
	tar.append_dir_all("testdata", testdata)?;

	drop(lock);

	println!("cargo:rerun-if-changed=build.rs");
	println!("cargo:rerun-if-changed=testdata/Makefile");
	println!("cargo:rerun-if-changed=testdata/sleep.c");
	println!("cargo:rerun-if-changed=testdata/forkwait.c");
	println!("cargo:rerun-if-changed=testdata/waitpid.c");
	println!("cargo:rerun-if-changed=testdata/getpid.c");
	println!("cargo:rerun-if-env-changed=CARGO_CFG_FEATURE");
	println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET");
	Ok(())
}
