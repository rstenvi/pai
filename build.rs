use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use syzlang_parser::parser::{
	Arch, ArgOpt, ArgType, Argument, Const, Direction, Flag, Function, Parsed, Value,
};

include!("src/buildinfo.rs");

fn target_triple() -> String {
	let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
	let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
	let triple = match arch.as_str() {
		"x86_64" => match os.as_str() {
			"linux" => "x86_64-unknown-linux-gnu",
			"android" => "x86_64-linux-android",
			_ => panic!("unsupported os {os} on {arch}"),
		},
		"aarch64" => match os.as_str() {
			"linux" => "aarch64-unknown-linux-gnu",
			"android" => "aarch64-linux-android",
			_ => panic!("unsupported os {os} on {arch}"),
		},
		"x86" => match os.as_str() {
			"linux" => "i686-unknown-linux-gnu",
			"android" => "i686-linux-android",
			_ => panic!("unsupported os {os} on {arch}"),
		},
		_ => panic!("unsupported arch {arch}"),
	};
	triple.to_string()
}

fn get_build_info() -> anyhow::Result<BuildInfo> {
	use toml::Table;
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
	let ptrwidth = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
	let ptrwidth = ptrwidth.parse::<usize>().unwrap();
	let btarget = BuildTarget::new(arch, os, endian, ptrwidth);

	let hash = std::env::var("CARGO_MAKE_GIT_HEAD_LAST_COMMIT_HASH_PREFIX");

	let hash: Option<String> = hash.ok();

	if buf.is_file() {
		let data = std::fs::read(buf).unwrap();
		let data = std::str::from_utf8(&data).unwrap();
		let data = data.parse::<Table>().unwrap();
		let d: &toml::Value = &data["target"];
		println!("d = {d:?}");

		let triple = target_triple();
		let linker = if let Some(target) = d.get(&triple) {
			if let toml::Value::String(n) = &target["linker"] {
				n.clone()
			} else {
				panic!("");
			}
		} else {
			String::from("gcc")
		};
		Ok(BuildInfo::new(linker, version, btarget, triple, hash))
	} else {
		panic!("unable to find config.toml");
	}
}

fn compile_testdata(info: &BuildInfo) -> anyhow::Result<()> {
	for (key, value) in std::env::vars() {
		if key.starts_with("CARGO_") {
			println!("{}: {:?}", key, value);
		}
	}
	let manifest = env!("CARGO_MANIFEST_DIR");
	let mut manifest = std::path::PathBuf::from(manifest);
	manifest.push("testdata");

	let mut cmd = std::process::Command::new("make");
	let s = manifest.as_os_str();
	let s = s.to_str().expect("");
	cmd.args(["-C", s, "all"]);
	cmd.env("CC", info.linker());
	println!("cmd {cmd:?}");

	let mut child = cmd.spawn().expect("make command failed");
	let r = child.wait().expect("wait on child failed");
	assert!(r.success());
	Ok(())
}

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

fn main() -> anyhow::Result<()> {
	let build = get_build_info()?;
	compile_testdata(&build)?;

	let syzarch = match &build.target.arch {
		BuildArch::Aarch64 => syzlang_parser::parser::Arch::Aarch64,
		BuildArch::X86_64 => syzlang_parser::parser::Arch::X86_64,
		BuildArch::X86 => syzlang_parser::parser::Arch::X86,
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
	let testdata = env!("CARGO_MANIFEST_DIR");
	let mut testdata = PathBuf::from(testdata);
	testdata.push("testdata");

	outname.pop();
	outname.push("testdata.tar.gz");

	let tar_gz = std::fs::File::create(outname)?;
	let enc = flate2::write::GzEncoder::new(tar_gz, flate2::Compression::default());
	let mut tar = tar::Builder::new(enc);
	tar.append_dir_all("testdata", testdata)?;

	println!("cargo:rerun-if-changed=build.rs");
	println!("cargo:rerun-if-env-changed=CARGO_CFG_FEATURE");
	println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET");
	Ok(())
}
