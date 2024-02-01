// Info about program created when program is built
// This is included by build.rs so should be as minimal as possible

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BuildVersion {
	major: usize,
	minor: usize,
	patch: usize,
}
impl BuildVersion {
	// used by build.rs
	#[allow(unused)]
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum BuildArch {
	Aarch64,
	Aarch32,
	X86_64,
	X86,
}

impl std::str::FromStr for BuildArch {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"aarch64" => Ok(Self::Aarch64),
			"arm" => Ok(Self::Aarch32),
			"x86_64" => Ok(Self::X86_64),
			"x86" => Ok(Self::X86),
			_ => Err(anyhow::Error::msg(format!("unknown arch {s}"))),
		}
	}
}

#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildOs {
	Linux,
	Android,
}

impl std::str::FromStr for BuildOs {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"linux" => Ok(Self::Linux),
			"android" => Ok(Self::Android),
			_ => Err(anyhow::Error::msg("unknown os")),
		}
	}
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum BuildEndian {
	Little,
	Big,
}

impl std::str::FromStr for BuildEndian {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"little" => Ok(Self::Little),
			"big" => Ok(Self::Big),
			_ => Err(anyhow::Error::msg(format!("unknown endian {s}"))),
		}
	}
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub enum BuildEnv {
	#[default]
	Undefined,
	Gnu,
	Musl,
}

impl std::str::FromStr for BuildEnv {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"" => Ok(Self::Undefined),
			"gnu" => Ok(Self::Gnu),
			"musl" => Ok(Self::Musl),
			_ => Err(anyhow::Error::msg(format!("unknown env {s}"))),
		}
	}
}


#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub enum BuildAbi {
	#[default]
	Undefined,
	Eabi,
	Eabihf,
}

impl std::str::FromStr for BuildAbi {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"" => Ok(Self::Undefined),
			"eabi" => Ok(Self::Eabi),
			"eabihf" => Ok(Self::Eabihf),
			_ => Err(anyhow::Error::msg(format!("unknown abi {s}"))),
		}
	}
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BuildTarget {
	arch: BuildArch,
	os: BuildOs,
	endian: BuildEndian,
	ptrwidth: usize,
	abi: BuildAbi,
	env: BuildEnv,
}
impl BuildTarget {
	pub fn new(arch: BuildArch, os: BuildOs, endian: BuildEndian, ptrwidth: usize, abi: BuildAbi, env: BuildEnv) -> Self {
		Self {
			arch,
			os,
			endian,
			ptrwidth,
			abi,
			env,
		}
	}
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct BuildInfo {
	linker: String,
	version: BuildVersion,
	triple: String,
	target: BuildTarget,
	githash: Option<String>,
}

impl BuildInfo {
	#[allow(unused)]
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
	// fn linker(&self) -> &str {
	// 	&self.linker
	// }
}
