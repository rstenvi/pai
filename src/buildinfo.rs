// Info about program created when program is built
// This is included by build.rs so should be as minimal as possible

#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BuildVersion {
	major: usize,
	minor: usize,
	patch: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildArch {
	Aarch64,
	Aarch32,
	X86_64,
	X86,
	Mips,
	RiscV64,
}

impl std::str::FromStr for BuildArch {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"aarch64" => Ok(Self::Aarch64),
			"arm" => Ok(Self::Aarch32),
			"x86_64" => Ok(Self::X86_64),
			"x86" => Ok(Self::X86),
			"mips" => Ok(Self::Mips),
			"riscv64" => Ok(Self::RiscV64),
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

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildEndian {
	Little,
	Big,
	Native,
}

impl std::str::FromStr for BuildEndian {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"little" => Ok(Self::Little),
			"big" => Ok(Self::Big),
			"native" => Ok(Self::Native),
			_ => Err(anyhow::Error::msg(format!("unknown endian {s}"))),
		}
	}
}

#[derive(Default, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum BuildEnv {
	#[default]
	Undefined,
	Gnu,
	Musl,
	Uclibc,
}

impl std::str::FromStr for BuildEnv {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"" => Ok(Self::Undefined),
			"gnu" => Ok(Self::Gnu),
			"musl" => Ok(Self::Musl),
			"uclibc" => Ok(Self::Uclibc),
			_ => Err(anyhow::Error::msg(format!("unknown env {s}"))),
		}
	}
}

#[derive(Default, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
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
	pub arch: BuildArch,
	pub os: BuildOs,
	pub endian: BuildEndian,
	pub ptrwidth: usize,
	pub abi: BuildAbi,
	pub env: BuildEnv,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct BuildInfo {
	linker: String,
	version: BuildVersion,
	triple: String,
	pub target: BuildTarget,
	githash: Option<String>,
}

#[cfg(test)]
mod test {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn buildinfo() {
		assert_eq!(BuildAbi::from_str("eabi").unwrap(), BuildAbi::Eabi);
		assert!(BuildAbi::from_str("qwert").is_err());

		assert_eq!(BuildArch::from_str("Aarch64").unwrap(), BuildArch::Aarch64);
		assert!(BuildArch::from_str("qwert").is_err());

		assert_eq!(
			BuildEndian::from_str("little").unwrap(),
			BuildEndian::Little
		);
		assert!(BuildEndian::from_str("qwert").is_err());

		assert_eq!(BuildOs::from_str("lInux").unwrap(), BuildOs::Linux);
		assert!(BuildOs::from_str("qwert").is_err());

		assert_eq!(BuildEnv::from_str("GNU").unwrap(), BuildEnv::Gnu);
		assert!(BuildEnv::from_str("qwert").is_err());
	}
}
